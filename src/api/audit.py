"""
Immutable Invoice Audit Trail API Route (P9-3).

Implements ``GET /api/v1/invoices/{id}/audit`` per BR-031, N3, N6, N8, PRD Screen 5,
LLD §2.1 & §3.1, and CLAUDE.md §4.2, §4.3, §6, §8, §9:
1. Enforces Entra ID / Demo RBAC for all three authorized roles
   (``ap_clerk``, ``finance_manager``, ``system_admin``; unauthenticated -> 401; no-role -> 403).
2. Exposes strictly read-only GET access (zero mutating HTTP verbs; append-only invariant).
3. Verifies invoice existence (404 on unknown invoice_id) and validates path & filter syntax
   against strict allowlists (zero XSS reflection, bounded query params, CWE-20/116/400).
4. Masks sensitive identifier fields (``SENSITIVE_AUDIT_FIELDS``: Tax IDs, IBAN, bank accounts,
   SSNs) as ``***-**-XXXX`` per CLAUDE.md §8 / N8 before returning to the UI.
5. Emits ``Cache-Control: no-store`` and PII-free structured JSON telemetry.
"""

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.api.invoices import get_upload_session_factory
from src.api.schemas.invoices import AuditEventResponse, InvoiceAuditTrailResponse
from src.core.audit import SENSITIVE_AUDIT_FIELDS, AuditActionType
from src.core.logging import get_logger
from src.core.security import AuthenticatedUser, Role, require_role
from src.database.repositories import AuditLogRepository, InvoiceRepository

logger = get_logger("ap.api.audit")

router = APIRouter(prefix="/api/v1/invoices", tags=["Audit"])

_INVOICE_ID_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_ALLOWED_ACTION_TYPES: frozenset[str] = frozenset(a.value for a in AuditActionType)
_MAX_ACTION_TYPE_PARAM_CHARS: int = 50

# Precision digit-bearing PII patterns for free-text audit comments (SEC-181, CLAUDE.md §8):
# Matches SSNs, US EINs (US-NN-NNNNNNN / NN-NNNNNNN), EU VAT IDs (DE/GB/ES + digits), and IBANs
# without corrupting English words, invoice statuses, or [request_id=...] prefixes.
_AUDIT_COMMENT_PII_RE = re.compile(
    r"\b(?:"
    r"\d{3}-\d{2}-\d{4}"  # SSN
    r"|(?:US-)?\d{2}-\d{7}"  # US EIN
    r"|[A-Z]{2}\d{2}[A-Z0-9]{11,30}"  # IBAN
    r"|(?:DE|GB|ES|FR|IT|NL)[A-Z]?\d{8,10}"  # EU VAT
    r")\b"
)


def _mask_token(raw: str) -> str:
    clean = raw.strip()
    if len(clean) >= 4:
        return f"***-**-{clean[-4:]}"
    return "***"


def _mask_sensitive_value(field_name: str | None, value: str | None) -> str | None:
    """
    Mask sensitive identifier values as ``***-**-XXXX`` per CLAUDE.md §8 / N8 (SEC-181, CWE-200).

    Inspects both exact and dotted/prefixed field names (e.g. ``vendor_tax_id`` and
    ``header.vendor_tax_id`` or ``vendor.iban``).
    """
    if value is None or not field_name:
        return value
    leaf_field = field_name.strip().lower().rsplit(".", 1)[-1]
    if leaf_field not in SENSITIVE_AUDIT_FIELDS:
        return value
    return _mask_token(value)


def _mask_sensitive_comment(comment: str | None) -> str | None:
    """Redact embedded SSN, EIN, EU VAT, or IBAN identifiers inside audit comments (SEC-181)."""
    if comment is None:
        return None
    return _AUDIT_COMMENT_PII_RE.sub(lambda m: _mask_token(m.group(0)), comment)


def _sanitize_optional_user_id(raw: str | None) -> str | None:
    """Validate optional user_id filter, rejecting control/bidi/blank strings (SEC-183, CWE-20/117/451)."""
    if raw is None:
        return None
    if _CONTROL_CHAR_RE.search(raw) or _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise HTTPException(status_code=422, detail="Invalid characters in user_id filter")
    trimmed = raw.strip()
    if not trimmed:
        raise HTTPException(status_code=422, detail="user_id filter cannot be blank")
    if len(trimmed) > 100:
        raise HTTPException(
            status_code=422, detail="user_id filter exceeds maximum length of 100 characters"
        )
    return trimmed


@router.get(
    "/{invoice_id}/audit",
    status_code=status.HTTP_200_OK,
    response_model=InvoiceAuditTrailResponse,
    summary="Retrieve full immutable chronological audit trail for an invoice (P9-3)",
)
async def get_invoice_audit_trail(
    invoice_id: str,
    response: Response,
    _current_user: Annotated[
        AuthenticatedUser,
        Depends(require_role(Role.AP_CLERK, Role.FINANCE_MANAGER, Role.SYSTEM_ADMIN)),
    ],
    session_factory: Annotated[
        async_sessionmaker[AsyncSession],
        Depends(get_upload_session_factory),
    ],
    action_type: Annotated[
        list[str] | None,
        Query(description="Filter by one or more canonical AuditActionType values"),
    ] = None,
    user_id: Annotated[
        str | None,
        Query(max_length=100, description="Filter by exact actor user_id"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> InvoiceAuditTrailResponse:
    """
    Return paginated, chronologically ordered immutable ``AuditLog`` entries for an invoice
    (BR-031, N3, PRD Screen 5, CLAUDE.md §9).
    """
    if not _INVOICE_ID_PATH_RE.match(invoice_id):
        raise HTTPException(status_code=422, detail="Invalid invoice_id format")

    validated_actions: list[str] | None = None
    if action_type is not None:
        if len(action_type) > len(_ALLOWED_ACTION_TYPES):
            raise HTTPException(
                status_code=422,
                detail="Too many action_type filter parameters supplied",
            )
        normalized: list[str] = []
        for raw_action in action_type:
            if len(raw_action) > _MAX_ACTION_TYPE_PARAM_CHARS:
                raise HTTPException(
                    status_code=422,
                    detail="Unsupported audit action_type filter",
                )
            act = raw_action.strip().upper()
            if act not in _ALLOWED_ACTION_TYPES:
                raise HTTPException(
                    status_code=422,
                    detail="Unsupported audit action_type filter",
                )
            if act not in normalized:
                normalized.append(act)
        validated_actions = normalized

    clean_user_id = _sanitize_optional_user_id(user_id)

    try:
        async with session_factory() as session:
            invoice = await InvoiceRepository(session).get_by_id(
                invoice_id,
                include_relations=False,
            )
            if invoice is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Invoice not found",
                )
            rows, total_events = await AuditLogRepository(session).list_for_invoice(
                invoice.invoice_id,
                action_types=validated_actions,
                user_id=clean_user_id,
                limit=limit,
                offset=offset,
            )
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.error(
            "Database error retrieving invoice audit trail",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice database is temporarily unavailable",
        ) from None

    events = [
        AuditEventResponse(
            audit_id=row.audit_id,
            invoice_id=row.invoice_id,
            user_id=row.user_id,
            action_type=row.action_type,
            field_name=row.field_name,
            previous_value=_mask_sensitive_value(row.field_name, row.previous_value),
            new_value=_mask_sensitive_value(row.field_name, row.new_value),
            reason_code=row.reason_code,
            comment=_mask_sensitive_comment(row.comment),
            timestamp=row.timestamp,
        )
        for row in rows
    ]

    filters_applied: dict[str, Any] = {
        k: v
        for k, v in {
            "action_type": validated_actions,
            "user_id": clean_user_id,
        }.items()
        if v is not None
    }

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    logger.info(
        "Retrieved invoice audit trail",
        extra={
            "invoice_id": invoice.invoice_id,
            "returned": len(events),
            "total_events": total_events,
            "limit": limit,
            "offset": offset,
        },
    )
    return InvoiceAuditTrailResponse(
        invoice_id=invoice.invoice_id,
        invoice_number=invoice.invoice_number,
        current_status=invoice.status,
        immutable=True,
        total_events=total_events,
        limit=limit,
        offset=offset,
        filters_applied=filters_applied,
        events=events,
    )
