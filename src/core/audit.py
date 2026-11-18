"""
Immutable Append-Only Audit Logger (P3-4).

Writes tamper-evident ``AuditLog`` entries to SQL via ``AuditLogRepository`` in an
isolated database session/transaction so audit records are NEVER rolled back if a
caller's business transaction fails (CLAUDE.md §6, §7.1, §16 rule 9).

Propagates active ``request_id`` from ``request_id_ctx`` into both persisted audit
metadata and structured JSON audit telemetry while protecting sensitive financial
identifiers from log leakage (N3, N8, CWE-532).
"""

import re
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.logging import get_logger, request_id_ctx
from src.database.models import AuditLog
from src.database.repositories import AuditLogRepository

logger = get_logger("ap.core.audit")

MAX_COMMENT_LENGTH: int = 1000
MAX_AUDIT_VALUE_LENGTH: int = 4096
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# Financial and tax fields requiring a mandatory reason_code on manual EDIT (CLAUDE.md §5)
FINANCIAL_AUDIT_FIELDS: frozenset[str] = frozenset(
    {
        "subtotal",
        "total_tax_amount",
        "total_amount",
        "total_amount_usd",
        "line_total",
        "line_tax_rate",
        "unit_price",
        "quantity",
    }
)

# Fields whose raw values must never be echoed into application logs (CLAUDE.md §8, N8)
SENSITIVE_AUDIT_FIELDS: frozenset[str] = frozenset(
    {
        "vendor_tax_id",
        "bank_account",
        "iban",
        "routing_number",
        "ssn",
    }
)


class AuditActionType(StrEnum):
    """Canonical immutable audit action types (LLD §3.1, CLAUDE.md §6)."""

    INGEST = "INGEST"
    EXTRACTION = "EXTRACTION"
    VALIDATION = "VALIDATION"
    EDIT = "EDIT"
    REVALIDATE = "REVALIDATE"
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    STATUS_TRANSITION = "STATUS_TRANSITION"
    EXPORT = "EXPORT"


class ReasonCode(StrEnum):
    """Mandatory correction reason codes for invoice edits (CLAUDE.md §5, BR-017)."""

    OCR_MISREAD = "OCR_MISREAD"
    VENDOR_ROUNDING = "VENDOR_ROUNDING"
    TAX_CODE_OVERRIDE = "TAX_CODE_OVERRIDE"
    VENDOR_DISCOUNT = "VENDOR_DISCOUNT"
    OTHER = "OTHER"


_ACTION_LOOKUP: dict[str, AuditActionType] = {a.value: a for a in AuditActionType}
_REASON_LOOKUP: dict[str, ReasonCode] = {r.value: r for r in ReasonCode}


def _parse_action_type(value: AuditActionType | str) -> AuditActionType:
    if isinstance(value, AuditActionType):
        return value
    if isinstance(value, str) and value.upper() in _ACTION_LOOKUP:
        return _ACTION_LOOKUP[value.upper()]
    raise ValueError(f"Unknown audit action_type: {value!r}")


def _parse_reason_code(value: ReasonCode | str | None) -> ReasonCode | None:
    if value is None:
        return None
    if isinstance(value, ReasonCode):
        return value
    if isinstance(value, str) and value.upper() in _REASON_LOOKUP:
        return _REASON_LOOKUP[value.upper()]
    raise ValueError(f"Unknown audit reason_code: {value!r}")


def _sanitize_text(value: str | None) -> str | None:
    if value is None:
        return None
    return _CONTROL_CHAR_RE.sub("", value)


def _format_audit_comment(comment: str | None, request_id: str) -> str | None:
    """Attach strictly validated request_id correlation prefix while respecting String(1000) bound."""
    clean_req = (
        request_id.strip()
        if isinstance(request_id, str) and _SAFE_REQUEST_ID_RE.match(request_id.strip())
        else ""
    )
    clean_comment = _sanitize_text(comment.strip()) if isinstance(comment, str) else ""

    prefix = f"[request_id={clean_req}]" if clean_req else ""
    if prefix and clean_comment:
        combined = f"{prefix} {clean_comment}"
    elif prefix:
        combined = prefix
    elif clean_comment:
        combined = clean_comment
    else:
        return None

    return combined[:MAX_COMMENT_LENGTH]


class AuditLogger:
    """
    Append-only immutable audit trail writer (CLAUDE.md §7.1, §16 rule 9).

    Opens a dedicated isolated ``AsyncSession`` per ``record()`` call so audit
    writes commit independently of caller business transactions. Exposes zero
    update or delete methods.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        *,
        invoice_id: str,
        user_id: str,
        action_type: AuditActionType | str,
        field_name: str | None = None,
        previous_value: str | None = None,
        new_value: str | None = None,
        reason_code: ReasonCode | str | None = None,
        comment: str | None = None,
        request_id: str | None = None,
    ) -> AuditLog:
        """
        Validate and persist an immutable ``AuditLog`` row in an isolated transaction.

        Enforces:
        - Canonical ``AuditActionType`` and ``ReasonCode`` enums.
        - No-op edit rejection (``previous_value == new_value`` on ``EDIT``).
        - Mandatory ``reason_code`` on financial/tax field edits.
        - Mandatory non-blank ``comment`` when ``reason_code == ReasonCode.OTHER``.
        - Automatic ``request_id`` propagation from ``request_id_ctx``.
        """
        if not isinstance(invoice_id, str) or not invoice_id.strip():
            raise ValueError("invoice_id must be a non-empty string")
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")

        if previous_value is not None and len(previous_value) > MAX_AUDIT_VALUE_LENGTH:
            raise ValueError(f"previous_value exceeds maximum length of {MAX_AUDIT_VALUE_LENGTH}")
        if new_value is not None and len(new_value) > MAX_AUDIT_VALUE_LENGTH:
            raise ValueError(f"new_value exceeds maximum length of {MAX_AUDIT_VALUE_LENGTH}")

        parsed_action = _parse_action_type(action_type)
        parsed_reason = _parse_reason_code(reason_code)
        clean_field = (
            field_name.strip() if isinstance(field_name, str) and field_name.strip() else None
        )

        # Reject no-op EDIT records (CLAUDE.md §16.1)
        if parsed_action is AuditActionType.EDIT:
            if (
                previous_value is not None
                and new_value is not None
                and previous_value.strip() == new_value.strip()
            ):
                raise ValueError(
                    "No-op audit log rejected: previous_value and new_value must differ on EDIT."
                )
            if (
                clean_field
                and clean_field.lower() in FINANCIAL_AUDIT_FIELDS
                and parsed_reason is None
            ):
                raise ValueError(
                    f"A valid reason_code is mandatory when editing financial field '{clean_field}'."
                )

        # ReasonCode.OTHER requires an explanatory comment (CLAUDE.md §5)
        if parsed_reason is ReasonCode.OTHER:
            if not isinstance(comment, str) or not comment.strip():
                raise ValueError("A non-empty comment is mandatory when reason_code is OTHER.")

        active_request_id = request_id if request_id is not None else request_id_ctx.get()
        formatted_comment = _format_audit_comment(comment, active_request_id)

        entry = AuditLog(
            invoice_id=invoice_id.strip(),
            user_id=user_id.strip()[:100],
            action_type=parsed_action.value,
            field_name=clean_field[:100] if clean_field else None,
            previous_value=previous_value,
            new_value=new_value,
            reason_code=parsed_reason.value if parsed_reason else None,
            comment=formatted_comment,
        )

        # Isolated session & transaction — survives caller rollbacks (CLAUDE.md §16 rule 9)
        async with self._session_factory() as isolated_session:
            repo = AuditLogRepository(isolated_session)
            persisted = await repo.create(entry)

        # Emit PII-safe structured telemetry (never echo sensitive field values)
        log_field = clean_field or "invoice"
        logger.info(
            f"Audit recorded: action={parsed_action.value} field={log_field}",
            extra={
                "audit_id": persisted.audit_id,
                "invoice_id": persisted.invoice_id,
                "actor_id": persisted.user_id,
                "action_type": parsed_action.value,
                "field_name": clean_field,
                "reason_code": persisted.reason_code,
                "is_sensitive_field": bool(
                    clean_field and clean_field.lower() in SENSITIVE_AUDIT_FIELDS
                ),
            },
        )
        return persisted

    async def get_invoice_audit_trail(self, invoice_id: str) -> list[AuditLog]:
        """Return chronological immutable audit trail for an invoice (read-only)."""
        async with self._session_factory() as session:
            repo = AuditLogRepository(session)
            return await repo.get_by_invoice_id(invoice_id)
