"""
Invoice Approval API Route (P9-2, FR-13).

Implements ``POST /api/v1/invoices/{id}/approve`` per FR-13, BR-014, BR-015,
PRD Journey 7, LLD §2.1 & §4, and CLAUDE.md §2, §3, §4.2, §8, §9, §16.1:
1. Enforces Entra ID / Demo RBAC (``ap_clerk`` and ``finance_manager``; ``system_admin`` -> 403).
2. Enforces bounded 64 KB JSON request size (anti-DoS CWE-400) and strict ``invoice_id`` path syntax.
3. Blocks ``approver_id`` actor spoofing (verifies optional payload ``approver_id`` against JWT).
4. Delegates all threshold, FX, FSM transition, and audit orchestration to ``ApprovalService``
   (``src/services/approval.py``) with zero validation logic in the API layer (CLAUDE.md §4.2).
"""

import re
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.api.invoices import get_upload_session_factory
from src.api.schemas.invoices import InvoiceApprovalRequest, InvoiceApprovalResponse
from src.core.logging import get_logger, request_id_ctx
from src.core.security import AuthenticatedUser, Role, require_role
from src.services.approval import (
    ApprovalConflictError,
    ApprovalForbiddenError,
    ApprovalInput,
    ApprovalNotFoundError,
    ApprovalService,
    ApprovalValidationError,
)

logger = get_logger("ap.api.approvals")

router = APIRouter(prefix="/api/v1/invoices", tags=["Approvals"])

_INVOICE_ID_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_APPROVAL_BODY_BYTES: int = 64 * 1024


async def guard_approval_content_length(request: Request) -> None:
    """Fail fast on oversized or malformed JSON bodies on /approve, including chunked streams (SEC-180, CWE-400)."""
    raw_len = request.headers.get("content-length")
    if raw_len is not None:
        try:
            declared_len = int(raw_len.strip())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header",
            ) from None
        if declared_len < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header",
            )
        if declared_len > MAX_APPROVAL_BODY_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Approval payload exceeds maximum limit of {MAX_APPROVAL_BODY_BYTES} bytes",
            )
    else:
        body_bytes = await request.body()
        if len(body_bytes) > MAX_APPROVAL_BODY_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Approval payload exceeds maximum limit of {MAX_APPROVAL_BODY_BYTES} bytes",
            )


def _resolve_effective_approver_role(user: AuthenticatedUser) -> str:
    """Resolve highest authorized approval role held by JWT principal (fail-closed: SEC-179)."""
    if user.has_role(Role.FINANCE_MANAGER):
        return Role.FINANCE_MANAGER.value
    if user.has_role(Role.AP_CLERK):
        return Role.AP_CLERK.value
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient permissions",
    )


@router.post(
    "/{invoice_id}/approve",
    status_code=status.HTTP_200_OK,
    response_model=InvoiceApprovalResponse,
    dependencies=[Depends(guard_approval_content_length)],
    summary="Execute one-click AP Clerk (<= $10k) or Finance Manager (> $10k) approval (P9-2)",
)
async def approve_invoice(
    invoice_id: str,
    response: Response,
    current_user: Annotated[
        AuthenticatedUser,
        Depends(require_role(Role.AP_CLERK, Role.FINANCE_MANAGER)),
    ],
    session_factory: Annotated[
        async_sessionmaker[AsyncSession],
        Depends(get_upload_session_factory),
    ],
    payload: Annotated[InvoiceApprovalRequest | None, Body()] = None,
) -> InvoiceApprovalResponse:
    """
    Approve a validated or manager-escalated invoice with strict role-threshold RBAC,
    live invoice-date ECB FX conversion, legal FSM state transition, and immutable
    ``APPROVE`` audit logging (FR-13, BR-014, BR-015, CLAUDE.md §9 & §16.1).
    """
    if not _INVOICE_ID_PATH_RE.match(invoice_id):
        raise HTTPException(status_code=422, detail="Invalid invoice_id format")

    req = payload or InvoiceApprovalRequest()

    # Anti-impersonation check (CWE-290 / CWE-345): optional approver_id MUST match verified JWT
    if req.approver_id is not None:
        allowed_identities = {current_user.user_id.lower()}
        if current_user.email:
            allowed_identities.add(current_user.email.lower())
        if req.approver_id.lower() not in allowed_identities:
            logger.warning(
                "Rejected approval request due to approver_id actor mismatch",
                extra={"invoice_id": invoice_id, "actor_id": current_user.user_id},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Actor mismatch: approver_id does not match authenticated user",
            )

    cmd = ApprovalInput(
        invoice_id=invoice_id,
        actor_id=current_user.user_id,
        actor_role=_resolve_effective_approver_role(current_user),
        comment=req.comment,
        po_amount=req.po_amount,
        request_id=request_id_ctx.get() or None,
    )

    service = ApprovalService(session_factory)
    try:
        outcome = await service.approve(cmd)
    except ApprovalNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invoice not found"
        ) from None
    except ApprovalForbiddenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from None
    except ApprovalConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except ApprovalValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except SQLAlchemyError as exc:
        logger.error(
            "Database error during invoice approval",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice database is temporarily unavailable",
        ) from None

    response.headers["Cache-Control"] = "no-store"
    return InvoiceApprovalResponse(
        invoice_id=outcome.invoice_id,
        previous_status=outcome.previous_status,
        status=outcome.status,
        approved_by=outcome.approved_by,
        approver_role=outcome.approver_role,
        total_amount=outcome.total_amount,
        currency=outcome.currency,
        total_amount_usd=outcome.total_amount_usd,
        high_value_threshold_usd=outcome.high_value_threshold_usd,
        requires_manager_approval=outcome.requires_manager_approval,
        approved_at=outcome.approved_at,
        audit_event_id=outcome.audit_event_id,
        comment=outcome.comment,
    )
