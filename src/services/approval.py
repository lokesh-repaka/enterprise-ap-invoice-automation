"""
Invoice Approval Orchestration Service (P9-2, FR-13).

Orchestrates AP Clerk one-click approval (<= $10,000 USD, within PO tolerance) and
Finance Manager high-value / PO-variance sign-off (> $10,000 USD or > 5% PO variance)
per FR-13, BR-012a, BR-014, BR-015, PRD Journey 7, LLD §2.1 & §4, and
CLAUDE.md §2, §4.2, §8, §9, §16 Rule 8 & §16.1:
1. Loads invoice, active Vendor Master record, and line items via async SQL repositories.
2. Rejects non-approvable / already-approved / terminal statuses (409) and negative-balance
   credit notes (CLAUDE.md §16.1 -> 409).
3. Computes authoritative invoice-date USD equivalent via ``EscalationEvaluator`` and
   ``ExchangeRateRepository`` (blocking stale or missing FX bypasses) using thresholds
   read strictly from ``get_settings()``.
4. Enforces strict RBAC: ``REQUIRES_MANAGER_APPROVAL`` or >$10k USD / >5% PO variance
   requires ``finance_manager`` (``ap_clerk`` -> 403 Forbidden).
5. Executes legal FSM transitions (``VALIDATED -> APPROVED_CLERK``,
   ``REQUIRES_MANAGER_APPROVAL -> APPROVED_MANAGER``, or
   ``VALIDATED -> REQUIRES_MANAGER_APPROVAL -> APPROVED_MANAGER``) strictly through
   ``InvoiceStateMachine`` with atomic CAS optimistic locking (CWE-362).
6. Writes an immutable ``APPROVE`` audit record in an isolated database transaction via
   ``AuditLogger`` (CLAUDE.md §16 rule 9).

Layering invariant (CLAUDE.md §4.2):
- ``src/services/`` orchestrates repositories, validation rules, and audit logging.
- MUST NOT import FastAPI, Starlette, HTTP clients, OpenAI, or ``src/api/``.
"""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.audit import AuditActionType, AuditLogger
from src.core.config import get_settings
from src.core.logging import get_logger
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
    InvoiceRepository,
)
from src.validation.duplicate_detector import detect_credit_note
from src.validation.escalation_rules import EscalationEvaluator, MissingExchangeRateError
from src.validation.state_machine import (
    ActorRole,
    ConcurrentStateTransitionError,
    IllegalStateTransitionError,
    InvalidInvoiceStatusError,
    InvoiceStateMachine,
    InvoiceStatus,
    UnauthorizedStateTransitionError,
    parse_actor_role,
    parse_invoice_status,
)

logger = get_logger("ap.services.approval")

_APPROVABLE_ENTRY_STATUSES: frozenset[InvoiceStatus] = frozenset(
    {
        InvoiceStatus.VALIDATED,
        InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
    }
)

_ALLOWED_APPROVER_ROLES: frozenset[ActorRole] = frozenset(
    {
        ActorRole.AP_CLERK,
        ActorRole.FINANCE_MANAGER,
    }
)


# ---------------------------------------------------------------------------
# Typed Domain Exceptions (Mapped to HTTP status codes by src/api/approvals.py)
# ---------------------------------------------------------------------------


class ApprovalError(Exception):
    """Base domain exception for invoice approval failures."""


class ApprovalNotFoundError(ApprovalError, LookupError):
    """Raised when the requested invoice_id does not exist (HTTP 404)."""


class ApprovalForbiddenError(ApprovalError, PermissionError):
    """Raised when the authenticated actor lacks RBAC authority to approve (HTTP 403)."""


class ApprovalConflictError(ApprovalError, RuntimeError):
    """Raised on non-approvable status, credit note, or concurrent CAS conflict (HTTP 409)."""


class ApprovalValidationError(ApprovalError, ValueError):
    """Raised when domain prerequisites (active vendor, FX rate, dates) fail (HTTP 422)."""


# ---------------------------------------------------------------------------
# Service Input / Output DTOs (Decoupled from API/HTTP schemas)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalInput:
    """Verified approval command constructed from an authenticated Entra ID / demo principal."""

    invoice_id: str
    actor_id: str
    actor_role: ActorRole | str
    comment: str | None = None
    po_amount: Decimal | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class ApprovalOutcome:
    """Immutable receipt returned after verified approval persistence and audit logging."""

    invoice_id: str
    previous_status: str
    status: str
    approved_by: str
    approver_role: str
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal
    high_value_threshold_usd: Decimal
    requires_manager_approval: bool
    approved_at: datetime
    audit_event_id: str
    comment: str | None = None


# ---------------------------------------------------------------------------
# Approval Orchestration Service
# ---------------------------------------------------------------------------


class ApprovalService:
    """
    Deterministic invoice approval service enforcing RBAC thresholds, invoice-date ECB FX
    normalization, atomic FSM CAS transitions, and isolated-transaction audit logging.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def approve(self, cmd: ApprovalInput) -> ApprovalOutcome:
        """Validate RBAC + escalation thresholds, transition invoice status, and write APPROVE audit."""
        try:
            actor_role = parse_actor_role(cmd.actor_role)
        except ValueError:
            raise ApprovalForbiddenError(
                "Only authenticated ap_clerk or finance_manager users may approve invoices"
            ) from None

        if actor_role not in _ALLOWED_APPROVER_ROLES:
            raise ApprovalForbiddenError(
                "Only authenticated ap_clerk or finance_manager users may approve invoices"
            )

        async with self._session_factory() as session:
            inv_repo = InvoiceRepository(session)
            fx_repo = ExchangeRateRepository(session)

            # 1. Load invoice with vendor master & line items
            invoice = await inv_repo.get_by_id(
                cmd.invoice_id,
                include_relations=True,
                include_audit_logs=False,
            )
            if invoice is None:
                raise ApprovalNotFoundError("Invoice not found")

            # 2. Enforce approvable FSM entry state BEFORE RBAC/FX mutations
            try:
                previous_status = parse_invoice_status(invoice.status)
            except InvalidInvoiceStatusError as exc:
                raise ApprovalConflictError(str(exc)) from None

            if previous_status not in _APPROVABLE_ENTRY_STATUSES:
                raise ApprovalConflictError(
                    f"Invoice in status '{previous_status.value}' cannot be approved; "
                    "must be in VALIDATED or REQUIRES_MANAGER_APPROVAL"
                )

            # 3. Active Vendor Master & non-placeholder invoice prerequisite (SEC-178)
            if invoice.vendor is None or not invoice.vendor.is_active:
                raise ApprovalValidationError(
                    "Cannot approve invoice for an inactive or unresolved vendor"
                )
            if (
                invoice.vendor_tax_id.strip().upper() == "UNKNOWN"
                or invoice.invoice_number.strip().upper().startswith("PENDING-")
            ):
                raise ApprovalValidationError(
                    "Cannot approve an unextracted placeholder invoice record"
                )

            # 4. Unconditional negative-balance credit-note guard (CLAUDE.md §16.1, SEC-166)
            line_totals = tuple(line.line_total for line in invoice.lines)
            is_cn, _, _ = detect_credit_note(
                invoice.total_amount,
                subtotal=invoice.subtotal,
                line_totals=line_totals,
            )
            if is_cn:
                raise ApprovalConflictError(
                    "Negative-balance credit notes cannot be approved as regular invoices"
                )

            # 4b. BR-015 / SEC-177: AP Clerk one-click approval requires >= CONFIDENCE_HIGH_THRESHOLD
            #     across header & lines UNLESS the invoice was already human-reviewed/re-validated.
            if actor_role == ActorRole.AP_CLERK and previous_status == InvoiceStatus.VALIDATED:
                high_conf_threshold = Decimal(str(get_settings().CONFIDENCE_HIGH_THRESHOLD))
                scores = [invoice.confidence_macro_avg]
                scores.extend(
                    line.confidence_score
                    for line in invoice.lines
                    if line.confidence_score is not None
                )
                if min(scores) < high_conf_threshold:
                    prior_logs = await AuditLogRepository(session).get_by_invoice_id(cmd.invoice_id)
                    was_revalidated = any(
                        log.action_type == AuditActionType.REVALIDATE.value for log in prior_logs
                    )
                    if not was_revalidated:
                        raise ApprovalConflictError(
                            f"Invoice confidence below {high_conf_threshold}% requires clerk "
                            "review and re-validation prior to approval (BR-015)"
                        )

            # 5. Live authoritative USD conversion & escalation threshold evaluation (FR-13, BR-012a/014)
            currency = invoice.currency.strip().upper()
            evaluator = EscalationEvaluator(exchange_rate_repo=fx_repo)
            if currency == "USD":
                escalation_result = evaluator.evaluate(
                    total_amount=invoice.total_amount,
                    currency="USD",
                    po_amount=cmd.po_amount,
                    current_status=previous_status.value,
                )
            else:
                if invoice.invoice_date is None:
                    raise ApprovalValidationError(
                        "invoice_date is required to convert non-USD currency to USD"
                    )
                try:
                    escalation_result = await evaluator.evaluate_with_fx(
                        total_amount=invoice.total_amount,
                        currency=currency,
                        invoice_date=invoice.invoice_date,
                        po_amount=cmd.po_amount,
                        current_status=previous_status.value,
                    )
                except MissingExchangeRateError as exc:
                    raise ApprovalValidationError(str(exc)) from None
                except ValueError as exc:
                    raise ApprovalValidationError(str(exc)) from None

            # 6. Strict RBAC enforcement (CLAUDE.md §2, §8, §9, §16.1, FR-13)
            needs_manager = (
                previous_status == InvoiceStatus.REQUIRES_MANAGER_APPROVAL
                or escalation_result.requires_manager_approval
            )
            if needs_manager and actor_role != ActorRole.FINANCE_MANAGER:
                logger.warning(
                    "Blocked ap_clerk approval attempt on invoice requiring Finance Manager sign-off",
                    extra={
                        "invoice_id": cmd.invoice_id,
                        "actor_id": cmd.actor_id,
                        "previous_status": previous_status.value,
                        "high_value_exceeded": escalation_result.high_value_exceeded,
                        "po_variance_exceeded": escalation_result.po_variance_exceeded,
                    },
                )
                raise ApprovalForbiddenError(
                    "Finance Manager approval is required for invoices exceeding "
                    f"${escalation_result.high_value_threshold_usd} USD, exceeding "
                    f"{escalation_result.po_variance_tolerance_percent}% PO variance, "
                    "or routed to REQUIRES_MANAGER_APPROVAL"
                )

            final_status = (
                InvoiceStatus.APPROVED_MANAGER if needs_manager else InvoiceStatus.APPROVED_CLERK
            )

            # 7. Sync authoritative ECB-converted total_amount_usd if stale/missing (atomic CAS)
            if escalation_result.total_amount_usd != invoice.total_amount_usd:
                synced = await inv_repo.apply_revalidation_edits(
                    cmd.invoice_id,
                    expected_status=previous_status.value,
                    header_updates={"total_amount_usd": escalation_result.total_amount_usd},
                    line_updates=[],
                )
                if synced is None:
                    raise ApprovalConflictError(
                        f"Concurrent status conflict while syncing FX total for invoice '{cmd.invoice_id}'"
                    )

            # 8. Persist legal FSM transition(s) via InvoiceStateMachine with atomic CAS (CWE-362)
            escalated_from_validated = (
                previous_status == InvoiceStatus.VALIDATED
                and final_status == InvoiceStatus.APPROVED_MANAGER
            )
            state_machine = InvoiceStateMachine(inv_repo)
            try:
                if escalated_from_validated:
                    await state_machine.transition(
                        cmd.invoice_id,
                        InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                        actor_id=cmd.actor_id,
                        actor_role=actor_role,
                        expected_status=InvoiceStatus.VALIDATED,
                        reason="Escalated to Finance Manager approval prior to sign-off",
                    )
                    transition_receipt = await state_machine.transition(
                        cmd.invoice_id,
                        InvoiceStatus.APPROVED_MANAGER,
                        actor_id=cmd.actor_id,
                        actor_role=actor_role,
                        expected_status=InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                        reason=cmd.comment or "Approved by Finance Manager",
                    )
                else:
                    transition_receipt = await state_machine.transition(
                        cmd.invoice_id,
                        final_status,
                        actor_id=cmd.actor_id,
                        actor_role=actor_role,
                        expected_status=previous_status,
                        reason=cmd.comment or f"Approved by {actor_role.value}",
                    )
            except UnauthorizedStateTransitionError as exc:
                raise ApprovalForbiddenError(str(exc)) from None
            except (ConcurrentStateTransitionError, IllegalStateTransitionError) as exc:
                raise ApprovalConflictError(str(exc)) from None

            invoice_total = invoice.total_amount

        # 9. Write immutable audit record(s) in isolated transactions (CLAUDE.md §16 rule 9, SEC-177)
        audit_logger = AuditLogger(self._session_factory)
        audit_comment = (
            cmd.comment
            if cmd.comment
            else (
                f"Approved by {actor_role.value}: {previous_status.value} -> {final_status.value}"
            )
        )
        try:
            if escalated_from_validated:
                await audit_logger.record(
                    invoice_id=cmd.invoice_id,
                    user_id=cmd.actor_id,
                    action_type=AuditActionType.STATUS_TRANSITION,
                    field_name="status",
                    previous_value=InvoiceStatus.VALIDATED.value,
                    new_value=InvoiceStatus.REQUIRES_MANAGER_APPROVAL.value,
                    comment="Escalated to Finance Manager approval prior to sign-off",
                    request_id=cmd.request_id,
                )
            approve_prev_status = (
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL.value
                if escalated_from_validated
                else previous_status.value
            )
            audit_entry = await audit_logger.record(
                invoice_id=cmd.invoice_id,
                user_id=cmd.actor_id,
                action_type=AuditActionType.APPROVE,
                field_name="status",
                previous_value=approve_prev_status,
                new_value=final_status.value,
                comment=audit_comment,
                request_id=cmd.request_id,
            )
        except Exception as exc:
            logger.critical(
                "Invoice approval committed but immutable audit trail write failed",
                extra={
                    "invoice_id": cmd.invoice_id,
                    "actor_id": cmd.actor_id,
                    "final_status": final_status.value,
                    "error_type": type(exc).__name__,
                },
            )
            raise

        logger.info(
            "Invoice approved",
            extra={
                "invoice_id": cmd.invoice_id,
                "previous_status": previous_status.value,
                "final_status": final_status.value,
                "approver_role": actor_role.value,
                "requires_manager_approval": needs_manager,
                "audit_event_id": audit_entry.audit_id,
            },
        )

        return ApprovalOutcome(
            invoice_id=cmd.invoice_id,
            previous_status=previous_status.value,
            status=final_status.value,
            approved_by=cmd.actor_id,
            approver_role=actor_role.value,
            total_amount=invoice_total,
            currency=currency,
            total_amount_usd=escalation_result.total_amount_usd,
            high_value_threshold_usd=escalation_result.high_value_threshold_usd,
            requires_manager_approval=needs_manager,
            approved_at=transition_receipt.transitioned_at,
            audit_event_id=audit_entry.audit_id,
            comment=cmd.comment,
        )


__all__ = [
    "ApprovalConflictError",
    "ApprovalError",
    "ApprovalForbiddenError",
    "ApprovalInput",
    "ApprovalNotFoundError",
    "ApprovalOutcome",
    "ApprovalService",
    "ApprovalValidationError",
]
