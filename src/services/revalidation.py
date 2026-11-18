"""
Invoice Re-Validation Orchestration Service (P9-1, FR-12).

Orchestrates clerk edits and deterministic re-validation per CLAUDE.md §4.2, §7.4, §16.1,
BR-016, BR-017, BR-018, PRD Journey 5, and LLD §2.2 & §4:
1. Loads invoice, vendor master context, and line items via async SQL repositories.
2. Enforces FSM entry legality (``LEGAL_TRANSITIONS`` -> ``REVALIDATING``) with atomic CAS
   optimistic locking to prevent concurrent edit races (CWE-362).
3. Applies allowlisted header and line-item edits in memory and checks ``composite_hash``
   uniqueness against other active invoices (FR-09, CLAUDE.md §16.1).
4. Re-runs ``RulesEngine.validate_revalidation()`` (FR-05 line arithmetic, FR-06 invoice
   total, FR-07 multi-country tax, FR-08 date normalization, FR-11 credit-note check).
5. Re-evaluates routing via ``ConfidenceRouter.route_revalidation()`` while strictly
   preserving original model confidence scores unchanged (CLAUDE.md §7.4).
6. Evaluates high-value (>$10,000 USD via invoice-date ECB FX) and PO-variance (>5%)
   escalation rules via ``EscalationEvaluator`` (FR-13, BR-012a, BR-014, BR-018).
7. Persists updated invoice/line values and final FSM status transition
   (``REVALIDATING -> VALIDATED | REQUIRES_MANAGER_APPROVAL | REQUIRES_APPROVAL | CREDIT_NOTE``).
8. Writes immutable ``EDIT`` (for changed fields only) and ``REVALIDATE`` audit records in
   isolated database transactions via ``AuditLogger`` (CLAUDE.md §16 rule 9).

Layering invariant (CLAUDE.md §4.2):
- ``src/services/`` orchestrates repositories, validation rules, and audit logging.
- MUST NOT import FastAPI, Starlette, HTTP clients, or ``src/api/``.
"""

import unicodedata
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.audit import AuditActionType, AuditLogger, ReasonCode
from src.core.logging import get_logger
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
    InvoiceRepository,
    compute_composite_hash,
)
from src.validation.confidence_router import ConfidenceRouter
from src.validation.escalation_rules import EscalationEvaluator, MissingExchangeRateError
from src.validation.rules_engine import RulesEngine, VendorRuleContext
from src.validation.state_machine import (
    ActorRole,
    ConcurrentStateTransitionError,
    IllegalStateTransitionError,
    InvalidInvoiceStatusError,
    InvoiceStateMachine,
    InvoiceStatus,
    validate_transition,
)

logger = get_logger("ap.services.revalidation")

_MONEY_QUANTUM = Decimal("0.01")
_UNIT_QUANTUM = Decimal("0.0001")


# ---------------------------------------------------------------------------
# Typed Domain Exceptions (Mapped to HTTP status codes by src/api/invoices.py)
# ---------------------------------------------------------------------------


class RevalidationError(Exception):
    """Base domain exception for invoice re-validation failures."""


class RevalidationNotFoundError(RevalidationError, LookupError):
    """Raised when the requested invoice_id does not exist (HTTP 404)."""


class RevalidationConflictError(RevalidationError, RuntimeError):
    """Raised on illegal FSM status, concurrent CAS conflict, or composite_hash collision (HTTP 409)."""


class RevalidationValidationError(RevalidationError, ValueError):
    """Raised when re-validation inputs or domain prerequisites fail validation (HTTP 422)."""


class RevalidationNoOpError(RevalidationValidationError):
    """Raised when a re-validation edit has previous_value == new_value (P9-4, CLAUDE.md §16.1, HTTP 422)."""


# ---------------------------------------------------------------------------
# Service Input / Output DTOs (Decoupled from API/HTTP schemas)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeaderEditsInput:
    """Allowlisted header field overrides submitted by an AP Clerk."""

    invoice_number: str | None = None
    invoice_date: date | None = None
    due_date: date | None = None
    po_number: str | None = None
    subtotal: Decimal | None = None
    total_tax_amount: Decimal | None = None
    total_amount: Decimal | None = None


@dataclass(frozen=True)
class LineEditInput:
    """Allowlisted line-item field overrides keyed by existing ``line_number``."""

    line_number: int
    description: str | None = None
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    line_total: Decimal | None = None
    line_tax_rate: Decimal | None = None


@dataclass(frozen=True)
class RevalidationInput:
    """Complete verified input command for ``RevalidationService.revalidate``."""

    invoice_id: str
    actor_id: str
    reason_code: ReasonCode
    comment: str | None = None
    is_reverse_charge: bool = False
    is_exempt: bool = False
    po_amount: Decimal | None = None
    header_edits: HeaderEditsInput | None = None
    line_edits: tuple[LineEditInput, ...] = ()
    request_id: str | None = None


@dataclass(frozen=True)
class RevalidationOutcome:
    """Immutable orchestration result returned to the API controller."""

    invoice_id: str
    previous_status: str
    status: str
    is_revalidated: bool
    line_arithmetic_valid: bool
    invoice_total_valid: bool
    tax_valid: bool
    date_valid: bool
    all_passed: bool
    currency_converted_amount_usd: Decimal | None
    active_exceptions: tuple[str, ...]
    confidence_tier: str
    confidence_macro_avg: Decimal
    eligible_for_clerk_approval: bool
    requires_manager_approval: bool
    audit_event_id: str
    edited_fields: tuple[str, ...]


# ---------------------------------------------------------------------------
# Precision & Canonical Formatting Helpers
# ---------------------------------------------------------------------------


def _q_money(val: Decimal) -> Decimal:
    quantized = val.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if quantized == 0 else quantized


def _q_unit(val: Decimal) -> Decimal:
    quantized = val.quantize(_UNIT_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.0000") if quantized == 0 else quantized


def _norm_text(val: str | None) -> str | None:
    """Canonical Unicode NFC + trimmed comparison form preventing NFD/whitespace no-op evasion (CWE-176)."""
    if val is None:
        return None
    return unicodedata.normalize("NFC", val.strip())


def _fmt_money(val: Decimal | None) -> str | None:
    return f"{_q_money(val):.2f}" if val is not None else None


def _fmt_unit(val: Decimal | None) -> str | None:
    return f"{_q_unit(val):.4f}" if val is not None else None


def _fmt_date(val: date | None) -> str | None:
    return val.isoformat() if val is not None else None


# ---------------------------------------------------------------------------
# Re-Validation Orchestration Service
# ---------------------------------------------------------------------------


class RevalidationService:
    """
    Deterministic invoice re-validation service orchestrating repositories,
    Phase 7 Rules Engine, Phase 8 Confidence Router / State Machine / Escalation Evaluator,
    and Phase 3 immutable Audit Logger.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _restore_status_best_effort(
        self,
        invoice_id: str,
        previous_status: InvoiceStatus,
    ) -> None:
        """Atomically release a transient REVALIDATING lock back to previous_status on abort."""
        try:
            async with self._session_factory() as rollback_session:
                repo = InvoiceRepository(rollback_session)
                await repo.compare_and_update_status(
                    invoice_id,
                    expected_status=InvoiceStatus.REVALIDATING.value,
                    new_status=previous_status.value,
                )
        except Exception as exc:
            logger.error(
                "Failed best-effort rollback from REVALIDATING to prior status",
                extra={
                    "invoice_id": invoice_id,
                    "previous_status": previous_status.value,
                    "error_type": type(exc).__name__,
                },
            )

    async def revalidate(self, cmd: RevalidationInput) -> RevalidationOutcome:
        """Execute full clerk edit + deterministic re-validation + immutable audit workflow."""
        if not isinstance(cmd.reason_code, ReasonCode):
            raise RevalidationValidationError("A valid ReasonCode enum value is required")
        if cmd.reason_code is ReasonCode.OTHER and (
            not isinstance(cmd.comment, str) or not cmd.comment.strip()
        ):
            raise RevalidationValidationError(
                "A non-empty comment is mandatory when reason_code is OTHER"
            )
        # SEC-174 (CWE-840): Statutory tax overrides require explicit TAX_CODE_OVERRIDE or OTHER
        if (cmd.is_reverse_charge or cmd.is_exempt) and cmd.reason_code not in (
            ReasonCode.TAX_CODE_OVERRIDE,
            ReasonCode.OTHER,
        ):
            raise RevalidationValidationError(
                "is_reverse_charge and is_exempt require reason_code TAX_CODE_OVERRIDE or OTHER"
            )

        # SEC-185 (P9-4): Fast-fail empty service command before opening a DB session
        header_has_values = cmd.header_edits is not None and any(
            getattr(cmd.header_edits, f) is not None
            for f in (
                "invoice_number",
                "invoice_date",
                "due_date",
                "po_number",
                "subtotal",
                "total_tax_amount",
                "total_amount",
            )
        )
        if (
            not header_has_values
            and not cmd.line_edits
            and not cmd.is_reverse_charge
            and not cmd.is_exempt
        ):
            raise RevalidationNoOpError(
                "No-op edit rejected: at least one header edit, line edit, "
                "or tax override flag must be provided"
            )

        async with self._session_factory() as session:
            inv_repo = InvoiceRepository(session)
            fx_repo = ExchangeRateRepository(session)

            # 1. Load invoice with Vendor Master & ordered lines
            invoice = await inv_repo.get_by_id(
                cmd.invoice_id,
                include_relations=True,
                include_audit_logs=False,
            )
            if invoice is None:
                raise RevalidationNotFoundError("Invoice not found")

            if invoice.vendor is None:
                raise RevalidationValidationError("Invoice has no associated vendor master record")

            # SEC-176 (CWE-840): Never re-validate against an inactive or placeholder UNKNOWN vendor
            if not invoice.vendor.is_active:
                raise RevalidationValidationError(
                    "Cannot re-validate invoice for an inactive or unresolved vendor"
                )

            # 2. Pre-check FSM entry legality (blocks UPLOADED/EXTRACTING/APPROVED/TERMINAL -> 409)
            try:
                previous_status, _ = validate_transition(
                    invoice.status,
                    InvoiceStatus.REVALIDATING,
                    actor_role=ActorRole.AP_CLERK,
                )
            except (IllegalStateTransitionError, InvalidInvoiceStatusError) as exc:
                raise RevalidationConflictError(str(exc)) from None

            # 3. Validate line_edits reference existing persisted lines
            existing_lines_by_num = {line.line_number: line for line in invoice.lines}
            for edit in cmd.line_edits:
                if edit.line_number not in existing_lines_by_num:
                    raise RevalidationValidationError(
                        f"Line number {edit.line_number} does not exist on this invoice"
                    )

            # 4. Compute candidate edited header fields & diffs (tracking explicit no-op fields: P9-4)
            header_edits = cmd.header_edits or HeaderEditsInput()
            field_diffs: list[tuple[str, str | None, str]] = []
            header_updates: dict[str, Any] = {}
            noop_header_fields: list[str] = []

            new_invoice_number = (
                _norm_text(header_edits.invoice_number)
                if header_edits.invoice_number is not None
                else invoice.invoice_number
            )
            assert new_invoice_number is not None
            if header_edits.invoice_number is not None:
                if new_invoice_number == _norm_text(invoice.invoice_number):
                    noop_header_fields.append("invoice_number")
                else:
                    header_updates["invoice_number"] = new_invoice_number
                    field_diffs.append(
                        ("invoice_number", invoice.invoice_number, new_invoice_number)
                    )

            new_invoice_date = (
                header_edits.invoice_date
                if header_edits.invoice_date is not None
                else invoice.invoice_date
            )
            if header_edits.invoice_date is not None:
                if new_invoice_date == invoice.invoice_date:
                    noop_header_fields.append("invoice_date")
                else:
                    header_updates["invoice_date"] = new_invoice_date
                    field_diffs.append(
                        (
                            "invoice_date",
                            _fmt_date(invoice.invoice_date),
                            _fmt_date(new_invoice_date) or "",
                        )
                    )

            new_due_date = (
                header_edits.due_date if header_edits.due_date is not None else invoice.due_date
            )
            if header_edits.due_date is not None:
                if new_due_date == invoice.due_date:
                    noop_header_fields.append("due_date")
                else:
                    header_updates["due_date"] = new_due_date
                    field_diffs.append(
                        ("due_date", _fmt_date(invoice.due_date), _fmt_date(new_due_date) or "")
                    )

            new_po_number = (
                _norm_text(header_edits.po_number)
                if header_edits.po_number is not None
                else invoice.po_number
            )
            if header_edits.po_number is not None:
                if new_po_number == _norm_text(invoice.po_number):
                    noop_header_fields.append("po_number")
                else:
                    header_updates["po_number"] = new_po_number
                    field_diffs.append(("po_number", invoice.po_number, new_po_number or ""))

            old_subtotal = _q_money(invoice.subtotal) if invoice.subtotal is not None else None
            new_subtotal = (
                _q_money(header_edits.subtotal)
                if header_edits.subtotal is not None
                else old_subtotal
            )
            if header_edits.subtotal is not None:
                if new_subtotal == old_subtotal:
                    noop_header_fields.append("subtotal")
                else:
                    header_updates["subtotal"] = new_subtotal
                    field_diffs.append(
                        ("subtotal", _fmt_money(old_subtotal), _fmt_money(new_subtotal) or "")
                    )

            old_tax_amount = (
                _q_money(invoice.total_tax_amount) if invoice.total_tax_amount is not None else None
            )
            new_tax_amount = (
                _q_money(header_edits.total_tax_amount)
                if header_edits.total_tax_amount is not None
                else old_tax_amount
            )
            if header_edits.total_tax_amount is not None:
                if new_tax_amount == old_tax_amount:
                    noop_header_fields.append("total_tax_amount")
                else:
                    header_updates["total_tax_amount"] = new_tax_amount
                    field_diffs.append(
                        (
                            "total_tax_amount",
                            _fmt_money(old_tax_amount),
                            _fmt_money(new_tax_amount) or "",
                        )
                    )

            old_total_amount = _q_money(invoice.total_amount)
            new_total_amount = (
                _q_money(header_edits.total_amount)
                if header_edits.total_amount is not None
                else old_total_amount
            )
            if header_edits.total_amount is not None:
                if new_total_amount == old_total_amount:
                    noop_header_fields.append("total_amount")
                else:
                    header_updates["total_amount"] = new_total_amount
                    field_diffs.append(
                        (
                            "total_amount",
                            _fmt_money(old_total_amount),
                            _fmt_money(new_total_amount) or "",
                        )
                    )

            if new_subtotal is None or new_tax_amount is None:
                raise RevalidationValidationError(
                    "Invoice subtotal and total_tax_amount are required for re-validation"
                )

            # Record explicit tax exemption / reverse-charge flag overrides (blocking flag-only no-op replays)
            if cmd.is_reverse_charge or cmd.is_exempt:
                prior_logs = await AuditLogRepository(session).get_by_invoice_id(cmd.invoice_id)
                prior_rc = any(
                    log.action_type == AuditActionType.EDIT.value
                    and log.field_name == "is_reverse_charge"
                    and log.new_value == "true"
                    for log in prior_logs
                )
                prior_ex = any(
                    log.action_type == AuditActionType.EDIT.value
                    and log.field_name == "is_exempt"
                    and log.new_value == "true"
                    for log in prior_logs
                )
                if cmd.is_reverse_charge and not prior_rc:
                    field_diffs.append(("is_reverse_charge", "false", "true"))
                if cmd.is_exempt and not prior_ex:
                    field_diffs.append(("is_exempt", "false", "true"))

            # 5. Compute candidate edited line items & diffs (original line confidence_score preserved!)
            edits_by_line_num = {e.line_number: e for e in cmd.line_edits}
            candidate_lines_for_rules: list[dict[str, Any]] = []
            line_updates_to_persist: list[tuple[str, dict[str, Any]]] = []
            noop_line_numbers: list[int] = []

            for line in invoice.lines:
                edit = edits_by_line_num.get(line.line_number)
                cand_desc = line.description
                cand_qty = _q_unit(line.quantity)
                cand_unit_price = _q_unit(line.unit_price)
                cand_line_total = _q_money(line.line_total)
                cand_tax_rate = _q_unit(line.line_tax_rate)

                if edit is not None:
                    changes: dict[str, Any] = {}
                    if edit.description is not None:
                        norm_new_desc = _norm_text(edit.description)
                        assert norm_new_desc is not None
                        if norm_new_desc != _norm_text(cand_desc):
                            changes["description"] = norm_new_desc
                            field_diffs.append(
                                (f"line_{line.line_number}.description", cand_desc, norm_new_desc)
                            )
                            cand_desc = norm_new_desc

                    if edit.quantity is not None:
                        q_new = _q_unit(edit.quantity)
                        if q_new != cand_qty:
                            changes["quantity"] = q_new
                            field_diffs.append(
                                (
                                    f"line_{line.line_number}.quantity",
                                    _fmt_unit(cand_qty),
                                    _fmt_unit(q_new) or "",
                                )
                            )
                            cand_qty = q_new

                    if edit.unit_price is not None:
                        p_new = _q_unit(edit.unit_price)
                        if p_new != cand_unit_price:
                            changes["unit_price"] = p_new
                            field_diffs.append(
                                (
                                    f"line_{line.line_number}.unit_price",
                                    _fmt_unit(cand_unit_price),
                                    _fmt_unit(p_new) or "",
                                )
                            )
                            cand_unit_price = p_new

                    if edit.line_total is not None:
                        lt_new = _q_money(edit.line_total)
                        if lt_new != cand_line_total:
                            changes["line_total"] = lt_new
                            field_diffs.append(
                                (
                                    f"line_{line.line_number}.line_total",
                                    _fmt_money(cand_line_total),
                                    _fmt_money(lt_new) or "",
                                )
                            )
                            cand_line_total = lt_new

                    if edit.line_tax_rate is not None:
                        tr_new = _q_unit(edit.line_tax_rate)
                        if tr_new != cand_tax_rate:
                            changes["line_tax_rate"] = tr_new
                            field_diffs.append(
                                (
                                    f"line_{line.line_number}.line_tax_rate",
                                    _fmt_unit(cand_tax_rate),
                                    _fmt_unit(tr_new) or "",
                                )
                            )
                            cand_tax_rate = tr_new

                    if changes:
                        line_updates_to_persist.append((line.line_id, changes))
                    else:
                        noop_line_numbers.append(line.line_number)

                candidate_lines_for_rules.append(
                    {
                        "line_number": line.line_number,
                        "quantity": cand_qty,
                        "unit_price": cand_unit_price,
                        "line_total": cand_line_total,
                        "line_tax_rate": cand_tax_rate,
                    }
                )

            # 5b. P9-4 No-Op Edit Guard (CLAUDE.md §16.1): reject unchanged edits BEFORE acquiring CAS lock
            if noop_header_fields:
                logger.warning(
                    "Rejected no-op header edit during re-validation",
                    extra={
                        "invoice_id": cmd.invoice_id,
                        "actor_id": cmd.actor_id,
                        "unchanged_header_fields": sorted(noop_header_fields),
                    },
                )
                raise RevalidationNoOpError(
                    f"No-op edit rejected: header field(s) {sorted(noop_header_fields)} "
                    "unchanged (previous_value == new_value)"
                )
            if noop_line_numbers:
                logger.warning(
                    "Rejected no-op line edit during re-validation",
                    extra={
                        "invoice_id": cmd.invoice_id,
                        "actor_id": cmd.actor_id,
                        "unchanged_line_numbers": sorted(noop_line_numbers),
                    },
                )
                raise RevalidationNoOpError(
                    f"No-op edit rejected: line(s) {sorted(noop_line_numbers)} "
                    "have no changed fields (previous_value == new_value)"
                )
            if not field_diffs:
                logger.warning(
                    "Rejected empty/no-op re-validation request",
                    extra={"invoice_id": cmd.invoice_id, "actor_id": cmd.actor_id},
                )
                raise RevalidationNoOpError(
                    "No-op edit rejected: no invoice fields changed (previous_value == new_value)"
                )

            # SEC-174 (CWE-840): Reverse-charge/exempt invoices cannot leave non-zero line tax rates
            if cmd.is_reverse_charge or cmd.is_exempt:
                non_zero_lines = [
                    ln["line_number"]
                    for ln in candidate_lines_for_rules
                    if ln["line_tax_rate"] != Decimal("0.0000")
                ]
                if non_zero_lines:
                    raise RevalidationValidationError(
                        "All line_tax_rate values must be 0.0000 when is_reverse_charge or "
                        f"is_exempt is enabled (non-zero lines: {non_zero_lines})"
                    )

            # Snapshot immutable model confidence scores BEFORE any mutation (CLAUDE.md §7.4)
            original_macro_confidence = invoice.confidence_macro_avg
            field_scores: dict[str, Decimal] = {
                "invoice.confidence_macro_avg": original_macro_confidence,
            }
            for line in invoice.lines:
                if line.confidence_score is not None:
                    field_scores[f"line_{line.line_number}.confidence_score"] = (
                        line.confidence_score
                    )

            vendor_tax_id = invoice.vendor_tax_id
            old_composite_hash = invoice.composite_hash
            currency = invoice.currency.strip().upper()
            vendor_context = VendorRuleContext.from_vendor(invoice.vendor)

            # 6. Acquire atomic CAS lock: previous_status -> REVALIDATING (CWE-362)
            state_machine = InvoiceStateMachine(inv_repo)
            try:
                await state_machine.transition(
                    cmd.invoice_id,
                    InvoiceStatus.REVALIDATING,
                    actor_id=cmd.actor_id,
                    actor_role=ActorRole.AP_CLERK,
                    expected_status=previous_status,
                    reason=f"Re-validation initiated ({cmd.reason_code.value})",
                )
            except (ConcurrentStateTransitionError, IllegalStateTransitionError) as exc:
                raise RevalidationConflictError(str(exc)) from None

            # 7. Run deterministic rules, confidence re-evaluation, FX/escalation, & persist
            lock_acquired = True
            try:
                # 7a. Composite hash collision guard (FR-09, CLAUDE.md §16.1)
                new_composite_hash = compute_composite_hash(
                    vendor_tax_id=vendor_tax_id,
                    invoice_number=new_invoice_number,
                    total_amount=new_total_amount,
                )
                if new_composite_hash != old_composite_hash:
                    existing_dup = await inv_repo.get_by_composite_hash(new_composite_hash)
                    if existing_dup is not None and existing_dup.invoice_id != cmd.invoice_id:
                        raise RevalidationConflictError(
                            "Edited invoice matches an existing active invoice composite_hash"
                        )
                    header_updates["composite_hash"] = new_composite_hash

                # 7b. Re-run Phase 7 Rules Engine (FR-05, FR-06, FR-07, FR-08, FR-11)
                rules_engine = RulesEngine()
                try:
                    rules_result = rules_engine.validate_revalidation(
                        lines=candidate_lines_for_rules,
                        subtotal=new_subtotal,
                        tax_amount=new_tax_amount,
                        total_amount=new_total_amount,
                        vendor_context=vendor_context,
                        is_reverse_charge=cmd.is_reverse_charge,
                        is_exempt=cmd.is_exempt,
                        invoice_date=_fmt_date(new_invoice_date),
                        due_date=_fmt_date(new_due_date),
                        check_lines_subtotal=bool(candidate_lines_for_rules),
                    )
                except ValueError as exc:
                    raise RevalidationValidationError(str(exc)) from None

                # 7c. Re-evaluate Confidence Router (preserves original model confidence: CLAUDE.md §7.4)
                confidence_router = ConfidenceRouter()
                confidence_result = confidence_router.route_revalidation(
                    field_scores,
                    rules_result=rules_result,
                )

                # 7d. Evaluate High-Value (>$10k USD via ECB FX) & PO-Variance (>5%) Escalation (BR-014/018)
                escalation_evaluator = EscalationEvaluator(exchange_rate_repo=fx_repo)
                if currency == "USD":
                    escalation_result = escalation_evaluator.evaluate(
                        total_amount=new_total_amount,
                        currency="USD",
                        po_amount=cmd.po_amount,
                        confidence_result=confidence_result,
                    )
                else:
                    if new_invoice_date is None:
                        raise RevalidationValidationError(
                            "invoice_date is required to convert non-USD currency to USD"
                        )
                    try:
                        escalation_result = await escalation_evaluator.evaluate_with_fx(
                            total_amount=new_total_amount,
                            currency=currency,
                            invoice_date=new_invoice_date,
                            po_amount=cmd.po_amount,
                            confidence_result=confidence_result,
                        )
                    except MissingExchangeRateError as exc:
                        raise RevalidationValidationError(str(exc)) from None
                    except ValueError as exc:
                        raise RevalidationValidationError(str(exc)) from None

                final_status = InvoiceStatus(escalation_result.target_status)

                if escalation_result.total_amount_usd != invoice.total_amount_usd:
                    header_updates["total_amount_usd"] = escalation_result.total_amount_usd

                # 7e. Atomically persist edited header & line values in ONE transaction (SEC-173)
                if header_updates or line_updates_to_persist:
                    try:
                        updated_inv = await inv_repo.apply_revalidation_edits(
                            cmd.invoice_id,
                            expected_status=InvoiceStatus.REVALIDATING.value,
                            header_updates=header_updates,
                            line_updates=line_updates_to_persist,
                        )
                    except IntegrityError:
                        raise RevalidationConflictError(
                            "Edited invoice conflicts with an existing active invoice composite_hash"
                        ) from None
                    if updated_inv is None:
                        raise RevalidationConflictError(
                            f"Concurrent status conflict while persisting edits for invoice '{cmd.invoice_id}'"
                        )

                # 7f. Persist final FSM status transition: REVALIDATING -> final_status
                await state_machine.transition(
                    cmd.invoice_id,
                    final_status,
                    actor_id=cmd.actor_id,
                    actor_role=ActorRole.AP_CLERK,
                    expected_status=InvoiceStatus.REVALIDATING,
                    reason=(
                        f"Re-validation completed ({cmd.reason_code.value}): "
                        f"all_passed={rules_result.all_passed}"
                    ),
                )
                lock_acquired = False
            except Exception:
                if lock_acquired:
                    await self._restore_status_best_effort(cmd.invoice_id, previous_status)
                raise

        # 8. Write immutable EDIT + REVALIDATE audit records in isolated transactions (CLAUDE.md §16 rule 9)
        audit_logger = AuditLogger(self._session_factory)
        edited_field_names: list[str] = []
        try:
            for field_name, prev_val, new_val in field_diffs:
                await audit_logger.record(
                    invoice_id=cmd.invoice_id,
                    user_id=cmd.actor_id,
                    action_type=AuditActionType.EDIT,
                    field_name=field_name,
                    previous_value=prev_val,
                    new_value=new_val,
                    reason_code=cmd.reason_code,
                    comment=cmd.comment,
                    request_id=cmd.request_id,
                )
                edited_field_names.append(field_name)

            revalidate_comment = (
                cmd.comment
                if cmd.comment
                else (
                    f"Re-validated with reason {cmd.reason_code.value}: "
                    f"{previous_status.value} -> {final_status.value}"
                )
            )
            revalidate_audit = await audit_logger.record(
                invoice_id=cmd.invoice_id,
                user_id=cmd.actor_id,
                action_type=AuditActionType.REVALIDATE,
                field_name="status",
                previous_value=previous_status.value,
                new_value=final_status.value,
                reason_code=cmd.reason_code,
                comment=revalidate_comment,
                request_id=cmd.request_id,
            )
        except Exception as exc:
            # SEC-176 (CWE-778): Emit critical compliance alert so SIEM catches any audit gap
            logger.critical(
                "Re-validation committed but immutable audit trail write failed",
                extra={
                    "invoice_id": cmd.invoice_id,
                    "actor_id": cmd.actor_id,
                    "final_status": final_status.value,
                    "error_type": type(exc).__name__,
                },
            )
            raise

        logger.info(
            "Invoice re-validation completed",
            extra={
                "invoice_id": cmd.invoice_id,
                "previous_status": previous_status.value,
                "final_status": final_status.value,
                "reason_code": cmd.reason_code.value,
                "edited_field_count": len(edited_field_names),
                "all_rules_passed": rules_result.all_passed,
                "eligible_for_clerk_approval": escalation_result.eligible_for_clerk_approval,
                "requires_manager_approval": escalation_result.requires_manager_approval,
                "audit_event_id": revalidate_audit.audit_id,
            },
        )

        return RevalidationOutcome(
            invoice_id=cmd.invoice_id,
            previous_status=previous_status.value,
            status=final_status.value,
            is_revalidated=True,
            line_arithmetic_valid=rules_result.line_arithmetic_valid,
            invoice_total_valid=rules_result.invoice_total_valid,
            tax_valid=rules_result.tax_valid,
            date_valid=rules_result.date_valid,
            all_passed=rules_result.all_passed,
            currency_converted_amount_usd=escalation_result.total_amount_usd,
            active_exceptions=rules_result.errors,
            confidence_tier=confidence_result.confidence_tier.value,
            confidence_macro_avg=original_macro_confidence,
            eligible_for_clerk_approval=escalation_result.eligible_for_clerk_approval,
            requires_manager_approval=escalation_result.requires_manager_approval,
            audit_event_id=revalidate_audit.audit_id,
            edited_fields=tuple(edited_field_names),
        )


__all__ = [
    "HeaderEditsInput",
    "LineEditInput",
    "RevalidationConflictError",
    "RevalidationError",
    "RevalidationInput",
    "RevalidationNoOpError",
    "RevalidationNotFoundError",
    "RevalidationOutcome",
    "RevalidationService",
    "RevalidationValidationError",
]
