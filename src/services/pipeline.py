"""
End-to-End Deterministic Invoice Processing Pipeline (P12-2).

Implements ``InvoicePipelineProtocol`` for ``InvoiceBackgroundWorker`` (CLAUDE.md §4.1):
  1. Classify & extract raw document bytes via ``ExtractionEngine`` (GPT-4o-mini / GPT-4o Vision).
  2. Resolve Vendor Master context from SQL (safely binding ``UNKNOWN`` auto-detect uploads to
     verified active vendors via ``InvoiceRepository.bind_extracted_vendor``; fail-closed on
     unregistered or inactive vendors: SEC-212).
  3. Execute ``RulesEngine`` (P7-1..P7-5: duplicate/revision/credit-note, line arithmetic,
     invoice total, multi-country tax, date locale normalization).
  4. Execute ``ConfidenceRouter`` (P8-1: worst-field-wins tri-tier confidence + Rules-First).
  5. Execute ``EscalationEvaluator`` (P8-3: invoice-date ECB FX conversion + >$10k / >5% PO
     escalation; fail-closed to ``REQUIRES_REVIEW`` on missing non-USD FX: SEC-213).
  6. Persist extracted header fields and ``InvoiceLine`` rows in SQL without ever overwriting
     an existing invoice on ``composite_hash`` collision (CLAUDE.md §16.1, SEC-213).
  7. Return immutable ``PipelineResult`` with non-approval ``target_status``, extraction JSON
     payload for WORM Blob archiving, and PII-free aggregate summary comment (SEC-214).
"""

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.logging import get_logger
from src.database.models import InvoiceLine, Vendor
from src.database.repositories import (
    ExchangeRateRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
)
from src.extraction.extract_engine import ExtractionEngine
from src.services.worker import (
    ALLOWED_PIPELINE_TARGET_STATUSES,
    PipelineContext,
    PipelineResult,
    PipelineStatusViolationError,
)
from src.validation.confidence_router import ConfidenceRouter
from src.validation.duplicate_detector import DuplicateOutcome, compute_composite_hash
from src.validation.escalation_rules import EscalationEvaluator, MissingExchangeRateError
from src.validation.rules_engine import RulesEngine, VendorRuleContext

logger = get_logger("ap.services.pipeline")

_MONEY_QUANTUM = Decimal("0.01")


def _quantize_money(val: Decimal) -> Decimal:
    return val.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _build_vendor_context(vendor: Vendor) -> VendorRuleContext:
    return VendorRuleContext.from_vendor(vendor)


class InvoiceProcessingPipeline:
    """
    Production orchestration pipeline wiring Extraction -> Rules -> Confidence -> Escalation -> SQL.

    Strictly obeys CLAUDE.md §4.2 (Services layer orchestrates repositories, extraction, and
    validation; never calls external HTTP systems directly and never self-approves invoices).
    """

    def __init__(
        self,
        *,
        extraction_engine: ExtractionEngine,
        session_factory: async_sessionmaker[AsyncSession],
        confidence_router: ConfidenceRouter | None = None,
    ) -> None:
        self._extraction_engine = extraction_engine
        self._session_factory = session_factory
        self._confidence_router = confidence_router or ConfidenceRouter()

    async def execute(self, context: PipelineContext) -> PipelineResult:
        """Execute extract -> validate -> route -> persist for a verified worker job."""
        job = context.job

        # 1. Classify document & run structured extraction (<invoice_text> delimiter-protected)
        ext_result = await self._extraction_engine.extract(context.raw_bytes)
        extraction = ext_result.extraction
        header = extraction.header
        macro_avg = extraction.header_macro_avg_confidence()

        extracted_tax_id = header.vendor_tax_id.value.strip()
        extracted_inv_num = header.invoice_number.value.strip()
        extracted_subtotal = _quantize_money(header.subtotal.value)
        extracted_tax = _quantize_money(header.tax_amount.value)
        extracted_total = _quantize_money(header.total_amount.value)
        extracted_currency = header.currency.value.strip().upper()

        # 2. Resolve active Vendor Master record (fail-closed on unregistered/inactive vendor: SEC-212)
        async with self._session_factory() as session:
            vendor_repo = VendorRepository(session)
            inv_repo = InvoiceRepository(session)
            fx_repo = ExchangeRateRepository(session)

            vendor: Vendor | None = await vendor_repo.get_by_tax_id(extracted_tax_id)
            if vendor is None and job.vendor_id and job.vendor_id.upper() != "UNKNOWN":
                vendor = await vendor_repo.get_by_vendor_id(job.vendor_id)

            vendor_unregistered = vendor is None or not vendor.is_active
            if not vendor_unregistered and vendor is not None:
                # Bind UNKNOWN auto-detect uploads safely (anti-IDOR: refuses post-bind reassignment)
                await inv_repo.bind_extracted_vendor(job.invoice_id, vendor.vendor_tax_id)

            # 3. Deterministic Rules Engine (P7-1..P7-5)
            vendor_ctx = (
                _build_vendor_context(vendor)
                if vendor is not None and vendor.is_active
                else VendorRuleContext(
                    country_code="US",
                    date_locale=None,
                    standard_tax_rate=None,
                )
            )
            rules_engine = RulesEngine(repository=inv_repo)
            rules_result = await rules_engine.validate_extraction(
                extraction,
                vendor_context=vendor_ctx,
                filename=job.filename,
                current_invoice_id=job.invoice_id,
            )

            # 4. Tri-Tier Confidence Router with Rules-First precedence (P8-1)
            conf_result = self._confidence_router.route_extraction(
                extraction,
                rules_result=rules_result,
            )
            final_status: str = conf_result.target_status

            # Fail closed if vendor is not an active Vendor Master record (SEC-212)
            vendor_note = ""
            if vendor_unregistered and final_status == "VALIDATED":
                final_status = "REQUIRES_REVIEW"
                vendor_note = "; unregistered_or_inactive_vendor"

            # 5. Escalation & Invoice-Date ECB FX Conversion (P8-3, FR-13)
            resolved_inv_date = (
                rules_result.date_result.invoice_date
                if rules_result.date_result is not None
                else None
            )
            resolved_due_date = (
                rules_result.date_result.due_date if rules_result.date_result is not None else None
            )

            total_amount_usd: Decimal | None = None
            escalation_note = ""
            evaluator = EscalationEvaluator(exchange_rate_repo=fx_repo)

            if extracted_currency == "USD":
                esc_res = evaluator.evaluate(
                    total_amount=extracted_total,
                    currency="USD",
                    current_status=final_status,  # type: ignore[arg-type]
                )
                total_amount_usd = esc_res.total_amount_usd
                final_status = esc_res.target_status
                if esc_res.requires_manager_approval:
                    reasons_str = ",".join(r.value for r in esc_res.escalation_reasons)
                    escalation_note = f"; escalated={reasons_str}"
            elif resolved_inv_date is not None:
                try:
                    esc_res = await evaluator.evaluate_with_fx(
                        total_amount=extracted_total,
                        currency=extracted_currency,
                        invoice_date=resolved_inv_date,
                        current_status=final_status,  # type: ignore[arg-type]
                    )
                    total_amount_usd = esc_res.total_amount_usd
                    final_status = esc_res.target_status
                    if esc_res.requires_manager_approval:
                        reasons_str = ",".join(r.value for r in esc_res.escalation_reasons)
                        escalation_note = f"; escalated={reasons_str}"
                except MissingExchangeRateError:
                    # SEC-213: Fail closed when non-USD invoice cannot be priced against $10k cap
                    if final_status == "VALIDATED":
                        final_status = "REQUIRES_REVIEW"
                    escalation_note = "; missing_ecb_fx_rate"
            else:
                if final_status == "VALIDATED":
                    final_status = "REQUIRES_REVIEW"
                escalation_note = "; unresolved_invoice_date_for_fx"

            # Double-lock non-approval invariant (CLAUDE.md §16.1, SEC-214)
            if final_status not in ALLOWED_PIPELINE_TARGET_STATUSES:
                raise PipelineStatusViolationError(
                    f"Pipeline produced disallowed target status: {final_status!r}"
                )

            # 6. Persist extracted header fields + InvoiceLine rows cleanly (SEC-213 duplicate guard)
            is_duplicate_outcome = (
                rules_result.duplicate_result is not None
                and rules_result.duplicate_result.outcome is DuplicateOutcome.DUPLICATE_INVOICE
            )
            canonical_hash = compute_composite_hash(
                vendor_tax_id=extracted_tax_id,
                invoice_number=extracted_inv_num,
                total_amount=extracted_total,
            )

            header_updates: dict[str, Any] = {
                "vendor_name": (
                    vendor.vendor_name
                    if vendor is not None and vendor.is_active
                    else header.vendor_name.value.strip()[:255]
                ),
                "invoice_number": extracted_inv_num[:100],
                "invoice_date": resolved_inv_date,
                "due_date": resolved_due_date,
                "po_number": (
                    header.po_number.value.strip()[:100]
                    if header.po_number.value is not None
                    else None
                ),
                "subtotal": extracted_subtotal,
                "total_tax_amount": extracted_tax,
                "total_amount": extracted_total,
                "currency": extracted_currency[:10],
                "total_amount_usd": total_amount_usd,
                "confidence_macro_avg": macro_avg,
            }
            if not is_duplicate_outcome:
                header_updates["composite_hash"] = canonical_hash

            try:
                await inv_repo.update_fields(job.invoice_id, **header_updates)
            except IntegrityError:
                # Concurrent duplicate composite_hash race (CWE-362 / CLAUDE.md §16.1):
                # Never overwrite original record; route this duplicate row cleanly.
                await session.rollback()
                header_updates.pop("composite_hash", None)
                await inv_repo.update_fields(job.invoice_id, **header_updates)
                final_status = "DUPLICATE_INVOICE"

            line_models = [
                InvoiceLine(
                    invoice_id=job.invoice_id,
                    line_number=idx,
                    description=line.description.value.strip()[:500],
                    quantity=line.quantity.value,
                    unit_price=line.unit_price.value,
                    line_total=_quantize_money(line.line_total.value),
                    line_tax_rate=line.tax_rate.value,
                    confidence_score=line.min_confidence(),
                )
                for idx, line in enumerate(extraction.line_items, start=1)
            ]
            await InvoiceLineRepository(session).replace_for_invoice(job.invoice_id, line_models)

        # 7. Return PII-free summary + extraction JSON payload for WORM Blob archival (SEC-214)
        summary_comment = (
            f"Pipeline completed via {ext_result.routing.route.value} "
            f"(model={ext_result.model_version}, rules_passed={rules_result.all_passed}, "
            f"failed_rules={len(rules_result.failed_rules)}, "
            f"confidence_tier={conf_result.confidence_tier.value}{vendor_note}{escalation_note})"
        )
        logger.info(
            "Invoice processing pipeline finished",
            extra={
                "invoice_id": job.invoice_id,
                "route": ext_result.routing.route.value,
                "model_version": ext_result.model_version,
                "rules_passed": rules_result.all_passed,
                "target_status": final_status,
            },
        )
        return PipelineResult(
            target_status=final_status,
            extraction_payload=ext_result.raw_json,
            confidence_macro_avg=macro_avg,
            summary_comment=summary_comment,
        )


__all__ = ["InvoiceProcessingPipeline"]
