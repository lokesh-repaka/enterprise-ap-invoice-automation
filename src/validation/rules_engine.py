"""
Deterministic Validation Rules Engine Orchestrator (P7-6).

Covers FR-05, FR-06, FR-07, FR-08, FR-09, FR-10, FR-11, and CLAUDE.md §4.1, §4.2, §7.1, §7.2,
§7.4, §10, §16.1, LLD §2.2, §4, §5:
- Chains all five Phase-7 deterministic validators in canonical order:
  1. **Duplicate / Revision / Credit-Note Detector** (`P7-1`, FR-09/FR-10/FR-11)
  2. **Line-Item Arithmetic Validator** (`P7-2`, FR-05: Qty × Unit Price = Total ± config tol)
  3. **Invoice Total Arithmetic Validator** (`P7-3`, FR-06: Subtotal + Tax = Total ± config tol,
     with header-subtotal vs. line-item-sum cross-check)
  4. **Multi-Country Tax Validator** (`P7-4`, FR-07: US sales tax, UK VAT, DE MwSt, ES IVA,
     mixed-rate lines, reverse-charge & exemption flags)
  5. **Date Normaliser** (`P7-5`, FR-08: Vendor Master locale resolution + chronological check)
- Returns an immutable ``RulesEngineResult`` containing per-rule pass/fail outcomes, aggregated
  human-readable errors, LLD §2.2 ``validation_summary`` booleans, and deterministic
  highest-precedence ``recommended_status``.
- Directly re-exports ``validate_line_items`` (FR-05), ``validate_invoice_total`` (FR-06),
  ``validate_tax_rate`` (FR-07), and ``parse_invoice_date`` (FR-08) per CLAUDE.md §3 & §7.4.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never emits approval statuses (``APPROVED_CLERK``, ``APPROVED_MANAGER``,
  ``STAGED_FOR_EXPORT``) — enforced via strict ``Literal`` allowlist + ``frozen=True`` (CWE-863).
- Negative-balance documents are NEVER classified as regular passing invoices even during
  clerk re-validation (``CLAUDE.md §16.1``).
- Fails closed without unhandled crashes on malformed OCR dates (``AC-005`` / ``CLAUDE.md §10``).
- Logs aggregate rule-outcome summaries only — zero raw PII in logs (CWE-532).
"""

from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema, InvoiceLineItemExtraction
from src.validation.date_normalizer import (
    AmbiguousDateError,
    InvoiceDatesValidationResult,
    normalize_extraction_dates,
    normalize_invoice_dates,
    parse_invoice_date,
    resolve_date_locale,
)
from src.validation.duplicate_detector import (
    DuplicateDetectionResult,
    DuplicateDetector,
    DuplicateOutcome,
    InvoiceLookupProtocol,
    detect_credit_note,
)
from src.validation.invoice_total import (
    InvoiceTotalValidationResult,
    evaluate_invoice_total,
    validate_extraction_invoice_total,
    validate_invoice_total,
)
from src.validation.line_arithmetic import (
    LineItemArithmeticInput,
    LineItemLike,
    LineItemsValidationResult,
    evaluate_line_items,
    validate_extraction_line_items,
    validate_line_items,
)
from src.validation.tax_validator import (
    TaxLineInput,
    TaxValidationResult,
    _require_strict_bool,
    evaluate_tax_rate,
    normalize_country_code,
    validate_extraction_tax,
    validate_tax_rate,
)
from src.validation.tax_validator import (
    _parse_finite_decimal as _parse_tax_decimal,
)

logger = get_logger("ap.validation.rules_engine")

# Explicit non-approval status allowlist (CLAUDE.md §16.1, LLD §4, CWE-863)
AllowedRuleStatus = Literal[
    "DUPLICATE_INVOICE",
    "FLAGGED_POTENTIAL_REVISION",
    "CREDIT_NOTE",
    "REJECTED_TAX_MISMATCH",
    "REQUIRES_APPROVAL",
    "REQUIRES_REVIEW",
]

# Deterministic precedence order when multiple rules fail simultaneously (lower rank wins)
_STATUS_PRIORITY: dict[str, int] = {
    "DUPLICATE_INVOICE": 1,
    "CREDIT_NOTE": 2,
    "FLAGGED_POTENTIAL_REVISION": 3,
    "REJECTED_TAX_MISMATCH": 4,
    "REQUIRES_APPROVAL": 5,
    "REQUIRES_REVIEW": 6,
}


class RuleName(StrEnum):
    """Canonical identifiers for every validator chained by the Rules Engine."""

    DUPLICATE_CHECK = "duplicate_check"
    LINE_ARITHMETIC = "line_arithmetic"
    INVOICE_TOTAL = "invoice_total"
    TAX_VALIDATION = "tax_validation"
    DATE_NORMALIZATION = "date_normalization"


class VendorRuleContext(BaseModel):
    """Immutable validated Vendor Master jurisdiction & tax context for rule execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    country_code: str
    date_locale: str | None = None
    standard_tax_rate: Decimal | None = None
    require_exemption_for_zero_tax: bool = False

    @field_validator("country_code", mode="before")
    @classmethod
    def _validate_country(cls, v: Any) -> str:
        return normalize_country_code(v)

    @field_validator("date_locale", mode="before")
    @classmethod
    def _validate_date_locale(cls, v: Any) -> str | None:
        return resolve_date_locale(v)

    @field_validator("standard_tax_rate", mode="before")
    @classmethod
    def _validate_standard_tax_rate(cls, v: Any) -> Decimal | None:
        if v is None:
            return None
        val = _parse_tax_decimal(v, field_name="standard_tax_rate", max_abs=Decimal("1.0000"))
        if val < Decimal("0"):
            raise ValueError("standard_tax_rate must be non-negative within [0.0000, 1.0000]")
        return val

    @field_validator("require_exemption_for_zero_tax", mode="before")
    @classmethod
    def _validate_req_zero_ex(cls, v: Any) -> bool:
        return _require_strict_bool(v, field_name="require_exemption_for_zero_tax")

    @property
    def effective_date_locale(self) -> str:
        """Return explicit date_locale when set, otherwise derive from canonical country_code."""
        if self.date_locale is not None:
            return self.date_locale
        return "US" if self.country_code == "US" else "EU"

    @classmethod
    def from_vendor(
        cls,
        vendor: Any,
        *,
        require_exemption_for_zero_tax: bool = False,
    ) -> "VendorRuleContext":
        """Construct ``VendorRuleContext`` from a SQLAlchemy ``Vendor`` ORM or ``vendor_master.json`` dict."""
        if isinstance(vendor, cls):
            return vendor
        if isinstance(vendor, Mapping):
            country = vendor.get("country_code", vendor.get("CountryCode"))
            locale = vendor.get("date_format_locale", vendor.get("DateLocalePreference"))
            tax_rate = vendor.get("standard_tax_rate", vendor.get("StandardTaxRate"))
            return cls(
                country_code=country,
                date_locale=locale,
                standard_tax_rate=tax_rate,
                require_exemption_for_zero_tax=require_exemption_for_zero_tax,
            )
        if hasattr(vendor, "country_code"):
            return cls(
                country_code=vendor.country_code,
                date_locale=getattr(vendor, "date_format_locale", None),
                standard_tax_rate=getattr(vendor, "standard_tax_rate", None),
                require_exemption_for_zero_tax=require_exemption_for_zero_tax,
            )
        raise ValueError(f"Unsupported vendor object type: {type(vendor).__name__}")


class RuleCheckOutcome(BaseModel):
    """Immutable pass/fail outcome for a single deterministic validation rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule: RuleName
    passed: bool
    skipped: bool = False
    errors: tuple[str, ...] = ()
    recommended_status: AllowedRuleStatus | None = None


class RulesEngineResult(BaseModel):
    """Immutable aggregated validation outcome produced by ``RulesEngine`` (P7-6, LLD §2.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    all_passed: bool
    rule_outcomes: tuple[RuleCheckOutcome, ...]
    failed_rules: tuple[RuleName, ...]
    errors: tuple[str, ...]
    recommended_status: AllowedRuleStatus | None
    duplicate_passed: bool
    line_arithmetic_valid: bool
    invoice_total_valid: bool
    tax_valid: bool
    date_valid: bool
    duplicate_result: DuplicateDetectionResult | None = None
    line_result: LineItemsValidationResult | None = None
    total_result: InvoiceTotalValidationResult | None = None
    tax_result: TaxValidationResult | None = None
    date_result: InvoiceDatesValidationResult | None = None

    def to_validation_summary(self) -> dict[str, Any]:
        """Serialize concise validation summary matching LLD §2.2 ``/revalidate`` response contract."""
        return {
            "duplicate_passed": self.duplicate_passed,
            "line_arithmetic_valid": self.line_arithmetic_valid,
            "invoice_total_valid": self.invoice_total_valid,
            "tax_valid": self.tax_valid,
            "date_valid": self.date_valid,
            "all_passed": self.all_passed,
            "recommended_status": self.recommended_status,
            "active_exceptions": list(self.errors),
        }


def _select_recommended_status(
    outcomes: Sequence[RuleCheckOutcome],
) -> AllowedRuleStatus | None:
    """Select deterministic highest-precedence workflow status across all failed rule outcomes."""
    candidates: list[AllowedRuleStatus] = [
        o.recommended_status
        for o in outcomes
        if (not o.passed and not o.skipped and o.recommended_status is not None)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda st: _STATUS_PRIORITY[st])


def _extract_tax_lines_for_revalidation(
    lines: Sequence[
        LineItemArithmeticInput | InvoiceLineItemExtraction | LineItemLike | Mapping[str, Any]
    ],
) -> tuple[TaxLineInput, ...] | None:
    """
    Extract per-line tax breakdown when every line supplies a tax_rate / line_tax_rate.

    Fails closed (SEC-158 / CWE-840) if only a subset of lines specify tax_rate so a caller
    cannot silently bypass non-statutory per-line tax validation by omitting one line's rate.
    """
    if not lines:
        return None
    extracted: list[TaxLineInput | None] = []
    for raw in lines:
        if isinstance(raw, InvoiceLineItemExtraction):
            extracted.append(
                TaxLineInput(
                    line_total=raw.line_total.value,
                    tax_rate=raw.tax_rate.value,
                )
            )
        elif isinstance(raw, Mapping):
            rate = raw.get("tax_rate", raw.get("line_tax_rate"))
            if rate is None:
                extracted.append(None)
            else:
                extracted.append(TaxLineInput(line_total=raw["line_total"], tax_rate=rate))
        elif hasattr(raw, "line_tax_rate") and getattr(raw, "line_tax_rate", None) is not None:
            extracted.append(
                TaxLineInput(
                    line_total=raw.line_total,
                    tax_rate=raw.line_tax_rate,
                )
            )
        else:
            extracted.append(None)

    present_count = sum(1 for item in extracted if item is not None)
    if present_count == 0:
        return None
    if present_count != len(extracted):
        raise ValueError(
            "Partial per-line tax_rate payload rejected: provide tax_rate on all lines or none"
        )
    return tuple(item for item in extracted if item is not None)


class RulesEngine:
    """
    Deterministic Validation Rules Engine orchestrator (P7-6).

    Chains P7-1 (Duplicate/Revision/Credit-Note), P7-2 (Line Arithmetic), P7-3 (Invoice Total),
    P7-4 (Multi-Country Tax), and P7-5 (Date Normaliser) into a single auditable pass/fail report.
    """

    def __init__(self, repository: InvoiceLookupProtocol | None = None) -> None:
        self._duplicate_detector = DuplicateDetector(repository=repository)

    async def validate_extraction(
        self,
        extraction: InvoiceExtractionSchema,
        *,
        vendor_context: VendorRuleContext,
        filename: str | None = None,
        current_invoice_id: str | None = None,
        check_lines_subtotal: bool = True,
        run_duplicate_check: bool = True,
    ) -> RulesEngineResult:
        """
        Run the complete 5-rule deterministic validation pipeline on a P6-3 extraction payload.
        """
        if not isinstance(extraction, InvoiceExtractionSchema):
            raise ValueError("extraction must be a validated InvoiceExtractionSchema instance")
        if not isinstance(vendor_context, VendorRuleContext):
            raise ValueError("vendor_context must be a validated VendorRuleContext instance")
        _require_strict_bool(check_lines_subtotal, field_name="check_lines_subtotal")
        _require_strict_bool(run_duplicate_check, field_name="run_duplicate_check")

        outcomes: list[RuleCheckOutcome] = []

        # 1. P7-1: Duplicate, Revision, and Credit Note Detection (FR-09, FR-10, FR-11)
        dup_result: DuplicateDetectionResult | None = None
        if run_duplicate_check:
            dup_result = await self._duplicate_detector.detect_from_extraction(
                extraction,
                filename=filename,
                current_invoice_id=current_invoice_id,
            )
            dup_passed = dup_result.outcome == DuplicateOutcome.PROCEED
            outcomes.append(
                RuleCheckOutcome(
                    rule=RuleName.DUPLICATE_CHECK,
                    passed=dup_passed,
                    errors=() if dup_passed else (dup_result.reason,),
                    recommended_status=None if dup_passed else dup_result.target_status,
                )
            )
        else:
            # SEC-157 (CLAUDE.md §16.1): Even when DB duplicate lookup is skipped, NEVER let a
            # negative-balance credit note pass as a regular invoice.
            ext_line_totals = tuple(item.line_total.value for item in extraction.line_items)
            is_cn, neg_tot, neg_lines = detect_credit_note(
                extraction.header.total_amount.value,
                subtotal=extraction.header.subtotal.value,
                line_totals=ext_line_totals,
            )
            if is_cn:
                outcomes.append(
                    RuleCheckOutcome(
                        rule=RuleName.DUPLICATE_CHECK,
                        passed=False,
                        skipped=False,
                        errors=(
                            "Negative balance detected "
                            f"(negative_total={neg_tot}, negative_lines={list(neg_lines)}); "
                            "must be routed as CREDIT_NOTE.",
                        ),
                        recommended_status="CREDIT_NOTE",
                    )
                )
            else:
                outcomes.append(
                    RuleCheckOutcome(rule=RuleName.DUPLICATE_CHECK, passed=True, skipped=True)
                )

        # 2. P7-2: Line-Item Arithmetic Validation (FR-05)
        line_result = validate_extraction_line_items(extraction)
        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.LINE_ARITHMETIC,
                passed=line_result.is_valid,
                errors=line_result.errors,
                recommended_status=None if line_result.is_valid else "REQUIRES_APPROVAL",
            )
        )

        # 3. P7-3: Invoice Total Arithmetic Validation (FR-06)
        total_result = validate_extraction_invoice_total(
            extraction,
            check_lines_subtotal=check_lines_subtotal,
        )
        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.INVOICE_TOTAL,
                passed=total_result.is_valid,
                errors=total_result.errors,
                recommended_status=None if total_result.is_valid else "REQUIRES_APPROVAL",
            )
        )

        # 4. P7-4: Multi-Country Tax Validation (FR-07)
        tax_result = validate_extraction_tax(
            extraction,
            country_code=vendor_context.country_code,
            vendor_tax_rate=vendor_context.standard_tax_rate,
            require_exemption_for_zero_tax=vendor_context.require_exemption_for_zero_tax,
        )
        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.TAX_VALIDATION,
                passed=tax_result.is_valid,
                errors=() if tax_result.is_valid else (tax_result.message,),
                recommended_status=tax_result.recommended_status,
            )
        )

        # 5. P7-5: Date Normalization & Chronological Locale Check (FR-08)
        date_result: InvoiceDatesValidationResult | None = None
        try:
            date_result = normalize_extraction_dates(
                extraction,
                locale=vendor_context.effective_date_locale,
            )
            date_passed = date_result.is_valid and not date_result.is_ambiguous
            outcomes.append(
                RuleCheckOutcome(
                    rule=RuleName.DATE_NORMALIZATION,
                    passed=date_passed,
                    errors=() if date_passed else (date_result.message,),
                    recommended_status=None if date_passed else "REQUIRES_REVIEW",
                )
            )
        except (AmbiguousDateError, ValueError) as exc:
            # Batch stability (AC-005 / CLAUDE.md §10): fail closed cleanly without crashing batch
            outcomes.append(
                RuleCheckOutcome(
                    rule=RuleName.DATE_NORMALIZATION,
                    passed=False,
                    errors=(str(exc),),
                    recommended_status="REQUIRES_REVIEW",
                )
            )

        return self._finalize_result(
            outcomes=outcomes,
            duplicate_result=dup_result,
            line_result=line_result,
            total_result=total_result,
            tax_result=tax_result,
            date_result=date_result,
        )

    def validate_revalidation(
        self,
        *,
        lines: Sequence[
            LineItemArithmeticInput | InvoiceLineItemExtraction | LineItemLike | Mapping[str, Any]
        ],
        subtotal: Decimal | str | float | int,
        tax_amount: Decimal | str | float | int,
        total_amount: Decimal | str | float | int,
        vendor_context: VendorRuleContext,
        is_reverse_charge: bool = False,
        is_exempt: bool = False,
        invoice_date: str | None = None,
        due_date: str | None = None,
        check_lines_subtotal: bool = True,
    ) -> RulesEngineResult:
        """
        Synchronous re-validation pipeline for clerk edits (CLAUDE.md §7.4, LLD §2.2).

        Re-runs line arithmetic (FR-05), invoice total arithmetic (FR-06), multi-country tax (FR-07),
        optional date normalization (FR-08), and enforces the non-negotiable credit-note invariant
        (CLAUDE.md §16.1: negative-balance edits can never pass as a regular invoice).
        """
        if not isinstance(vendor_context, VendorRuleContext):
            raise ValueError("vendor_context must be a validated VendorRuleContext instance")
        _require_strict_bool(is_reverse_charge, field_name="is_reverse_charge")
        _require_strict_bool(is_exempt, field_name="is_exempt")
        _require_strict_bool(check_lines_subtotal, field_name="check_lines_subtotal")

        outcomes: list[RuleCheckOutcome] = []

        # 1. Line-item arithmetic (FR-05)
        line_result = evaluate_line_items(lines)
        line_totals = tuple(r.stated_total for r in line_result.line_results)

        # 2. Credit-note safety check (CLAUDE.md §16.1: never let negative edits pass as regular)
        is_cn, neg_tot, neg_lines = detect_credit_note(
            total_amount, subtotal=subtotal, line_totals=line_totals
        )
        if is_cn:
            cn_reason = (
                "Negative balance detected during re-validation "
                f"(negative_total={neg_tot}, negative_lines={list(neg_lines)}); "
                "must be routed as CREDIT_NOTE."
            )
            outcomes.append(
                RuleCheckOutcome(
                    rule=RuleName.DUPLICATE_CHECK,
                    passed=False,
                    skipped=False,
                    errors=(cn_reason,),
                    recommended_status="CREDIT_NOTE",
                )
            )
        else:
            outcomes.append(
                RuleCheckOutcome(rule=RuleName.DUPLICATE_CHECK, passed=True, skipped=True)
            )

        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.LINE_ARITHMETIC,
                passed=line_result.is_valid,
                errors=line_result.errors,
                recommended_status=None if line_result.is_valid else "REQUIRES_APPROVAL",
            )
        )

        # 3. Invoice total arithmetic (FR-06)
        lines_sum = line_result.computed_subtotal if (check_lines_subtotal and lines) else None
        total_result = evaluate_invoice_total(
            subtotal=subtotal,
            tax=tax_amount,
            grand_total=total_amount,
            lines_subtotal=lines_sum,
        )
        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.INVOICE_TOTAL,
                passed=total_result.is_valid,
                errors=total_result.errors,
                recommended_status=None if total_result.is_valid else "REQUIRES_APPROVAL",
            )
        )

        # 4. Multi-country tax validation (FR-07)
        tax_lines = (
            _extract_tax_lines_for_revalidation(lines)
            if vendor_context.country_code != "US"
            else None
        )
        tax_result = evaluate_tax_rate(
            country_code=vendor_context.country_code,
            subtotal=subtotal,
            stated_tax=tax_amount,
            is_reverse_charge=is_reverse_charge,
            is_exempt=is_exempt,
            vendor_tax_rate=vendor_context.standard_tax_rate,
            line_items=tax_lines,
            require_exemption_for_zero_tax=vendor_context.require_exemption_for_zero_tax,
        )
        outcomes.append(
            RuleCheckOutcome(
                rule=RuleName.TAX_VALIDATION,
                passed=tax_result.is_valid,
                errors=() if tax_result.is_valid else (tax_result.message,),
                recommended_status=tax_result.recommended_status,
            )
        )

        # 5. Optional date normalization (FR-08)
        date_result: InvoiceDatesValidationResult | None = None
        if invoice_date is not None:
            try:
                date_result = normalize_invoice_dates(
                    invoice_date,
                    due_date,
                    locale=vendor_context.effective_date_locale,
                )
                date_passed = date_result.is_valid and not date_result.is_ambiguous
                outcomes.append(
                    RuleCheckOutcome(
                        rule=RuleName.DATE_NORMALIZATION,
                        passed=date_passed,
                        errors=() if date_passed else (date_result.message,),
                        recommended_status=None if date_passed else "REQUIRES_REVIEW",
                    )
                )
            except (AmbiguousDateError, ValueError) as exc:
                outcomes.append(
                    RuleCheckOutcome(
                        rule=RuleName.DATE_NORMALIZATION,
                        passed=False,
                        errors=(str(exc),),
                        recommended_status="REQUIRES_REVIEW",
                    )
                )
        else:
            outcomes.append(
                RuleCheckOutcome(rule=RuleName.DATE_NORMALIZATION, passed=True, skipped=True)
            )

        return self._finalize_result(
            outcomes=outcomes,
            duplicate_result=None,
            line_result=line_result,
            total_result=total_result,
            tax_result=tax_result,
            date_result=date_result,
        )

    def _finalize_result(
        self,
        *,
        outcomes: list[RuleCheckOutcome],
        duplicate_result: DuplicateDetectionResult | None,
        line_result: LineItemsValidationResult | None,
        total_result: InvoiceTotalValidationResult | None,
        tax_result: TaxValidationResult | None,
        date_result: InvoiceDatesValidationResult | None,
    ) -> RulesEngineResult:
        """Assemble immutable ``RulesEngineResult`` and emit PII-free structured summary log."""
        by_rule = {o.rule: o for o in outcomes}
        failed_rules = tuple(o.rule for o in outcomes if not o.passed and not o.skipped)
        all_errors = tuple(err for o in outcomes if not o.passed for err in o.errors)
        all_passed = len(failed_rules) == 0
        recommended_status = _select_recommended_status(outcomes)

        result = RulesEngineResult(
            all_passed=all_passed,
            rule_outcomes=tuple(outcomes),
            failed_rules=failed_rules,
            errors=all_errors,
            recommended_status=recommended_status,
            duplicate_passed=by_rule[RuleName.DUPLICATE_CHECK].passed,
            line_arithmetic_valid=by_rule[RuleName.LINE_ARITHMETIC].passed,
            invoice_total_valid=by_rule[RuleName.INVOICE_TOTAL].passed,
            tax_valid=by_rule[RuleName.TAX_VALIDATION].passed,
            date_valid=by_rule[RuleName.DATE_NORMALIZATION].passed,
            duplicate_result=duplicate_result,
            line_result=line_result,
            total_result=total_result,
            tax_result=tax_result,
            date_result=date_result,
        )

        logger.info(
            "Validation rules engine completed",
            extra={
                "all_passed": result.all_passed,
                "failed_rules": [r.value for r in result.failed_rules],
                "recommended_status": result.recommended_status,
                "error_count": len(result.errors),
            },
        )
        return result


__all__ = [
    "AllowedRuleStatus",
    "RuleCheckOutcome",
    "RuleName",
    "RulesEngine",
    "RulesEngineResult",
    "VendorRuleContext",
    "parse_invoice_date",
    "validate_invoice_total",
    "validate_line_items",
    "validate_tax_rate",
]
