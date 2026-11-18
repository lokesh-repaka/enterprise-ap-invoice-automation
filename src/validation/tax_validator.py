"""
Deterministic Multi-Country Tax Validator (P7-4, FR-07).

Covers FR-07, BR-011, Q-05, LLD §5.3, PRD Journey 5, and CLAUDE.md §4.2, §5, §7.1, §16 Rule 8:
- **United Kingdom (``GB`` / alias ``UK`` — UK VAT):** 20% standard, 5% reduced, 0% zero-rated.
- **Germany (``DE`` — MwSt):** 19% standard, 7% reduced, 0% zero-rated.
- **Spain (``ES`` — IVA):** 21% standard, 10% reduced, 4% super-reduced, 0% zero-rated.
- **United States (``US`` — Sales Tax):** Verified against Vendor Master ``standard_tax_rate``
  when provided, or bounded within realistic US combined statutory sales tax ceiling (0%–15%)
  when called via the 5-argument LLD §5.3 signature.
- **Mixed-Rate Invoices:** Supports multi-rate line-item validation (e.g. UK 20% + 5% mixed
  invoices per CLAUDE.md §5 V-004), ensuring every line rate is statutory and the summed
  expected tax matches stated tax within ``get_settings().INVOICE_ROUNDING_TOLERANCE``.
- **Reverse Charge & Exemption:** ``is_reverse_charge`` or ``is_exempt`` enforces zero tax
  (``abs(stated_tax) < 0.01``); non-zero tax fails with ``REJECTED_TAX_MISMATCH``.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Fail-closed country allowlist: unknown/unsupported country codes NEVER silently fall back
  to US acceptance (closes LLD §5.3 fallback bypass).
- Strict boolean enforcement on ``is_reverse_charge`` and ``is_exempt`` (string ``"false"``
  can never coerce to ``True``).
- Rejects opposite-sign tax injection (positive subtotal with negative tax), ASCII-only
  ``[0-9]`` numeric parsing, fail-closed tolerance bounds ``[0.00, 100.00]``, and bounded
  line counts (``<= 500``) (CWE-20 / CWE-190 / CWE-400 / CWE-840 / CWE-915).
- Logs aggregate validation metadata only — zero PII in logs (CWE-532).
"""

import re
import unicodedata
from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from src.core.config import get_settings
from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema

logger = get_logger("ap.validation.tax_validator")

# Statutory VAT / MwSt / IVA rate tables (CLAUDE.md FR-07, PRD BR-011, LLD §5.3)
COUNTRY_TAX_RATES: dict[str, tuple[Decimal, ...]] = {
    "GB": (Decimal("0.20"), Decimal("0.05"), Decimal("0.00")),  # UK VAT
    "DE": (Decimal("0.19"), Decimal("0.07"), Decimal("0.00")),  # Germany MwSt
    "ES": (Decimal("0.21"), Decimal("0.10"), Decimal("0.04"), Decimal("0.00")),  # Spain IVA
}

SUPPORTED_COUNTRY_CODES: frozenset[str] = frozenset({"US", "GB", "DE", "ES"})
_COUNTRY_ALIASES: dict[str, str] = {"UK": "GB"}

# Realistic maximum combined US state + local sales tax rate ceiling (fail-closed without Vendor Master)
MAX_US_SALES_TAX_RATE: Decimal = Decimal("0.15")
ZERO_TAX_THRESHOLD: Decimal = Decimal("0.01")

# Operational & SQL DECIMAL(18, 2/4) ceilings (CWE-190 / CWE-400)
MAX_LINE_ITEMS: int = 500
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_ALLOWED_TAX_TOLERANCE: Decimal = Decimal("100.00")
MONETARY_QUANTUM: Decimal = Decimal("0.01")
RATE_QUANTUM: Decimal = Decimal("0.0001")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_DISALLOWED_UNICODE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)


def _require_strict_bool(value: Any, *, field_name: str) -> bool:
    """Enforce strict Python bool (prevents truthy string 'false' or int 1 coercion: CWE-704)."""
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a strict boolean")
    return value


def _parse_finite_decimal(raw: Any, *, field_name: str, max_abs: Decimal) -> Decimal:
    """Parse a finite, bounded strict-ASCII Decimal rejecting bool/NaN/Inf/underscores/non-ASCII."""
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} cannot be a boolean")
    if isinstance(raw, Decimal):
        val = raw
    elif isinstance(raw, int):
        if raw.bit_length() > 64:
            raise ValueError(f"{field_name} integer magnitude exceeds safe bounds")
        val = Decimal(raw)
    elif isinstance(raw, float):
        val = Decimal(str(raw))
    elif isinstance(raw, str):
        if _CONTROL_CHAR_RE.search(raw):
            raise ValueError(f"{field_name} contains disallowed control characters")
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_name} cannot be empty")
        if len(stripped) > MAX_DECIMAL_INPUT_CHARS:
            raise ValueError(
                f"{field_name} string exceeds maximum length of {MAX_DECIMAL_INPUT_CHARS}"
            )
        if not _STRICT_ASCII_DECIMAL_RE.match(stripped):
            raise ValueError(
                f"{field_name} must be a strict ASCII decimal number (underscores/non-ASCII digits rejected)"
            )
        try:
            val = Decimal(stripped)
        except InvalidOperation:
            raise ValueError(f"{field_name} must be a valid decimal number") from None
    else:
        raise ValueError(f"{field_name} must be a numeric value")

    if not val.is_finite():
        raise ValueError(f"{field_name} must be finite (NaN/Infinity rejected)")

    if val != 0:
        adjusted = val.adjusted()
        if adjusted > 12 or adjusted < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(f"{field_name} exponent exceeds allowed precision bounds")
        norm_exp = val.normalize().as_tuple().exponent
        if isinstance(norm_exp, int) and norm_exp < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(
                f"{field_name} exceeds maximum {MAX_DECIMAL_FRACTION_DIGITS} fractional digits"
            )
    else:
        val = Decimal("0")

    if abs(val) > max_abs:
        raise ValueError(f"{field_name} magnitude exceeds maximum allowed bound {max_abs}")

    return val


def _resolve_tolerance(tolerance: Decimal | str | float | int | None) -> Decimal:
    """
    Resolve and validate tax calculation rounding tolerance.

    Always reads ``get_settings().INVOICE_ROUNDING_TOLERANCE`` when ``tolerance`` is ``None``
    (CLAUDE.md §16 Rule 8 — never hardcode tolerances).
    """
    raw_tol = get_settings().INVOICE_ROUNDING_TOLERANCE if tolerance is None else tolerance
    parsed = _parse_finite_decimal(
        raw_tol,
        field_name="tax_rounding_tolerance",
        max_abs=MAX_ALLOWED_TAX_TOLERANCE,
    )
    if parsed < Decimal("0"):
        raise ValueError("tax_rounding_tolerance must be non-negative")
    return parsed


def _format_amount(value: Decimal) -> str:
    """Format monetary Decimal cleanly with 2 decimal places unless higher precision exists."""
    quantized = value.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized == value:
        return f"{quantized:.2f}"
    return f"{value.normalize():f}"


def _format_rate_pct(rate: Decimal) -> str:
    """Format a fractional tax rate (e.g. Decimal('0.0825') -> '8.25%', Decimal('0.20') -> '20%')."""
    pct = (rate * Decimal("100")).normalize()
    return f"{pct:f}%"


def normalize_country_code(country_code: str) -> str:
    """
    Validate and normalize country code to canonical ISO 3166-1 alpha-2 (``US``, ``GB``, ``DE``, ``ES``).

    Maps ``UK`` → ``GB``. Fails closed with ``ValueError`` on unsupported/spoofed codes (CWE-20/840).
    """
    if not isinstance(country_code, str):
        raise ValueError("country_code must be a string")
    if _CONTROL_CHAR_RE.search(country_code):
        raise ValueError("country_code contains disallowed control characters")
    for ch in country_code:
        if unicodedata.category(ch) in _DISALLOWED_UNICODE_CATEGORIES:
            raise ValueError("country_code contains disallowed invisible Unicode characters")
        if ch.isspace() and ch != " ":
            raise ValueError("country_code contains disallowed non-ASCII whitespace")
    nfc = unicodedata.normalize("NFC", country_code)
    if unicodedata.normalize("NFKC", nfc) != nfc:
        raise ValueError("country_code contains disallowed homograph characters")

    cleaned = nfc.strip().upper()
    canonical = _COUNTRY_ALIASES.get(cleaned, cleaned)
    if canonical not in SUPPORTED_COUNTRY_CODES:
        raise ValueError(
            f"Unsupported country_code '{cleaned}': supported jurisdictions are "
            f"{sorted(SUPPORTED_COUNTRY_CODES)}"
        )
    return canonical


class TaxLineInput(BaseModel):
    """Immutable validated line-item tax breakdown for mixed-rate invoice verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_total: Decimal
    tax_rate: Decimal

    @field_validator("line_total", mode="before")
    @classmethod
    def _validate_line_total(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="line_total", max_abs=MAX_MONETARY_AMOUNT)

    @field_validator("tax_rate", mode="before")
    @classmethod
    def _validate_tax_rate(cls, v: Any) -> Decimal:
        val = _parse_finite_decimal(v, field_name="tax_rate", max_abs=Decimal("1.0000"))
        if val < Decimal("0"):
            raise ValueError("tax_rate must be non-negative within [0.0000, 1.0000]")
        return val


class TaxValidationResult(BaseModel):
    """Immutable structured result from multi-country tax verification (FR-07)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    country_code: str
    subtotal: Decimal
    stated_tax: Decimal
    expected_tax: Decimal | None = None
    matched_rate: Decimal | None = None
    tolerance: Decimal
    is_reverse_charge: bool = False
    is_exempt: bool = False
    is_mixed_rate: bool = False
    tax_scheme_applied: str
    recommended_status: Literal["REJECTED_TAX_MISMATCH"] | None = None
    message: str


def _quantize_money(val: Decimal) -> Decimal:
    q = val.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if q == 0 else q


def _quantize_rate(val: Decimal) -> Decimal:
    q = val.quantize(RATE_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.0000") if q == 0 else q


def evaluate_tax_rate(
    country_code: str,
    subtotal: Decimal | str | float | int,
    stated_tax: Decimal | str | float | int,
    *,
    is_reverse_charge: bool = False,
    is_exempt: bool = False,
    vendor_tax_rate: Decimal | str | float | int | None = None,
    line_items: Sequence[TaxLineInput] | None = None,
    tolerance: Decimal | str | float | int | None = None,
    require_exemption_for_zero_tax: bool = False,
) -> TaxValidationResult:
    """
    Evaluate multi-country tax compliance (FR-07, BR-011, LLD §5.3, PRD Journey 5).

    Supports:
    - Reverse-charge and exemption verification (strictly requires ``abs(stated_tax) < 0.01``).
    - US sales tax (against Vendor Master ``vendor_tax_rate`` or bounded 0%–15% ceiling).
    - UK VAT (20/5/0%), DE MwSt (19/7/0%), ES IVA (21/10/4/0%) — both single-rate and mixed-rate lines.
    """
    canonical_cc = normalize_country_code(country_code)
    rc_flag = _require_strict_bool(is_reverse_charge, field_name="is_reverse_charge")
    ex_flag = _require_strict_bool(is_exempt, field_name="is_exempt")
    req_zero_ex = _require_strict_bool(
        require_exemption_for_zero_tax, field_name="require_exemption_for_zero_tax"
    )
    parsed_subtotal = _parse_finite_decimal(
        subtotal, field_name="subtotal", max_abs=MAX_MONETARY_AMOUNT
    )
    parsed_tax = _parse_finite_decimal(
        stated_tax, field_name="stated_tax", max_abs=MAX_MONETARY_AMOUNT
    )
    resolved_tol = _resolve_tolerance(tolerance)

    parsed_vendor_rate: Decimal | None = None
    if vendor_tax_rate is not None:
        parsed_vendor_rate = _parse_finite_decimal(
            vendor_tax_rate, field_name="vendor_tax_rate", max_abs=Decimal("1.0000")
        )
        if parsed_vendor_rate < Decimal("0"):
            raise ValueError("vendor_tax_rate must be non-negative within [0.0000, 1.0000]")

    validated_lines: tuple[TaxLineInput, ...] = ()
    if line_items is not None:
        if isinstance(line_items, (str, bytes)) or not isinstance(line_items, Sequence):
            raise ValueError("line_items must be a sequence of TaxLineInput items")
        if len(line_items) > MAX_LINE_ITEMS:
            raise ValueError(f"line_items exceeds maximum allowed count of {MAX_LINE_ITEMS}")
        validated_lines = tuple(
            item if isinstance(item, TaxLineInput) else TaxLineInput.model_validate(item)
            for item in line_items
        )

    # 1. Reverse Charge / Tax Exemption branch (LLD §5.3)
    if rc_flag or ex_flag:
        scheme = (
            "REVERSE_CHARGE_AND_EXEMPT"
            if (rc_flag and ex_flag)
            else ("REVERSE_CHARGE" if rc_flag else "EXEMPT")
        )
        if abs(parsed_tax) < ZERO_TAX_THRESHOLD:
            res = TaxValidationResult(
                is_valid=True,
                country_code=canonical_cc,
                subtotal=parsed_subtotal,
                stated_tax=parsed_tax,
                expected_tax=Decimal("0.00"),
                matched_rate=Decimal("0.00"),
                tolerance=resolved_tol,
                is_reverse_charge=rc_flag,
                is_exempt=ex_flag,
                tax_scheme_applied=scheme,
                recommended_status=None,
                message="Valid Exemption / Reverse Charge verified.",
            )
        else:
            res = TaxValidationResult(
                is_valid=False,
                country_code=canonical_cc,
                subtotal=parsed_subtotal,
                stated_tax=parsed_tax,
                expected_tax=Decimal("0.00"),
                matched_rate=None,
                tolerance=resolved_tol,
                is_reverse_charge=rc_flag,
                is_exempt=ex_flag,
                tax_scheme_applied=scheme,
                recommended_status="REJECTED_TAX_MISMATCH",
                message="Tax amount must be zero for reverse charge or exempt transactions.",
            )
        _log_tax_outcome(res)
        return res

    # 2. Opposite-sign tax guard (blocks positive subtotal + negative tax manipulation: CWE-840)
    if (parsed_subtotal > Decimal("0") and parsed_tax < Decimal("0")) or (
        parsed_subtotal < Decimal("0") and parsed_tax > Decimal("0")
    ):
        res = TaxValidationResult(
            is_valid=False,
            country_code=canonical_cc,
            subtotal=parsed_subtotal,
            stated_tax=parsed_tax,
            expected_tax=None,
            matched_rate=None,
            tolerance=resolved_tol,
            tax_scheme_applied=f"{canonical_cc}_TAX",
            recommended_status="REJECTED_TAX_MISMATCH",
            message=(
                f"Stated tax ({_format_amount(parsed_tax)}) has opposite sign to "
                f"subtotal ({_format_amount(parsed_subtotal)})."
            ),
        )
        _log_tax_outcome(res)
        return res

    # 3. Zero subtotal check
    if parsed_subtotal == Decimal("0"):
        is_zero_ok = abs(parsed_tax) <= resolved_tol
        res = TaxValidationResult(
            is_valid=is_zero_ok,
            country_code=canonical_cc,
            subtotal=parsed_subtotal,
            stated_tax=parsed_tax,
            expected_tax=Decimal("0.00"),
            matched_rate=Decimal("0.00") if is_zero_ok else None,
            tolerance=resolved_tol,
            tax_scheme_applied=f"{canonical_cc}_ZERO_SUBTOTAL",
            recommended_status=None if is_zero_ok else "REJECTED_TAX_MISMATCH",
            message=(
                "Zero tax verified on zero-subtotal invoice."
                if is_zero_ok
                else f"Non-zero stated tax ({_format_amount(parsed_tax)}) on zero-subtotal invoice."
            ),
        )
        _log_tax_outcome(res)
        return res

    # 4. United States Sales Tax (FR-07, BR-011)
    if canonical_cc == "US":
        if parsed_vendor_rate is not None:
            if parsed_vendor_rate > MAX_US_SALES_TAX_RATE:
                raise ValueError(
                    f"vendor_tax_rate ({_format_rate_pct(parsed_vendor_rate)}) exceeds maximum "
                    f"US statutory sales tax ceiling ({_format_rate_pct(MAX_US_SALES_TAX_RATE)})"
                )
            expected_tax = _quantize_money(parsed_subtotal * parsed_vendor_rate)
            diff = abs(expected_tax - parsed_tax)
            is_ok = diff <= resolved_tol
            res = TaxValidationResult(
                is_valid=is_ok,
                country_code="US",
                subtotal=parsed_subtotal,
                stated_tax=parsed_tax,
                expected_tax=expected_tax,
                matched_rate=parsed_vendor_rate if is_ok else None,
                tolerance=resolved_tol,
                tax_scheme_applied="US_SALES_TAX_VENDOR_MASTER",
                recommended_status=None if is_ok else "REJECTED_TAX_MISMATCH",
                message=(
                    f"Matched Vendor Master US sales tax rate of {_format_rate_pct(parsed_vendor_rate)}."
                    if is_ok
                    else (
                        f"Stated US sales tax ({_format_amount(parsed_tax)}) differs from "
                        f"Vendor Master expected tax ({expected_tax:.2f} at "
                        f"{_format_rate_pct(parsed_vendor_rate)}) by {_format_amount(diff)}."
                    )
                ),
            )
            _log_tax_outcome(res)
            return res

        # 5-arg LLD §5.3 US fallback without Vendor Master: verify within realistic [0%, 15%] bounds
        max_allowed_us_tax = _quantize_money(abs(parsed_subtotal) * MAX_US_SALES_TAX_RATE)
        is_within_us_cap = abs(parsed_tax) <= (max_allowed_us_tax + resolved_tol)
        implied_rate = _quantize_rate(abs(parsed_tax) / abs(parsed_subtotal))
        res = TaxValidationResult(
            is_valid=is_within_us_cap,
            country_code="US",
            subtotal=parsed_subtotal,
            stated_tax=parsed_tax,
            expected_tax=parsed_tax if is_within_us_cap else max_allowed_us_tax,
            matched_rate=implied_rate if is_within_us_cap else None,
            tolerance=resolved_tol,
            tax_scheme_applied="US_SALES_TAX",
            recommended_status=None if is_within_us_cap else "REJECTED_TAX_MISMATCH",
            message=(
                "US sales tax accepted based on vendor tax jurisdiction."
                if is_within_us_cap
                else (
                    f"Stated US sales tax ({_format_amount(parsed_tax)}) exceeds maximum "
                    f"allowable US sales tax ceiling ({_format_rate_pct(MAX_US_SALES_TAX_RATE)})."
                )
            ),
        )
        _log_tax_outcome(res)
        return res

    # 5. UK / EU Statutory VAT, MwSt, IVA (GB, DE, ES)
    statutory_rates = COUNTRY_TAX_RATES[canonical_cc]
    allowed_rates = tuple(r for r in statutory_rates if not (req_zero_ex and r == Decimal("0.00")))
    allowed_rates_q = {_quantize_rate(r) for r in allowed_rates}

    # 5a. Line-level / mixed-rate validation when line_items are supplied (e.g. UK 20% + 5% mixed)
    if validated_lines:
        distinct_line_rates = {_quantize_rate(line.tax_rate) for line in validated_lines}
        is_mixed = len(distinct_line_rates) > 1
        for idx, line in enumerate(validated_lines, start=1):
            rate_q = _quantize_rate(line.tax_rate)
            if rate_q not in allowed_rates_q:
                res = TaxValidationResult(
                    is_valid=False,
                    country_code=canonical_cc,
                    subtotal=parsed_subtotal,
                    stated_tax=parsed_tax,
                    expected_tax=None,
                    matched_rate=None,
                    tolerance=resolved_tol,
                    is_mixed_rate=is_mixed,
                    tax_scheme_applied=f"{canonical_cc}_VAT_LINE_ITEMS",
                    recommended_status="REJECTED_TAX_MISMATCH",
                    message=(
                        f"Line {idx} carries non-statutory tax rate "
                        f"{_format_rate_pct(line.tax_rate)} for {canonical_cc}."
                    ),
                )
                _log_tax_outcome(res)
                return res

        raw_line_subtotal = Decimal("0")
        raw_line_tax_sum = Decimal("0")
        for line in validated_lines:
            raw_line_subtotal += line.line_total
            raw_line_tax_sum += line.line_total * line.tax_rate
            if (
                abs(raw_line_subtotal) > MAX_MONETARY_AMOUNT
                or abs(raw_line_tax_sum) > MAX_MONETARY_AMOUNT
            ):
                raise ValueError(
                    f"Aggregate line tax sum exceeds maximum allowed bound {MAX_MONETARY_AMOUNT}"
                )

        # SEC-150 (CWE-840): Ensure line totals actually reconcile with header subtotal
        # so an attacker cannot evade VAT by supplying partial lines that match a low stated_tax
        lines_subtotal_q = _quantize_money(raw_line_subtotal)
        subtotal_diff = abs(lines_subtotal_q - parsed_subtotal)
        if subtotal_diff > resolved_tol:
            res = TaxValidationResult(
                is_valid=False,
                country_code=canonical_cc,
                subtotal=parsed_subtotal,
                stated_tax=parsed_tax,
                expected_tax=None,
                matched_rate=None,
                tolerance=resolved_tol,
                is_mixed_rate=is_mixed,
                tax_scheme_applied=f"{canonical_cc}_VAT_LINE_ITEMS",
                recommended_status="REJECTED_TAX_MISMATCH",
                message=(
                    f"Line items subtotal ({lines_subtotal_q:.2f}) does not reconcile with "
                    f"header subtotal ({_format_amount(parsed_subtotal)}) for {canonical_cc} "
                    f"tax calculation (diff={_format_amount(subtotal_diff)})."
                ),
            )
            _log_tax_outcome(res)
            return res

        expected_line_tax = _quantize_money(raw_line_tax_sum)
        diff = abs(expected_line_tax - parsed_tax)
        is_ok = diff <= resolved_tol
        single_matched_rate = next(iter(distinct_line_rates)) if (is_ok and not is_mixed) else None
        res = TaxValidationResult(
            is_valid=is_ok,
            country_code=canonical_cc,
            subtotal=parsed_subtotal,
            stated_tax=parsed_tax,
            expected_tax=expected_line_tax,
            matched_rate=single_matched_rate,
            tolerance=resolved_tol,
            is_mixed_rate=is_mixed,
            tax_scheme_applied=f"{canonical_cc}_VAT_MIXED" if is_mixed else f"{canonical_cc}_VAT",
            recommended_status=None if is_ok else "REJECTED_TAX_MISMATCH",
            message=(
                (
                    f"Matched approved mixed statutory VAT rates for {canonical_cc} "
                    f"(expected {expected_line_tax:.2f})."
                    if is_mixed
                    else f"Matched approved statutory rate of {_format_rate_pct(single_matched_rate or Decimal('0'))}."
                )
                if is_ok
                else (
                    f"Stated tax ({_format_amount(parsed_tax)}) does not match line-item "
                    f"statutory VAT sum ({expected_line_tax:.2f}) for {canonical_cc} "
                    f"(diff={_format_amount(diff)})."
                )
            ),
        )
        _log_tax_outcome(res)
        return res

    # 5b. Header-only statutory rate match (LLD §5.3)
    for rate in allowed_rates:
        expected_tax = _quantize_money(parsed_subtotal * rate)
        if abs(expected_tax - parsed_tax) <= resolved_tol:
            res = TaxValidationResult(
                is_valid=True,
                country_code=canonical_cc,
                subtotal=parsed_subtotal,
                stated_tax=parsed_tax,
                expected_tax=expected_tax,
                matched_rate=rate,
                tolerance=resolved_tol,
                tax_scheme_applied=f"{canonical_cc}_VAT",
                recommended_status=None,
                message=f"Matched approved statutory rate of {_format_rate_pct(rate)}.",
            )
            _log_tax_outcome(res)
            return res

    rates_display = ", ".join(_format_rate_pct(r) for r in allowed_rates)
    res = TaxValidationResult(
        is_valid=False,
        country_code=canonical_cc,
        subtotal=parsed_subtotal,
        stated_tax=parsed_tax,
        expected_tax=None,
        matched_rate=None,
        tolerance=resolved_tol,
        tax_scheme_applied=f"{canonical_cc}_VAT",
        recommended_status="REJECTED_TAX_MISMATCH",
        message=(
            f"Stated tax {_format_amount(parsed_tax)} does not match any statutory VAT rate "
            f"({rates_display}) for {canonical_cc}."
        ),
    )
    _log_tax_outcome(res)
    return res


def _log_tax_outcome(result: TaxValidationResult) -> None:
    """Emit structured PII-free tax validation telemetry."""
    logger.info(
        "Multi-country tax validation evaluated",
        extra={
            "country_code": result.country_code,
            "is_valid": result.is_valid,
            "tax_scheme_applied": result.tax_scheme_applied,
            "is_reverse_charge": result.is_reverse_charge,
            "is_exempt": result.is_exempt,
            "is_mixed_rate": result.is_mixed_rate,
            "recommended_status": result.recommended_status,
        },
    )


def validate_tax_rate(
    country_code: str,
    subtotal: Decimal | str | float | int,
    stated_tax: Decimal | str | float | int,
    is_reverse_charge: bool,
    is_exempt: bool,
    *,
    vendor_tax_rate: Decimal | str | float | int | None = None,
    tolerance: Decimal | str | float | int | None = None,
) -> tuple[bool, str]:
    """
    LLD §5.3 / FR-07 contract: validate country-specific tax rate with reverse-charge/exemption support.

    Returns:
        ``(is_valid, message)``
    """
    result = evaluate_tax_rate(
        country_code=country_code,
        subtotal=subtotal,
        stated_tax=stated_tax,
        is_reverse_charge=is_reverse_charge,
        is_exempt=is_exempt,
        vendor_tax_rate=vendor_tax_rate,
        tolerance=tolerance,
    )
    return result.is_valid, result.message


def validate_extraction_tax(
    extraction: InvoiceExtractionSchema,
    *,
    country_code: str,
    vendor_tax_rate: Decimal | str | float | int | None = None,
    tolerance: Decimal | str | float | int | None = None,
    require_exemption_for_zero_tax: bool = False,
) -> TaxValidationResult:
    """Validate multi-country tax directly on a P6-3 ``InvoiceExtractionSchema``."""
    canonical_cc = normalize_country_code(country_code)
    tax_lines = (
        tuple(
            TaxLineInput(
                line_total=item.line_total.value,
                tax_rate=item.tax_rate.value,
            )
            for item in extraction.line_items
        )
        if (canonical_cc != "US" and extraction.line_items)
        else None
    )
    return evaluate_tax_rate(
        country_code=canonical_cc,
        subtotal=extraction.header.subtotal.value,
        stated_tax=extraction.header.tax_amount.value,
        is_reverse_charge=extraction.is_reverse_charge,
        is_exempt=extraction.is_exempt,
        vendor_tax_rate=vendor_tax_rate,
        line_items=tax_lines,
        tolerance=tolerance,
        require_exemption_for_zero_tax=require_exemption_for_zero_tax,
    )


__all__ = [
    "COUNTRY_TAX_RATES",
    "MAX_ALLOWED_TAX_TOLERANCE",
    "MAX_US_SALES_TAX_RATE",
    "SUPPORTED_COUNTRY_CODES",
    "ZERO_TAX_THRESHOLD",
    "TaxLineInput",
    "TaxValidationResult",
    "evaluate_tax_rate",
    "normalize_country_code",
    "validate_extraction_tax",
    "validate_tax_rate",
]
