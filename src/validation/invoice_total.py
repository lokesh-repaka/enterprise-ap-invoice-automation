"""
Deterministic Invoice Total Arithmetic Validator (P7-3, FR-06).

Covers FR-06, BR-010, Q-05, LLD §5.2, and CLAUDE.md §4.2, §5, §7.1, §7.2, §11.1, §16 Rule 8:
- Verifies ``Subtotal + Tax = Grand Total`` within the configured tolerance
  (``get_settings().INVOICE_ROUNDING_TOLERANCE``, default ``±0.05``).
- Uses exact ``Decimal`` arithmetic with ``ROUND_HALF_UP`` quantization (eliminates IEEE 754
  floating-point boundary artifacts) while preserving exact unrounded precision on stated
  ``grand_total`` so sub-cent overruns (e.g. ``+0.051 > 0.05``) never round into a false pass.
- Flags ``rounding_within_tolerance=True`` when ``0 < diff <= tolerance`` (surfaces ``INV-2026-1030``
  style minor vendor rounding cleanly for audit telemetry).
- Supports optional cross-checking of header ``subtotal`` against the sum of line-item totals
  (``lines_subtotal``) to catch header-vs-line subtotal tampering.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never hardcodes tolerance thresholds — always reads ``get_settings().INVOICE_ROUNDING_TOLERANCE``
  (CLAUDE.md §16 Rule 8) and enforces fail-closed bounds ``[0.00, MAX_ALLOWED_TOLERANCE]``.
- Rejects booleans, NaN, Infinity, Python underscore literals, non-ASCII Unicode digits, CRLF
  control characters, scientific-notation exponent bombs, SQL ``DECIMAL(18, 2)`` sum overflow,
  missing ORM monetary fields, and extra injected fields (CWE-20 / CWE-117 / CWE-190 / CWE-436 / CWE-915).
- Logs aggregate validation metrics only — zero PII or identifiers in logs (CWE-532).
"""

import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator

from src.core.config import get_settings
from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema

logger = get_logger("ap.validation.invoice_total")

# Operational & SQL DECIMAL(18, 2) ceilings (CWE-190 / CWE-400)
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_ALLOWED_INVOICE_TOLERANCE: Decimal = Decimal("100.00")
MONETARY_QUANTUM: Decimal = Decimal("0.01")

# Strict ASCII numeric format (blocks underscores '1_000', Arabic-Indic digits '١٠', and CRLF)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)


@runtime_checkable
class InvoiceTotalRecordLike(Protocol):
    """Duck-typed protocol satisfied by SQLAlchemy Invoice ORM records without importing SQLAlchemy."""

    subtotal: Decimal | None
    total_tax_amount: Decimal | None
    total_amount: Decimal


def _parse_finite_decimal(raw: Any, *, field_name: str, max_abs: Decimal) -> Decimal:
    """
    Parse a finite, bounded ASCII Decimal rejecting booleans, NaN/Inf, underscores,
    non-ASCII digits, control characters, and scientific-notation exponent bombs.
    """
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
    Resolve and validate the invoice grand-total rounding tolerance.

    Always reads ``get_settings().INVOICE_ROUNDING_TOLERANCE`` when ``tolerance`` is ``None``
    (CLAUDE.md §16 Rule 8 — never hardcode thresholds in validation logic).
    """
    raw_tol = get_settings().INVOICE_ROUNDING_TOLERANCE if tolerance is None else tolerance
    parsed = _parse_finite_decimal(
        raw_tol,
        field_name="invoice_rounding_tolerance",
        max_abs=MAX_ALLOWED_INVOICE_TOLERANCE,
    )
    if parsed < Decimal("0"):
        raise ValueError("invoice_rounding_tolerance must be non-negative")
    return parsed


def _format_decimal_amount(value: Decimal) -> str:
    """Format a Decimal with 2 decimal places unless higher non-zero precision is present."""
    quantized = value.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized == value:
        return f"{quantized:.2f}"
    return f"{value.normalize():f}"


class InvoiceTotalInput(BaseModel):
    """Immutable validated header monetary inputs for FR-06 grand-total verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subtotal: Decimal
    tax_amount: Decimal
    total_amount: Decimal
    lines_subtotal: Decimal | None = None

    @field_validator("subtotal", mode="before")
    @classmethod
    def _validate_subtotal(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="subtotal", max_abs=MAX_MONETARY_AMOUNT)

    @field_validator("tax_amount", mode="before")
    @classmethod
    def _validate_tax_amount(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="tax_amount", max_abs=MAX_MONETARY_AMOUNT)

    @field_validator("total_amount", mode="before")
    @classmethod
    def _validate_total_amount(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="total_amount", max_abs=MAX_MONETARY_AMOUNT)

    @field_validator("lines_subtotal", mode="before")
    @classmethod
    def _validate_lines_subtotal(cls, v: Any) -> Decimal | None:
        if v is None:
            return None
        return _parse_finite_decimal(v, field_name="lines_subtotal", max_abs=MAX_MONETARY_AMOUNT)


class InvoiceTotalValidationResult(BaseModel):
    """Immutable structured result for FR-06 invoice total arithmetic verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    subtotal: Decimal
    tax_amount: Decimal
    stated_total: Decimal
    expected_total: Decimal
    difference: Decimal
    tolerance: Decimal
    rounding_within_tolerance: bool
    sign_consistent: bool = True
    lines_subtotal: Decimal | None = None
    subtotal_lines_difference: Decimal | None = None
    subtotal_matches_lines: bool | None = None
    error: str = ""
    errors: tuple[str, ...] = ()


def evaluate_invoice_total(
    subtotal: Decimal | str | float | int,
    tax: Decimal | str | float | int,
    grand_total: Decimal | str | float | int,
    *,
    tolerance: Decimal | str | float | int | None = None,
    lines_subtotal: Decimal | str | float | int | None = None,
) -> InvoiceTotalValidationResult:
    """
    Evaluate ``Subtotal + Tax = Grand Total`` within ``±tolerance`` (FR-06, BR-010, LLD §5.2).

    Reads ``INVOICE_ROUNDING_TOLERANCE`` from ``get_settings()`` unless explicitly overridden.
    When ``lines_subtotal`` is supplied, also verifies ``abs(lines_subtotal - subtotal) <= tolerance``.
    """
    validated = InvoiceTotalInput(
        subtotal=subtotal,
        tax_amount=tax,
        total_amount=grand_total,
        lines_subtotal=lines_subtotal,
    )
    resolved_tolerance = _resolve_tolerance(tolerance)

    raw_expected = validated.subtotal + validated.tax_amount
    if abs(raw_expected) > MAX_MONETARY_AMOUNT:
        raise ValueError(f"Subtotal + Tax sum exceeds maximum allowed bound {MAX_MONETARY_AMOUNT}")

    expected_total = raw_expected.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if expected_total == 0:
        expected_total = Decimal("0.00")

    diff = abs(expected_total - validated.total_amount)
    if diff == 0:
        diff = Decimal("0.00")

    errors: list[str] = []

    # Guard against opposite-sign tax injection (e.g. +$10,000 subtotal + -$100 tax = $9,900
    # attempting to evade the $10,000 manager approval threshold: SEC-146 / CWE-840)
    sign_consistent = not (
        (validated.subtotal > Decimal("0") and validated.tax_amount < Decimal("0"))
        or (validated.subtotal < Decimal("0") and validated.tax_amount > Decimal("0"))
    )
    if not sign_consistent:
        errors.append(
            f"Tax ({_format_decimal_amount(validated.tax_amount)}) has opposite sign to "
            f"Subtotal ({_format_decimal_amount(validated.subtotal)})"
        )

    header_valid = diff <= resolved_tolerance
    if not header_valid:
        errors.append(
            f"Subtotal ({_format_decimal_amount(validated.subtotal)}) + "
            f"Tax ({_format_decimal_amount(validated.tax_amount)}) = {expected_total:.2f}, "
            f"which differs from Grand Total ({_format_decimal_amount(validated.total_amount)}) "
            f"by {_format_decimal_amount(diff)} "
            f"(tolerance: +/-{_format_decimal_amount(resolved_tolerance)})"
        )

    subtotal_lines_diff: Decimal | None = None
    subtotal_matches_lines: bool | None = None
    if validated.lines_subtotal is not None:
        subtotal_lines_diff = abs(validated.lines_subtotal - validated.subtotal)
        if subtotal_lines_diff == 0:
            subtotal_lines_diff = Decimal("0.00")
        subtotal_matches_lines = subtotal_lines_diff <= resolved_tolerance
        if not subtotal_matches_lines:
            errors.append(
                f"Line items sum ({_format_decimal_amount(validated.lines_subtotal)}) "
                f"differs from Header Subtotal ({_format_decimal_amount(validated.subtotal)}) "
                f"by {_format_decimal_amount(subtotal_lines_diff)} "
                f"(tolerance: +/-{_format_decimal_amount(resolved_tolerance)})"
            )

    is_valid = len(errors) == 0
    rounding_within_tolerance = header_valid and diff > Decimal("0.00")
    combined_error = "; ".join(errors)

    logger.info(
        "Invoice total arithmetic validation evaluated",
        extra={
            "is_valid": is_valid,
            "rounding_within_tolerance": rounding_within_tolerance,
            "difference": _format_decimal_amount(diff),
            "subtotal_matches_lines": subtotal_matches_lines,
        },
    )

    return InvoiceTotalValidationResult(
        is_valid=is_valid,
        subtotal=validated.subtotal,
        tax_amount=validated.tax_amount,
        stated_total=validated.total_amount,
        expected_total=expected_total,
        difference=diff,
        tolerance=resolved_tolerance,
        rounding_within_tolerance=rounding_within_tolerance,
        sign_consistent=sign_consistent,
        lines_subtotal=validated.lines_subtotal,
        subtotal_lines_difference=subtotal_lines_diff,
        subtotal_matches_lines=subtotal_matches_lines,
        error=combined_error,
        errors=tuple(errors),
    )


def validate_invoice_total(
    subtotal: Decimal | str | float | int,
    tax: Decimal | str | float | int,
    grand_total: Decimal | str | float | int,
    *,
    tolerance: Decimal | str | float | int | None = None,
) -> tuple[bool, str]:
    """
    LLD §5.2 / FR-06 contract: validate ``Subtotal + Tax = Grand Total ± tol``.

    Returns:
        ``(True, "")`` when balanced within ``get_settings().INVOICE_ROUNDING_TOLERANCE``
        (default ``±0.05``), otherwise ``(False, error_message)``.
    """
    result = evaluate_invoice_total(subtotal, tax, grand_total, tolerance=tolerance)
    return result.is_valid, result.error


def validate_extraction_invoice_total(
    extraction: InvoiceExtractionSchema,
    *,
    tolerance: Decimal | str | float | int | None = None,
    check_lines_subtotal: bool = False,
) -> InvoiceTotalValidationResult:
    """Validate invoice grand-total arithmetic directly on a P6-3 ``InvoiceExtractionSchema``."""
    lines_sum: Decimal | None = None
    if check_lines_subtotal:
        running = Decimal("0.00")
        for item in extraction.line_items:
            running += item.line_total.value
            if abs(running) > MAX_MONETARY_AMOUNT:
                raise ValueError(
                    f"Aggregate line subtotal exceeds maximum allowed bound {MAX_MONETARY_AMOUNT}"
                )
        lines_sum = running.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
        if lines_sum == 0:
            lines_sum = Decimal("0.00")

    return evaluate_invoice_total(
        subtotal=extraction.header.subtotal.value,
        tax=extraction.header.tax_amount.value,
        grand_total=extraction.header.total_amount.value,
        tolerance=tolerance,
        lines_subtotal=lines_sum,
    )


def evaluate_invoice_record(
    invoice: InvoiceTotalRecordLike,
    *,
    tolerance: Decimal | str | float | int | None = None,
    lines_subtotal: Decimal | str | float | int | None = None,
) -> InvoiceTotalValidationResult:
    """
    Validate grand-total arithmetic on a persisted ``Invoice`` ORM record (fail-closed on NULL fields).
    """
    if not isinstance(invoice, InvoiceTotalRecordLike):
        raise ValueError(f"Unsupported invoice record type: {type(invoice).__name__}")
    if invoice.subtotal is None:
        raise ValueError("Invoice record is missing required subtotal for FR-06 validation")
    if invoice.total_tax_amount is None:
        raise ValueError("Invoice record is missing required total_tax_amount for FR-06 validation")

    return evaluate_invoice_total(
        subtotal=invoice.subtotal,
        tax=invoice.total_tax_amount,
        grand_total=invoice.total_amount,
        tolerance=tolerance,
        lines_subtotal=lines_subtotal,
    )


__all__ = [
    "MAX_ALLOWED_INVOICE_TOLERANCE",
    "InvoiceTotalInput",
    "InvoiceTotalRecordLike",
    "InvoiceTotalValidationResult",
    "evaluate_invoice_record",
    "evaluate_invoice_total",
    "validate_extraction_invoice_total",
    "validate_invoice_total",
]
