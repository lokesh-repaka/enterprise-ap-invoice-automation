"""
Deterministic Line-Item Arithmetic Validator (P7-2, FR-05).

Covers FR-05, BR-009, Q-05, LLD §5.1, and CLAUDE.md §4.2, §7.1, §7.2, §11.1, §16 Rule 8:
- Verifies ``Qty × Unit Price = Line Total`` within the configured tolerance
  (``get_settings().LINE_ROUNDING_TOLERANCE``, default ``±0.02``).
- Uses exact ``Decimal`` arithmetic with ``ROUND_HALF_UP`` quantization (eliminates IEEE 754
  binary floating-point boundary bugs such as ``10.02 - 10.00 = 0.02000000000000135``).
- Preserves exact unrounded precision on stated ``line_total`` when comparing against tolerance
  so sub-cent overruns (e.g. ``+0.021 > 0.02``) are never silently rounded into a false pass.
- Accepts ``LineItemArithmeticInput``, P6-3 ``InvoiceLineItemExtraction``, P2-1 SQLAlchemy
  ``InvoiceLine`` (duck-typed without importing SQLAlchemy), or plain ``dict`` line payloads.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never hardcodes tolerance thresholds — always reads ``get_settings().LINE_ROUNDING_TOLERANCE``
  (CLAUDE.md §16 Rule 8) and bounds tolerance to ``[0.00, MAX_ALLOWED_TOLERANCE]``.
- Rejects booleans, NaN, Infinity, oversized numeric strings, scientific-notation exponent bombs,
  product/subtotal overflow past SQL ``DECIMAL(18, 2)``, unbounded line lists (``>500``), and
  injected extra fields (CWE-20 / CWE-190 / CWE-400 / CWE-915).
- Logs aggregate validation counts only — zero PII or line descriptions in logs (CWE-532).
"""

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator

from src.core.config import get_settings
from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema, InvoiceLineItemExtraction

logger = get_logger("ap.validation.line_arithmetic")

# Operational & SQL DECIMAL(18, 2/4) ceilings (CWE-190 / CWE-400)
MAX_LINE_ITEMS: int = 500
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_QUANTITY_AMOUNT: Decimal = Decimal("999999999999.9999")
MAX_ALLOWED_TOLERANCE: Decimal = Decimal("100.00")
MONETARY_QUANTUM: Decimal = Decimal("0.01")

# Strict ASCII numeric format (blocks underscores '1_000', Arabic-Indic digits '١٠', and CRLF: CWE-20/436)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)

# Allowed keys when coercing raw dict payloads (blocks injected fields like status/approved_by: CWE-915)
_ALLOWED_DICT_LINE_KEYS: frozenset[str] = frozenset(
    {
        "line_number",
        "description",
        "quantity",
        "unit_price",
        "line_total",
        "tax_rate",
        "line_tax_rate",
        "confidence_score",
    }
)


@runtime_checkable
class LineItemLike(Protocol):
    """Minimal duck-typed protocol satisfied by SQLAlchemy InvoiceLine and custom line objects."""

    quantity: Decimal | str | float | int
    unit_price: Decimal | str | float | int
    line_total: Decimal | str | float | int


def _parse_finite_decimal(raw: Any, *, field_name: str, max_abs: Decimal) -> Decimal:
    """
    Parse a finite, bounded Decimal rejecting booleans, NaN/Inf, and exponent bombs
    (CWE-20 / CWE-190 / CWE-400). Canonicalizes signed zero to ``Decimal("0")``.
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
    Resolve and validate the line-item rounding tolerance.

    Always reads ``get_settings().LINE_ROUNDING_TOLERANCE`` when ``tolerance`` is ``None``
    (CLAUDE.md §16 Rule 8 — never hardcode thresholds in validation logic).
    """
    raw_tol = get_settings().LINE_ROUNDING_TOLERANCE if tolerance is None else tolerance
    parsed = _parse_finite_decimal(
        raw_tol,
        field_name="line_rounding_tolerance",
        max_abs=MAX_ALLOWED_TOLERANCE,
    )
    if parsed < Decimal("0"):
        raise ValueError("line_rounding_tolerance must be non-negative")
    return parsed


def _format_decimal_amount(value: Decimal) -> str:
    """Format a Decimal with 2 decimal places unless higher non-zero precision is present."""
    quantized = value.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized == value:
        return f"{quantized:.2f}"
    return f"{value.normalize():f}"


class LineItemArithmeticInput(BaseModel):
    """Immutable validated line-item input for FR-05 arithmetic verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_number: int
    quantity: Decimal
    unit_price: Decimal
    line_total: Decimal

    @field_validator("line_number", mode="before")
    @classmethod
    def _validate_line_number(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("line_number must be a positive integer")
        if v < 1 or v > MAX_LINE_ITEMS:
            raise ValueError(f"line_number must be between 1 and {MAX_LINE_ITEMS}")
        return v

    @field_validator("quantity", mode="before")
    @classmethod
    def _validate_quantity(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="quantity", max_abs=MAX_QUANTITY_AMOUNT)

    @field_validator("unit_price", mode="before")
    @classmethod
    def _validate_unit_price(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="unit_price", max_abs=MAX_MONETARY_AMOUNT)

    @field_validator("line_total", mode="before")
    @classmethod
    def _validate_line_total(cls, v: Any) -> Decimal:
        return _parse_finite_decimal(v, field_name="line_total", max_abs=MAX_MONETARY_AMOUNT)


class LineItemCheckResult(BaseModel):
    """Immutable per-line arithmetic verification outcome (FR-05)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_number: int
    quantity: Decimal
    unit_price: Decimal
    stated_total: Decimal
    expected_total: Decimal
    difference: Decimal
    tolerance: Decimal
    is_valid: bool
    error: str | None = None


class LineItemsValidationResult(BaseModel):
    """Immutable aggregate result for all validated invoice line items (FR-05, P7-6)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    tolerance: Decimal
    total_lines_checked: int
    passed_count: int
    failed_count: int
    computed_subtotal: Decimal
    expected_subtotal: Decimal
    cumulative_rounding_drift: Decimal
    line_results: tuple[LineItemCheckResult, ...]
    errors: tuple[str, ...]


def _coerce_line_input(raw: Any, *, default_line_number: int) -> LineItemArithmeticInput:
    """Convert supported line-item representations into a validated ``LineItemArithmeticInput``."""
    if isinstance(raw, LineItemArithmeticInput):
        return raw

    if isinstance(raw, InvoiceLineItemExtraction):
        return LineItemArithmeticInput(
            line_number=default_line_number,
            quantity=raw.quantity.value,
            unit_price=raw.unit_price.value,
            line_total=raw.line_total.value,
        )

    if isinstance(raw, Mapping):
        unknown_keys = set(raw.keys()) - _ALLOWED_DICT_LINE_KEYS
        if unknown_keys:
            raise ValueError(f"Disallowed fields in line item payload: {sorted(unknown_keys)}")
        missing_keys = {"quantity", "unit_price", "line_total"} - set(raw.keys())
        if missing_keys:
            raise ValueError(f"Missing required line item fields: {sorted(missing_keys)}")
        raw_line_num = raw.get("line_number")
        line_num = default_line_number if raw_line_num is None else raw_line_num
        return LineItemArithmeticInput(
            line_number=line_num,
            quantity=raw["quantity"],
            unit_price=raw["unit_price"],
            line_total=raw["line_total"],
        )

    if isinstance(raw, LineItemLike):
        raw_line_num = getattr(raw, "line_number", None)
        line_num = default_line_number if raw_line_num is None else raw_line_num
        return LineItemArithmeticInput(
            line_number=line_num,
            quantity=raw.quantity,
            unit_price=raw.unit_price,
            line_total=raw.line_total,
        )

    raise ValueError(
        f"Unsupported line item type at position {default_line_number}: {type(raw).__name__}"
    )


def evaluate_line_items(
    lines: Sequence[
        LineItemArithmeticInput | InvoiceLineItemExtraction | LineItemLike | Mapping[str, Any]
    ],
    *,
    tolerance: Decimal | str | float | int | None = None,
) -> LineItemsValidationResult:
    """
    Evaluate ``Qty × Unit Price = Line Total`` within ``±tolerance`` for all invoice lines (FR-05).

    Reads ``LINE_ROUNDING_TOLERANCE`` from ``get_settings()`` unless explicitly overridden.
    """
    if isinstance(lines, (str, bytes)) or not isinstance(lines, Sequence):
        raise ValueError("lines must be a sequence of invoice line items")
    if len(lines) > MAX_LINE_ITEMS:
        raise ValueError(f"lines exceeds maximum allowed count of {MAX_LINE_ITEMS}")

    resolved_tolerance = _resolve_tolerance(tolerance)

    line_results: list[LineItemCheckResult] = []
    errors: list[str] = []
    seen_line_numbers: set[int] = set()
    computed_subtotal = Decimal("0.00")
    expected_subtotal = Decimal("0.00")

    for idx, raw_line in enumerate(lines, start=1):
        line = _coerce_line_input(raw_line, default_line_number=idx)
        if line.line_number in seen_line_numbers:
            raise ValueError(f"Duplicate line_number detected: {line.line_number}")
        seen_line_numbers.add(line.line_number)

        raw_product = line.quantity * line.unit_price
        if abs(raw_product) > MAX_MONETARY_AMOUNT:
            raise ValueError(
                f"Line {line.line_number}: Qty * Unit Price product exceeds maximum allowed bound "
                f"{MAX_MONETARY_AMOUNT}"
            )

        expected_total = raw_product.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
        if expected_total == 0:
            expected_total = Decimal("0.00")

        diff = abs(expected_total - line.line_total)
        if diff == 0:
            diff = Decimal("0.00")

        line_valid = diff <= resolved_tolerance
        error_msg: str | None = None
        if not line_valid:
            error_msg = (
                f"Line {line.line_number}: Stated total {_format_decimal_amount(line.line_total)} "
                f"differs from Qty ({line.quantity}) * Price ({line.unit_price}) = "
                f"{expected_total:.2f} by {_format_decimal_amount(diff)} "
                f"(tolerance: +/-{_format_decimal_amount(resolved_tolerance)})"
            )
            errors.append(error_msg)

        computed_subtotal += line.line_total
        expected_subtotal += expected_total
        if (
            abs(computed_subtotal) > MAX_MONETARY_AMOUNT
            or abs(expected_subtotal) > MAX_MONETARY_AMOUNT
        ):
            raise ValueError(
                f"Aggregate line subtotal exceeds maximum allowed bound {MAX_MONETARY_AMOUNT}"
            )

        line_results.append(
            LineItemCheckResult(
                line_number=line.line_number,
                quantity=line.quantity,
                unit_price=line.unit_price,
                stated_total=line.line_total,
                expected_total=expected_total,
                difference=diff,
                tolerance=resolved_tolerance,
                is_valid=line_valid,
                error=error_msg,
            )
        )

    passed_count = len(line_results) - len(errors)
    is_valid = len(errors) == 0

    norm_computed = computed_subtotal.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if norm_computed == 0:
        norm_computed = Decimal("0.00")
    norm_expected = expected_subtotal.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if norm_expected == 0:
        norm_expected = Decimal("0.00")
    cumulative_drift = abs(norm_computed - norm_expected).quantize(
        MONETARY_QUANTUM, rounding=ROUND_HALF_UP
    )
    if cumulative_drift == 0:
        cumulative_drift = Decimal("0.00")

    logger.info(
        "Line-item arithmetic validation evaluated",
        extra={
            "total_lines_checked": len(line_results),
            "passed_count": passed_count,
            "failed_count": len(errors),
            "is_valid": is_valid,
            "cumulative_rounding_drift": str(cumulative_drift),
        },
    )

    return LineItemsValidationResult(
        is_valid=is_valid,
        tolerance=resolved_tolerance,
        total_lines_checked=len(line_results),
        passed_count=passed_count,
        failed_count=len(errors),
        computed_subtotal=norm_computed,
        expected_subtotal=norm_expected,
        cumulative_rounding_drift=cumulative_drift,
        line_results=tuple(line_results),
        errors=tuple(errors),
    )


def validate_line_items(
    lines: Sequence[
        LineItemArithmeticInput | InvoiceLineItemExtraction | LineItemLike | Mapping[str, Any]
    ],
    *,
    tolerance: Decimal | str | float | int | None = None,
) -> tuple[bool, list[str]]:
    """
    LLD §5.1 / FR-05 contract: validate line-item arithmetic (``Qty × Unit Price = Total ± tol``).

    Returns:
        ``(is_valid, errors)`` where ``is_valid`` is True iff every line balances within
        ``get_settings().LINE_ROUNDING_TOLERANCE`` (default ``±0.02``).
    """
    result = evaluate_line_items(lines, tolerance=tolerance)
    return result.is_valid, list(result.errors)


def validate_extraction_line_items(
    extraction: InvoiceExtractionSchema,
    *,
    tolerance: Decimal | str | float | int | None = None,
) -> LineItemsValidationResult:
    """Convenience wrapper validating all line items of a P6-3 ``InvoiceExtractionSchema``."""
    return evaluate_line_items(extraction.line_items, tolerance=tolerance)


__all__ = [
    "MAX_ALLOWED_TOLERANCE",
    "MAX_LINE_ITEMS",
    "MAX_MONETARY_AMOUNT",
    "MAX_QUANTITY_AMOUNT",
    "LineItemArithmeticInput",
    "LineItemCheckResult",
    "LineItemLike",
    "LineItemsValidationResult",
    "evaluate_line_items",
    "validate_extraction_line_items",
    "validate_line_items",
]
