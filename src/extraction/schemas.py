"""
Pydantic v2 Extraction Schemas for AP Invoice Automation (P6-3).

Covers FR-02, FR-03, FR-11, BR-004, BR-005, BR-006, and CLAUDE.md §4.2, §7.2, §7.3, §8:
- 10 header fields with per-field confidence scores (``InvoiceHeaderExtraction``).
- 5 line-item fields per line with per-field confidence scores (``InvoiceLineItemExtraction``).
- Immutable ``extra="forbid"`` contracts so prompt-injected fields (e.g. ``status``,
  ``skip_validation``, ``approved_by``) can never enter downstream pipelines (CWE-915).
- Strict ``FiniteDecimal`` precision with SQL ``DECIMAL(18, 2/4)`` bounds and exponent
  bomb protection (blocks NaN/Infinity/bool coercion/1E-5000000 DoS: CWE-20/190/400).
- Confidence scores strictly enforced on ``[0.00, 100.00]`` percentage scale with zero
  heuristic rescaling (prevents low ``0.85%`` confidence from silently becoming ``85%``).
- Unicode bidi/zero-width homograph blocking on text/identifiers (prevents duplicate-hash
  bypass attacks: CWE-74 / CWE-451) and angle-bracket blocking on strict identifiers (CWE-79).
- PII-safe ``__repr__`` masking ``vendor_tax_id`` as ``***-**-XXXX`` (CWE-532).
- Zero imports from ``src/database/`` or ``src/validation/`` and zero business-rule execution
  (CLAUDE.md §4.2).
"""

import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

T = TypeVar("T")

# Canonical FR-03 / BR-004 / BR-005 / BR-006 field registries
HEADER_FIELD_NAMES: tuple[str, ...] = (
    "vendor_name",
    "vendor_tax_id",
    "invoice_number",
    "invoice_date",
    "due_date",
    "po_number",
    "subtotal",
    "tax_amount",
    "total_amount",
    "currency",
)

CRITICAL_HEADER_FIELD_NAMES: tuple[str, ...] = (
    "vendor_tax_id",
    "invoice_number",
    "invoice_date",
    "total_amount",
)

LINE_ITEM_FIELD_NAMES: tuple[str, ...] = (
    "description",
    "quantity",
    "unit_price",
    "line_total",
    "tax_rate",
)

# Operational & SQL column parity ceilings (CWE-190 / CWE-400)
MAX_LINE_ITEMS: int = 500
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_QUANTITY_AMOUNT: Decimal = Decimal("999999999999.9999")
MIN_TAX_RATE: Decimal = Decimal("0.0000")
MAX_TAX_RATE: Decimal = Decimal("1.0000")
CONFIDENCE_MIN: Decimal = Decimal("0.00")
CONFIDENCE_MAX: Decimal = Decimal("100.00")
CONFIDENCE_QUANTUM: Decimal = Decimal("0.01")

MAX_VENDOR_NAME_CHARS: int = 200
MAX_VENDOR_TAX_ID_CHARS: int = 50
MAX_INVOICE_NUMBER_CHARS: int = 100
MAX_PO_NUMBER_CHARS: int = 100
MAX_DATE_STR_CHARS: int = 40
MAX_DESCRIPTION_CHARS: int = 1000

_ISO_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_INLINE_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Invisible Unicode bidi overrides & zero-width spoofing chars (defeats composite_hash bypass)
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_HTML_ANGLE_BRACKET_RE = re.compile(r"[<>]")


def _mask_tax_id(tax_id: str) -> str:
    """Mask a vendor Tax ID as ***-**-XXXX for safe logging/repr (CLAUDE.md §8)."""
    clean = tax_id.strip()
    return f"***-**-{clean[-4:]}" if len(clean) >= 4 else "***"


def _parse_finite_decimal(raw: Any, *, field_label: str = "numeric_field") -> Decimal:
    """
    Convert raw numeric input to a finite, bounded-precision Decimal while rejecting:
    - Booleans (``True``/``False`` must never coerce to ``1``/``0``)
    - Non-finite values (``NaN``, ``Infinity``, ``-Infinity``)
    - Oversized strings (>32 chars) and scientific-notation exponent bombs (e.g. ``1E-5000000``)
    """
    if isinstance(raw, bool):
        raise ValueError(f"{field_label} cannot be a boolean")
    if isinstance(raw, Decimal):
        val = raw
    elif isinstance(raw, int):
        if raw.bit_length() > 64:
            raise ValueError(f"{field_label} integer magnitude exceeds safe bounds")
        val = Decimal(raw)
    elif isinstance(raw, float):
        val = Decimal(str(raw))
    elif isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_label} cannot be empty")
        if len(stripped) > MAX_DECIMAL_INPUT_CHARS:
            raise ValueError(
                f"{field_label} string exceeds maximum length of {MAX_DECIMAL_INPUT_CHARS}"
            )
        try:
            val = Decimal(stripped)
        except InvalidOperation:
            raise ValueError(f"{field_label} must be a valid decimal number") from None
    else:
        raise ValueError(f"{field_label} must be a numeric value")

    if not val.is_finite():
        raise ValueError(f"{field_label} must be finite (NaN/Infinity rejected)")

    if val != 0:
        adjusted = val.adjusted()
        if adjusted > 12 or adjusted < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(f"{field_label} exponent exceeds allowed precision bounds")
        norm_exp = val.normalize().as_tuple().exponent
        if isinstance(norm_exp, int) and norm_exp < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(
                f"{field_label} exceeds maximum {MAX_DECIMAL_FRACTION_DIGITS} fractional digits"
            )
    else:
        # Canonicalize signed/extreme zero (e.g. 0E-5000000) to plain Decimal("0")
        val = Decimal("0")

    return val


FiniteDecimal = Annotated[Decimal, BeforeValidator(_parse_finite_decimal)]


def _validate_clean_text(
    raw: str | None,
    *,
    field_label: str,
    max_length: int,
    allow_none: bool = False,
    allow_newlines: bool = False,
    forbid_angle_brackets: bool = False,
) -> str | None:
    """Validate bounded, control-char-free, bidi/zero-width-free text (CWE-20/74/79/117/451)."""
    if raw is None:
        if allow_none:
            return None
        raise ValueError(f"{field_label} cannot be null")
    if not isinstance(raw, str):
        raise ValueError(f"{field_label} must be a string")

    pattern = _INLINE_CONTROL_CHAR_RE if allow_newlines else _CONTROL_CHAR_RE
    if pattern.search(raw):
        raise ValueError(f"{field_label} contains disallowed control characters")
    if _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise ValueError(f"{field_label} contains disallowed invisible bidi/zero-width characters")
    if forbid_angle_brackets and _HTML_ANGLE_BRACKET_RE.search(raw):
        raise ValueError(f"{field_label} contains disallowed angle bracket characters")

    stripped = raw.strip()
    if not stripped:
        if allow_none:
            return None
        raise ValueError(f"{field_label} cannot be empty")
    if len(stripped) > max_length:
        raise ValueError(f"{field_label} exceeds maximum length of {max_length} characters")
    return stripped


def _validate_monetary(raw: Any, *, field_label: str, limit: Decimal) -> Decimal:
    """Enforce finite bounded Decimal matching SQL DECIMAL(18, 2/4) precision (CWE-190)."""
    val = _parse_finite_decimal(raw, field_label=field_label)
    if abs(val) > limit:
        raise ValueError(f"{field_label} magnitude exceeds maximum allowed bound {limit}")
    return val


class ExtractedField(BaseModel, Generic[T]):
    """
    Generic typed extraction field paired with an explicit per-field confidence score (FR-03).

    Confidence is strictly constrained to ``[0.00, 100.00]`` (percentage scale matching
    Azure SQL ``DECIMAL(5, 2)`` and PRD BR-007 thresholds) with no silent rescaling.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: T
    confidence: Decimal = Field(
        ...,
        description="Model extraction confidence percentage in [0.00, 100.00].",
    )

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence(cls, v: Any) -> Decimal:
        val = _parse_finite_decimal(v, field_label="confidence")
        if val < CONFIDENCE_MIN or val > CONFIDENCE_MAX:
            raise ValueError("confidence must be within [0.00, 100.00]")
        return val.quantize(CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP)


class InvoiceHeaderExtraction(BaseModel):
    """
    All 10 canonical invoice header fields with per-field confidence scores (FR-03, BR-004).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor_name: ExtractedField[str]
    vendor_tax_id: ExtractedField[str]
    invoice_number: ExtractedField[str]
    invoice_date: ExtractedField[str]
    due_date: ExtractedField[str | None]
    po_number: ExtractedField[str | None]
    subtotal: ExtractedField[FiniteDecimal]
    tax_amount: ExtractedField[FiniteDecimal]
    total_amount: ExtractedField[FiniteDecimal]
    currency: ExtractedField[str]

    @field_validator("vendor_name")
    @classmethod
    def _check_vendor_name(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="vendor_name",
            max_length=MAX_VENDOR_NAME_CHARS,
        )
        assert cleaned is not None
        return ExtractedField[str](value=cleaned, confidence=field.confidence)

    @field_validator("vendor_tax_id")
    @classmethod
    def _check_vendor_tax_id(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="vendor_tax_id",
            max_length=MAX_VENDOR_TAX_ID_CHARS,
            forbid_angle_brackets=True,
        )
        assert cleaned is not None
        return ExtractedField[str](value=cleaned, confidence=field.confidence)

    @field_validator("invoice_number")
    @classmethod
    def _check_invoice_number(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="invoice_number",
            max_length=MAX_INVOICE_NUMBER_CHARS,
            forbid_angle_brackets=True,
        )
        assert cleaned is not None
        return ExtractedField[str](value=cleaned, confidence=field.confidence)

    @field_validator("invoice_date")
    @classmethod
    def _check_invoice_date(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="invoice_date",
            max_length=MAX_DATE_STR_CHARS,
            forbid_angle_brackets=True,
        )
        assert cleaned is not None
        return ExtractedField[str](value=cleaned, confidence=field.confidence)

    @field_validator("due_date")
    @classmethod
    def _check_due_date(cls, field: ExtractedField[str | None]) -> ExtractedField[str | None]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="due_date",
            max_length=MAX_DATE_STR_CHARS,
            allow_none=True,
            forbid_angle_brackets=True,
        )
        return ExtractedField[str | None](value=cleaned, confidence=field.confidence)

    @field_validator("po_number")
    @classmethod
    def _check_po_number(cls, field: ExtractedField[str | None]) -> ExtractedField[str | None]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="po_number",
            max_length=MAX_PO_NUMBER_CHARS,
            allow_none=True,
            forbid_angle_brackets=True,
        )
        return ExtractedField[str | None](value=cleaned, confidence=field.confidence)

    @field_validator("subtotal", "tax_amount", "total_amount")
    @classmethod
    def _check_monetary_fields(
        cls, field: ExtractedField[FiniteDecimal]
    ) -> ExtractedField[FiniteDecimal]:
        val = _validate_monetary(
            field.value,
            field_label="monetary_header_field",
            limit=MAX_MONETARY_AMOUNT,
        )
        return ExtractedField[FiniteDecimal](value=val, confidence=field.confidence)

    @field_validator("currency")
    @classmethod
    def _check_currency(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="currency",
            max_length=3,
            forbid_angle_brackets=True,
        )
        assert cleaned is not None
        upper = cleaned.upper()
        if not _ISO_CURRENCY_RE.match(upper):
            raise ValueError("currency must be a 3-letter ISO 4217 code (e.g. USD, EUR, GBP)")
        return ExtractedField[str](value=upper, confidence=field.confidence)

    def field_confidences(self) -> dict[str, Decimal]:
        """Return per-field confidence map for all 10 canonical header fields."""
        return {name: getattr(self, name).confidence for name in HEADER_FIELD_NAMES}

    def macro_avg_confidence(self) -> Decimal:
        """Compute deterministic arithmetic mean confidence across all 10 header fields."""
        scores = self.field_confidences().values()
        total = sum(scores, Decimal("0.00"))
        return (total / Decimal(len(HEADER_FIELD_NAMES))).quantize(
            CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP
        )

    def min_confidence(self) -> Decimal:
        """Return minimum confidence score across all 10 header fields."""
        return min(self.field_confidences().values())

    def min_critical_confidence(self) -> Decimal:
        """Return minimum confidence across the 4 BR-006 critical fields."""
        return min(getattr(self, name).confidence for name in CRITICAL_HEADER_FIELD_NAMES)

    def to_plain_dict(self) -> dict[str, Any]:
        """Serialize header values (without confidence wrappers) matching ground_truth JSON."""
        return {
            "vendor_name": self.vendor_name.value,
            "vendor_tax_id": self.vendor_tax_id.value,
            "invoice_number": self.invoice_number.value,
            "invoice_date": self.invoice_date.value,
            "due_date": self.due_date.value,
            "po_number": self.po_number.value,
            "subtotal": float(self.subtotal.value),
            "tax_amount": float(self.tax_amount.value),
            "total_amount": float(self.total_amount.value),
            "currency": self.currency.value,
        }

    def __repr__(self) -> str:
        return (
            f"InvoiceHeaderExtraction(vendor_name={self.vendor_name.value!r}, "
            f"vendor_tax_id={_mask_tax_id(self.vendor_tax_id.value)!r}, "
            f"invoice_number={self.invoice_number.value!r}, "
            f"total_amount={self.total_amount.value} {self.currency.value}, "
            f"macro_avg_confidence={self.macro_avg_confidence()})"
        )


class InvoiceLineItemExtraction(BaseModel):
    """
    All 5 canonical invoice line-item fields with per-field confidence scores (FR-03, BR-005).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: ExtractedField[str]
    quantity: ExtractedField[FiniteDecimal]
    unit_price: ExtractedField[FiniteDecimal]
    line_total: ExtractedField[FiniteDecimal]
    tax_rate: ExtractedField[FiniteDecimal]

    @field_validator("description")
    @classmethod
    def _check_description(cls, field: ExtractedField[str]) -> ExtractedField[str]:
        cleaned = _validate_clean_text(
            field.value,
            field_label="description",
            max_length=MAX_DESCRIPTION_CHARS,
            allow_newlines=True,
        )
        assert cleaned is not None
        return ExtractedField[str](value=cleaned, confidence=field.confidence)

    @field_validator("quantity")
    @classmethod
    def _check_quantity(cls, field: ExtractedField[FiniteDecimal]) -> ExtractedField[FiniteDecimal]:
        val = _validate_monetary(
            field.value,
            field_label="quantity",
            limit=MAX_QUANTITY_AMOUNT,
        )
        return ExtractedField[FiniteDecimal](value=val, confidence=field.confidence)

    @field_validator("unit_price", "line_total")
    @classmethod
    def _check_line_money(
        cls, field: ExtractedField[FiniteDecimal]
    ) -> ExtractedField[FiniteDecimal]:
        val = _validate_monetary(
            field.value,
            field_label="line_monetary_field",
            limit=MAX_MONETARY_AMOUNT,
        )
        return ExtractedField[FiniteDecimal](value=val, confidence=field.confidence)

    @field_validator("tax_rate")
    @classmethod
    def _check_tax_rate(cls, field: ExtractedField[FiniteDecimal]) -> ExtractedField[FiniteDecimal]:
        val = _parse_finite_decimal(field.value, field_label="tax_rate")
        if val < MIN_TAX_RATE or val > MAX_TAX_RATE:
            raise ValueError("tax_rate must be a decimal fraction within [0.0000, 1.0000]")
        return ExtractedField[FiniteDecimal](value=val, confidence=field.confidence)

    def field_confidences(self) -> dict[str, Decimal]:
        """Return per-field confidence map for all 5 line-item fields."""
        return {name: getattr(self, name).confidence for name in LINE_ITEM_FIELD_NAMES}

    def line_confidence(self) -> Decimal:
        """Compute deterministic mean confidence across all 5 line-item fields."""
        scores = self.field_confidences().values()
        total = sum(scores, Decimal("0.00"))
        return (total / Decimal(len(LINE_ITEM_FIELD_NAMES))).quantize(
            CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP
        )

    def min_confidence(self) -> Decimal:
        """Return minimum confidence score across all 5 line-item fields."""
        return min(self.field_confidences().values())

    def to_plain_dict(self) -> dict[str, Any]:
        """Serialize line-item values (without confidence wrappers) matching ground_truth JSON."""
        return {
            "description": self.description.value,
            "quantity": float(self.quantity.value),
            "unit_price": float(self.unit_price.value),
            "line_total": float(self.line_total.value),
            "tax_rate": float(self.tax_rate.value),
        }


class InvoiceExtractionSchema(BaseModel):
    """
    Complete validated AI extraction output for an AP invoice (P6-3, FR-03).

    Enforces ``extra="forbid"`` and ``frozen=True`` so LLM outputs remain pure untrusted-to-typed
    extracted data; deterministic arithmetic, tax validation, and status routing occur exclusively
    in ``src/validation/`` (CLAUDE.md §4.2, §7.2).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    header: InvoiceHeaderExtraction
    line_items: list[InvoiceLineItemExtraction] = Field(..., max_length=MAX_LINE_ITEMS)
    is_reverse_charge: bool = False
    is_exempt: bool = False
    detected_language: Literal["en", "de", "es"] | None = None

    @field_validator("is_reverse_charge", "is_exempt", mode="before")
    @classmethod
    def _strict_bool_flags(cls, v: Any) -> bool:
        if not isinstance(v, bool):
            raise ValueError("Annotation flag must be a strict boolean")
        return v

    @field_validator("detected_language", mode="before")
    @classmethod
    def _normalize_language(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip().lower()
        return v

    def header_macro_avg_confidence(self) -> Decimal:
        """Return macro-average confidence across all 10 header fields."""
        return self.header.macro_avg_confidence()

    def overall_min_confidence(self) -> Decimal:
        """Return lowest per-field confidence across all header and line-item fields."""
        candidates = [self.header.min_confidence()]
        for item in self.line_items:
            candidates.append(item.min_confidence())
        return min(candidates)

    def all_field_confidences(self) -> dict[str, Decimal]:
        """Return flat path-indexed map of every extracted field confidence score."""
        scores: dict[str, Decimal] = {
            f"header.{name}": conf for name, conf in self.header.field_confidences().items()
        }
        for idx, item in enumerate(self.line_items):
            for name, conf in item.field_confidences().items():
                scores[f"line_items[{idx}].{name}"] = conf
        return scores

    def to_ground_truth_dict(self) -> dict[str, Any]:
        """Export plain field values matching ``sample_data/ground_truth/`` schema."""
        return {
            "header": self.header.to_plain_dict(),
            "line_items": [item.to_plain_dict() for item in self.line_items],
        }

    @classmethod
    def from_ground_truth_dict(
        cls,
        data: dict[str, Any],
        *,
        default_confidence: Decimal = Decimal("100.00"),
        is_reverse_charge: bool = False,
        is_exempt: bool = False,
        detected_language: Literal["en", "de", "es"] | None = None,
    ) -> "InvoiceExtractionSchema":
        """
        Convert a plain ground-truth JSON dictionary into a validated ``InvoiceExtractionSchema``
        with uniform ``default_confidence`` (used by P6-5 Mock AOAI client and P13 evaluator).
        """
        if not isinstance(data, dict) or "header" not in data or "line_items" not in data:
            raise ValueError("Ground-truth dict must contain 'header' and 'line_items' keys")

        raw_header = data["header"]
        raw_lines = data["line_items"]
        if not isinstance(raw_header, dict) or not isinstance(raw_lines, list):
            raise ValueError("Ground-truth 'header' must be a dict and 'line_items' must be a list")
        if len(raw_lines) > MAX_LINE_ITEMS:
            raise ValueError(f"Ground-truth line_items exceeds maximum of {MAX_LINE_ITEMS}")

        wrapped_header = {
            name: {"value": raw_header.get(name), "confidence": default_confidence}
            for name in HEADER_FIELD_NAMES
        }
        wrapped_lines = []
        for idx, line in enumerate(raw_lines):
            if not isinstance(line, dict):
                raise ValueError(f"Ground-truth line_items[{idx}] must be a dict")
            wrapped_lines.append(
                {
                    name: {"value": line.get(name), "confidence": default_confidence}
                    for name in LINE_ITEM_FIELD_NAMES
                }
            )
        return cls.model_validate(
            {
                "header": wrapped_header,
                "line_items": wrapped_lines,
                "is_reverse_charge": is_reverse_charge,
                "is_exempt": is_exempt,
                "detected_language": detected_language,
            }
        )

    @classmethod
    def json_schema_for_prompt(cls) -> dict[str, Any]:
        """Return Pydantic v2 JSON Schema dictionary for P6-4 system prompt enforcement."""
        return cls.model_json_schema()

    def __repr__(self) -> str:
        return (
            f"InvoiceExtractionSchema(header={self.header!r}, "
            f"line_count={len(self.line_items)}, "
            f"overall_min_confidence={self.overall_min_confidence()})"
        )


__all__ = [
    "CONFIDENCE_MAX",
    "CONFIDENCE_MIN",
    "CRITICAL_HEADER_FIELD_NAMES",
    "ExtractedField",
    "FiniteDecimal",
    "HEADER_FIELD_NAMES",
    "InvoiceExtractionSchema",
    "InvoiceHeaderExtraction",
    "InvoiceLineItemExtraction",
    "LINE_ITEM_FIELD_NAMES",
    "MAX_LINE_ITEMS",
    "MAX_MONETARY_AMOUNT",
    "MAX_QUANTITY_AMOUNT",
    "MAX_TAX_RATE",
    "MIN_TAX_RATE",
]
