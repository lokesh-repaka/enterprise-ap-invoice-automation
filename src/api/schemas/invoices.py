"""
Pydantic schemas for Invoice Upload, Read Detail, Exception Queue, Re-Validation, and Async Job Payloads (P5-1, P5-4, P9-1).
"""

import re
import unicodedata
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.core.audit import MAX_COMMENT_LENGTH, ReasonCode

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_EXOTIC_SPACE_RE = re.compile(r"[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)

MAX_REVALIDATE_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_REVALIDATE_DECIMAL_CHARS: int = 32
MAX_REVALIDATE_LINES: int = 500
MIN_VALID_YEAR: int = 1990
MAX_VALID_YEAR: int = 2100


def _parse_strict_schema_decimal(
    raw: Any,
    *,
    field_name: str,
    max_abs: Decimal,
    max_fraction_digits: int,
) -> Decimal | None:
    """Parse strict-ASCII finite bounded Decimal rejecting bool/NaN/Inf/underscores/non-ASCII."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} cannot be a boolean")
    if isinstance(raw, Decimal):
        val = raw
    elif isinstance(raw, int):
        if raw.bit_length() > 64:
            raise ValueError(f"{field_name} integer magnitude exceeds safe bounds")
        val = Decimal(raw)
    elif isinstance(raw, float):
        text = repr(raw)
        if not _STRICT_ASCII_DECIMAL_RE.match(text):
            raise ValueError(f"{field_name} must be a finite numeric value")
        val = Decimal(text)
    elif isinstance(raw, str):
        if _CONTROL_CHAR_RE.search(raw) or _BIDI_OR_ZERO_WIDTH_RE.search(raw):
            raise ValueError(f"{field_name} contains disallowed characters")
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_name} cannot be empty")
        if len(stripped) > MAX_REVALIDATE_DECIMAL_CHARS:
            raise ValueError(
                f"{field_name} exceeds maximum length of {MAX_REVALIDATE_DECIMAL_CHARS}"
            )
        if not _STRICT_ASCII_DECIMAL_RE.match(stripped):
            raise ValueError(f"{field_name} must be a strict ASCII decimal number")
        try:
            val = Decimal(stripped)
        except InvalidOperation:
            raise ValueError(f"{field_name} must be a valid decimal number") from None
    else:
        raise ValueError(f"{field_name} must be a numeric value")

    if not val.is_finite():
        raise ValueError(f"{field_name} must be finite")

    if val != 0:
        adjusted = val.adjusted()
        if adjusted > 12 or adjusted < -max_fraction_digits:
            raise ValueError(f"{field_name} exponent exceeds allowed precision bounds")
        norm_exp = val.normalize().as_tuple().exponent
        if isinstance(norm_exp, int) and norm_exp < -max_fraction_digits:
            raise ValueError(
                f"{field_name} exceeds maximum {max_fraction_digits} fractional digits"
            )
    else:
        val = Decimal("0")

    if abs(val) > max_abs:
        raise ValueError(f"{field_name} exceeds maximum allowed magnitude {max_abs}")
    return val


def _validate_clean_optional_text(
    raw: Any,
    *,
    field_name: str,
    max_length: int,
    allow_empty: bool = False,
) -> str | None:
    """Validate optional bounded text blocking control/bidi characters (CWE-20/117/451)."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed control characters")
    if _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed invisible bidi/zero-width characters")
    if _EXOTIC_SPACE_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed non-ASCII whitespace characters")
    cleaned = unicodedata.normalize("NFC", raw.strip())
    if not cleaned:
        if allow_empty:
            return None
        raise ValueError(f"{field_name} cannot be empty")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length} characters")
    return cleaned


def _validate_optional_date(raw: Any, *, field_name: str) -> date | None:
    """Validate strict ISO calendar date within [1990, 2100] (rejects datetime/bool)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} cannot be a boolean")
    if isinstance(raw, datetime):
        raise ValueError(f"{field_name} must be an ISO calendar date (YYYY-MM-DD), not a datetime")
    if isinstance(raw, date):
        parsed = raw
    elif isinstance(raw, str):
        if _CONTROL_CHAR_RE.search(raw) or _BIDI_OR_ZERO_WIDTH_RE.search(raw):
            raise ValueError(f"{field_name} contains disallowed characters")
        stripped = raw.strip()
        try:
            parsed = date.fromisoformat(stripped)
        except ValueError:
            raise ValueError(f"{field_name} must be a valid ISO date (YYYY-MM-DD)") from None
    else:
        raise ValueError(f"{field_name} must be a valid ISO date (YYYY-MM-DD)")

    if parsed.year < MIN_VALID_YEAR or parsed.year > MAX_VALID_YEAR:
        raise ValueError(
            f"{field_name} year {parsed.year} outside allowed bounds [{MIN_VALID_YEAR}, {MAX_VALID_YEAR}]"
        )
    return parsed


class InvoiceUploadResponse(BaseModel):
    """HTTP 202 Accepted (or HTTP 200 OK on idempotent replay) invoice upload receipt."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    status: str = "UPLOADED"
    queued: bool = True
    deduplicated: bool = False
    idempotency_key: str | None = None
    filename: str
    detected_mime: str
    size_bytes: int
    file_hash: str
    blob_url: str
    vendor_id: str
    uploaded_at: datetime
    request_id: str | None = None


class InvoiceJobPayload(BaseModel):
    """Structured JSON job message pushed onto the Redis invoice processing queue."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    blob_name: str
    blob_url: str
    file_hash: str
    filename: str
    detected_mime: str
    vendor_id: str
    uploaded_by: str
    request_id: str | None = None
    enqueued_at: str


class InvoiceLineResponse(BaseModel):
    """Immutable line-item representation returned in ``GET /api/v1/invoices/{id}``."""

    model_config = ConfigDict(frozen=True)

    line_id: str
    line_number: int
    description: str
    quantity: Decimal
    unit_price: Decimal
    line_total: Decimal
    line_tax_rate: Decimal
    confidence_score: Decimal | None = None


class InvoiceDetailResponse(BaseModel):
    """Full invoice header, extracted line items, and audit summary for clerk/manager review."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    vendor_id: str | None = None
    vendor_tax_id: str
    vendor_name: str | None = None
    invoice_number: str
    invoice_date: date | None = None
    due_date: date | None = None
    po_number: str | None = None
    subtotal: Decimal | None = None
    total_tax_amount: Decimal | None = None
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal | None = None
    confidence_macro_avg: Decimal
    status: str
    blob_raw_url: str | None = None
    blob_json_url: str | None = None
    created_at: datetime
    updated_at: datetime
    lines: list[InvoiceLineResponse]
    audit_event_count: int = 0


class ExceptionQueueItem(BaseModel):
    """Data-minimized exception queue row (omits raw Tax ID and composite hash: CWE-200)."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    invoice_number: str
    vendor_id: str | None = None
    vendor_name: str | None = None
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal | None = None
    confidence_macro_avg: Decimal
    status: str
    invoice_date: date | None = None
    created_at: datetime


class ExceptionQueueResponse(BaseModel):
    """Paginated response for ``GET /api/v1/invoices/exceptions``."""

    model_config = ConfigDict(frozen=True)

    items: list[ExceptionQueueItem]
    total: int
    limit: int
    offset: int
    filters_applied: dict[str, Any]


class InvoiceHeaderEdits(BaseModel):
    """
    Allowlisted AP Clerk editable invoice header fields (BR-016, BR-017, LLD §2.2).

    Strictly forbids mass assignment of workflow ``status``, model ``confidence_macro_avg``,
    FX-derived ``total_amount_usd``, ``vendor_tax_id``, ``currency``, or ``composite_hash``
    (CWE-915, CLAUDE.md §7.4, §16.1).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    invoice_number: str | None = None
    invoice_date: date | None = None
    due_date: date | None = None
    po_number: str | None = None
    subtotal: Decimal | None = None
    total_tax_amount: Decimal | None = None
    total_amount: Decimal | None = None

    @field_validator("invoice_number", mode="before")
    @classmethod
    def _validate_invoice_number(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(v, field_name="invoice_number", max_length=100)

    @field_validator("po_number", mode="before")
    @classmethod
    def _validate_po_number(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(v, field_name="po_number", max_length=100)

    @field_validator("invoice_date", mode="before")
    @classmethod
    def _validate_invoice_date(cls, v: Any) -> date | None:
        return _validate_optional_date(v, field_name="invoice_date")

    @field_validator("due_date", mode="before")
    @classmethod
    def _validate_due_date(cls, v: Any) -> date | None:
        return _validate_optional_date(v, field_name="due_date")

    @field_validator("subtotal", "total_tax_amount", "total_amount", mode="before")
    @classmethod
    def _validate_monetary_amounts(cls, v: Any, info: Any) -> Decimal | None:
        return _parse_strict_schema_decimal(
            v,
            field_name=str(info.field_name),
            max_abs=MAX_REVALIDATE_MONETARY_AMOUNT,
            max_fraction_digits=2,
        )

    @model_validator(mode="after")
    def _require_at_least_one_header_field(self) -> "InvoiceHeaderEdits":
        """Reject empty header_edits={} and explicit null fields as no-op edits at the API layer (P9-4, SEC-184)."""
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"Explicit null value is not permitted for header_edits.{field}")
        if all(
            getattr(self, field) is None
            for field in (
                "invoice_number",
                "invoice_date",
                "due_date",
                "po_number",
                "subtotal",
                "total_tax_amount",
                "total_amount",
            )
        ):
            raise ValueError(
                "No-op edit rejected: header_edits must specify at least one editable field"
            )
        return self


class InvoiceLineEdit(BaseModel):
    """
    Allowlisted AP Clerk editable line-item fields (BR-016, LLD §2.2).

    Strictly forbids tampering with model ``confidence_score``, ``line_id``, or ``invoice_id``
    (CWE-915, CLAUDE.md §7.4).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_number: int
    description: str | None = None
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    line_total: Decimal | None = None
    line_tax_rate: Decimal | None = None

    @field_validator("line_number", mode="before")
    @classmethod
    def _validate_line_number(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("line_number must be an integer")
        if v < 1 or v > MAX_REVALIDATE_LINES:
            raise ValueError(f"line_number must be between 1 and {MAX_REVALIDATE_LINES}")
        return v

    @field_validator("description", mode="before")
    @classmethod
    def _validate_description(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(v, field_name="description", max_length=2000)

    @field_validator("quantity", "unit_price", mode="before")
    @classmethod
    def _validate_line_unit_fields(cls, v: Any, info: Any) -> Decimal | None:
        return _parse_strict_schema_decimal(
            v,
            field_name=str(info.field_name),
            max_abs=MAX_REVALIDATE_MONETARY_AMOUNT,
            max_fraction_digits=4,
        )

    @field_validator("line_total", mode="before")
    @classmethod
    def _validate_line_total(cls, v: Any) -> Decimal | None:
        return _parse_strict_schema_decimal(
            v,
            field_name="line_total",
            max_abs=MAX_REVALIDATE_MONETARY_AMOUNT,
            max_fraction_digits=2,
        )

    @field_validator("line_tax_rate", mode="before")
    @classmethod
    def _validate_line_tax_rate(cls, v: Any) -> Decimal | None:
        parsed = _parse_strict_schema_decimal(
            v,
            field_name="line_tax_rate",
            max_abs=Decimal("1.0000"),
            max_fraction_digits=4,
        )
        if parsed is not None and parsed < Decimal("0"):
            raise ValueError("line_tax_rate must be non-negative within [0.0000, 1.0000]")
        return parsed

    @model_validator(mode="after")
    def _require_at_least_one_line_field(self) -> "InvoiceLineEdit":
        """Reject fieldless line_edits entries and explicit null fields at the API layer (P9-4, SEC-184)."""
        for field in self.model_fields_set:
            if field != "line_number" and getattr(self, field) is None:
                raise ValueError(f"Explicit null value is not permitted for line_edits.{field}")
        if all(
            getattr(self, field) is None
            for field in ("description", "quantity", "unit_price", "line_total", "line_tax_rate")
        ):
            raise ValueError(
                f"No-op edit rejected: line_edits entry for line {self.line_number} "
                "must specify at least one editable field"
            )
        return self


class InvoiceRevalidateRequest(BaseModel):
    """
    Request payload for ``POST /api/v1/invoices/{id}/revalidate`` (P9-1, FR-12, BR-017, LLD §2.2).

    Enforces:
    - Mandatory canonical ``ReasonCode`` enum.
    - Mandatory non-blank ``comment`` when ``reason_code == ReasonCode.OTHER``.
    - Strict booleans for ``is_reverse_charge`` and ``is_exempt`` (blocks string coercion).
    - Bounded, duplicate-free ``line_edits``.
    - Optional ``clerk_id`` (LLD §2.2 compatibility; verified against JWT identity by route).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    clerk_id: str | None = None
    reason_code: ReasonCode
    comment: str | None = None
    is_reverse_charge: bool = False
    is_exempt: bool = False
    po_amount: Decimal | None = None
    header_edits: InvoiceHeaderEdits | None = None
    line_edits: list[InvoiceLineEdit] = Field(default_factory=list, max_length=MAX_REVALIDATE_LINES)

    @field_validator("clerk_id", mode="before")
    @classmethod
    def _validate_clerk_id(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(
            v, field_name="clerk_id", max_length=128, allow_empty=False
        )

    @field_validator("comment", mode="before")
    @classmethod
    def _validate_comment(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(
            v, field_name="comment", max_length=MAX_COMMENT_LENGTH, allow_empty=True
        )

    @field_validator("is_reverse_charge", "is_exempt", mode="before")
    @classmethod
    def _validate_strict_flags(cls, v: Any, info: Any) -> bool:
        if not isinstance(v, bool):
            raise ValueError(f"{info.field_name} must be a strict boolean")
        return v

    @field_validator("po_amount", mode="before")
    @classmethod
    def _validate_po_amount(cls, v: Any) -> Decimal | None:
        parsed = _parse_strict_schema_decimal(
            v,
            field_name="po_amount",
            max_abs=MAX_REVALIDATE_MONETARY_AMOUNT,
            max_fraction_digits=2,
        )
        if parsed is not None and parsed < Decimal("0"):
            raise ValueError("po_amount must be non-negative")
        return parsed

    @model_validator(mode="after")
    def _validate_cross_field_rules(self) -> "InvoiceRevalidateRequest":
        if self.reason_code is ReasonCode.OTHER and not self.comment:
            raise ValueError("A non-empty comment is mandatory when reason_code is OTHER")
        if (self.is_reverse_charge or self.is_exempt) and self.reason_code not in (
            ReasonCode.TAX_CODE_OVERRIDE,
            ReasonCode.OTHER,
        ):
            raise ValueError(
                "is_reverse_charge and is_exempt require reason_code TAX_CODE_OVERRIDE or OTHER"
            )
        if (
            self.header_edits is None
            and not self.line_edits
            and not self.is_reverse_charge
            and not self.is_exempt
        ):
            raise ValueError(
                "No-op edit rejected: at least one header edit, line edit, "
                "or tax override flag must be provided"
            )
        seen_lines: set[int] = set()
        for edit in self.line_edits:
            if edit.line_number in seen_lines:
                raise ValueError(f"Duplicate line_number in line_edits: {edit.line_number}")
            seen_lines.add(edit.line_number)
        return self


class RevalidationSummary(BaseModel):
    """Deterministic rules summary matching LLD §2.2 ``validation_summary`` contract."""

    model_config = ConfigDict(frozen=True)

    line_arithmetic_valid: bool
    invoice_total_valid: bool
    tax_valid: bool
    date_valid: bool
    all_passed: bool
    currency_converted_amount_usd: Decimal | None = None
    active_exceptions: list[str]


class InvoiceRevalidateResponse(BaseModel):
    """HTTP 200 OK response for ``POST /api/v1/invoices/{id}/revalidate`` (LLD §2.2)."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    previous_status: str
    status: str
    is_revalidated: bool = True
    validation_summary: RevalidationSummary
    confidence_tier: str
    confidence_macro_avg: Decimal
    eligible_for_clerk_approval: bool
    requires_manager_approval: bool
    audit_event_id: str
    edited_fields: list[str]


class InvoiceApprovalRequest(BaseModel):
    """
    Optional request payload for ``POST /api/v1/invoices/{id}/approve`` (P9-2, FR-13, BR-014/015).

    Supports true one-click approval (empty body or ``{}``) as well as manager approval
    comments and optional matched PO amount verification. Strictly forbids mass assignment
    of status, roles, or USD totals (CWE-915).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approver_id: str | None = None
    comment: str | None = None
    po_amount: Decimal | None = None

    @field_validator("approver_id", mode="before")
    @classmethod
    def _validate_approver_id(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(
            v, field_name="approver_id", max_length=128, allow_empty=False
        )

    @field_validator("comment", mode="before")
    @classmethod
    def _validate_comment(cls, v: Any) -> str | None:
        return _validate_clean_optional_text(
            v, field_name="comment", max_length=MAX_COMMENT_LENGTH, allow_empty=True
        )

    @field_validator("po_amount", mode="before")
    @classmethod
    def _validate_po_amount(cls, v: Any) -> Decimal | None:
        parsed = _parse_strict_schema_decimal(
            v,
            field_name="po_amount",
            max_abs=MAX_REVALIDATE_MONETARY_AMOUNT,
            max_fraction_digits=2,
        )
        if parsed is not None and parsed < Decimal("0"):
            raise ValueError("po_amount must be non-negative")
        return parsed


class InvoiceApprovalResponse(BaseModel):
    """HTTP 200 OK receipt for ``POST /api/v1/invoices/{id}/approve`` (P9-2, FR-13)."""

    model_config = ConfigDict(frozen=True)

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


class AuditEventResponse(BaseModel):
    """Immutable single audit trail event returned by ``GET /api/v1/invoices/{id}/audit`` (P9-3)."""

    model_config = ConfigDict(frozen=True)

    audit_id: str
    invoice_id: str
    user_id: str
    action_type: str
    field_name: str | None = None
    previous_value: str | None = None
    new_value: str | None = None
    reason_code: str | None = None
    comment: str | None = None
    timestamp: datetime


class InvoiceAuditTrailResponse(BaseModel):
    """Paginated chronological immutable audit trail for an invoice (P9-3, BR-031, PRD Screen 5)."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    invoice_number: str
    current_status: str
    immutable: bool = True
    total_events: int
    limit: int
    offset: int
    filters_applied: dict[str, Any]
    events: list[AuditEventResponse]
