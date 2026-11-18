"""
Deterministic Duplicate, Revision, and Credit Note Detector (P7-1).

Covers FR-09, FR-10, FR-11, BR-013, BR-013a, BR-013b, ADR-006, and CLAUDE.md §4.2, §6, §7.1, §8:
- **FR-09 (Exact Duplicate):** SHA-256 composite business key
  ``SHA256(f"{vendor_tax_id}_{invoice_number}_{total_amount:.2f}")`` matching ``dbo.Invoices``
  and ``sample_data/ground_truth/`` (excludes ``REJECTED_DUPLICATE`` and ``VOID`` rows and
  excludes ``current_invoice_id`` self-matches).
- **FR-10 (Potential Revision):** Same vendor + invoice number with differing total amount, OR
  revision suffix on invoice number / filename (``-REV``, ``-REV2``, ``Rev``, ``v2``, ``ver2``,
  ``-REVISION``) → ``FLAGGED_POTENTIAL_REVISION`` with matched original invoice reference for
  the side-by-side comparison screen.
- **FR-11 (Credit Note):** Negative grand total, negative subtotal, or any negative line-item
  total → ``CREDIT_NOTE`` routed to the credit netting workflow. Never classified as a regular
  invoice (CLAUDE.md §16.1).

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports ``openai`` / ``model_gateway``
  (CLAUDE.md §4.2, §7.2).
- Decoupled from SQLAlchemy via ``InvoiceLookupProtocol`` (satisfied directly by
  ``src.database.repositories.InvoiceRepository``).
- Rejects invisible Unicode bidi/zero-width homographs and control characters in identifiers
  to defeat composite-hash bypass attacks (CWE-74 / CWE-451).
- Rejects NaN, Infinity, booleans, oversized strings, and scientific-notation exponent bombs
  (CWE-20 / CWE-190 / CWE-400).
- Masks ``vendor_tax_id`` as ``***-**-XXXX`` in all logs, reasons, and ``__repr__`` outputs
  (CLAUDE.md §8, CWE-532).
- Can NEVER emit an approval status (``APPROVED_CLERK``, ``APPROVED_MANAGER``,
  ``STAGED_FOR_EXPORT``) (CLAUDE.md §16.1).
"""

import hashlib
import hmac
import ntpath
import posixpath
import re
import unicodedata
from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema

logger = get_logger("ap.validation.duplicate_detector")

# Excluded statuses matching UX_invoices_composite_hash partial unique index (CLAUDE.md §6, LLD §3.1)
IGNORED_DUPLICATE_STATUSES: frozenset[str] = frozenset({"REJECTED_DUPLICATE", "VOID"})

# Strict bounds aligned with SQL column precision & DoS ceilings (CWE-190 / CWE-400)
MAX_VENDOR_TAX_ID_CHARS: int = 50
MAX_INVOICE_NUMBER_CHARS: int = 100
MAX_FILENAME_CHARS: int = 255
MAX_LINE_ITEMS: int = 500
MAX_EXISTING_LOOKUP_RECORDS: int = 1_000
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MONETARY_QUANTUM: Decimal = Decimal("0.01")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
# Invisible Unicode bidi overrides & zero-width spoofing chars (defeats SHA-256 hash bypass)
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_DISALLOWED_UNICODE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

# Linear-time, ReDoS-safe anchored revision suffix detector (CLAUDE.md §7.1, PRD BR-013a):
# Matches trailing markers preceded by a separator (-, _, ., whitespace):
#   -REV, -REV1, -REV-02, _Rev, " Rev 2", -Rev.3, -RevA, -REVISION, -REVISION-2
#   -v2, _V3, " v2.1", -v10, -ver2, _version_2 (version >= 2; never flags v0 or v1)
_REVISION_SUFFIX_RE = re.compile(
    r"(?:"
    r"[-_.\s]+rev(?:ision)?(?:[-_.\s]?(?:\d{1,3}|[A-Za-z]))?"
    r"|"
    r"[-_.\s]+(?:ver(?:sion)?|v)[-_.\s]?(?:0*[2-9]\d{0,2}|[1-9]\d{1,2})(?:\.\d{1,2})?"
    r")$",
    re.IGNORECASE,
)

TargetDuplicateStatus = Literal[
    "DUPLICATE_INVOICE",
    "FLAGGED_POTENTIAL_REVISION",
    "CREDIT_NOTE",
]


class DuplicateOutcome(StrEnum):
    """Deterministic routing outcome produced by DuplicateDetector (CLAUDE.md §7.1)."""

    PROCEED = "PROCEED"
    DUPLICATE_INVOICE = "DUPLICATE_INVOICE"
    FLAGGED_POTENTIAL_REVISION = "FLAGGED_POTENTIAL_REVISION"
    CREDIT_NOTE = "CREDIT_NOTE"


@runtime_checkable
class ExistingInvoiceRecord(Protocol):
    """Minimal read-only projection of a persisted invoice record (satisfied by SQL Invoice ORM)."""

    invoice_id: str
    vendor_tax_id: str
    invoice_number: str
    total_amount: Decimal
    status: str
    composite_hash: str


@runtime_checkable
class InvoiceLookupProtocol(Protocol):
    """Read-only async lookup contract (satisfied directly by src.database.repositories.InvoiceRepository)."""

    async def get_by_composite_hash(self, composite_hash: str) -> ExistingInvoiceRecord | None: ...

    async def get_by_vendor_and_number(
        self, vendor_tax_id: str, invoice_number: str
    ) -> Sequence[ExistingInvoiceRecord]: ...


def _mask_tax_id(tax_id: str) -> str:
    """Mask vendor Tax ID as ***-**-XXXX for safe logging/repr (CLAUDE.md §8, CWE-532)."""
    clean = tax_id.strip()
    return f"***-**-{clean[-4:]}" if len(clean) >= 4 else "***"


def _sanitize_identifier(raw: Any, *, field_name: str, max_length: int) -> str:
    """
    Validate and trim a non-empty identifier, defeating SHA-256 hash bypass and log injection:
    - Rejects ASCII control characters and Unicode Cc/Cf/Cs/Co/Cn (blocks soft hyphen ``\\u00ad``,
      zero-width spaces, bidi overrides, and surrogates: CWE-74 / CWE-172 / CWE-451).
    - Rejects non-ASCII whitespace (e.g. NBSP ``\\u00a0``) and NFKC compatibility spoofing
      (e.g. fullwidth digits ``１`` or fullwidth hyphens ``－``).
    """
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed control characters")
    if _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed invisible bidi/zero-width characters")
    for ch in raw:
        cat = unicodedata.category(ch)
        if cat in _DISALLOWED_UNICODE_CATEGORIES:
            raise ValueError(
                f"{field_name} contains disallowed invisible Unicode format/control characters"
            )
        if ch.isspace() and ch != " ":
            raise ValueError(f"{field_name} contains disallowed non-ASCII whitespace characters")
    nfc = unicodedata.normalize("NFC", raw)
    if unicodedata.normalize("NFKC", nfc) != nfc:
        raise ValueError(
            f"{field_name} contains disallowed compatibility/fullwidth homograph characters"
        )
    cleaned = nfc.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must be non-empty")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length} characters")
    return cleaned


def _sanitize_log_fragment(raw: str, *, max_length: int = 120) -> str:
    """Strip control/format characters from persisted DB fields before embedding in reason text (CWE-117)."""
    safe_chars = [
        ch
        for ch in raw
        if unicodedata.category(ch) not in _DISALLOWED_UNICODE_CATEGORIES
        and not (ch.isspace() and ch != " ")
    ]
    return "".join(safe_chars).strip()[:max_length]


def _parse_monetary_decimal(raw: Any, *, field_name: str) -> Decimal:
    """
    Parse a finite, bounded monetary Decimal quantized to 2 decimal places (ROUND_HALF_UP).

    Rejects booleans, NaN, Infinity, oversized inputs, and scientific-notation exponent bombs
    (CWE-20 / CWE-190 / CWE-400). Canonicalizes ``-0.00`` to ``Decimal("0.00")``.
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
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_name} cannot be empty")
        if len(stripped) > MAX_DECIMAL_INPUT_CHARS:
            raise ValueError(
                f"{field_name} string exceeds maximum length of {MAX_DECIMAL_INPUT_CHARS}"
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

    if abs(val) > MAX_MONETARY_AMOUNT:
        raise ValueError(
            f"{field_name} magnitude exceeds maximum allowed bound {MAX_MONETARY_AMOUNT}"
        )

    quantized = val.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized == 0:
        return Decimal("0.00")
    return quantized


def _extract_safe_filename_stem(filename: str | None) -> str | None:
    """
    Extract the sanitized basename stem (without directory components or final extension).

    Handles both POSIX and Windows path separators without touching the filesystem (CWE-22).
    """
    if filename is None:
        return None
    cleaned = _sanitize_identifier(filename, field_name="filename", max_length=MAX_FILENAME_CHARS)
    # Strip any directory traversal prefix on either POSIX or Windows path syntax
    base = posixpath.basename(ntpath.basename(cleaned)).strip()
    if not base:
        return None
    stem, _ext = posixpath.splitext(base)
    return stem.strip() or base


def compute_composite_hash(
    vendor_tax_id: str,
    invoice_number: str,
    total_amount: Decimal | str | float | int,
) -> str:
    """
    Compute canonical SHA-256 composite business key for invoice duplicate detection (FR-09).

    Format: ``SHA256(f"{vendor_tax_id}_{invoice_number}_{total_amount:.2f}")``
    Guaranteed 100% parity with ``src.database.repositories.compute_composite_hash`` and
    ``sample_data/ground_truth/`` metadata hashes.
    """
    clean_tax_id = _sanitize_identifier(
        vendor_tax_id,
        field_name="vendor_tax_id",
        max_length=MAX_VENDOR_TAX_ID_CHARS,
    )
    clean_inv_num = _sanitize_identifier(
        invoice_number,
        field_name="invoice_number",
        max_length=MAX_INVOICE_NUMBER_CHARS,
    )
    normalized_total = _parse_monetary_decimal(total_amount, field_name="total_amount")
    payload = f"{clean_tax_id}_{clean_inv_num}_{normalized_total:.2f}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_revision_suffix(value: str) -> tuple[bool, str, str | None]:
    """
    Detect trailing revision markers (``-REV``, ``Rev2``, ``-v2``, ``-REVISION``, etc.) (FR-10).

    Returns:
        ``(has_suffix, base_value, detected_suffix)``:
        - ``has_suffix`` is True iff a valid revision suffix follows a non-empty base string.
        - ``base_value`` is ``value`` with trailing revision suffix(es) stripped (up to 2 passes
          for chained markers such as ``INV-1002-REV-v2``).
        - ``detected_suffix`` is the exact matched trailing suffix string, or ``None``.
    """
    cleaned = _sanitize_identifier(
        value,
        field_name="revision_candidate",
        max_length=MAX_FILENAME_CHARS,
    )
    current = cleaned
    stripped_parts: list[str] = []

    for _ in range(2):
        match = _REVISION_SUFFIX_RE.search(current)
        if match is None or match.start() == 0:
            break
        candidate_base = current[: match.start()].strip()
        if not candidate_base:
            break
        stripped_parts.append(match.group(0))
        current = candidate_base

    if not stripped_parts:
        return False, cleaned, None

    # Reconstruct full stripped suffix in original left-to-right order
    full_suffix = "".join(reversed(stripped_parts))
    return True, current, full_suffix


def detect_credit_note(
    total_amount: Decimal | str | float | int,
    *,
    subtotal: Decimal | str | float | int | None = None,
    line_totals: Sequence[Decimal | str | float | int] = (),
) -> tuple[bool, bool, tuple[int, ...]]:
    """
    Classify whether an invoice is a credit note based on negative balances (FR-11, BR-013b).

    A document is classified as ``CREDIT_NOTE`` if ANY of the following hold:
    - ``total_amount < 0`` (negative grand total)
    - ``subtotal < 0`` (negative subtotal)
    - Any line item has ``line_total < 0`` (partial or full credit line item)

    Returns:
        ``(is_credit_note, negative_total_detected, negative_line_numbers)`` where
        ``negative_line_numbers`` is a tuple of 1-based line indices with negative totals.
    """
    if len(line_totals) > MAX_LINE_ITEMS:
        raise ValueError(f"line_totals exceeds maximum allowed count of {MAX_LINE_ITEMS}")

    norm_total = _parse_monetary_decimal(total_amount, field_name="total_amount")
    norm_subtotal = (
        _parse_monetary_decimal(subtotal, field_name="subtotal") if subtotal is not None else None
    )

    neg_lines: list[int] = []
    for idx, raw_line_total in enumerate(line_totals, start=1):
        norm_line = _parse_monetary_decimal(raw_line_total, field_name=f"line_totals[{idx}]")
        if norm_line < Decimal("0.00"):
            neg_lines.append(idx)

    negative_total_detected = norm_total < Decimal("0.00")
    negative_subtotal_detected = norm_subtotal is not None and norm_subtotal < Decimal("0.00")
    is_credit_note = negative_total_detected or negative_subtotal_detected or bool(neg_lines)
    return is_credit_note, negative_total_detected, tuple(neg_lines)


class DuplicateCheckInput(BaseModel):
    """Immutable validated input payload for duplicate, revision, and credit note checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor_tax_id: str
    invoice_number: str
    total_amount: Decimal
    subtotal: Decimal | None = None
    line_totals: tuple[Decimal, ...] = Field(default=(), max_length=MAX_LINE_ITEMS)
    filename: str | None = None
    current_invoice_id: str | None = None

    @field_validator("vendor_tax_id", mode="before")
    @classmethod
    def _validate_vendor_tax_id(cls, v: Any) -> str:
        return _sanitize_identifier(
            v, field_name="vendor_tax_id", max_length=MAX_VENDOR_TAX_ID_CHARS
        )

    @field_validator("invoice_number", mode="before")
    @classmethod
    def _validate_invoice_number(cls, v: Any) -> str:
        return _sanitize_identifier(
            v, field_name="invoice_number", max_length=MAX_INVOICE_NUMBER_CHARS
        )

    @field_validator("total_amount", mode="before")
    @classmethod
    def _validate_total_amount(cls, v: Any) -> Decimal:
        return _parse_monetary_decimal(v, field_name="total_amount")

    @field_validator("subtotal", mode="before")
    @classmethod
    def _validate_subtotal(cls, v: Any) -> Decimal | None:
        if v is None:
            return None
        return _parse_monetary_decimal(v, field_name="subtotal")

    @field_validator("line_totals", mode="before")
    @classmethod
    def _validate_line_totals(cls, v: Any) -> tuple[Decimal, ...]:
        if v is None:
            return ()
        if isinstance(v, (str, bytes)) or not isinstance(v, Sequence):
            raise ValueError("line_totals must be a sequence of numeric values")
        if len(v) > MAX_LINE_ITEMS:
            raise ValueError(f"line_totals exceeds maximum allowed count of {MAX_LINE_ITEMS}")
        return tuple(
            _parse_monetary_decimal(item, field_name=f"line_totals[{idx}]")
            for idx, item in enumerate(v, start=1)
        )

    @field_validator("filename", mode="before")
    @classmethod
    def _validate_filename(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _sanitize_identifier(v, field_name="filename", max_length=MAX_FILENAME_CHARS)

    @field_validator("current_invoice_id", mode="before")
    @classmethod
    def _validate_current_invoice_id(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _sanitize_identifier(v, field_name="current_invoice_id", max_length=64)

    def __repr__(self) -> str:
        return (
            f"DuplicateCheckInput(vendor_tax_id={_mask_tax_id(self.vendor_tax_id)!r}, "
            f"invoice_number={self.invoice_number!r}, "
            f"total_amount={self.total_amount}, line_count={len(self.line_totals)})"
        )


class DuplicateDetectionResult(BaseModel):
    """Immutable structured result from DuplicateDetector (FR-09, FR-10, FR-11)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: DuplicateOutcome
    target_status: TargetDuplicateStatus | None
    should_proceed: bool
    composite_hash: str
    normalized_invoice_number: str
    base_invoice_number: str
    is_duplicate: bool = False
    is_potential_revision: bool = False
    is_credit_note: bool = False
    revision_suffix_detected: bool = False
    detected_revision_suffix: str | None = None
    revision_detected_in: Literal["invoice_number", "filename", "both"] | None = None
    negative_total_detected: bool = False
    negative_line_numbers: tuple[int, ...] = ()
    matched_invoice_id: str | None = None
    matched_invoice_number: str | None = None
    matched_total_amount: Decimal | None = None
    amount_difference: Decimal | None = None
    reason: str


def _is_active_other_invoice(
    record: ExistingInvoiceRecord,
    *,
    current_invoice_id: str | None,
) -> bool:
    """Return True if a persisted record is active (non-VOID/non-REJECTED_DUPLICATE) and not self."""
    if current_invoice_id is not None and record.invoice_id == current_invoice_id:
        return False
    status_upper = (record.status or "").strip().upper()
    return status_upper not in IGNORED_DUPLICATE_STATUSES


def _quantize_record_total(record: ExistingInvoiceRecord) -> Decimal:
    """Safely normalize an existing persisted invoice's total_amount to 2dp Decimal."""
    return _parse_monetary_decimal(record.total_amount, field_name="existing.total_amount")


def evaluate_duplicate_rules(
    candidate: DuplicateCheckInput,
    *,
    existing_by_hash: ExistingInvoiceRecord | None = None,
    existing_vendor_invoices: Sequence[ExistingInvoiceRecord] = (),
) -> DuplicateDetectionResult:
    """
    Pure deterministic evaluation of duplicate, credit note, and revision rules.

    Decision precedence (CLAUDE.md §7.1, §16.1, ADR-006, FR-09..FR-11):
      1. **Exact Duplicate (`DUPLICATE_INVOICE`)**: An active existing invoice (excluding self,
         ``VOID``, and ``REJECTED_DUPLICATE``) matches the SHA-256 ``composite_hash`` OR matches
         the same ``(vendor_tax_id, invoice_number, total_amount)``. Prevents double payment and
         double credit-note netting.
      2. **Credit Note (`CREDIT_NOTE`)**: Negative ``total_amount``, negative ``subtotal``, or any
         negative ``line_total``. Guarantees negative-balance documents are NEVER classified as
         regular invoices (CLAUDE.md §16.1); attaches ``matched_invoice_id`` if a prior invoice
         exists for credit netting context.
      3. **Potential Revision (`FLAGGED_POTENTIAL_REVISION`)**: Revision suffix in invoice number
         or filename (``-REV``, ``Rev``, ``v2``, etc.) OR an active existing invoice for the same
         vendor and invoice number (or base invoice number) with a differing total amount.
      4. **Proceed (`PROCEED`)**: Unique regular invoice — pipeline continues to math/tax/date rules.
    """
    if len(existing_vendor_invoices) > MAX_EXISTING_LOOKUP_RECORDS:
        raise ValueError(
            f"existing_vendor_invoices exceeds maximum allowed count of {MAX_EXISTING_LOOKUP_RECORDS}"
        )

    composite_hash = compute_composite_hash(
        vendor_tax_id=candidate.vendor_tax_id,
        invoice_number=candidate.invoice_number,
        total_amount=candidate.total_amount,
    )
    upper_composite_hash = (
        compute_composite_hash(
            vendor_tax_id=candidate.vendor_tax_id,
            invoice_number=candidate.invoice_number.upper(),
            total_amount=candidate.total_amount,
        )
        if candidate.invoice_number != candidate.invoice_number.upper()
        else composite_hash
    )

    # 1. Inspect revision suffixes in invoice_number and optional filename stem
    num_has_rev, base_invoice_number, num_rev_suffix = detect_revision_suffix(
        candidate.invoice_number
    )
    filename_stem = _extract_safe_filename_stem(candidate.filename)
    file_has_rev = False
    file_rev_suffix: str | None = None
    if filename_stem is not None:
        file_has_rev, _file_base, file_rev_suffix = detect_revision_suffix(filename_stem)

    revision_suffix_detected = num_has_rev or file_has_rev
    detected_revision_suffix = num_rev_suffix if num_has_rev else file_rev_suffix
    revision_detected_in: Literal["invoice_number", "filename", "both"] | None
    if num_has_rev and file_has_rev:
        revision_detected_in = "both"
    elif num_has_rev:
        revision_detected_in = "invoice_number"
    elif file_has_rev:
        revision_detected_in = "filename"
    else:
        revision_detected_in = None

    # 2. Inspect credit-note indicators (negative grand total, subtotal, or line items)
    is_credit_note, negative_total_detected, negative_line_numbers = detect_credit_note(
        candidate.total_amount,
        subtotal=candidate.subtotal,
        line_totals=candidate.line_totals,
    )

    # 3. Filter active non-self existing records strictly scoped to this vendor (CWE-284)
    cand_tax_upper = candidate.vendor_tax_id.upper()
    active_vendor_records: list[ExistingInvoiceRecord] = [
        rec
        for rec in existing_vendor_invoices
        if _is_active_other_invoice(rec, current_invoice_id=candidate.current_invoice_id)
        and rec.vendor_tax_id.strip().upper() == cand_tax_upper
    ]

    # 4. Priority 1 — Exact Duplicate (FR-09)
    exact_match: ExistingInvoiceRecord | None = None
    if (
        existing_by_hash is not None
        and _is_active_other_invoice(
            existing_by_hash, current_invoice_id=candidate.current_invoice_id
        )
        and existing_by_hash.vendor_tax_id.strip().upper() == cand_tax_upper
    ):
        existing_hash = (existing_by_hash.composite_hash or "").strip().lower()
        if existing_hash and (
            hmac.compare_digest(existing_hash, composite_hash)
            or hmac.compare_digest(existing_hash, upper_composite_hash)
        ):
            exact_match = existing_by_hash

    if exact_match is None:
        # Defense-in-depth fallback: check vendor records for exact same normalized number + total (CWE-178)
        cand_num_upper = candidate.invoice_number.upper()
        for rec in active_vendor_records:
            rec_num_upper = rec.invoice_number.strip().upper()
            if (
                rec_num_upper == cand_num_upper
                and _quantize_record_total(rec) == candidate.total_amount
            ):
                exact_match = rec
                break

    if exact_match is not None:
        matched_total = _quantize_record_total(exact_match)
        safe_match_id = _sanitize_log_fragment(exact_match.invoice_id)
        safe_match_num = _sanitize_log_fragment(exact_match.invoice_number)
        return DuplicateDetectionResult(
            outcome=DuplicateOutcome.DUPLICATE_INVOICE,
            target_status="DUPLICATE_INVOICE",
            should_proceed=False,
            composite_hash=composite_hash,
            normalized_invoice_number=candidate.invoice_number,
            base_invoice_number=base_invoice_number,
            is_duplicate=True,
            is_potential_revision=False,
            is_credit_note=is_credit_note,
            revision_suffix_detected=revision_suffix_detected,
            detected_revision_suffix=detected_revision_suffix,
            revision_detected_in=revision_detected_in,
            negative_total_detected=negative_total_detected,
            negative_line_numbers=negative_line_numbers,
            matched_invoice_id=exact_match.invoice_id,
            matched_invoice_number=exact_match.invoice_number,
            matched_total_amount=matched_total,
            amount_difference=(candidate.total_amount - matched_total).quantize(
                MONETARY_QUANTUM, rounding=ROUND_HALF_UP
            ),
            reason=(
                f"Exact duplicate detected via SHA-256 composite key matching existing "
                f"invoice {safe_match_id} ({safe_match_num}, "
                f"total={matched_total:.2f})."
            ),
        )

    # Locate best related existing invoice (exact number or stripped base number) for netting/revision
    related_record: ExistingInvoiceRecord | None = None
    cand_num_upper = candidate.invoice_number.upper()
    base_num_upper = base_invoice_number.upper()
    for rec in active_vendor_records:
        rec_num_upper = rec.invoice_number.strip().upper()
        if rec_num_upper in (cand_num_upper, base_num_upper):
            related_record = rec
            break

    related_id = related_record.invoice_id if related_record is not None else None
    related_number = related_record.invoice_number if related_record is not None else None
    related_total = _quantize_record_total(related_record) if related_record is not None else None
    amount_diff = (
        (candidate.total_amount - related_total).quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)
        if related_total is not None
        else None
    )

    # 5. Priority 2 — Credit Note (FR-11, BR-013b, CLAUDE.md §16.1)
    if is_credit_note:
        details: list[str] = []
        if negative_total_detected:
            details.append(f"negative grand total ({candidate.total_amount:.2f})")
        if candidate.subtotal is not None and candidate.subtotal < Decimal("0.00"):
            details.append(f"negative subtotal ({candidate.subtotal:.2f})")
        if negative_line_numbers:
            lines_csv = ", ".join(str(n) for n in negative_line_numbers)
            details.append(f"negative line item(s) at line(s) {lines_csv}")
        detail_text = "; ".join(details)
        netting_note = (
            f" Related original invoice: {_sanitize_log_fragment(related_id)} "
            f"({_sanitize_log_fragment(related_number or '')})."
            if related_id is not None
            else ""
        )
        return DuplicateDetectionResult(
            outcome=DuplicateOutcome.CREDIT_NOTE,
            target_status="CREDIT_NOTE",
            should_proceed=False,
            composite_hash=composite_hash,
            normalized_invoice_number=candidate.invoice_number,
            base_invoice_number=base_invoice_number,
            is_duplicate=False,
            is_potential_revision=False,
            is_credit_note=True,
            revision_suffix_detected=revision_suffix_detected,
            detected_revision_suffix=detected_revision_suffix,
            revision_detected_in=revision_detected_in,
            negative_total_detected=negative_total_detected,
            negative_line_numbers=negative_line_numbers,
            matched_invoice_id=related_id,
            matched_invoice_number=related_number,
            matched_total_amount=related_total,
            amount_difference=amount_diff,
            reason=f"Credit note classified ({detail_text}); routed to credit netting workflow.{netting_note}",
        )

    # 6. Priority 3 — Potential Revision (FR-10, BR-013a)
    has_amount_diff_match = (
        related_record is not None
        and related_total is not None
        and related_total != candidate.total_amount
    )
    if revision_suffix_detected or has_amount_diff_match:
        reasons: list[str] = []
        if revision_suffix_detected and detected_revision_suffix is not None:
            reasons.append(
                f"revision suffix '{detected_revision_suffix}' detected in {revision_detected_in}"
            )
        if related_record is not None and related_total is not None:
            safe_rel_id = _sanitize_log_fragment(related_record.invoice_id)
            safe_rel_num = _sanitize_log_fragment(related_record.invoice_number)
            if has_amount_diff_match:
                reasons.append(
                    f"matches existing invoice {safe_rel_id} "
                    f"({safe_rel_num}) with differing total "
                    f"({related_total:.2f} -> {candidate.total_amount:.2f}, "
                    f"diff={amount_diff:+.2f})"
                )
            else:
                reasons.append(
                    f"references existing base invoice {safe_rel_id} "
                    f"({safe_rel_num}, total={related_total:.2f})"
                )
        return DuplicateDetectionResult(
            outcome=DuplicateOutcome.FLAGGED_POTENTIAL_REVISION,
            target_status="FLAGGED_POTENTIAL_REVISION",
            should_proceed=False,
            composite_hash=composite_hash,
            normalized_invoice_number=candidate.invoice_number,
            base_invoice_number=base_invoice_number,
            is_duplicate=False,
            is_potential_revision=True,
            is_credit_note=False,
            revision_suffix_detected=revision_suffix_detected,
            detected_revision_suffix=detected_revision_suffix,
            revision_detected_in=revision_detected_in,
            negative_total_detected=False,
            negative_line_numbers=(),
            matched_invoice_id=related_id,
            matched_invoice_number=related_number,
            matched_total_amount=related_total,
            amount_difference=amount_diff,
            reason=(
                "Potential revision flagged for side-by-side comparison: "
                + "; ".join(reasons)
                + "."
            ),
        )

    # 7. Priority 4 — Unique Regular Invoice (Proceed to Math/Tax/Date Validation)
    return DuplicateDetectionResult(
        outcome=DuplicateOutcome.PROCEED,
        target_status=None,
        should_proceed=True,
        composite_hash=composite_hash,
        normalized_invoice_number=candidate.invoice_number,
        base_invoice_number=base_invoice_number,
        is_duplicate=False,
        is_potential_revision=False,
        is_credit_note=False,
        revision_suffix_detected=False,
        detected_revision_suffix=None,
        revision_detected_in=None,
        negative_total_detected=False,
        negative_line_numbers=(),
        matched_invoice_id=None,
        matched_invoice_number=None,
        matched_total_amount=None,
        amount_difference=None,
        reason="No duplicate, revision, or credit note indicators detected; proceed to validation.",
    )


class DuplicateDetector:
    """
    Async duplicate, revision, and credit note detector backed by ``InvoiceLookupProtocol``.

    Works seamlessly with ``src.database.repositories.InvoiceRepository`` in production/tests
    or with ``repository=None`` for pure offline rule-only evaluation (suffix + credit note).
    """

    def __init__(self, repository: InvoiceLookupProtocol | None = None) -> None:
        self._repository = repository

    async def detect(self, candidate: DuplicateCheckInput) -> DuplicateDetectionResult:
        """Execute full duplicate, credit note, and revision detection for a validated candidate."""
        composite_hash = compute_composite_hash(
            vendor_tax_id=candidate.vendor_tax_id,
            invoice_number=candidate.invoice_number,
            total_amount=candidate.total_amount,
        )
        _has_rev, base_invoice_number, _suffix = detect_revision_suffix(candidate.invoice_number)

        existing_by_hash: ExistingInvoiceRecord | None = None
        vendor_records_by_id: dict[str, ExistingInvoiceRecord] = {}

        if self._repository is not None:
            existing_by_hash = await self._repository.get_by_composite_hash(composite_hash)
            if (
                existing_by_hash is None
                and candidate.invoice_number != candidate.invoice_number.upper()
            ):
                # Defeat mixed-case duplicate bypass on case-sensitive engines like SQLite (CWE-178)
                upper_hash = compute_composite_hash(
                    vendor_tax_id=candidate.vendor_tax_id,
                    invoice_number=candidate.invoice_number.upper(),
                    total_amount=candidate.total_amount,
                )
                existing_by_hash = await self._repository.get_by_composite_hash(upper_hash)

            # Deduplicated lookup keys covering exact, base, and uppercase variants (CWE-178)
            lookup_numbers: list[str] = []
            for num in (
                candidate.invoice_number,
                candidate.invoice_number.upper(),
                base_invoice_number,
                base_invoice_number.upper(),
            ):
                if num not in lookup_numbers:
                    lookup_numbers.append(num)

            for lookup_num in lookup_numbers:
                records = await self._repository.get_by_vendor_and_number(
                    candidate.vendor_tax_id, lookup_num
                )
                for rec in records:
                    vendor_records_by_id.setdefault(rec.invoice_id, rec)
                    if len(vendor_records_by_id) >= MAX_EXISTING_LOOKUP_RECORDS:
                        break
                if len(vendor_records_by_id) >= MAX_EXISTING_LOOKUP_RECORDS:
                    break

        result = evaluate_duplicate_rules(
            candidate,
            existing_by_hash=existing_by_hash,
            existing_vendor_invoices=list(vendor_records_by_id.values()),
        )

        # Structured PII-safe logging (mask vendor_tax_id per CLAUDE.md §8, CWE-532)
        logger.info(
            "Duplicate detection evaluated",
            extra={
                "outcome": result.outcome.value,
                "target_status": result.target_status,
                "vendor_tax_id_masked": _mask_tax_id(candidate.vendor_tax_id),
                "invoice_number": result.normalized_invoice_number,
                "matched_invoice_id": result.matched_invoice_id,
                "revision_suffix_detected": result.revision_suffix_detected,
                "is_credit_note": result.is_credit_note,
            },
        )
        return result

    async def check_invoice(
        self,
        *,
        vendor_tax_id: str,
        invoice_number: str,
        total_amount: Decimal | str | float | int,
        subtotal: Decimal | str | float | int | None = None,
        line_totals: Sequence[Decimal | str | float | int] = (),
        filename: str | None = None,
        current_invoice_id: str | None = None,
    ) -> DuplicateDetectionResult:
        """Convenience wrapper constructing ``DuplicateCheckInput`` and running ``detect``."""
        candidate = DuplicateCheckInput(
            vendor_tax_id=vendor_tax_id,
            invoice_number=invoice_number,
            total_amount=total_amount,
            subtotal=subtotal,
            line_totals=tuple(line_totals),
            filename=filename,
            current_invoice_id=current_invoice_id,
        )
        return await self.detect(candidate)

    async def detect_from_extraction(
        self,
        extraction: InvoiceExtractionSchema,
        *,
        filename: str | None = None,
        current_invoice_id: str | None = None,
    ) -> DuplicateDetectionResult:
        """Run duplicate, revision, and credit note detection directly on a P6-3 extraction payload."""
        line_totals = tuple(item.line_total.value for item in extraction.line_items)
        return await self.check_invoice(
            vendor_tax_id=extraction.header.vendor_tax_id.value,
            invoice_number=extraction.header.invoice_number.value,
            total_amount=extraction.header.total_amount.value,
            subtotal=extraction.header.subtotal.value,
            line_totals=line_totals,
            filename=filename,
            current_invoice_id=current_invoice_id,
        )


__all__ = [
    "DuplicateCheckInput",
    "DuplicateDetectionResult",
    "DuplicateDetector",
    "DuplicateOutcome",
    "ExistingInvoiceRecord",
    "IGNORED_DUPLICATE_STATUSES",
    "InvoiceLookupProtocol",
    "MAX_EXISTING_LOOKUP_RECORDS",
    "MAX_FILENAME_CHARS",
    "MAX_INVOICE_NUMBER_CHARS",
    "MAX_LINE_ITEMS",
    "MAX_MONETARY_AMOUNT",
    "MAX_VENDOR_TAX_ID_CHARS",
    "TargetDuplicateStatus",
    "compute_composite_hash",
    "detect_credit_note",
    "detect_revision_suffix",
    "evaluate_duplicate_rules",
]
