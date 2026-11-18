"""
Deterministic High-Value & PO-Variance Escalation Rules (P8-3, FR-13).

Covers FR-13, BR-012a, BR-014, BR-015, BR-018, CLAUDE.md §2, §3, §4.2, §6, §7.2, §11.1,
§16 Rule 8, §16.1, LLD §4, and PRD Journey 7:
- **High-Value Threshold:** ``total_amount_usd > get_settings().HIGH_VALUE_THRESHOLD_USD``
  (default ``$10,000.00``) → ``REQUIRES_MANAGER_APPROVAL`` (strict ``>``; exact ``$10,000.00``
  remains eligible for AP Clerk approval).
- **PO-Variance Tolerance:** ``abs(invoice_total - po_amount) / po_amount * 100 >
  get_settings().PO_VARIANCE_TOLERANCE_PERCENT`` (default ``5.0%``) → ``REQUIRES_MANAGER_APPROVAL``
  (strict ``>``; exact ``±5.00%`` remains within tolerance).
- **Exact Unrounded ``Decimal`` Boundary Checks:** Compares exact unrounded ``Decimal`` values
  against resolved thresholds so sub-cent/sub-basis-point overruns (e.g. ``$10,000.001`` or
  ``5.001%``) can never round downward into clerk-only approval.
- **ECB Daily FX Normalization on Invoice Date (CLAUDE.md §6, BR-012a):** Converts non-USD
  invoices (EUR, GBP, etc.) to USD using ``ExchangeRateLookupProtocol.get_latest_rate_on_or_before``
  keyed on ``invoice_date`` (never upload date), failing closed if no rate exists.
- **Exception & Credit-Note Precedence:** Escalates ``VALIDATED`` invoices to
  ``REQUIRES_MANAGER_APPROVAL`` while preserving higher-precedence unresolved exceptions
  (``DUPLICATE_INVOICE``, ``CREDIT_NOTE``, ``FLAGGED_POTENTIAL_REVISION``,
  ``REJECTED_TAX_MISMATCH``, ``REQUIRES_APPROVAL``, ``REQUIRES_REVIEW``) and unconditionally
  preventing negative-balance documents from routing to ``VALIDATED`` (CLAUDE.md §16.1).

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway,
  extraction engine, or SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never emits approval statuses (``APPROVED_CLERK``, ``APPROVED_MANAGER``,
  ``STAGED_FOR_EXPORT``) — enforced via strict ``Literal`` allowlist + ``frozen=True`` +
  ``extra="forbid"`` (CLAUDE.md §16.1, CWE-863 / CWE-915).
- Rejects booleans, NaN, Infinity, non-ASCII digits, underscores, oversized numeric strings,
  scientific-notation exponent bombs, invalid ISO-4217 currency codes, and negative PO amounts
  (CWE-20 / CWE-190 / CWE-400 / CWE-436).
- Logs aggregate escalation outcomes only — zero raw PII in logs (CWE-532).
"""

import re
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from src.core.config import get_settings
from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.confidence_router import ConfidenceRoutingResult
from src.validation.duplicate_detector import detect_credit_note

logger = get_logger("ap.validation.escalation_rules")

# Operational & SQL DECIMAL(18, 2/6) bounds (CWE-190 / CWE-400)
MAX_MONETARY_AMOUNT: Decimal = Decimal("999999999999.99")
MAX_ALLOWED_HIGH_VALUE_THRESHOLD_USD: Decimal = Decimal("100000000.00")
MAX_ALLOWED_PO_VARIANCE_PERCENT: Decimal = Decimal("100.00")
MAX_EXCHANGE_RATE: Decimal = Decimal("10000.000000")
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6
MONETARY_QUANTUM: Decimal = Decimal("0.01")
PERCENT_QUANTUM: Decimal = Decimal("0.01")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_ISO_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)

# Explicit non-approval status allowlist (CLAUDE.md §16.1, LLD §4, CWE-863)
AllowedEscalationStatus = Literal[
    "VALIDATED",
    "REQUIRES_MANAGER_APPROVAL",
    "REQUIRES_REVIEW",
    "REQUIRES_APPROVAL",
    "REJECTED_TAX_MISMATCH",
    "DUPLICATE_INVOICE",
    "FLAGGED_POTENTIAL_REVISION",
    "CREDIT_NOTE",
]

_BLOCKING_EXCEPTION_STATUSES: frozenset[str] = frozenset(
    {
        "DUPLICATE_INVOICE",
        "CREDIT_NOTE",
        "FLAGGED_POTENTIAL_REVISION",
        "REJECTED_TAX_MISMATCH",
        "REQUIRES_APPROVAL",
        "REQUIRES_REVIEW",
    }
)


class EscalationReason(StrEnum):
    """Canonical Finance Manager escalation triggers (FR-13, BR-014)."""

    HIGH_VALUE = "HIGH_VALUE"
    PO_VARIANCE = "PO_VARIANCE"


class MissingExchangeRateError(ValueError):
    """Raised when no ECB exchange rate exists on or before the invoice date for a non-USD currency."""


@runtime_checkable
class ExchangeRateRecordLike(Protocol):
    """Minimal duck-typed exchange rate row satisfied by SQLAlchemy ``ExchangeRate``."""

    rate_date: date
    exchange_rate: Decimal


@runtime_checkable
class ExchangeRateLookupProtocol(Protocol):
    """Minimal async FX lookup protocol satisfied by ``ExchangeRateRepository``."""

    async def get_latest_rate_on_or_before(
        self,
        target_date: date,
        from_currency: str,
        to_currency: str = "USD",
    ) -> ExchangeRateRecordLike | None: ...


class EscalationResult(BaseModel):
    """
    Immutable high-value & PO-variance escalation decision (P8-3, FR-13, BR-014).

    ``target_status`` is strictly constrained to non-approval states (CLAUDE.md §16.1, CWE-863).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_status: AllowedEscalationStatus
    requires_manager_approval: bool
    eligible_for_clerk_approval: bool
    high_value_exceeded: bool
    po_variance_exceeded: bool
    escalation_reasons: tuple[EscalationReason, ...]
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal
    fx_rate_applied: Decimal | None = None
    fx_rate_date: date | None = None
    po_amount: Decimal | None = None
    po_variance_percent: Decimal | None = None
    high_value_threshold_usd: Decimal
    po_variance_tolerance_percent: Decimal
    reason: str


def _parse_strict_decimal(
    raw: Any,
    *,
    field_name: str,
    max_abs: Decimal = MAX_MONETARY_AMOUNT,
) -> Decimal:
    """
    Parse a strict-ASCII finite bounded Decimal rejecting booleans, NaN, Infinity,
    underscores, non-ASCII digits, control characters, and exponent bombs (CWE-20/190/400/436).
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
        text = repr(raw)
        if not _STRICT_ASCII_DECIMAL_RE.match(text):
            raise ValueError(f"{field_name} must be a finite numeric value")
        val = Decimal(text)
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
            raise ValueError(f"{field_name} must be a strict ASCII decimal number")
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


def _normalize_currency(raw: Any) -> str:
    """Validate and normalize a 3-letter ISO-4217 uppercase currency code."""
    if not isinstance(raw, str):
        raise ValueError("currency must be a 3-letter ISO-4217 string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError("currency contains disallowed control characters")
    cleaned = raw.strip().upper()
    if not _ISO_CURRENCY_RE.match(cleaned):
        raise ValueError(f"Invalid currency code: {raw!r}; expected 3-letter ISO-4217 code")
    return cleaned


def _resolve_thresholds(
    *,
    high_value_threshold_usd: Decimal | str | float | int | None = None,
    po_variance_tolerance_percent: Decimal | str | float | int | None = None,
) -> tuple[Decimal, Decimal]:
    """
    Resolve and bound escalation thresholds from explicit args or ``get_settings()``
    (CLAUDE.md §16 Rule 8).
    """
    settings = get_settings()
    raw_hv = (
        settings.HIGH_VALUE_THRESHOLD_USD
        if high_value_threshold_usd is None
        else high_value_threshold_usd
    )
    raw_po = (
        settings.PO_VARIANCE_TOLERANCE_PERCENT
        if po_variance_tolerance_percent is None
        else po_variance_tolerance_percent
    )

    hv = _parse_strict_decimal(
        raw_hv,
        field_name="high_value_threshold_usd",
        max_abs=MAX_ALLOWED_HIGH_VALUE_THRESHOLD_USD,
    )
    po_tol = _parse_strict_decimal(
        raw_po,
        field_name="po_variance_tolerance_percent",
        max_abs=MAX_ALLOWED_PO_VARIANCE_PERCENT,
    )

    if hv <= Decimal("0"):
        raise ValueError("high_value_threshold_usd must be strictly positive")
    if po_tol < Decimal("0"):
        raise ValueError("po_variance_tolerance_percent must be non-negative")
    return hv, po_tol


def compute_po_variance_percent(
    invoice_total: Decimal | str | float | int,
    po_amount: Decimal | str | float | int,
) -> Decimal:
    """
    Compute exact unrounded absolute PO variance percentage:
    ``abs(invoice_total - po_amount) / po_amount * 100``.

    Fail-closed zero-PO behavior:
    - ``po_amount == 0`` and ``invoice_total == 0`` → ``Decimal("0")``
    - ``po_amount == 0`` and ``invoice_total != 0`` → ``Decimal("100.00")`` (or >100% overrun)
    - ``po_amount < 0`` → raises ``ValueError``.
    """
    inv = _parse_strict_decimal(invoice_total, field_name="invoice_total")
    po = _parse_strict_decimal(po_amount, field_name="po_amount")
    if po < Decimal("0"):
        raise ValueError("po_amount must be non-negative")
    if po == Decimal("0"):
        return Decimal("0") if inv == Decimal("0") else Decimal("100.00")
    return (abs(inv - po) / po) * Decimal("100")


_USD_CONSISTENCY_TOLERANCE: Decimal = Decimal("0.01")
_FX_CONSISTENCY_TOLERANCE: Decimal = Decimal("0.05")
MIN_VALID_FX_YEAR: int = 1990
MAX_VALID_FX_YEAR: int = 2100


def _validate_pure_date(raw: Any, *, field_name: str) -> date:
    """Enforce strict ``datetime.date`` (rejecting ``datetime`` subclasses & out-of-range years: SEC-171)."""
    if isinstance(raw, datetime) or not isinstance(raw, date):
        raise ValueError(
            f"{field_name} must be a strict datetime.date (not datetime or {type(raw).__name__})"
        )
    if raw.year < MIN_VALID_FX_YEAR or raw.year > MAX_VALID_FX_YEAR:
        raise ValueError(
            f"{field_name} year {raw.year} outside allowed bounds [{MIN_VALID_FX_YEAR}, {MAX_VALID_FX_YEAR}]"
        )
    return raw


def _resolve_usd_amount(
    *,
    total_amount: Decimal,
    currency: str,
    total_amount_usd: Decimal | str | float | int | None,
    exchange_rate_to_usd: Decimal | str | float | int | None,
) -> tuple[Decimal, Decimal | None]:
    """
    Compute exact unrounded USD equivalent for high-value threshold comparison (BR-012a).

    Fails closed on:
    - Non-USD currencies lacking both ``total_amount_usd`` and ``exchange_rate_to_usd``.
    - Non-unity FX rates on USD invoices or spoofed ``total_amount_usd`` contradicting
      ``total_amount`` / ``total_amount * exchange_rate_to_usd`` (SEC-169).
    """
    if currency == "USD":
        rate = (
            _parse_strict_decimal(
                exchange_rate_to_usd, field_name="exchange_rate_to_usd", max_abs=MAX_EXCHANGE_RATE
            )
            if exchange_rate_to_usd is not None
            else Decimal("1.000000")
        )
        if rate != Decimal("1"):
            raise ValueError(
                f"USD invoice requires exchange_rate_to_usd == 1.0 (got {rate}; SEC-169)"
            )
        if total_amount_usd is not None:
            usd_explicit = _parse_strict_decimal(total_amount_usd, field_name="total_amount_usd")
            if abs(usd_explicit - total_amount) > _USD_CONSISTENCY_TOLERANCE:
                raise ValueError(
                    f"Conflicting USD totals: total_amount ({total_amount}) != "
                    f"total_amount_usd ({usd_explicit}); SEC-169"
                )
        return total_amount, rate

    # Non-USD currency
    if exchange_rate_to_usd is not None:
        rate = _parse_strict_decimal(
            exchange_rate_to_usd, field_name="exchange_rate_to_usd", max_abs=MAX_EXCHANGE_RATE
        )
        if rate <= Decimal("0"):
            raise ValueError("exchange_rate_to_usd must be strictly positive")
        usd_exact = total_amount * rate
        if abs(usd_exact) > MAX_MONETARY_AMOUNT:
            raise ValueError("Converted USD amount exceeds maximum SQL DECIMAL(18, 2) bound")
        if total_amount_usd is not None:
            usd_explicit = _parse_strict_decimal(total_amount_usd, field_name="total_amount_usd")
            if abs(usd_explicit - usd_exact) > _FX_CONSISTENCY_TOLERANCE:
                raise ValueError(
                    f"Conflicting FX conversion: total_amount_usd ({usd_explicit}) differs from "
                    f"total_amount * rate ({usd_exact.quantize(MONETARY_QUANTUM)}); SEC-169"
                )
        return usd_exact, rate

    if total_amount_usd is not None:
        usd_exact = _parse_strict_decimal(total_amount_usd, field_name="total_amount_usd")
        return usd_exact, None

    raise ValueError(
        f"Non-USD currency '{currency}' requires exchange_rate_to_usd or pre-converted "
        "total_amount_usd (BR-012a, FR-13)."
    )


def evaluate_escalation(
    *,
    total_amount: Decimal | str | float | int,
    currency: str = "USD",
    total_amount_usd: Decimal | str | float | int | None = None,
    exchange_rate_to_usd: Decimal | str | float | int | None = None,
    fx_rate_date: date | None = None,
    po_amount: Decimal | str | float | int | None = None,
    po_variance_percent: Decimal | str | float | int | None = None,
    current_status: AllowedEscalationStatus | None = None,
    confidence_result: ConfidenceRoutingResult | None = None,
    high_value_threshold_usd: Decimal | str | float | int | None = None,
    po_variance_tolerance_percent: Decimal | str | float | int | None = None,
) -> EscalationResult:
    """
    Evaluate deterministic high-value (>$10k USD) and PO-variance (>5%) manager escalation rules
    (P8-3, FR-13, BR-014, CLAUDE.md §7.2 & §16 Rule 8).
    """
    total_dec = _parse_strict_decimal(total_amount, field_name="total_amount")
    ccy = _normalize_currency(currency)
    hv_threshold, po_tolerance = _resolve_thresholds(
        high_value_threshold_usd=high_value_threshold_usd,
        po_variance_tolerance_percent=po_variance_tolerance_percent,
    )

    if confidence_result is not None and not isinstance(confidence_result, ConfidenceRoutingResult):
        raise ValueError("confidence_result must be a validated ConfidenceRoutingResult instance")
    if fx_rate_date is not None:
        _validate_pure_date(fx_rate_date, field_name="fx_rate_date")
    if po_amount is not None and po_variance_percent is not None:
        raise ValueError("Provide either po_amount or po_variance_percent, not both (SEC-169)")
    if (
        current_status is not None
        and confidence_result is not None
        and current_status != confidence_result.target_status
    ):
        raise ValueError(
            f"Conflicting current_status ({current_status!r}) and "
            f"confidence_result.target_status ({confidence_result.target_status!r}); SEC-170"
        )

    # Resolve base workflow status (confidence_result takes precedence if current_status not passed)
    base_status: AllowedEscalationStatus = (
        current_status
        if current_status is not None
        else (confidence_result.target_status if confidence_result is not None else "VALIDATED")
    )
    if base_status not in _BLOCKING_EXCEPTION_STATUSES and base_status not in (
        "VALIDATED",
        "REQUIRES_MANAGER_APPROVAL",
    ):
        raise ValueError(f"Unsupported current_status for escalation evaluation: {base_status!r}")

    # Convert to USD (exact unrounded Decimal for strict > comparison)
    usd_exact, fx_rate = _resolve_usd_amount(
        total_amount=total_dec,
        currency=ccy,
        total_amount_usd=total_amount_usd,
        exchange_rate_to_usd=exchange_rate_to_usd,
    )
    usd_display = usd_exact.quantize(MONETARY_QUANTUM, rounding=ROUND_HALF_UP)

    # Evaluate High-Value trigger (strict > against exact unrounded USD amount)
    high_value_exceeded = abs(usd_exact) > hv_threshold

    # Evaluate PO-Variance trigger (strict > against exact unrounded percentage)
    po_dec: Decimal | None = None
    variance_exact: Decimal | None = None
    variance_display: Decimal | None = None
    po_variance_exceeded = False

    if po_amount is not None:
        po_dec = _parse_strict_decimal(po_amount, field_name="po_amount")
        if po_dec < Decimal("0"):
            raise ValueError("po_amount must be non-negative")
        if po_dec == Decimal("0") and total_dec != Decimal("0"):
            variance_exact = Decimal("100.00")
            variance_display = Decimal("100.00")
            po_variance_exceeded = True
        else:
            variance_exact = compute_po_variance_percent(total_dec, po_dec)
            variance_display = variance_exact.quantize(PERCENT_QUANTUM, rounding=ROUND_HALF_UP)
            po_variance_exceeded = variance_exact > po_tolerance
    elif po_variance_percent is not None:
        raw_pct = _parse_strict_decimal(
            po_variance_percent,
            field_name="po_variance_percent",
            max_abs=Decimal("1000000.00"),
        )
        variance_exact = abs(raw_pct)
        variance_display = variance_exact.quantize(PERCENT_QUANTUM, rounding=ROUND_HALF_UP)
        po_variance_exceeded = variance_exact > po_tolerance

    reasons: list[EscalationReason] = []
    if high_value_exceeded:
        reasons.append(EscalationReason.HIGH_VALUE)
    if po_variance_exceeded:
        reasons.append(EscalationReason.PO_VARIANCE)

    requires_manager = bool(reasons) or base_status == "REQUIRES_MANAGER_APPROVAL"

    # Unconditional negative-balance credit-note invariant (CLAUDE.md §16.1)
    if total_dec < Decimal("0"):
        target_status: AllowedEscalationStatus = (
            "DUPLICATE_INVOICE" if base_status == "DUPLICATE_INVOICE" else "CREDIT_NOTE"
        )
        eligible_clerk = False
        reason_text = (
            "Negative balance detected; routed to CREDIT_NOTE (not eligible for clerk approval)."
        )
    elif base_status in _BLOCKING_EXCEPTION_STATUSES:
        # Preserve higher-precedence unresolved exception (duplicate/tax/review/approval)
        target_status = base_status
        eligible_clerk = False
        reason_text = (
            f"Preserved blocking status '{base_status}' pending exception resolution "
            f"(requires_manager_approval={requires_manager})."
        )
    elif requires_manager:
        target_status = "REQUIRES_MANAGER_APPROVAL"
        eligible_clerk = False
        reason_codes = ", ".join(r.value for r in reasons) or "PRE_ESCALATED"
        reason_text = f"Escalated to Finance Manager approval ({reason_codes})."
    else:
        target_status = "VALIDATED"
        eligible_clerk = True
        reason_text = (
            f"Within clerk approval thresholds (USD {usd_display} <= ${hv_threshold}, "
            f"PO variance within {po_tolerance}%)."
        )

    result = EscalationResult(
        target_status=target_status,
        requires_manager_approval=requires_manager,
        eligible_for_clerk_approval=eligible_clerk,
        high_value_exceeded=high_value_exceeded,
        po_variance_exceeded=po_variance_exceeded,
        escalation_reasons=tuple(reasons),
        total_amount=total_dec,
        currency=ccy,
        total_amount_usd=usd_display,
        fx_rate_applied=fx_rate,
        fx_rate_date=fx_rate_date,
        po_amount=po_dec,
        po_variance_percent=variance_display,
        high_value_threshold_usd=hv_threshold,
        po_variance_tolerance_percent=po_tolerance,
        reason=reason_text,
    )

    logger.info(
        "Escalation rule evaluation completed",
        extra={
            "target_status": result.target_status,
            "requires_manager_approval": result.requires_manager_approval,
            "high_value_exceeded": result.high_value_exceeded,
            "po_variance_exceeded": result.po_variance_exceeded,
            "currency": result.currency,
            "escalation_reasons": [r.value for r in result.escalation_reasons],
        },
    )
    return result


def evaluate_extraction_escalation(
    extraction: InvoiceExtractionSchema,
    *,
    total_amount_usd: Decimal | str | float | int | None = None,
    exchange_rate_to_usd: Decimal | str | float | int | None = None,
    fx_rate_date: date | None = None,
    po_amount: Decimal | str | float | int | None = None,
    po_variance_percent: Decimal | str | float | int | None = None,
    confidence_result: ConfidenceRoutingResult | None = None,
    high_value_threshold_usd: Decimal | str | float | int | None = None,
    po_variance_tolerance_percent: Decimal | str | float | int | None = None,
) -> EscalationResult:
    """
    Evaluate high-value and PO-variance escalation rules directly on a P6-3 extraction schema.
    """
    if not isinstance(extraction, InvoiceExtractionSchema):
        raise ValueError("extraction must be a validated InvoiceExtractionSchema instance")

    if confidence_result is not None and not isinstance(confidence_result, ConfidenceRoutingResult):
        raise ValueError("confidence_result must be a validated ConfidenceRoutingResult instance")

    # Check line-level negative balances too (credit note with positive/zero total & negative line)
    line_totals = tuple(item.line_total.value for item in extraction.line_items)
    is_cn, _, _ = detect_credit_note(
        extraction.header.total_amount.value,
        subtotal=extraction.header.subtotal.value,
        line_totals=line_totals,
    )
    effective_status: AllowedEscalationStatus | None = (
        confidence_result.target_status if confidence_result is not None else None
    )
    forwarded_conf: ConfidenceRoutingResult | None = confidence_result
    if is_cn and effective_status != "DUPLICATE_INVOICE":
        effective_status = "CREDIT_NOTE"
        forwarded_conf = None

    return evaluate_escalation(
        total_amount=extraction.header.total_amount.value,
        currency=extraction.header.currency.value,
        total_amount_usd=total_amount_usd,
        exchange_rate_to_usd=exchange_rate_to_usd,
        fx_rate_date=fx_rate_date,
        po_amount=po_amount,
        po_variance_percent=po_variance_percent,
        current_status=effective_status,
        confidence_result=forwarded_conf,
        high_value_threshold_usd=high_value_threshold_usd,
        po_variance_tolerance_percent=po_variance_tolerance_percent,
    )


class EscalationEvaluator:
    """
    Configurable deterministic High-Value & PO-Variance Escalation Evaluator (P8-3, FR-13).

    Reads ``HIGH_VALUE_THRESHOLD_USD`` and ``PO_VARIANCE_TOLERANCE_PERCENT`` from
    ``get_settings()`` unless explicitly overridden, and integrates with
    ``ExchangeRateLookupProtocol`` (``ExchangeRateRepository``) for invoice-date ECB FX conversion.
    """

    def __init__(
        self,
        *,
        exchange_rate_repo: ExchangeRateLookupProtocol | None = None,
        high_value_threshold_usd: Decimal | str | float | int | None = None,
        po_variance_tolerance_percent: Decimal | str | float | int | None = None,
    ) -> None:
        if exchange_rate_repo is not None and not isinstance(
            exchange_rate_repo, ExchangeRateLookupProtocol
        ):
            raise ValueError(
                "exchange_rate_repo must satisfy ExchangeRateLookupProtocol "
                "(get_latest_rate_on_or_before)"
            )
        self._fx_repo = exchange_rate_repo
        self._explicit_hv = high_value_threshold_usd
        self._explicit_po = po_variance_tolerance_percent
        # Validate eagerly at construction so misconfigured thresholds fail immediately
        _resolve_thresholds(
            high_value_threshold_usd=high_value_threshold_usd,
            po_variance_tolerance_percent=po_variance_tolerance_percent,
        )

    @property
    def high_value_threshold_usd(self) -> Decimal:
        """Resolved high-value manager approval threshold in USD."""
        hv, _ = _resolve_thresholds(
            high_value_threshold_usd=self._explicit_hv,
            po_variance_tolerance_percent=self._explicit_po,
        )
        return hv

    @property
    def po_variance_tolerance_percent(self) -> Decimal:
        """Resolved PO variance tolerance percentage."""
        _, po_tol = _resolve_thresholds(
            high_value_threshold_usd=self._explicit_hv,
            po_variance_tolerance_percent=self._explicit_po,
        )
        return po_tol

    def evaluate(
        self,
        *,
        total_amount: Decimal | str | float | int,
        currency: str = "USD",
        total_amount_usd: Decimal | str | float | int | None = None,
        exchange_rate_to_usd: Decimal | str | float | int | None = None,
        fx_rate_date: date | None = None,
        po_amount: Decimal | str | float | int | None = None,
        po_variance_percent: Decimal | str | float | int | None = None,
        current_status: AllowedEscalationStatus | None = None,
        confidence_result: ConfidenceRoutingResult | None = None,
    ) -> EscalationResult:
        """Synchronously evaluate escalation rules with provided USD or FX rate."""
        return evaluate_escalation(
            total_amount=total_amount,
            currency=currency,
            total_amount_usd=total_amount_usd,
            exchange_rate_to_usd=exchange_rate_to_usd,
            fx_rate_date=fx_rate_date,
            po_amount=po_amount,
            po_variance_percent=po_variance_percent,
            current_status=current_status,
            confidence_result=confidence_result,
            high_value_threshold_usd=self._explicit_hv,
            po_variance_tolerance_percent=self._explicit_po,
        )

    async def _lookup_fx_rate(
        self,
        *,
        currency: str,
        invoice_date: date,
    ) -> tuple[Decimal, date]:
        """Resolve ECB daily rate on or before ``invoice_date`` via ExchangeRateRepository."""
        ccy = _normalize_currency(currency)
        validated_inv_date = _validate_pure_date(invoice_date, field_name="invoice_date")
        if ccy == "USD":
            return Decimal("1.000000"), validated_inv_date
        if self._fx_repo is None:
            raise MissingExchangeRateError(
                f"Cannot convert non-USD currency '{ccy}' without an exchange_rate_repo"
            )
        rate_row = await self._fx_repo.get_latest_rate_on_or_before(validated_inv_date, ccy, "USD")
        if rate_row is None:
            raise MissingExchangeRateError(
                f"No ECB exchange rate found for {ccy}->USD on or before "
                f"{validated_inv_date.isoformat()}"
            )
        row_date = _validate_pure_date(rate_row.rate_date, field_name="fx_rate_date")
        if row_date > validated_inv_date:
            raise ValueError(
                f"ECB exchange rate date ({row_date.isoformat()}) cannot be after "
                f"invoice_date ({validated_inv_date.isoformat()}); SEC-171"
            )
        row_rate = _parse_strict_decimal(
            rate_row.exchange_rate,
            field_name="exchange_rate",
            max_abs=MAX_EXCHANGE_RATE,
        )
        if row_rate <= Decimal("0"):
            raise ValueError("ECB exchange_rate must be strictly positive (SEC-171)")
        return row_rate, row_date

    async def evaluate_with_fx(
        self,
        *,
        total_amount: Decimal | str | float | int,
        currency: str,
        invoice_date: date,
        po_amount: Decimal | str | float | int | None = None,
        po_variance_percent: Decimal | str | float | int | None = None,
        current_status: AllowedEscalationStatus | None = None,
        confidence_result: ConfidenceRoutingResult | None = None,
    ) -> EscalationResult:
        """
        Asynchronously resolve the invoice-date ECB exchange rate via repository and evaluate
        high-value and PO-variance escalation rules (CLAUDE.md §6, BR-012a, FR-13).
        """
        rate, rate_dt = await self._lookup_fx_rate(currency=currency, invoice_date=invoice_date)
        return self.evaluate(
            total_amount=total_amount,
            currency=currency,
            exchange_rate_to_usd=rate,
            fx_rate_date=rate_dt,
            po_amount=po_amount,
            po_variance_percent=po_variance_percent,
            current_status=current_status,
            confidence_result=confidence_result,
        )

    async def evaluate_extraction_with_fx(
        self,
        extraction: InvoiceExtractionSchema,
        *,
        invoice_date: date,
        po_amount: Decimal | str | float | int | None = None,
        po_variance_percent: Decimal | str | float | int | None = None,
        confidence_result: ConfidenceRoutingResult | None = None,
    ) -> EscalationResult:
        """
        Asynchronously resolve ECB FX on ``invoice_date`` and evaluate escalation on a P6-3 extraction.
        """
        if not isinstance(extraction, InvoiceExtractionSchema):
            raise ValueError("extraction must be a validated InvoiceExtractionSchema instance")
        rate, rate_dt = await self._lookup_fx_rate(
            currency=extraction.header.currency.value,
            invoice_date=invoice_date,
        )
        return evaluate_extraction_escalation(
            extraction,
            exchange_rate_to_usd=rate,
            fx_rate_date=rate_dt,
            po_amount=po_amount,
            po_variance_percent=po_variance_percent,
            confidence_result=confidence_result,
            high_value_threshold_usd=self._explicit_hv,
            po_variance_tolerance_percent=self._explicit_po,
        )


__all__ = [
    "AllowedEscalationStatus",
    "EscalationEvaluator",
    "EscalationReason",
    "EscalationResult",
    "ExchangeRateLookupProtocol",
    "ExchangeRateRecordLike",
    "MAX_ALLOWED_HIGH_VALUE_THRESHOLD_USD",
    "MAX_ALLOWED_PO_VARIANCE_PERCENT",
    "MAX_EXCHANGE_RATE",
    "MissingExchangeRateError",
    "compute_po_variance_percent",
    "evaluate_escalation",
    "evaluate_extraction_escalation",
]
