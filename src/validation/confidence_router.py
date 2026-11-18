"""
Deterministic Tri-Tier Confidence Router (P8-1, FR-04).

Covers FR-04, BR-007, Q-03, BRD §6.3, PRD Journeys 2–4 & §5.2, HLD §5, LLD §4,
and CLAUDE.md §3, §4.2, §7.1, §7.2, §7.4, §12, §16 Rule 8, §16.1:
- Evaluates per-field extraction confidence scores across all header and line-item fields
  on the strict ``[0.00, 100.00]`` percentage scale (zero silent 0–1 rescaling):
  - **High Confidence (``>= 90.00%``):** ``ConfidenceTier.HIGH`` -> ``VALIDATED`` (Green ``#22c55e``)
  - **Medium Confidence (``80.00% <= score < 90.00%``):** ``ConfidenceTier.MEDIUM`` -> ``REQUIRES_REVIEW`` (Light-Yellow ``#fef08a``)
  - **Low Confidence (``< 80.00%``):** ``ConfidenceTier.LOW`` -> ``REQUIRES_APPROVAL`` (Amber/Red ``#ef4444``)
- Applies **worst-field-wins (minimum per-field confidence)** aggregation per BRD BR-007 and
  PRD Journeys 2–4 so a single low-confidence field (e.g. ``total_amount = 74%``) can never be
  masked by a high macro-average across the remaining fields.
- Compares **exact unrounded ``Decimal`` scores** against configured thresholds from
  ``get_settings()`` so sub-cent values (e.g. ``89.999%`` or ``79.999%``) never round upward
  into a higher trust tier.
- Enforces the **Rules-First Principle** (CLAUDE.md §7.2): deterministic ``RulesEngineResult``
  failures always override high confidence, and when both fail, the highest-precedence
  (strictest) status wins.
- Supports **Clerk Re-Validation** (CLAUDE.md §7.4, LLD §4): preserves immutable model
  confidence scores unchanged while transitioning to ``VALIDATED`` if all deterministic rules
  pass, ``CREDIT_NOTE`` if negative-balance edits are detected (CLAUDE.md §16.1), or
  ``REQUIRES_APPROVAL`` if rules still fail.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never emits approval or manager-escalation statuses (``APPROVED_CLERK``, ``APPROVED_MANAGER``,
  ``STAGED_FOR_EXPORT``, ``REQUIRES_MANAGER_APPROVAL``) — enforced via strict ``Literal``
  allowlist + ``frozen=True`` + ``extra="forbid"`` (CLAUDE.md §16.1, CWE-863 / CWE-915).
- Rejects booleans, NaN, Infinity, non-ASCII digits, underscores, oversized numeric strings,
  scientific-notation exponent bombs, unbounded field maps (``> 2,600``), and control/bidi
  characters in field names (CWE-20 / CWE-117 / CWE-190 / CWE-400 / CWE-436 / CWE-451).
- Logs aggregate confidence metrics only — zero raw PII or field values in logs (CWE-532).
"""

import re
from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from src.core.config import get_settings
from src.core.logging import get_logger
from src.extraction.schemas import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    CRITICAL_HEADER_FIELD_NAMES,
    HEADER_FIELD_NAMES,
    InvoiceExtractionSchema,
)
from src.validation.duplicate_detector import detect_credit_note
from src.validation.rules_engine import RulesEngineResult

logger = get_logger("ap.validation.confidence_router")

# Canonical FR-04 / BR-007 default thresholds (configurable via get_settings(): CLAUDE.md §16 Rule 8)
CONFIDENCE_HIGH_THRESHOLD: Decimal = Decimal("90.00")
CONFIDENCE_MEDIUM_THRESHOLD: Decimal = Decimal("80.00")
CONFIDENCE_QUANTUM: Decimal = Decimal("0.01")

# Percentage-scale safety floors (SEC-162: prevents 0.90/0.80 fraction typos from auto-validating OCR)
MIN_ALLOWED_HIGH_THRESHOLD: Decimal = Decimal("60.00")
MIN_ALLOWED_MEDIUM_THRESHOLD: Decimal = Decimal("50.00")

# Operational ceilings (10 header + 500 lines * 5 fields = 2,510; bounded DoS guard: CWE-400)
MAX_CONFIDENCE_FIELDS: int = 2600
MAX_FIELD_NAME_CHARS: int = 128
MAX_DECIMAL_INPUT_CHARS: int = 32
MAX_DECIMAL_FRACTION_DIGITS: int = 6

# Strict ASCII numeric format & safe field-name guards (CWE-20 / CWE-117 / CWE-436 / CWE-451)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_STRICT_ASCII_DECIMAL_RE = re.compile(
    r"^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$"
)

# Canonical critical header field names (both bare and 'header.' prefixed forms)
_CRITICAL_FIELD_KEYS: frozenset[str] = frozenset(CRITICAL_HEADER_FIELD_NAMES) | frozenset(
    f"header.{name}" for name in CRITICAL_HEADER_FIELD_NAMES
)
_HEADER_FIELD_KEYS: frozenset[str] = frozenset(HEADER_FIELD_NAMES) | frozenset(
    f"header.{name}" for name in HEADER_FIELD_NAMES
)

# Explicit non-approval status allowlists (CLAUDE.md §16.1, LLD §4, CWE-863)
TierStatus = Literal["VALIDATED", "REQUIRES_REVIEW", "REQUIRES_APPROVAL"]
AllowedConfidenceStatus = Literal[
    "VALIDATED",
    "REQUIRES_REVIEW",
    "REQUIRES_APPROVAL",
    "REJECTED_TAX_MISMATCH",
    "DUPLICATE_INVOICE",
    "FLAGGED_POTENTIAL_REVISION",
    "CREDIT_NOTE",
]
ColorLabel = Literal["green", "light_yellow", "amber_red"]

# Deterministic precedence table across rule + confidence outcomes (lower rank = stricter, wins)
_ROUTING_STATUS_PRIORITY: dict[str, int] = {
    "DUPLICATE_INVOICE": 1,
    "CREDIT_NOTE": 2,
    "FLAGGED_POTENTIAL_REVISION": 3,
    "REJECTED_TAX_MISMATCH": 4,
    "REQUIRES_APPROVAL": 5,
    "REQUIRES_REVIEW": 6,
    "VALIDATED": 7,
}


class ConfidenceTier(StrEnum):
    """Canonical FR-04 / BR-007 tri-tier confidence buckets."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ConfidenceColor(StrEnum):
    """UI confidence highlight hex tokens per CLAUDE.md §12."""

    GREEN = "#22c55e"
    LIGHT_YELLOW = "#fef08a"
    AMBER_RED = "#ef4444"


_TIER_TO_STATUS: dict[ConfidenceTier, TierStatus] = {
    ConfidenceTier.HIGH: "VALIDATED",
    ConfidenceTier.MEDIUM: "REQUIRES_REVIEW",
    ConfidenceTier.LOW: "REQUIRES_APPROVAL",
}

_TIER_TO_COLOR: dict[ConfidenceTier, tuple[str, ColorLabel]] = {
    ConfidenceTier.HIGH: (ConfidenceColor.GREEN.value, "green"),
    ConfidenceTier.MEDIUM: (ConfidenceColor.LIGHT_YELLOW.value, "light_yellow"),
    ConfidenceTier.LOW: (ConfidenceColor.AMBER_RED.value, "amber_red"),
}


class FieldConfidenceAssessment(BaseModel):
    """Immutable per-field confidence classification and UI highlight metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field_name: str
    score: Decimal
    tier: ConfidenceTier
    color_hex: str
    color_label: ColorLabel
    is_critical: bool


class ConfidenceRoutingResult(BaseModel):
    """
    Immutable tri-tier confidence routing outcome (P8-1, FR-04, BR-007).

    ``target_status`` is strictly constrained to non-approval states (CLAUDE.md §16.1, CWE-863).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_status: AllowedConfidenceStatus
    confidence_tier: ConfidenceTier
    confidence_status: TierStatus
    min_confidence: Decimal
    macro_avg_confidence: Decimal
    header_macro_avg_confidence: Decimal | None = None
    min_critical_confidence: Decimal | None = None
    color_hex: str
    color_label: ColorLabel
    evaluated_field_count: int
    low_confidence_fields: tuple[str, ...]
    review_confidence_fields: tuple[str, ...]
    field_assessments: tuple[FieldConfidenceAssessment, ...]
    rules_override_applied: bool = False
    is_revalidation: bool = False
    reason: str


def _require_strict_bool(value: Any, *, field_name: str) -> bool:
    """Enforce strict Python bool (prevents truthy string 'false' coercion: CWE-704)."""
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a strict boolean")
    return value


def _parse_confidence_decimal(raw: Any, *, field_name: str = "confidence") -> Decimal:
    """
    Parse a strict-ASCII finite Decimal on ``[0.00, 100.00]`` without rounding or rescaling.

    Rejects booleans, NaN, Infinity, underscores, non-ASCII digits, control characters,
    and scientific-notation exponent bombs (CWE-20 / CWE-190 / CWE-400 / CWE-436).
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
        if adjusted > 3 or adjusted < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(f"{field_name} exponent exceeds allowed precision bounds")
        norm_exp = val.normalize().as_tuple().exponent
        if isinstance(norm_exp, int) and norm_exp < -MAX_DECIMAL_FRACTION_DIGITS:
            raise ValueError(
                f"{field_name} exceeds maximum {MAX_DECIMAL_FRACTION_DIGITS} fractional digits"
            )
    else:
        val = Decimal("0")

    if val < CONFIDENCE_MIN or val > CONFIDENCE_MAX:
        raise ValueError(
            f"{field_name} must be within [{CONFIDENCE_MIN}, {CONFIDENCE_MAX}] (got {val})"
        )
    return val


def _validate_field_name(raw: Any) -> str:
    """Validate bounded, control-char-free, bidi-free field identifier (CWE-20/117/451)."""
    if not isinstance(raw, str):
        raise ValueError("field_name must be a string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError("field_name contains disallowed control characters")
    if _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise ValueError("field_name contains disallowed invisible bidi/zero-width characters")
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("field_name cannot be empty")
    if len(cleaned) > MAX_FIELD_NAME_CHARS:
        raise ValueError(f"field_name exceeds maximum length of {MAX_FIELD_NAME_CHARS} characters")
    return cleaned


def _canonical_field_key(name: str) -> str:
    """
    Canonicalize a field identifier for case-insensitive and header-alias deduplication (SEC-163).

    Maps both ``total_amount`` and ``header.total_amount`` (regardless of case) to
    ``header.total_amount`` so duplicate aliases cannot inflate macro-averages or evade
    critical-field classification.
    """
    lower = name.lower()
    if lower in HEADER_FIELD_NAMES:
        return f"header.{lower}"
    return lower


def _resolve_thresholds(
    *,
    high_threshold: Decimal | str | float | int | None = None,
    medium_threshold: Decimal | str | float | int | None = None,
) -> tuple[Decimal, Decimal]:
    """
    Resolve and validate confidence routing thresholds from explicit args or ``get_settings()``.

    Enforces percentage-scale safety floors and strict ordering
    ``50.00 <= medium_threshold < high_threshold <= 100.00`` with ``high_threshold >= 60.00``
    (SEC-162: blocks 0.90/0.80 fraction-scale misconfiguration typos fail-closed).
    """
    settings = get_settings()
    raw_high = settings.CONFIDENCE_HIGH_THRESHOLD if high_threshold is None else high_threshold
    raw_med = settings.CONFIDENCE_MEDIUM_THRESHOLD if medium_threshold is None else medium_threshold

    high = _parse_confidence_decimal(raw_high, field_name="high_threshold")
    med = _parse_confidence_decimal(raw_med, field_name="medium_threshold")

    if med < MIN_ALLOWED_MEDIUM_THRESHOLD:
        raise ValueError(
            f"medium_threshold ({med}) must be at least {MIN_ALLOWED_MEDIUM_THRESHOLD}% "
            "(percentage scale [50.00, 100.00])"
        )
    if high < MIN_ALLOWED_HIGH_THRESHOLD:
        raise ValueError(
            f"high_threshold ({high}) must be at least {MIN_ALLOWED_HIGH_THRESHOLD}% "
            "(percentage scale [60.00, 100.00])"
        )
    if med >= high:
        raise ValueError(
            f"medium_threshold ({med}) must be strictly less than high_threshold ({high})"
        )
    return high, med


def _verify_rules_result_integrity(rules_result: RulesEngineResult) -> None:
    """
    Fail closed if a ``RulesEngineResult`` carries internally contradictory pass/fail state
    (SEC-164 / CWE-345: prevents forged ``all_passed=True`` from bypassing failed rules).
    """
    if rules_result.all_passed:
        per_rule_flags_ok = (
            rules_result.duplicate_passed
            and rules_result.line_arithmetic_valid
            and rules_result.invoice_total_valid
            and rules_result.tax_valid
            and rules_result.date_valid
        )
        outcomes_ok = all(o.passed for o in rules_result.rule_outcomes if not o.skipped)
        if (
            rules_result.failed_rules
            or rules_result.errors
            or rules_result.recommended_status is not None
            or not per_rule_flags_ok
            or not outcomes_ok
        ):
            raise ValueError(
                "Inconsistent RulesEngineResult: all_passed=True contradicts failing rule state"
            )


def tier_to_status(tier: ConfidenceTier) -> TierStatus:
    """Map a ``ConfidenceTier`` to its canonical FR-04 workflow status."""
    if not isinstance(tier, ConfidenceTier):
        raise ValueError(f"tier must be a ConfidenceTier enum member, got {type(tier).__name__}")
    return _TIER_TO_STATUS[tier]


def tier_to_color(tier: ConfidenceTier) -> tuple[str, ColorLabel]:
    """Map a ``ConfidenceTier`` to its CLAUDE.md §12 UI highlight hex code and label."""
    if not isinstance(tier, ConfidenceTier):
        raise ValueError(f"tier must be a ConfidenceTier enum member, got {type(tier).__name__}")
    return _TIER_TO_COLOR[tier]


def classify_confidence_score(
    score: Decimal | str | float | int,
    *,
    high_threshold: Decimal | str | float | int | None = None,
    medium_threshold: Decimal | str | float | int | None = None,
) -> ConfidenceTier:
    """
    Classify a single extraction confidence percentage into HIGH / MEDIUM / LOW (FR-04, BR-007).

    Compares the exact unrounded ``Decimal`` against resolved thresholds so sub-cent values
    (e.g. ``89.999%`` or ``79.999%``) never round upward into a higher trust tier.
    """
    val = _parse_confidence_decimal(score, field_name="confidence")
    high, med = _resolve_thresholds(
        high_threshold=high_threshold,
        medium_threshold=medium_threshold,
    )
    if val >= high:
        return ConfidenceTier.HIGH
    if val >= med:
        return ConfidenceTier.MEDIUM
    return ConfidenceTier.LOW


def _resolve_final_status(
    *,
    confidence_status: TierStatus,
    rules_result: RulesEngineResult | None,
    is_revalidation: bool,
) -> tuple[AllowedConfidenceStatus, bool, str]:
    """
    Combine confidence-derived status with deterministic ``RulesEngineResult`` (CLAUDE.md §7.2/§7.4).
    """
    if is_revalidation:
        if rules_result is None:
            raise ValueError("rules_result is required when is_revalidation=True")
        if rules_result.all_passed:
            return (
                "VALIDATED",
                confidence_status != "VALIDATED",
                "Clerk re-validation passed all deterministic rules; promoted to VALIDATED "
                "(original model confidence preserved).",
            )
        if rules_result.recommended_status == "CREDIT_NOTE":
            return (
                "CREDIT_NOTE",
                True,
                "Clerk re-validation detected a negative-balance credit note; routed to CREDIT_NOTE.",
            )
        return (
            "REQUIRES_APPROVAL",
            True,
            "Clerk re-validation failed one or more deterministic rules; returned to REQUIRES_APPROVAL.",
        )

    if rules_result is not None and not rules_result.all_passed:
        # Fail closed if a malformed/tampered RulesEngineResult omitted recommended_status
        rule_status: AllowedConfidenceStatus = (
            rules_result.recommended_status
            if rules_result.recommended_status is not None
            else "REQUIRES_APPROVAL"
        )
        if _ROUTING_STATUS_PRIORITY[rule_status] < _ROUTING_STATUS_PRIORITY[confidence_status]:
            return (
                rule_status,
                True,
                f"Deterministic validation failure ({rule_status}) overrode confidence status "
                f"({confidence_status}).",
            )
        if rule_status == confidence_status:
            return (
                rule_status,
                True,
                f"Both deterministic validation and confidence routing require {rule_status}.",
            )
        return (
            confidence_status,
            False,
            f"Stricter confidence tier ({confidence_status}) took precedence over rule status "
            f"({rule_status}).",
        )

    return (
        confidence_status,
        False,
        f"All evaluated rules passed; routed to {confidence_status} by minimum field confidence.",
    )


def route_confidence_scores(
    field_scores: Mapping[str, Decimal | str | float | int],
    *,
    rules_result: RulesEngineResult | None = None,
    is_revalidation: bool = False,
    high_threshold: Decimal | str | float | int | None = None,
    medium_threshold: Decimal | str | float | int | None = None,
) -> ConfidenceRoutingResult:
    """
    Route an invoice based on a mapping of per-field extraction confidence scores (FR-04, BR-007).

    Uses worst-field-wins (minimum per-field confidence) so a single uncertain field cannot be
    masked by a high macro-average, and applies Rules-First precedence when ``rules_result`` is supplied.
    """
    if not isinstance(field_scores, Mapping):
        raise ValueError("field_scores must be a mapping of field_name -> confidence score")
    if len(field_scores) == 0:
        raise ValueError("field_scores must be non-empty")
    if len(field_scores) > MAX_CONFIDENCE_FIELDS:
        raise ValueError(
            f"field_scores count ({len(field_scores)}) exceeds maximum of {MAX_CONFIDENCE_FIELDS}"
        )
    if rules_result is not None:
        if not isinstance(rules_result, RulesEngineResult):
            raise ValueError("rules_result must be a validated RulesEngineResult instance")
        _verify_rules_result_integrity(rules_result)
    _require_strict_bool(is_revalidation, field_name="is_revalidation")

    high, med = _resolve_thresholds(
        high_threshold=high_threshold,
        medium_threshold=medium_threshold,
    )

    assessments: list[FieldConfidenceAssessment] = []
    seen_canonical_keys: set[str] = set()
    low_fields: list[str] = []
    review_fields: list[str] = []
    header_scores: list[Decimal] = []
    critical_scores: list[Decimal] = []
    all_scores: list[Decimal] = []

    for raw_name, raw_score in field_scores.items():
        name = _validate_field_name(raw_name)
        canonical_key = _canonical_field_key(name)
        if canonical_key in seen_canonical_keys:
            raise ValueError(f"Duplicate canonical field name in field_scores: '{name}'")
        seen_canonical_keys.add(canonical_key)

        score = _parse_confidence_decimal(raw_score, field_name=f"confidence[{name}]")
        if score >= high:
            tier = ConfidenceTier.HIGH
        elif score >= med:
            tier = ConfidenceTier.MEDIUM
            review_fields.append(name)
        else:
            tier = ConfidenceTier.LOW
            low_fields.append(name)

        color_hex, color_label = _TIER_TO_COLOR[tier]
        is_critical = canonical_key in _CRITICAL_FIELD_KEYS

        assessments.append(
            FieldConfidenceAssessment(
                field_name=name,
                score=score,
                tier=tier,
                color_hex=color_hex,
                color_label=color_label,
                is_critical=is_critical,
            )
        )
        all_scores.append(score)
        if canonical_key in _HEADER_FIELD_KEYS:
            header_scores.append(score)
        if is_critical:
            critical_scores.append(score)

    min_conf = min(all_scores)
    macro_avg = (sum(all_scores, Decimal("0")) / Decimal(len(all_scores))).quantize(
        CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP
    )
    header_macro_avg = (
        (sum(header_scores, Decimal("0")) / Decimal(len(header_scores))).quantize(
            CONFIDENCE_QUANTUM, rounding=ROUND_HALF_UP
        )
        if header_scores
        else None
    )
    min_critical = min(critical_scores) if critical_scores else None

    if min_conf >= high:
        overall_tier = ConfidenceTier.HIGH
    elif min_conf >= med:
        overall_tier = ConfidenceTier.MEDIUM
    else:
        overall_tier = ConfidenceTier.LOW

    confidence_status = _TIER_TO_STATUS[overall_tier]
    overall_hex, overall_label = _TIER_TO_COLOR[overall_tier]

    target_status, rules_override, reason = _resolve_final_status(
        confidence_status=confidence_status,
        rules_result=rules_result,
        is_revalidation=is_revalidation,
    )

    result = ConfidenceRoutingResult(
        target_status=target_status,
        confidence_tier=overall_tier,
        confidence_status=confidence_status,
        min_confidence=min_conf,
        macro_avg_confidence=macro_avg,
        header_macro_avg_confidence=header_macro_avg,
        min_critical_confidence=min_critical,
        color_hex=overall_hex,
        color_label=overall_label,
        evaluated_field_count=len(assessments),
        low_confidence_fields=tuple(sorted(low_fields)),
        review_confidence_fields=tuple(sorted(review_fields)),
        field_assessments=tuple(assessments),
        rules_override_applied=rules_override,
        is_revalidation=is_revalidation,
        reason=reason,
    )

    logger.info(
        "Confidence routing completed",
        extra={
            "target_status": result.target_status,
            "confidence_tier": result.confidence_tier.value,
            "min_confidence": str(result.min_confidence),
            "macro_avg_confidence": str(result.macro_avg_confidence),
            "evaluated_field_count": result.evaluated_field_count,
            "low_field_count": len(result.low_confidence_fields),
            "review_field_count": len(result.review_confidence_fields),
            "rules_override_applied": result.rules_override_applied,
            "is_revalidation": result.is_revalidation,
        },
    )
    return result


def route_extraction_confidence(
    extraction: InvoiceExtractionSchema,
    *,
    rules_result: RulesEngineResult | None = None,
    is_revalidation: bool = False,
    high_threshold: Decimal | str | float | int | None = None,
    medium_threshold: Decimal | str | float | int | None = None,
) -> ConfidenceRoutingResult:
    """
    Route a validated P6-3 ``InvoiceExtractionSchema`` using all header + line-item confidences.

    Enforces unconditional negative-balance credit-note protection (CLAUDE.md §16.1, SEC-161):
    a credit note extraction can never be routed as ``VALIDATED`` even when ``rules_result`` is
    omitted or passed as passing during re-validation.
    """
    if not isinstance(extraction, InvoiceExtractionSchema):
        raise ValueError("extraction must be a validated InvoiceExtractionSchema instance")

    result = route_confidence_scores(
        extraction.all_field_confidences(),
        rules_result=rules_result,
        is_revalidation=is_revalidation,
        high_threshold=high_threshold,
        medium_threshold=medium_threshold,
    )

    # SEC-161 (CLAUDE.md §16.1): Unconditional credit-note invariant (only DUPLICATE_INVOICE outranks)
    ext_line_totals = tuple(item.line_total.value for item in extraction.line_items)
    is_cn, _, _ = detect_credit_note(
        extraction.header.total_amount.value,
        subtotal=extraction.header.subtotal.value,
        line_totals=ext_line_totals,
    )
    if (
        is_cn
        and _ROUTING_STATUS_PRIORITY["CREDIT_NOTE"] < _ROUTING_STATUS_PRIORITY[result.target_status]
    ):
        return result.model_copy(
            update={
                "target_status": "CREDIT_NOTE",
                "rules_override_applied": True,
                "reason": (
                    "Negative balance detected on extraction payload; "
                    "unconditionally routed to CREDIT_NOTE (CLAUDE.md §16.1)."
                ),
            }
        )

    return result


class ConfidenceRouter:
    """
    Configurable deterministic tri-tier confidence router (P8-1, FR-04).

    Reads default thresholds from ``get_settings()`` unless explicitly overridden at construction.
    """

    def __init__(
        self,
        *,
        high_threshold: Decimal | str | float | int | None = None,
        medium_threshold: Decimal | str | float | int | None = None,
    ) -> None:
        self._explicit_high = high_threshold
        self._explicit_med = medium_threshold
        # Validate eagerly at construction so misconfigured thresholds fail immediately
        _resolve_thresholds(high_threshold=high_threshold, medium_threshold=medium_threshold)

    @property
    def high_threshold(self) -> Decimal:
        """Resolved high-confidence threshold (default 90.00%)."""
        high, _ = _resolve_thresholds(
            high_threshold=self._explicit_high,
            medium_threshold=self._explicit_med,
        )
        return high

    @property
    def medium_threshold(self) -> Decimal:
        """Resolved medium-confidence threshold (default 80.00%)."""
        _, med = _resolve_thresholds(
            high_threshold=self._explicit_high,
            medium_threshold=self._explicit_med,
        )
        return med

    def classify_score(self, score: Decimal | str | float | int) -> ConfidenceTier:
        """Classify a single field confidence percentage into HIGH / MEDIUM / LOW."""
        return classify_confidence_score(
            score,
            high_threshold=self._explicit_high,
            medium_threshold=self._explicit_med,
        )

    def route_scores(
        self,
        field_scores: Mapping[str, Decimal | str | float | int],
        *,
        rules_result: RulesEngineResult | None = None,
        is_revalidation: bool = False,
    ) -> ConfidenceRoutingResult:
        """Route an invoice from a mapping of per-field confidence scores."""
        return route_confidence_scores(
            field_scores,
            rules_result=rules_result,
            is_revalidation=is_revalidation,
            high_threshold=self._explicit_high,
            medium_threshold=self._explicit_med,
        )

    def route_extraction(
        self,
        extraction: InvoiceExtractionSchema,
        *,
        rules_result: RulesEngineResult | None = None,
        is_revalidation: bool = False,
    ) -> ConfidenceRoutingResult:
        """Route a validated ``InvoiceExtractionSchema`` (all 10 header + all line-item fields)."""
        return route_extraction_confidence(
            extraction,
            rules_result=rules_result,
            is_revalidation=is_revalidation,
            high_threshold=self._explicit_high,
            medium_threshold=self._explicit_med,
        )

    def route_revalidation(
        self,
        extraction_or_scores: InvoiceExtractionSchema | Mapping[str, Decimal | str | float | int],
        *,
        rules_result: RulesEngineResult,
    ) -> ConfidenceRoutingResult:
        """
        Re-evaluate invoice status after clerk edits (CLAUDE.md §7.4, LLD §4).

        Preserves original model confidence scores while routing based on ``rules_result``.
        """
        if isinstance(extraction_or_scores, InvoiceExtractionSchema):
            return self.route_extraction(
                extraction_or_scores,
                rules_result=rules_result,
                is_revalidation=True,
            )
        if isinstance(extraction_or_scores, Mapping):
            return self.route_scores(
                extraction_or_scores,
                rules_result=rules_result,
                is_revalidation=True,
            )
        raise ValueError(
            "extraction_or_scores must be an InvoiceExtractionSchema or a field confidence mapping"
        )


__all__ = [
    "AllowedConfidenceStatus",
    "CONFIDENCE_HIGH_THRESHOLD",
    "CONFIDENCE_MEDIUM_THRESHOLD",
    "CONFIDENCE_QUANTUM",
    "ColorLabel",
    "ConfidenceColor",
    "ConfidenceRouter",
    "ConfidenceRoutingResult",
    "ConfidenceTier",
    "FieldConfidenceAssessment",
    "MAX_CONFIDENCE_FIELDS",
    "MAX_FIELD_NAME_CHARS",
    "MIN_ALLOWED_HIGH_THRESHOLD",
    "MIN_ALLOWED_MEDIUM_THRESHOLD",
    "TierStatus",
    "classify_confidence_score",
    "route_confidence_scores",
    "route_extraction_confidence",
    "tier_to_color",
    "tier_to_status",
]
