"""
Unit tests for P8-1 · Confidence Router (src/validation/confidence_router.py).

Tests: FR-04, BR-007, Q-03
Requirements: CLAUDE.md §3, §4.2, §7.1, §7.2, §7.4, §12, §16 Rule 8, §16.1,
BRD §6.3, PRD Journeys 2–4 & §5.2, HLD §5, LLD §4.
Strict offline isolation: zero external network or Azure calls.
"""

import asyncio
import json
import logging
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.core.config import get_settings
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.confidence_router import (
    CONFIDENCE_HIGH_THRESHOLD,
    CONFIDENCE_MEDIUM_THRESHOLD,
    MAX_CONFIDENCE_FIELDS,
    ConfidenceColor,
    ConfidenceRouter,
    ConfidenceRoutingResult,
    ConfidenceTier,
    FieldConfidenceAssessment,
    classify_confidence_score,
    route_confidence_scores,
    route_extraction_confidence,
    tier_to_color,
    tier_to_status,
)
from src.validation.rules_engine import (
    RuleCheckOutcome,
    RuleName,
    RulesEngine,
    RulesEngineResult,
    VendorRuleContext,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")
VENDOR_MASTER_PATH = Path("./sample_data/vendor_master.json")


def _load_gt_schema(
    invoice_number: str,
    *,
    default_confidence: Decimal = Decimal("100.00"),
) -> InvoiceExtractionSchema:
    gt = json.loads(
        (GROUND_TRUTH_DIR / f"{invoice_number}_ground_truth.json").read_text(encoding="utf-8")
    )
    return InvoiceExtractionSchema.from_ground_truth_dict(gt, default_confidence=default_confidence)


def _load_vendor_contexts() -> dict[str, VendorRuleContext]:
    vendors = json.loads(VENDOR_MASTER_PATH.read_text(encoding="utf-8"))
    return {v["TaxID_VAT"]: VendorRuleContext.from_vendor(v) for v in vendors}


def _schema_with_field_confidence(
    invoice_number: str,
    *,
    header_overrides: dict[str, Decimal] | None = None,
    line_overrides: dict[tuple[int, str], Decimal] | None = None,
    default_confidence: Decimal = Decimal("96.00"),
) -> InvoiceExtractionSchema:
    """Build a valid InvoiceExtractionSchema with targeted per-field confidence overrides."""
    base = _load_gt_schema(invoice_number, default_confidence=default_confidence)
    payload = base.model_dump(mode="python")
    if header_overrides:
        for field_name, score in header_overrides.items():
            payload["header"][field_name]["confidence"] = score
    if line_overrides:
        for (idx, field_name), score in line_overrides.items():
            payload["line_items"][idx][field_name]["confidence"] = score
    return InvoiceExtractionSchema.model_validate(payload)


def _make_rules_result(
    *,
    all_passed: bool,
    recommended_status: str | None = None,
    failed_rule: RuleName = RuleName.INVOICE_TOTAL,
    error_msg: str = "Rule violation",
) -> RulesEngineResult:
    """Construct an immutable RulesEngineResult fixture for precedence testing."""
    outcomes = []
    for rn in RuleName:
        if not all_passed and rn == failed_rule:
            outcomes.append(
                RuleCheckOutcome(
                    rule=rn,
                    passed=False,
                    errors=(error_msg,),
                    recommended_status=recommended_status,  # type: ignore[arg-type]
                )
            )
        else:
            outcomes.append(RuleCheckOutcome(rule=rn, passed=True))
    return RulesEngineResult(
        all_passed=all_passed,
        rule_outcomes=tuple(outcomes),
        failed_rules=() if all_passed else (failed_rule,),
        errors=() if all_passed else (error_msg,),
        recommended_status=recommended_status,  # type: ignore[arg-type]
        duplicate_passed=all_passed or failed_rule != RuleName.DUPLICATE_CHECK,
        line_arithmetic_valid=all_passed or failed_rule != RuleName.LINE_ARITHMETIC,
        invoice_total_valid=all_passed or failed_rule != RuleName.INVOICE_TOTAL,
        tax_valid=all_passed or failed_rule != RuleName.TAX_VALIDATION,
        date_valid=all_passed or failed_rule != RuleName.DATE_NORMALIZATION,
    )


# ---------------------------------------------------------------------------
# 1. FR-04 / BR-007 Tri-Tier Thresholds, Exact Boundaries & Sub-Cent Precision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected_tier", "expected_status", "expected_hex", "expected_label"),
    [
        # High confidence tier: >= 90.00%
        (Decimal("100.00"), ConfidenceTier.HIGH, "VALIDATED", "#22c55e", "green"),
        (Decimal("95.50"), ConfidenceTier.HIGH, "VALIDATED", "#22c55e", "green"),
        (Decimal("90.00"), ConfidenceTier.HIGH, "VALIDATED", "#22c55e", "green"),
        ("90", ConfidenceTier.HIGH, "VALIDATED", "#22c55e", "green"),
        (90, ConfidenceTier.HIGH, "VALIDATED", "#22c55e", "green"),
        # Medium confidence tier: 80.00% <= score < 90.00% (no gap between 89 and 90; no round-up)
        (Decimal("89.999"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        (Decimal("89.995"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        (Decimal("89.99"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        (Decimal("89.50"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        (Decimal("85.00"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        (Decimal("80.00"), ConfidenceTier.MEDIUM, "REQUIRES_REVIEW", "#fef08a", "light_yellow"),
        # Low confidence tier: < 80.00% (no round-up; no silent 0-1 -> 0-100 rescaling)
        (Decimal("79.999"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
        (Decimal("79.995"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
        (Decimal("79.99"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
        (Decimal("50.00"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
        (Decimal("0.95"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
        (Decimal("0.00"), ConfidenceTier.LOW, "REQUIRES_APPROVAL", "#ef4444", "amber_red"),
    ],
)
def test_classify_confidence_score_tri_tier_boundaries(
    score: Decimal | str | int,
    expected_tier: ConfidenceTier,
    expected_status: str,
    expected_hex: str,
    expected_label: str,
) -> None:
    """Tests: FR-04 — Exact tri-tier boundaries, UI colour mapping, and zero sub-cent round-up."""
    tier = classify_confidence_score(score)
    assert tier == expected_tier
    assert tier_to_status(tier) == expected_status
    color_hex, color_label = tier_to_color(tier)
    assert color_hex == expected_hex
    assert color_label == expected_label


def test_confidence_constants_match_claude_md_spec() -> None:
    """Tests: FR-04 — Canonical thresholds and hex colour tokens match CLAUDE.md §3 & §12."""
    assert CONFIDENCE_HIGH_THRESHOLD == Decimal("90.00")
    assert CONFIDENCE_MEDIUM_THRESHOLD == Decimal("80.00")
    assert ConfidenceColor.GREEN == "#22c55e"
    assert ConfidenceColor.LIGHT_YELLOW == "#fef08a"
    assert ConfidenceColor.AMBER_RED == "#ef4444"


# ---------------------------------------------------------------------------
# 2. Worst-Field-Wins Aggregation Across Header & Line-Item Fields (PRD J2-J4)
# ---------------------------------------------------------------------------


def test_route_confidence_scores_worst_field_wins_over_high_macro_average() -> None:
    """Tests: FR-04 — Single low or medium field governs status even when macro-avg >= 95%."""
    # All fields >= 90% -> VALIDATED
    all_high = {
        "header.vendor_name": Decimal("98.00"),
        "header.vendor_tax_id": Decimal("99.00"),
        "header.invoice_number": Decimal("97.00"),
        "header.invoice_date": Decimal("92.00"),
        "header.total_amount": Decimal("90.00"),
        "line_items[0].unit_price": Decimal("95.00"),
    }
    res_high = route_confidence_scores(all_high)
    assert isinstance(res_high, ConfidenceRoutingResult)
    assert res_high.target_status == "VALIDATED"
    assert res_high.confidence_tier == ConfidenceTier.HIGH
    assert res_high.confidence_status == "VALIDATED"
    assert res_high.min_confidence == Decimal("90.00")
    assert res_high.low_confidence_fields == ()
    assert res_high.review_confidence_fields == ()
    assert res_high.color_hex == "#22c55e"
    assert res_high.evaluated_field_count == 6
    assert res_high.rules_override_applied is False

    # 9 fields >= 98%, 1 field at 84.50% (macro-avg > 96%) -> REQUIRES_REVIEW (PRD Journey 3)
    one_medium = dict(all_high)
    one_medium["line_items[0].unit_price"] = Decimal("84.50")
    res_med = route_confidence_scores(one_medium)
    assert res_med.macro_avg_confidence >= Decimal("90.00")
    assert res_med.target_status == "REQUIRES_REVIEW"
    assert res_med.confidence_tier == ConfidenceTier.MEDIUM
    assert res_med.min_confidence == Decimal("84.50")
    assert res_med.review_confidence_fields == ("line_items[0].unit_price",)
    assert res_med.low_confidence_fields == ()
    assert res_med.color_hex == "#fef08a"

    # 9 fields >= 98%, 1 field at 74.00% (macro-avg > 92%) -> REQUIRES_APPROVAL (PRD Journey 4)
    one_low = dict(one_medium)
    one_low["header.total_amount"] = Decimal("74.00")
    res_low = route_confidence_scores(one_low)
    assert res_low.macro_avg_confidence >= Decimal("90.00")
    assert res_low.target_status == "REQUIRES_APPROVAL"
    assert res_low.confidence_tier == ConfidenceTier.LOW
    assert res_low.min_confidence == Decimal("74.00")
    assert res_low.low_confidence_fields == ("header.total_amount",)
    assert res_low.review_confidence_fields == ("line_items[0].unit_price",)
    assert res_low.color_hex == "#ef4444"

    # Critical field flag correctly marks the 4 BR-006 critical fields
    by_name = {a.field_name: a for a in res_low.field_assessments}
    assert by_name["header.total_amount"].is_critical is True
    assert by_name["header.vendor_tax_id"].is_critical is True
    assert by_name["header.vendor_name"].is_critical is False
    assert by_name["line_items[0].unit_price"].is_critical is False
    assert res_low.min_critical_confidence == Decimal("74.00")


# ---------------------------------------------------------------------------
# 3. InvoiceExtractionSchema Routing & Rules-First Precedence (CLAUDE.md §7.2)
# ---------------------------------------------------------------------------


def test_route_extraction_confidence_header_and_line_item_fields() -> None:
    """Tests: FR-04 — Routes InvoiceExtractionSchema inspecting all 10 header + all line fields."""
    # Single line-item field in 80-89% range triggers REQUIRES_REVIEW
    schema_review = _schema_with_field_confidence(
        "INV-2026-1001",
        line_overrides={(0, "quantity"): Decimal("82.50")},
        default_confidence=Decimal("98.00"),
    )
    res_review = route_extraction_confidence(schema_review)
    assert res_review.target_status == "REQUIRES_REVIEW"
    assert res_review.min_confidence == Decimal("82.50")
    assert res_review.header_macro_avg_confidence == Decimal("98.00")
    assert res_review.min_critical_confidence == Decimal("98.00")
    assert res_review.review_confidence_fields == ("line_items[0].quantity",)

    # Single header field < 80% triggers REQUIRES_APPROVAL
    schema_low = _schema_with_field_confidence(
        "INV-2026-1001",
        header_overrides={"invoice_date": Decimal("78.00")},
        default_confidence=Decimal("98.00"),
    )
    res_low = route_extraction_confidence(schema_low)
    assert res_low.target_status == "REQUIRES_APPROVAL"
    assert res_low.min_confidence == Decimal("78.00")
    assert res_low.min_critical_confidence == Decimal("78.00")
    assert res_low.low_confidence_fields == ("header.invoice_date",)


@pytest.mark.parametrize(
    ("rule_status", "failed_rule", "confidence", "expected_status", "expected_override"),
    [
        # High confidence (99%) MUST still defer to failing deterministic rules (Rules-First!)
        (
            "DUPLICATE_INVOICE",
            RuleName.DUPLICATE_CHECK,
            Decimal("99.00"),
            "DUPLICATE_INVOICE",
            True,
        ),
        ("CREDIT_NOTE", RuleName.DUPLICATE_CHECK, Decimal("99.00"), "CREDIT_NOTE", True),
        (
            "FLAGGED_POTENTIAL_REVISION",
            RuleName.DUPLICATE_CHECK,
            Decimal("99.00"),
            "FLAGGED_POTENTIAL_REVISION",
            True,
        ),
        (
            "REJECTED_TAX_MISMATCH",
            RuleName.TAX_VALIDATION,
            Decimal("99.00"),
            "REJECTED_TAX_MISMATCH",
            True,
        ),
        ("REQUIRES_APPROVAL", RuleName.INVOICE_TOTAL, Decimal("99.00"), "REQUIRES_APPROVAL", True),
        ("REQUIRES_REVIEW", RuleName.DATE_NORMALIZATION, Decimal("99.00"), "REQUIRES_REVIEW", True),
        # Stricter low confidence (<80% -> REQUIRES_APPROVAL) overrides softer REQUIRES_REVIEW rule
        (
            "REQUIRES_REVIEW",
            RuleName.DATE_NORMALIZATION,
            Decimal("72.00"),
            "REQUIRES_APPROVAL",
            False,
        ),
        # Higher-precedence tax/duplicate rules still override low confidence REQUIRES_APPROVAL
        (
            "REJECTED_TAX_MISMATCH",
            RuleName.TAX_VALIDATION,
            Decimal("65.00"),
            "REJECTED_TAX_MISMATCH",
            True,
        ),
        (
            "DUPLICATE_INVOICE",
            RuleName.DUPLICATE_CHECK,
            Decimal("65.00"),
            "DUPLICATE_INVOICE",
            True,
        ),
    ],
)
def test_rules_first_precedence_with_confidence_tiers(
    rule_status: str,
    failed_rule: RuleName,
    confidence: Decimal,
    expected_status: str,
    expected_override: bool,
) -> None:
    """Tests: FR-04 & CLAUDE.md §7.2 — Strictest status wins between RulesEngine and Confidence."""
    schema = _load_gt_schema("INV-2026-1001", default_confidence=confidence)
    rules_res = _make_rules_result(
        all_passed=False,
        recommended_status=rule_status,
        failed_rule=failed_rule,
    )
    router = ConfidenceRouter()
    result = router.route_extraction(schema, rules_result=rules_res)
    assert result.target_status == expected_status
    assert result.rules_override_applied is expected_override


def test_rules_engine_plus_confidence_router_across_all_300_ground_truth_invoices() -> None:
    """Tests: FR-04 & AC-005 — End-to-end RulesEngine + ConfidenceRouter across all 300 GT files."""
    contexts = _load_vendor_contexts()
    engine = RulesEngine(repository=None)
    router = ConfidenceRouter()
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    non_validated: dict[str, str] = {}

    async def _run() -> None:
        for path in gt_files:
            gt = json.loads(path.read_text(encoding="utf-8"))
            schema = InvoiceExtractionSchema.from_ground_truth_dict(
                gt, default_confidence=Decimal("97.50")
            )
            vctx = contexts[schema.header.vendor_tax_id.value]
            rules_res = await engine.validate_extraction(schema, vendor_context=vctx)
            routing = router.route_extraction(schema, rules_result=rules_res)
            if routing.target_status != "VALIDATED":
                non_validated[schema.header.invoice_number.value] = routing.target_status

    asyncio.run(_run())

    assert non_validated == {
        "INV-2026-1002-REV": "FLAGGED_POTENTIAL_REVISION",
        "INV-2026-1005": "REQUIRES_REVIEW",
        "INV-2026-1010": "REJECTED_TAX_MISMATCH",
        "INV-2026-1025": "CREDIT_NOTE",
    }


# ---------------------------------------------------------------------------
# 4. Clerk Re-Validation Semantics (CLAUDE.md §7.4, LLD §4, §16.1)
# ---------------------------------------------------------------------------


def test_revalidation_preserves_model_confidence_and_transitions_per_lld_fsm() -> None:
    """Tests: FR-04 & CLAUDE.md §7.4 — Re-validation promotes passing edits to VALIDATED without altering model scores."""
    router = ConfidenceRouter()
    # Original OCR confidence was 68% (immutable!)
    low_conf_schema = _load_gt_schema("INV-2026-1001", default_confidence=Decimal("68.00"))

    # Case 1: Clerk fixed values and all deterministic rules now pass -> VALIDATED
    passing_rules = _make_rules_result(all_passed=True)
    res_pass = router.route_revalidation(low_conf_schema, rules_result=passing_rules)
    assert res_pass.target_status == "VALIDATED"
    assert res_pass.is_revalidation is True
    assert res_pass.rules_override_applied is True
    # Model confidence scores remain untouched (CLAUDE.md §7.4 step 4)
    assert res_pass.min_confidence == Decimal("68.00")
    assert res_pass.confidence_tier == ConfidenceTier.LOW
    assert res_pass.confidence_status == "REQUIRES_APPROVAL"

    # Case 2: Rules still fail on re-validation -> REQUIRES_APPROVAL (even at 99% confidence)
    high_conf_schema = _load_gt_schema("INV-2026-1001", default_confidence=Decimal("99.00"))
    failing_tax = _make_rules_result(
        all_passed=False,
        recommended_status="REJECTED_TAX_MISMATCH",
        failed_rule=RuleName.TAX_VALIDATION,
    )
    res_fail = router.route_revalidation(high_conf_schema, rules_result=failing_tax)
    assert res_fail.target_status == "REQUIRES_APPROVAL"
    assert res_fail.is_revalidation is True
    assert res_fail.rules_override_applied is True

    # Case 3: Negative-balance edit triggers CREDIT_NOTE (CLAUDE.md §16.1 non-negotiable)
    failing_cn = _make_rules_result(
        all_passed=False,
        recommended_status="CREDIT_NOTE",
        failed_rule=RuleName.DUPLICATE_CHECK,
    )
    res_cn = router.route_revalidation(high_conf_schema, rules_result=failing_cn)
    assert res_cn.target_status == "CREDIT_NOTE"
    assert res_cn.is_revalidation is True

    # Case 4: Re-validation without a RulesEngineResult must fail closed
    with pytest.raises(ValueError, match="rules_result"):
        route_extraction_confidence(low_conf_schema, rules_result=None, is_revalidation=True)


# ---------------------------------------------------------------------------
# 5. Config-Driven Thresholds (CLAUDE.md §16 Rule 8)
# ---------------------------------------------------------------------------


def test_confidence_thresholds_driven_by_settings_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests: FR-04 & CLAUDE.md §16 Rule 8 — Thresholds load from get_settings() and reject invalid configs."""
    monkeypatch.setenv("CONFIDENCE_HIGH_THRESHOLD", "95.0")
    monkeypatch.setenv("CONFIDENCE_MEDIUM_THRESHOLD", "85.0")
    get_settings.cache_clear()
    try:
        # 92% is HIGH under defaults (90/80) but MEDIUM under env override (95/85)
        assert classify_confidence_score(Decimal("92.00")) == ConfidenceTier.MEDIUM
        assert classify_confidence_score(Decimal("95.00")) == ConfidenceTier.HIGH
        assert classify_confidence_score(Decimal("84.99")) == ConfidenceTier.LOW

        res = route_confidence_scores({"header.total_amount": Decimal("92.00")})
        assert res.target_status == "REQUIRES_REVIEW"
    finally:
        monkeypatch.delenv("CONFIDENCE_HIGH_THRESHOLD", raising=False)
        monkeypatch.delenv("CONFIDENCE_MEDIUM_THRESHOLD", raising=False)
        get_settings.cache_clear()

    # Invalid threshold orderings or bounds fail closed
    for bad_high, bad_med in [
        (Decimal("80.00"), Decimal("80.00")),  # equal
        (Decimal("75.00"), Decimal("80.00")),  # inverted
        (Decimal("101.00"), Decimal("80.00")),  # > 100
        (Decimal("90.00"), Decimal("0.00")),  # medium <= 0
        (Decimal("90.00"), Decimal("-5.00")),  # negative
        (True, Decimal("80.00")),  # bool
        (Decimal("NaN"), Decimal("80.00")),  # NaN
    ]:
        with pytest.raises(ValueError):
            ConfidenceRouter(high_threshold=bad_high, medium_threshold=bad_med)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 6. Security, Immutability, Tampering, DoS & Layering Hardening
# ---------------------------------------------------------------------------


def test_security_hardening_rejects_malicious_scores_names_and_tampering(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tests: FR-04 Security — Blocks NaN/Inf/bool/non-ASCII/exponent-bombs/DoS/tampering/PII leaks."""
    # Malicious numeric inputs (CWE-20 / CWE-190 / CWE-400 / CWE-436)
    bad_scores = [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-0.01"),
        Decimal("100.01"),
        "1E-5000000",
        "9_5.00",
        "٩٥.٠٠",  # Arabic-Indic digits
        "95.00\n",
        "",
        None,
    ]
    for bad in bad_scores:
        with pytest.raises(ValueError):
            classify_confidence_score(bad)  # type: ignore[arg-type]

    # Empty map & oversized field map DoS guard (CWE-400)
    with pytest.raises(ValueError, match="non-empty"):
        route_confidence_scores({})

    oversized = {f"f_{i}": Decimal("95.00") for i in range(MAX_CONFIDENCE_FIELDS + 1)}
    with pytest.raises(ValueError, match="maximum"):
        route_confidence_scores(oversized)

    # Disallowed control chars / bidi chars / empty field names (CWE-117 / CWE-451)
    for bad_name in ["", "   ", "header.total\ninjected", "header.\u202etotal", "x" * 129]:
        with pytest.raises(ValueError):
            route_confidence_scores({bad_name: Decimal("95.00")})

    # Strict bool on is_revalidation (string "false" must NOT coerce to True: CWE-704)
    passing_rules = _make_rules_result(all_passed=True)
    with pytest.raises(ValueError, match="boolean"):
        route_confidence_scores(
            {"header.total_amount": Decimal("70.00")},
            rules_result=passing_rules,
            is_revalidation="false",  # type: ignore[arg-type]
        )

    # Fail-closed on tampered RulesEngineResult(all_passed=False, recommended_status=None)
    tampered_rules = _make_rules_result(all_passed=False, recommended_status=None)
    res_tampered = route_confidence_scores(
        {"header.total_amount": Decimal("99.00")},
        rules_result=tampered_rules,
    )
    assert res_tampered.target_status == "REQUIRES_APPROVAL"
    assert res_tampered.rules_override_applied is True

    # Non-approval allowlist + frozen immutability + extra="forbid" (CWE-863 / CWE-915)
    for forbidden_status in (
        "APPROVED_CLERK",
        "APPROVED_MANAGER",
        "STAGED_FOR_EXPORT",
        "REQUIRES_MANAGER_APPROVAL",
    ):
        with pytest.raises(ValidationError):
            ConfidenceRoutingResult(
                target_status=forbidden_status,  # type: ignore[arg-type]
                confidence_tier=ConfidenceTier.HIGH,
                confidence_status="VALIDATED",
                min_confidence=Decimal("95.00"),
                macro_avg_confidence=Decimal("95.00"),
                color_hex="#22c55e",
                color_label="green",
                evaluated_field_count=1,
                low_confidence_fields=(),
                review_confidence_fields=(),
                field_assessments=(
                    FieldConfidenceAssessment(
                        field_name="header.total_amount",
                        score=Decimal("95.00"),
                        tier=ConfidenceTier.HIGH,
                        color_hex="#22c55e",
                        color_label="green",
                        is_critical=True,
                    ),
                ),
                reason="test",
            )

    clean_res = route_confidence_scores({"header.total_amount": Decimal("95.00")})
    with pytest.raises(ValidationError):
        clean_res.target_status = "APPROVED_CLERK"  # type: ignore[misc]

    # Zero PII in logs (CWE-532)
    schema = _load_gt_schema("INV-2026-1001", default_confidence=Decimal("95.00"))
    with caplog.at_level(logging.INFO, logger="ap.validation.confidence_router"):
        route_extraction_confidence(schema)
    log_blob = " ".join(record.getMessage() for record in caplog.records)
    assert schema.header.vendor_tax_id.value not in log_blob
    assert schema.header.vendor_name.value not in log_blob


def test_confidence_router_layering_invariant_zero_llm_or_sqlalchemy_imports() -> None:
    """Tests: CLAUDE.md §4.2 & §7.2 — src/validation/confidence_router.py never imports LLMs or SQLAlchemy."""
    src = Path("src/validation/confidence_router.py").read_text(encoding="utf-8")
    forbidden_tokens = [
        "import openai",
        "from openai",
        "model_gateway",
        "extract_engine",
        "sqlalchemy",
        "AsyncSession",
    ]
    for token in forbidden_tokens:
        assert token not in src, f"Layering violation: found forbidden token '{token}'"


# ---------------------------------------------------------------------------
# 7. Penetration Tests for Security Audit Findings (SEC-161 .. SEC-164)
# ---------------------------------------------------------------------------


def test_pentest_sec161_credit_note_never_validated_even_without_rules_result() -> None:
    """Tests: SEC-161 (CWE-840, CLAUDE.md §16.1) — Credit notes route to CREDIT_NOTE unconditionally."""
    credit_note = _load_gt_schema("INV-2026-1025", default_confidence=Decimal("100.00"))

    # Direct extraction routing with rules_result=None cannot classify credit note as VALIDATED
    direct_res = route_extraction_confidence(credit_note, rules_result=None)
    assert direct_res.target_status == "CREDIT_NOTE"
    assert direct_res.rules_override_applied is True

    # Even a miswired re-validation with a passing RulesEngineResult cannot promote credit note
    passing_rules = _make_rules_result(all_passed=True)
    reval_res = ConfidenceRouter().route_revalidation(credit_note, rules_result=passing_rules)
    assert reval_res.target_status == "CREDIT_NOTE"
    assert reval_res.rules_override_applied is True

    # Higher-precedence DUPLICATE_INVOICE still outranks CREDIT_NOTE
    dup_rules = _make_rules_result(
        all_passed=False,
        recommended_status="DUPLICATE_INVOICE",
        failed_rule=RuleName.DUPLICATE_CHECK,
    )
    dup_res = route_extraction_confidence(credit_note, rules_result=dup_rules)
    assert dup_res.target_status == "DUPLICATE_INVOICE"


def test_pentest_sec162_fraction_scale_threshold_misconfiguration_rejected() -> None:
    """Tests: SEC-162 (CWE-1188, CWE-636) — 0.90/0.80 fraction-scale threshold typos fail closed."""
    for bad_high, bad_med in [
        (Decimal("0.90"), Decimal("0.80")),  # classic 0-1 scale typo
        (Decimal("59.99"), Decimal("50.00")),  # below high floor (60%)
        (Decimal("90.00"), Decimal("49.99")),  # below medium floor (50%)
        (Decimal("10.00"), Decimal("5.00")),
    ]:
        with pytest.raises(ValueError):
            ConfidenceRouter(high_threshold=bad_high, medium_threshold=bad_med)


def test_pentest_sec163_canonical_key_aliasing_and_case_variant_evasion_blocked() -> None:
    """Tests: SEC-163 (CWE-840, CWE-20) — Duplicate bare/header aliases rejected & case-insensitive critical detection."""
    # Duplicate alias ("total_amount" + "header.total_amount") cannot inflate macro-avg
    with pytest.raises(ValueError, match="Duplicate canonical field name"):
        route_confidence_scores(
            {
                "total_amount": Decimal("99.00"),
                "header.total_amount": Decimal("99.00"),
            }
        )

    # Case-variant duplicate ("header.Total_Amount" + "header.total_amount") rejected
    with pytest.raises(ValueError, match="Duplicate canonical field name"):
        route_confidence_scores(
            {
                "header.Total_Amount": Decimal("99.00"),
                "header.total_amount": Decimal("75.00"),
            }
        )

    # Mixed-case critical field cannot evade is_critical or min_critical_confidence
    res = route_confidence_scores(
        {
            "header.Total_Amount": Decimal("72.00"),
            "header.Vendor_Name": Decimal("98.00"),
        }
    )
    by_name = {a.field_name: a for a in res.field_assessments}
    assert by_name["header.Total_Amount"].is_critical is True
    assert res.min_critical_confidence == Decimal("72.00")
    assert res.header_macro_avg_confidence == Decimal("85.00")


def test_pentest_sec164_contradictory_rules_engine_result_rejected_fail_closed() -> None:
    """Tests: SEC-164 (CWE-345, CWE-863) — Forged RulesEngineResult(all_passed=True) with failing state fails closed."""
    # Contradictory: all_passed=True yet tax_valid=False and errors non-empty
    forged_rules = RulesEngineResult(
        all_passed=True,
        rule_outcomes=tuple(RuleCheckOutcome(rule=rn, passed=True) for rn in RuleName),
        failed_rules=(),
        errors=("Tax mismatch hidden behind all_passed=True",),
        recommended_status=None,
        duplicate_passed=True,
        line_arithmetic_valid=True,
        invoice_total_valid=True,
        tax_valid=False,
        date_valid=True,
    )
    with pytest.raises(ValueError, match="Inconsistent RulesEngineResult"):
        route_confidence_scores(
            {"header.total_amount": Decimal("99.00")},
            rules_result=forged_rules,
            is_revalidation=True,
        )

    # Contradictory: all_passed=True yet recommended_status="REJECTED_TAX_MISMATCH"
    forged_status = RulesEngineResult(
        all_passed=True,
        rule_outcomes=tuple(RuleCheckOutcome(rule=rn, passed=True) for rn in RuleName),
        failed_rules=(),
        errors=(),
        recommended_status="REJECTED_TAX_MISMATCH",
        duplicate_passed=True,
        line_arithmetic_valid=True,
        invoice_total_valid=True,
        tax_valid=True,
        date_valid=True,
    )
    with pytest.raises(ValueError, match="Inconsistent RulesEngineResult"):
        route_confidence_scores(
            {"header.total_amount": Decimal("99.00")},
            rules_result=forged_status,
        )
