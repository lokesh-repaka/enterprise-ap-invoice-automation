"""
Unit & SQLite Integration tests for P8-3 · High-Value & PO-Variance Escalation Rules
(src/validation/escalation_rules.py).

Tests: FR-13, BR-012a, BR-014, BR-015, BR-018
Requirements: CLAUDE.md §2, §3, §4.2, §6, §7.2, §11.1, §16 Rule 8, §16.1, LLD §4, PRD Journey 7.
Strict offline isolation: zero external network or Azure calls (in-memory SQLite + pure rules).
"""

import asyncio
import json
import logging
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from src.core.config import Settings, get_settings
from src.database.models import Base, ExchangeRate
from src.database.repositories import ExchangeRateRepository
from src.database.session import create_db_engine, create_session_factory
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.confidence_router import ConfidenceRouter
from src.validation.escalation_rules import (
    EscalationEvaluator,
    EscalationReason,
    EscalationResult,
    MissingExchangeRateError,
    compute_po_variance_percent,
    evaluate_escalation,
    evaluate_extraction_escalation,
)
from src.validation.rules_engine import RulesEngine, VendorRuleContext

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")
VENDOR_MASTER_PATH = Path("./sample_data/vendor_master.json")
EXCHANGE_RATES_PATH = Path("./sample_data/exchange_rates.json")


async def _setup_fx_db() -> tuple[Any, Any]:
    """Create isolated in-memory SQLite DB seeded with sample_data/exchange_rates.json + 2026-01-01 baseline."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    raw_rates = json.loads(EXCHANGE_RATES_PATH.read_text(encoding="utf-8"))
    async with session_factory() as session:
        repo = ExchangeRateRepository(session)
        for entry in raw_rates:
            rate_dt = date.fromisoformat(entry["RateDate"])
            from_ccy = str(entry["FromCurrency"]).strip().upper()
            to_ccy = str(entry["ToCurrency"]).strip().upper()
            ex_rate = Decimal(str(entry["ExchangeRate"]))
            await repo.create(
                ExchangeRate(
                    rate_date=rate_dt,
                    from_currency=from_ccy,
                    to_currency=to_ccy,
                    exchange_rate=ex_rate,
                )
            )
            # Also seed an earlier 2026-01-01 rate for Jan 2026 pilot invoices
            if rate_dt > date(2026, 1, 1):
                await repo.create(
                    ExchangeRate(
                        rate_date=date(2026, 1, 1),
                        from_currency=from_ccy,
                        to_currency=to_ccy,
                        exchange_rate=ex_rate,
                    )
                )
    return engine, session_factory


def _load_vendor_contexts() -> dict[str, VendorRuleContext]:
    vendors = json.loads(VENDOR_MASTER_PATH.read_text(encoding="utf-8"))
    return {v["TaxID_VAT"]: VendorRuleContext.from_vendor(v) for v in vendors}


# ---------------------------------------------------------------------------
# 1. High-Value Threshold Boundaries (>$10,000 USD -> REQUIRES_MANAGER_APPROVAL)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("total_amount", "expected_escalated", "expected_status", "expected_clerk_eligible"),
    [
        (Decimal("0.00"), False, "VALIDATED", True),
        (Decimal("9999.99"), False, "VALIDATED", True),
        (Decimal("10000.00"), False, "VALIDATED", True),  # Exact $10k stays clerk-eligible (<=)
        (Decimal("10000.001"), True, "REQUIRES_MANAGER_APPROVAL", False),  # Sub-cent overrun!
        (Decimal("10000.01"), True, "REQUIRES_MANAGER_APPROVAL", False),
        (Decimal("14500.00"), True, "REQUIRES_MANAGER_APPROVAL", False),  # PRD Journey 7
        (Decimal("250000.00"), True, "REQUIRES_MANAGER_APPROVAL", False),
    ],
)
def test_high_value_threshold_exact_and_sub_cent_boundaries(
    total_amount: Decimal,
    expected_escalated: bool,
    expected_status: str,
    expected_clerk_eligible: bool,
) -> None:
    """Tests: FR-13, BR-014, BR-015 — Strict >$10,000 USD boundary with zero sub-cent rounding down."""
    res = evaluate_escalation(total_amount=total_amount, currency="USD")
    assert isinstance(res, EscalationResult)
    assert res.high_value_exceeded is expected_escalated
    assert res.po_variance_exceeded is False
    assert res.requires_manager_approval is expected_escalated
    assert res.target_status == expected_status
    assert res.eligible_for_clerk_approval is expected_clerk_eligible
    if expected_escalated:
        assert res.escalation_reasons == (EscalationReason.HIGH_VALUE,)
    else:
        assert res.escalation_reasons == ()


# ---------------------------------------------------------------------------
# 2. PO-Variance Tolerance Boundaries (>5% -> REQUIRES_MANAGER_APPROVAL)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("invoice_total", "po_amount", "expected_escalated", "expected_pct"),
    [
        (Decimal("1000.00"), Decimal("1000.00"), False, Decimal("0.00")),
        (Decimal("1050.00"), Decimal("1000.00"), False, Decimal("5.00")),  # Exact +5% (<=)
        (Decimal("950.00"), Decimal("1000.00"), False, Decimal("5.00")),  # Exact -5% (<=)
        (
            Decimal("1050.01"),
            Decimal("1000.00"),
            True,
            Decimal("5.00"),
        ),  # 5.001% > 5% (no round-down!)
        (Decimal("1050.10"), Decimal("1000.00"), True, Decimal("5.01")),
        (
            Decimal("949.90"),
            Decimal("1000.00"),
            True,
            Decimal("5.01"),
        ),  # Downward >5% also escalates
        (Decimal("5360.00"), Decimal("5000.00"), True, Decimal("7.20")),  # PRD Journey 7
        (Decimal("0.00"), Decimal("0.00"), False, Decimal("0.00")),  # Both zero -> 0%
        (
            Decimal("100.00"),
            Decimal("0.00"),
            True,
            Decimal("100.00"),
        ),  # Non-zero vs $0 PO -> escalate!
    ],
)
def test_po_variance_exact_and_edge_boundaries(
    invoice_total: Decimal,
    po_amount: Decimal,
    expected_escalated: bool,
    expected_pct: Decimal,
) -> None:
    """Tests: FR-13, BR-014 — Strict >5% PO variance (both upward/downward, sub-cent & $0 PO)."""
    res = evaluate_escalation(
        total_amount=invoice_total,
        currency="USD",
        po_amount=po_amount,
    )
    assert res.po_variance_exceeded is expected_escalated
    assert res.requires_manager_approval is expected_escalated
    assert res.po_variance_percent == expected_pct
    assert res.target_status == ("REQUIRES_MANAGER_APPROVAL" if expected_escalated else "VALIDATED")
    if expected_escalated:
        assert EscalationReason.PO_VARIANCE in res.escalation_reasons
    else:
        assert res.escalation_reasons == ()


def test_combined_high_value_and_po_variance_and_explicit_variance_percent() -> None:
    """Tests: FR-13, BR-014 — Both triggers reported simultaneously and explicit variance pct works."""
    both = evaluate_escalation(
        total_amount=Decimal("15000.00"),
        currency="USD",
        po_amount=Decimal("12000.00"),  # 25% variance + >$10k
    )
    assert both.high_value_exceeded is True
    assert both.po_variance_exceeded is True
    assert both.requires_manager_approval is True
    assert both.target_status == "REQUIRES_MANAGER_APPROVAL"
    assert both.escalation_reasons == (EscalationReason.HIGH_VALUE, EscalationReason.PO_VARIANCE)

    # Explicit po_variance_percent mode (e.g. from ERP PO match service)
    pct_ok = evaluate_escalation(
        total_amount=Decimal("5000.00"),
        currency="USD",
        po_variance_percent=Decimal("5.00"),
    )
    assert pct_ok.po_variance_exceeded is False
    assert pct_ok.target_status == "VALIDATED"

    pct_high = evaluate_escalation(
        total_amount=Decimal("5000.00"),
        currency="USD",
        po_variance_percent=Decimal("-5.01"),
    )
    assert pct_high.po_variance_exceeded is True
    assert pct_high.target_status == "REQUIRES_MANAGER_APPROVAL"

    # Exact variance helper check
    exact_pct = compute_po_variance_percent(Decimal("1050.01"), Decimal("1000.00"))
    assert exact_pct > Decimal("5.00")


# ---------------------------------------------------------------------------
# 3. ECB Daily Exchange-Rate Normalization on Invoice Date (CLAUDE.md §6, BR-012a)
# ---------------------------------------------------------------------------


def test_foreign_currency_ecb_fx_normalization_on_invoice_date() -> None:
    """Tests: FR-13, BR-012a, CLAUDE.md §6 — Converts EUR/GBP to USD using invoice_date ECB rate."""
    # Direct exchange_rate_to_usd: EUR 9,500 * 1.09 = $10,355 USD > $10,000 -> escalates!
    eur_high = evaluate_escalation(
        total_amount=Decimal("9500.00"),
        currency="EUR",
        exchange_rate_to_usd=Decimal("1.090000"),
    )
    assert eur_high.total_amount_usd == Decimal("10355.00")
    assert eur_high.high_value_exceeded is True
    assert eur_high.target_status == "REQUIRES_MANAGER_APPROVAL"

    # Direct exchange_rate_to_usd: GBP 7,500 * 1.27 = $9,525 USD <= $10,000 -> VALIDATED
    gbp_ok = evaluate_escalation(
        total_amount=Decimal("7500.00"),
        currency="GBP",
        exchange_rate_to_usd=Decimal("1.270000"),
    )
    assert gbp_ok.total_amount_usd == Decimal("9525.00")
    assert gbp_ok.high_value_exceeded is False
    assert gbp_ok.target_status == "VALIDATED"

    # Async repository lookup using seeded sample_data/exchange_rates.json (invoice_date lookup)
    async def _run() -> None:
        engine, session_factory = await _setup_fx_db()
        try:
            async with session_factory() as session:
                fx_repo = ExchangeRateRepository(session)
                evaluator = EscalationEvaluator(exchange_rate_repo=fx_repo)

                # EUR 9,500 on 2026-02-20 -> converts via 2026-02-15 ECB rate (1.085) -> $10,307.50 > $10k
                res_eur = await evaluator.evaluate_with_fx(
                    total_amount=Decimal("9500.00"),
                    currency="EUR",
                    invoice_date=date(2026, 2, 20),
                )
                assert res_eur.total_amount_usd == Decimal("10307.50")
                assert res_eur.high_value_exceeded is True
                assert res_eur.target_status == "REQUIRES_MANAGER_APPROVAL"
                assert res_eur.fx_rate_applied == Decimal("1.085")
                assert res_eur.fx_rate_date == date(2026, 2, 15)

                # Missing rate (date before all seeded ECB dates) fails closed
                with pytest.raises(MissingExchangeRateError):
                    await evaluator.evaluate_with_fx(
                        total_amount=Decimal("5000.00"),
                        currency="GBP",
                        invoice_date=date(2020, 1, 1),
                    )
        finally:
            await engine.dispose()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Config-Driven Thresholds (CLAUDE.md §16 Rule 8)
# ---------------------------------------------------------------------------


def test_escalation_thresholds_loaded_from_settings_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests: P8-3 & CLAUDE.md §16 Rule 8 — All thresholds read from get_settings() with safe bounds."""
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "25000.00")
    monkeypatch.setenv("PO_VARIANCE_TOLERANCE_PERCENT", "2.5")
    get_settings.cache_clear()
    try:
        # $15,000 is now under $25k threshold -> VALIDATED
        res_ok = evaluate_escalation(total_amount=Decimal("15000.00"), currency="USD")
        assert res_ok.high_value_threshold_usd == Decimal("25000.00")
        assert res_ok.po_variance_tolerance_percent == Decimal("2.5")
        assert res_ok.high_value_exceeded is False
        assert res_ok.target_status == "VALIDATED"

        # 3.0% PO variance now exceeds 2.5% tolerance -> REQUIRES_MANAGER_APPROVAL
        res_var = evaluate_escalation(
            total_amount=Decimal("1030.00"),
            currency="USD",
            po_amount=Decimal("1000.00"),
        )
        assert res_var.po_variance_exceeded is True
        assert res_var.target_status == "REQUIRES_MANAGER_APPROVAL"
    finally:
        monkeypatch.delenv("HIGH_VALUE_THRESHOLD_USD", raising=False)
        monkeypatch.delenv("PO_VARIANCE_TOLERANCE_PERCENT", raising=False)
        get_settings.cache_clear()

    # Invalid thresholds fail closed
    for bad_hv in (Decimal("0"), Decimal("-100"), Decimal("NaN"), True, Decimal("999999999999")):
        with pytest.raises(ValueError):
            EscalationEvaluator(high_value_threshold_usd=bad_hv)  # type: ignore[arg-type]

    for bad_po in (Decimal("-0.1"), Decimal("100.01"), Decimal("NaN"), False):
        with pytest.raises(ValueError):
            EscalationEvaluator(po_variance_tolerance_percent=bad_po)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 5. Precedence with Confidence Routing, Rules Engine & 300-Invoice Batch
# ---------------------------------------------------------------------------


def test_exception_status_precedence_and_credit_note_protection() -> None:
    """Tests: LLD §4, BR-018, CLAUDE.md §16.1 — Never masks unresolved exceptions or credit notes."""
    for blocking_status in (
        "DUPLICATE_INVOICE",
        "CREDIT_NOTE",
        "FLAGGED_POTENTIAL_REVISION",
        "REJECTED_TAX_MISMATCH",
        "REQUIRES_APPROVAL",
        "REQUIRES_REVIEW",
    ):
        res = evaluate_escalation(
            total_amount=Decimal("25000.00"),
            currency="USD",
            current_status=blocking_status,
        )
        assert res.target_status == blocking_status
        assert res.high_value_exceeded is True
        assert res.requires_manager_approval is True
        assert res.eligible_for_clerk_approval is False

    # Negative-balance credit note can NEVER route to VALIDATED or clerk-eligible
    cn_res = evaluate_escalation(total_amount=Decimal("-15000.00"), currency="USD")
    assert cn_res.target_status == "CREDIT_NOTE"
    assert cn_res.eligible_for_clerk_approval is False


def test_full_phase7_phase8_pipeline_across_all_300_ground_truth_invoices() -> None:
    """Tests: FR-04..FR-13 & AC-005 — End-to-end RulesEngine + ConfidenceRouter + EscalationEvaluator on 300 GT files."""
    contexts = _load_vendor_contexts()
    rules_engine = RulesEngine(repository=None)
    conf_router = ConfidenceRouter()
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    async def _run() -> dict[str, int]:
        engine, session_factory = await _setup_fx_db()
        counts: dict[str, int] = {}
        try:
            async with session_factory() as session:
                fx_repo = ExchangeRateRepository(session)
                evaluator = EscalationEvaluator(exchange_rate_repo=fx_repo)

                for path in gt_files:
                    gt = json.loads(path.read_text(encoding="utf-8"))
                    schema = InvoiceExtractionSchema.from_ground_truth_dict(
                        gt, default_confidence=Decimal("97.00")
                    )
                    vctx = contexts[schema.header.vendor_tax_id.value]
                    rules_res = await rules_engine.validate_extraction(schema, vendor_context=vctx)
                    conf_res = conf_router.route_extraction(schema, rules_result=rules_res)

                    inv_date = (
                        rules_res.date_result.invoice_date
                        if rules_res.date_result is not None
                        and rules_res.date_result.invoice_date is not None
                        else date(2026, 2, 15)
                    )
                    esc_res = await evaluator.evaluate_extraction_with_fx(
                        schema,
                        invoice_date=inv_date,
                        confidence_result=conf_res,
                    )
                    counts[esc_res.target_status] = counts.get(esc_res.target_status, 0) + 1
        finally:
            await engine.dispose()
        return counts

    status_counts = asyncio.run(_run())
    assert sum(status_counts.values()) == 300
    assert status_counts.get("FLAGGED_POTENTIAL_REVISION") == 1
    assert status_counts.get("REQUIRES_REVIEW") == 1
    assert status_counts.get("REJECTED_TAX_MISMATCH") == 1
    assert status_counts.get("CREDIT_NOTE") == 1
    assert (
        status_counts.get("VALIDATED", 0) + status_counts.get("REQUIRES_MANAGER_APPROVAL", 0) == 296
    )


# ---------------------------------------------------------------------------
# 6. Security, Immutability, Input Hygiene, Zero PII Logs & Layering
# ---------------------------------------------------------------------------


def test_escalation_security_input_validation_immutability_and_clean_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tests: CWE-20, CWE-400, CWE-532, CWE-863, CWE-915 — Strict parsing, frozen non-approval results, clean logs."""
    # Non-USD without FX rate or pre-converted USD fails closed
    with pytest.raises(ValueError, match="exchange_rate_to_usd"):
        evaluate_escalation(total_amount=Decimal("5000.00"), currency="EUR")

    # Malicious numeric inputs rejected
    for bad_val in (True, False, float("nan"), float("inf"), "1E-5000000", "1_000", "١٠٠٠", ""):
        with pytest.raises(ValueError):
            evaluate_escalation(total_amount=bad_val, currency="USD")  # type: ignore[arg-type]

    # Negative PO amount rejected
    with pytest.raises(ValueError, match="po_amount"):
        evaluate_escalation(
            total_amount=Decimal("1000.00"),
            currency="USD",
            po_amount=Decimal("-500.00"),
        )

    # Invalid currency code rejected
    for bad_ccy in ("", "US", "USDD", "U$D", "USD\n"):
        with pytest.raises(ValueError, match="currency"):
            evaluate_escalation(total_amount=Decimal("1000.00"), currency=bad_ccy)

    # Non-approval allowlist & immutability
    for forbidden in ("APPROVED_CLERK", "APPROVED_MANAGER", "STAGED_FOR_EXPORT"):
        with pytest.raises(ValidationError):
            EscalationResult(
                target_status=forbidden,  # type: ignore[arg-type]
                requires_manager_approval=False,
                eligible_for_clerk_approval=True,
                high_value_exceeded=False,
                po_variance_exceeded=False,
                escalation_reasons=(),
                total_amount=Decimal("100.00"),
                currency="USD",
                total_amount_usd=Decimal("100.00"),
                high_value_threshold_usd=Decimal("10000.00"),
                po_variance_tolerance_percent=Decimal("5.0"),
                reason="test",
            )

    with caplog.at_level(logging.INFO, logger="ap.validation.escalation_rules"):
        res = evaluate_escalation(total_amount=Decimal("12500.00"), currency="USD")

    with pytest.raises(ValidationError):
        res.target_status = "APPROVED_CLERK"  # type: ignore[misc]

    # Verify evaluate_extraction_escalation convenience helper works synchronously
    gt = json.loads(
        (GROUND_TRUTH_DIR / "INV-2026-1001_ground_truth.json").read_text(encoding="utf-8")
    )
    schema = InvoiceExtractionSchema.from_ground_truth_dict(gt, default_confidence=Decimal("98.00"))
    ext_res = evaluate_extraction_escalation(schema, exchange_rate_to_usd=Decimal("1.00"))
    assert ext_res.target_status in ("VALIDATED", "REQUIRES_MANAGER_APPROVAL")

    # Zero PII in logs
    log_text = " ".join(r.getMessage() for r in caplog.records)
    assert schema.header.vendor_tax_id.value not in log_text
    assert schema.header.vendor_name.value not in log_text


def test_escalation_rules_layering_invariant_zero_llm_or_sqlalchemy_imports() -> None:
    """Tests: CLAUDE.md §4.2 & §7.2 — src/validation/escalation_rules.py never imports LLMs or SQLAlchemy."""
    src = Path("src/validation/escalation_rules.py").read_text(encoding="utf-8")
    for forbidden in (
        "import openai",
        "from openai",
        "model_gateway",
        "extract_engine",
        "sqlalchemy",
        "AsyncSession",
    ):
        assert forbidden not in src, f"Layering violation: found forbidden token '{forbidden}'"


# ---------------------------------------------------------------------------
# 7. Penetration Tests for Security Audit Findings (SEC-169 .. SEC-172)
# ---------------------------------------------------------------------------


def test_pentest_sec169_spoofed_usd_total_non_unity_fx_and_conflicting_po_rejected() -> None:
    """Tests: SEC-169 (CWE-840, CWE-345) — Blocks spoofed total_amount_usd, non-unity USD rate, and dual PO args."""
    # 1. Spoofed total_amount_usd=$5,000 on $25,000 USD invoice rejected fail-closed
    with pytest.raises(ValueError, match="Conflicting USD totals"):
        evaluate_escalation(
            total_amount=Decimal("25000.00"),
            currency="USD",
            total_amount_usd=Decimal("5000.00"),
        )

    # 2. Non-unity FX rate (0.20) on USD invoice rejected fail-closed
    with pytest.raises(ValueError, match="exchange_rate_to_usd == 1.0"):
        evaluate_escalation(
            total_amount=Decimal("25000.00"),
            currency="USD",
            exchange_rate_to_usd=Decimal("0.20"),
        )

    # 3. Spoofed total_amount_usd contradicting EUR * rate rejected fail-closed
    with pytest.raises(ValueError, match="Conflicting FX conversion"):
        evaluate_escalation(
            total_amount=Decimal("9500.00"),
            currency="EUR",
            exchange_rate_to_usd=Decimal("1.09"),
            total_amount_usd=Decimal("5000.00"),
        )

    # 4. Supplying BOTH po_amount and po_variance_percent rejected fail-closed
    with pytest.raises(ValueError, match="not both"):
        evaluate_escalation(
            total_amount=Decimal("2000.00"),
            currency="USD",
            po_amount=Decimal("1000.00"),
            po_variance_percent=Decimal("1.0"),
        )


def test_pentest_sec170_conflicting_current_status_cannot_overwrite_failing_confidence_result() -> (
    None
):
    """Tests: SEC-170 (CWE-840, CWE-863) — current_status='VALIDATED' cannot override a failing ConfidenceRoutingResult."""
    low_conf_res = ConfidenceRouter().route_scores({"header.total_amount": Decimal("65.00")})
    assert low_conf_res.target_status == "REQUIRES_APPROVAL"

    with pytest.raises(ValueError, match="Conflicting current_status"):
        evaluate_escalation(
            total_amount=Decimal("500.00"),
            currency="USD",
            current_status="VALIDATED",
            confidence_result=low_conf_res,
        )


def test_pentest_sec171_datetime_confusion_and_future_or_malformed_fx_rows_blocked() -> None:
    """Tests: SEC-171 (CWE-20, CWE-704) — Rejects datetime objects, future FX rate_date, and invalid repo rates."""

    class _TamperedFutureFXRepo:
        async def get_latest_rate_on_or_before(
            self, target_date: date, from_currency: str, to_currency: str = "USD"
        ) -> Any:
            return ExchangeRate(
                rate_date=date(2026, 3, 1),  # AFTER invoice_date 2026-02-15!
                from_currency=from_currency,
                to_currency=to_currency,
                exchange_rate=Decimal("1.085"),
            )

    class _TamperedZeroRateFXRepo:
        async def get_latest_rate_on_or_before(
            self, target_date: date, from_currency: str, to_currency: str = "USD"
        ) -> Any:
            return ExchangeRate(
                rate_date=date(2026, 2, 15),
                from_currency=from_currency,
                to_currency=to_currency,
                exchange_rate=Decimal("0.00"),
            )

    # 1. datetime passed instead of pure date fails closed
    with pytest.raises(ValueError, match="strict datetime.date"):
        evaluate_escalation(
            total_amount=Decimal("500.00"),
            currency="USD",
            fx_rate_date=datetime.now(UTC),  # type: ignore[arg-type]
        )

    async def _run() -> None:
        # 2. Future FX rate_date > invoice_date rejected fail-closed
        ev_future = EscalationEvaluator(exchange_rate_repo=_TamperedFutureFXRepo())
        with pytest.raises(ValueError, match="cannot be after invoice_date"):
            await ev_future.evaluate_with_fx(
                total_amount=Decimal("5000.00"),
                currency="EUR",
                invoice_date=date(2026, 2, 15),
            )

        # 3. Non-positive FX rate from repo rejected fail-closed
        ev_zero = EscalationEvaluator(exchange_rate_repo=_TamperedZeroRateFXRepo())
        with pytest.raises(ValueError, match="strictly positive"):
            await ev_zero.evaluate_with_fx(
                total_amount=Decimal("5000.00"),
                currency="EUR",
                invoice_date=date(2026, 2, 15),
            )

    asyncio.run(_run())


def test_pentest_sec172_settings_rejects_negative_or_runaway_escalation_thresholds() -> None:
    """Tests: SEC-172 (CWE-1188, CWE-636) — Settings enforces safe bounds on HIGH_VALUE & PO_VARIANCE thresholds."""
    with pytest.raises(ValidationError):
        Settings(HIGH_VALUE_THRESHOLD_USD=0.0)
    with pytest.raises(ValidationError):
        Settings(HIGH_VALUE_THRESHOLD_USD=-500.0)
    with pytest.raises(ValidationError):
        Settings(HIGH_VALUE_THRESHOLD_USD=999_999_999.0)
    with pytest.raises(ValidationError):
        Settings(PO_VARIANCE_TOLERANCE_PERCENT=-1.0)
    with pytest.raises(ValidationError):
        Settings(PO_VARIANCE_TOLERANCE_PERCENT=150.0)
