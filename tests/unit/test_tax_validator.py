"""
Unit tests for P7-4 · Multi-Country Tax Validator (src/validation/tax_validator.py).

Tests: FR-07
Requirements: BR-011, Q-05, LLD §5.3, PRD Journey 5, CLAUDE.md §4.2, §5, §7.1, §16 Rule 8.
Strict offline isolation: zero external network or Azure calls.
"""

import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.core.config import get_settings
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.tax_validator import (
    COUNTRY_TAX_RATES,
    MAX_LINE_ITEMS,
    TaxLineInput,
    evaluate_tax_rate,
    normalize_country_code,
    validate_extraction_tax,
    validate_tax_rate,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")
VENDOR_MASTER_PATH = Path("./sample_data/vendor_master.json")


# ---------------------------------------------------------------------------
# 1. FR-07: UK (GB/UK), DE, ES Statutory VAT / MwSt / IVA Rate Tables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("country", "subtotal", "tax", "expected_rate"),
    [
        # UK VAT: 20%, 5%, 0% (supports both ISO 'GB' and alias 'UK')
        ("GB", Decimal("1000.00"), Decimal("200.00"), Decimal("0.20")),
        ("UK", Decimal("1000.00"), Decimal("200.00"), Decimal("0.20")),
        ("GB", Decimal("1000.00"), Decimal("50.00"), Decimal("0.05")),
        ("GB", Decimal("1000.00"), Decimal("0.00"), Decimal("0.00")),
        # Germany MwSt: 19%, 7%, 0%
        ("DE", Decimal("1000.00"), Decimal("190.00"), Decimal("0.19")),
        ("DE", Decimal("1000.00"), Decimal("70.00"), Decimal("0.07")),
        ("DE", Decimal("1000.00"), Decimal("0.00"), Decimal("0.00")),
        # Spain IVA: 21%, 10%, 4%, 0%
        ("ES", Decimal("1000.00"), Decimal("210.00"), Decimal("0.21")),
        ("ES", Decimal("1000.00"), Decimal("100.00"), Decimal("0.10")),
        ("ES", Decimal("1000.00"), Decimal("40.00"), Decimal("0.04")),
        ("ES", Decimal("1000.00"), Decimal("0.00"), Decimal("0.00")),
        # Within ±0.05 rounding tolerance
        ("DE", Decimal("1000.00"), Decimal("190.05"), Decimal("0.19")),
        ("ES", Decimal("1000.00"), Decimal("209.95"), Decimal("0.21")),
    ],
)
def test_statutory_eu_and_uk_tax_rates_pass(
    country: str, subtotal: Decimal, tax: Decimal, expected_rate: Decimal
) -> None:
    """Tests: FR-07 — UK VAT (20/5/0%), DE MwSt (19/7/0%), and ES IVA (21/10/4/0%) pass."""
    ok, msg = validate_tax_rate(country, subtotal, tax, False, False)
    assert ok is True
    assert msg

    res = evaluate_tax_rate(country, subtotal, tax)
    assert res.is_valid is True
    assert res.matched_rate == expected_rate
    assert res.recommended_status is None


@pytest.mark.parametrize(
    ("country", "subtotal", "tax"),
    [
        ("GB", Decimal("1000.00"), Decimal("150.00")),  # 15% invalid in UK
        ("UK", Decimal("1000.00"), Decimal("190.00")),  # 19% is DE, not UK
        ("DE", Decimal("1000.00"), Decimal("200.00")),  # 20% is UK, not DE
        ("DE", Decimal("1000.00"), Decimal("190.06")),  # exceeds ±0.05 tolerance
        ("ES", Decimal("1000.00"), Decimal("150.00")),  # 15% invalid in ES
        ("ES", Decimal("5187.50"), Decimal("1114.38")),  # INV-2026-1010 tax_mismatch (+25.00)
    ],
)
def test_non_statutory_eu_and_uk_tax_rates_fail(
    country: str, subtotal: Decimal, tax: Decimal
) -> None:
    """Tests: FR-07 — Non-statutory EU/UK rates fail and recommend REJECTED_TAX_MISMATCH."""
    ok, msg = validate_tax_rate(country, subtotal, tax, False, False)
    assert ok is False
    assert "does not match" in msg

    res = evaluate_tax_rate(country, subtotal, tax)
    assert res.is_valid is False
    assert res.recommended_status == "REJECTED_TAX_MISMATCH"


# ---------------------------------------------------------------------------
# 2. FR-07: US Sales Tax (Vendor Master Rate & Fallback Bounds)
# ---------------------------------------------------------------------------


def test_us_sales_tax_with_vendor_master_rate_and_fallback_bounds() -> None:
    """Tests: FR-07 & BR-011 — US sales tax verified against Vendor Master rate and bounded fallback."""
    # Exact CA 9.5% and TX 8.25% Vendor Master rates
    res_ca = evaluate_tax_rate("US", Decimal("1000.00"), Decimal("95.00"), vendor_tax_rate="0.095")
    assert res_ca.is_valid is True
    assert res_ca.matched_rate == Decimal("0.095")

    res_tx = evaluate_tax_rate("US", Decimal("1000.00"), Decimal("82.50"), vendor_tax_rate="0.0825")
    assert res_tx.is_valid is True

    # Mismatched stated tax vs Vendor Master rate (8.25% expected $82.50, stated $50.00) -> FAIL
    res_bad_us = evaluate_tax_rate(
        "US", Decimal("1000.00"), Decimal("50.00"), vendor_tax_rate="0.0825"
    )
    assert res_bad_us.is_valid is False
    assert res_bad_us.recommended_status == "REJECTED_TAX_MISMATCH"

    # Zero-tax US vendor (Oregon/Delaware 0% in Vendor Master) -> PASS
    res_or = evaluate_tax_rate("US", Decimal("1000.00"), Decimal("0.00"), vendor_tax_rate="0.0")
    assert res_or.is_valid is True

    # 5-arg LLD §5.3 call without vendor_tax_rate: realistic US rate (8.25%) passes
    ok_us, _ = validate_tax_rate("US", Decimal("1000.00"), Decimal("82.50"), False, False)
    assert ok_us is True

    # Without vendor_tax_rate: implausible 30% US sales tax fails closed (exceeds 15% US statutory ceiling)
    ok_us_high, msg_high = validate_tax_rate(
        "US", Decimal("1000.00"), Decimal("300.00"), False, False
    )
    assert ok_us_high is False
    assert "US sales tax" in msg_high


# ---------------------------------------------------------------------------
# 3. FR-07: Reverse Charge, Exemption Flags & PRD Journey 5
# ---------------------------------------------------------------------------


def test_reverse_charge_and_exemption_flags_and_journey_5_flow() -> None:
    """Tests: FR-07 & PRD Journey 5 — Reverse charge/exempt require zero tax; non-zero fails."""
    # Reverse charge with zero tax -> PASS
    ok_rc, msg_rc = validate_tax_rate("DE", Decimal("1250.00"), Decimal("0.00"), True, False)
    assert ok_rc is True
    assert "Reverse Charge" in msg_rc

    # Exempt with zero tax -> PASS
    ok_ex, msg_ex = validate_tax_rate("US", Decimal("1250.00"), Decimal("0.00"), False, True)
    assert ok_ex is True
    assert "Exemption" in msg_ex

    # Reverse charge or exempt with non-zero tax -> FAIL (LLD §5.3)
    ok_rc_nonzero, msg_nonzero = validate_tax_rate(
        "DE", Decimal("1250.00"), Decimal("237.50"), True, False
    )
    assert ok_rc_nonzero is False
    assert "must be zero" in msg_nonzero

    ok_ex_cent, _ = validate_tax_rate("GB", Decimal("100.00"), Decimal("0.01"), False, True)
    assert ok_ex_cent is False

    # PRD Journey 5: German vendor (19% standard) with 0% stated tax and require_exemption_for_zero_tax=True
    j5_fail = evaluate_tax_rate(
        "DE",
        Decimal("1250.00"),
        Decimal("0.00"),
        vendor_tax_rate="0.19",
        require_exemption_for_zero_tax=True,
    )
    assert j5_fail.is_valid is False
    assert j5_fail.recommended_status == "REJECTED_TAX_MISMATCH"

    # Clerk enables reverse charge -> re-validation PASSES!
    j5_pass = evaluate_tax_rate(
        "DE",
        Decimal("1250.00"),
        Decimal("0.00"),
        is_reverse_charge=True,
        vendor_tax_rate="0.19",
        require_exemption_for_zero_tax=True,
    )
    assert j5_pass.is_valid is True
    assert j5_pass.tax_scheme_applied == "REVERSE_CHARGE"


# ---------------------------------------------------------------------------
# 4. FR-07: Mixed-Rate Multi-Line Invoices (CLAUDE.md §5 V-004) & Credit Notes
# ---------------------------------------------------------------------------


def test_mixed_rate_multi_line_uk_invoice_and_credit_notes() -> None:
    """Tests: FR-07 & CLAUDE.md §5 — Mixed 20%/5% UK lines pass; bogus line rate fails; credit notes pass."""
    mixed_lines = [
        TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.20")),
        TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.05")),
    ]
    res_mixed = evaluate_tax_rate(
        "GB", Decimal("2000.00"), Decimal("250.00"), line_items=mixed_lines
    )
    assert res_mixed.is_valid is True
    assert res_mixed.is_mixed_rate is True

    # Mixed lines with non-statutory UK rate (15%) -> FAIL
    bad_line_rate = [
        TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.20")),
        TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.15")),
    ]
    res_bad_rate = evaluate_tax_rate(
        "GB", Decimal("2000.00"), Decimal("350.00"), line_items=bad_line_rate
    )
    assert res_bad_rate.is_valid is False
    assert "non-statutory" in res_bad_rate.message

    # Mixed lines whose tax sum (250.00) disagrees with stated tax (300.00) -> FAIL
    res_bad_sum = evaluate_tax_rate(
        "GB", Decimal("2000.00"), Decimal("300.00"), line_items=mixed_lines
    )
    assert res_bad_sum.is_valid is False

    # Credit note (negative subtotal + negative tax at DE 19%) -> PASS
    res_cn = evaluate_tax_rate("DE", Decimal("-1000.00"), Decimal("-190.00"))
    assert res_cn.is_valid is True
    assert res_cn.matched_rate == Decimal("0.19")


# ---------------------------------------------------------------------------
# 5. All 300 Ground-Truth Invoices + Config Tolerance (CLAUDE.md §16 Rule 8)
# ---------------------------------------------------------------------------


def test_all_300_ground_truth_invoices_and_settings_driven_tolerance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests: FR-07 & CLAUDE.md §16 Rule 8 — 299/300 GT pass, INV-2026-1010 fails, tolerance from settings."""
    vendors = {
        v["TaxID_VAT"]: v for v in json.loads(VENDOR_MASTER_PATH.read_text(encoding="utf-8"))
    }
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    failed_invoices: list[str] = []
    for path in gt_files:
        gt = json.loads(path.read_text(encoding="utf-8"))
        schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
        vendor = vendors[schema.header.vendor_tax_id.value]
        res = validate_extraction_tax(
            schema,
            country_code=vendor["CountryCode"],
            vendor_tax_rate=vendor["StandardTaxRate"],
        )
        if not res.is_valid:
            failed_invoices.append(schema.header.invoice_number.value)

    assert failed_invoices == ["INV-2026-1010"]

    # Verify tolerance loaded dynamically from get_settings().INVOICE_ROUNDING_TOLERANCE
    ok_default, _ = validate_tax_rate("DE", Decimal("1000.00"), Decimal("190.08"), False, False)
    assert ok_default is False

    monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", "0.10")
    get_settings.cache_clear()
    try:
        res_relaxed = evaluate_tax_rate("DE", Decimal("1000.00"), Decimal("190.08"))
        assert res_relaxed.tolerance == Decimal("0.10")
        assert res_relaxed.is_valid is True
    finally:
        monkeypatch.delenv("INVOICE_ROUNDING_TOLERANCE", raising=False)
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 6. Security, Fail-Closed Country Guards & Layer Isolation (CLAUDE.md §4.2)
# ---------------------------------------------------------------------------


def test_security_unknown_country_strict_booleans_and_layer_isolation() -> None:
    """Tests: FR-07 & CLAUDE.md §4.2 — Unknown country fails closed, strict bool flags, zero LLM/SQL."""
    # Canonical rates table exposed
    assert set(COUNTRY_TAX_RATES.keys()) == {"GB", "DE", "ES"}
    assert normalize_country_code("uk") == "GB"
    assert normalize_country_code(" de ") == "DE"

    # Unknown/unsupported country codes MUST fail closed (never silently fall back to US!)
    for bad_cc in ("FR", "XX", "CN", "", "   ", "DE\n", "GB\u200b"):
        with pytest.raises(ValueError):
            normalize_country_code(bad_cc)

    # Strict bool enforcement: string "false" must NEVER coerce to True for is_reverse_charge/is_exempt!
    with pytest.raises(ValueError, match="boolean"):
        validate_tax_rate("DE", Decimal("1000.00"), Decimal("0.00"), "false", False)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="boolean"):
        validate_tax_rate("DE", Decimal("1000.00"), Decimal("0.00"), False, 1)  # type: ignore[arg-type]

    # Opposite-sign tax (positive subtotal, negative stated tax) MUST fail!
    res_opp = evaluate_tax_rate("DE", Decimal("1000.00"), Decimal("-190.00"))
    assert res_opp.is_valid is False

    # Layer isolation check (CLAUDE.md §4.2): zero LLM/SQLAlchemy/API/UI/storage imports
    src_code = Path("src/validation/tax_validator.py").read_text(encoding="utf-8")
    for forbidden in (
        "import openai",
        "from openai",
        "sqlalchemy",
        "src.extraction.model_gateway",
        "src.extraction.extract_engine",
        "src.extraction.mock_aoai_client",
        "src.storage",
        "src.api",
        "src.ui",
        "api_key=",
        "sk-",
    ):
        assert forbidden not in src_code, f"Forbidden import/token '{forbidden}' found"

    # Extra injected fields rejected on TaxLineInput
    with pytest.raises(ValidationError):
        TaxLineInput(
            line_total=Decimal("100.00"),
            tax_rate=Decimal("0.20"),
            is_exempt=True,  # type: ignore[call-arg]
        )


def test_pentest_partial_line_subtotal_mismatch_vat_evasion_blocked() -> None:
    """Security (SEC-150 · CWE-840/CWE-682): Partial lines matching low stated_tax cannot bypass VAT on larger subtotal."""
    # Attacker claims £10,000 subtotal with £200 stated tax (2%), supplying one £1,000 @ 20% line (=£200)
    partial_lines = [TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.20"))]
    res = evaluate_tax_rate("GB", Decimal("10000.00"), Decimal("200.00"), line_items=partial_lines)
    assert res.is_valid is False
    assert res.recommended_status == "REJECTED_TAX_MISMATCH"
    assert "does not reconcile" in res.message


def test_pentest_homograph_country_code_us_rate_ceiling_and_numeric_parser_hardening() -> None:
    """Security (SEC-151/SEC-153 · CWE-20/172/436/840): Block homograph countries, >15% US rate, underscores/non-ASCII."""
    # Fullwidth / soft-hyphen / NBSP country codes must fail closed
    for spoofed_cc in ("ＵＳ", "DE\u00ad", "GB\u00a0", "ES\u202e"):
        with pytest.raises(ValueError):
            normalize_country_code(spoofed_cc)

    # US vendor_tax_rate > 15% rejected fail-closed
    with pytest.raises(ValueError, match="ceiling"):
        evaluate_tax_rate("US", Decimal("1000.00"), Decimal("250.00"), vendor_tax_rate="0.25")

    # Underscores, Arabic-Indic digits, CRLF rejected on monetary fields
    for bad_num in ("1_000.00", "١٠٠.٠٠", "100.00\r\n", "\x00100.00", "1E-5000000"):
        with pytest.raises(ValueError):
            evaluate_tax_rate("DE", bad_num, Decimal("0.00"))


def test_pentest_env_tolerance_dos_line_cap_and_frozen_result_immutability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security (SEC-152/SEC-153 · CWE-400/703/863): Env tolerance bounds, >500 line DoS cap, and frozen result."""
    for bad_env in ("-0.05", "5000.00"):
        monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", bad_env)
        get_settings.cache_clear()
        try:
            with pytest.raises(ValueError):
                validate_tax_rate("DE", Decimal("100.00"), Decimal("19.00"), False, False)
        finally:
            monkeypatch.delenv("INVOICE_ROUNDING_TOLERANCE", raising=False)
            get_settings.cache_clear()

    # >500 line_items DoS rejected (CWE-400)
    one_line = TaxLineInput(line_total=Decimal("1.00"), tax_rate=Decimal("0.20"))
    with pytest.raises(ValueError, match="maximum allowed count"):
        evaluate_tax_rate(
            "GB",
            Decimal("501.00"),
            Decimal("100.20"),
            line_items=[one_line] * (MAX_LINE_ITEMS + 1),
        )

    # Frozen result cannot be mutated into is_valid=True
    failed = evaluate_tax_rate("ES", Decimal("5187.50"), Decimal("1114.38"))
    assert failed.is_valid is False
    with pytest.raises(ValidationError):
        failed.is_valid = True  # type: ignore[misc]
