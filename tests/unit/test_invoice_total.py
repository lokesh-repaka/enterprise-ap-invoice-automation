"""
Unit tests for P7-3 · Invoice Total Arithmetic Validator (src/validation/invoice_total.py).

Tests: FR-06
Requirements: BR-010, Q-05, LLD §5.2, CLAUDE.md §4.2, §5, §7.1, §7.2, §11.1, §16 Rule 8.
Strict offline isolation: zero external network or Azure calls.
"""

import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.core.config import get_settings
from src.database.models import Invoice
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.invoice_total import (
    InvoiceTotalInput,
    evaluate_invoice_record,
    evaluate_invoice_total,
    validate_extraction_invoice_total,
    validate_invoice_total,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")


# ---------------------------------------------------------------------------
# 1. FR-06: Exact & Within-Tolerance Grand Total Arithmetic (BR-010, LLD §5.2)
# ---------------------------------------------------------------------------


def test_validate_invoice_total_exact_and_within_tolerance_boundaries() -> None:
    """Tests: FR-06 — Exact matches, float traps, and ±0.05 boundaries pass cleanly."""
    # Exact match
    ok, err = validate_invoice_total(Decimal("1000.00"), Decimal("190.00"), Decimal("1190.00"))
    assert ok is True
    assert err == ""

    # IEEE 754 float trap: 0.10 + 0.20 = 0.30, and 100.00 + 0.00 vs 100.05 exact boundary
    ok_float, err_float = validate_invoice_total(0.10, 0.20, 0.30)
    assert ok_float is True
    assert err_float == ""

    # Exact +0.05 boundary (must PASS)
    res_plus = evaluate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("120.05"))
    assert res_plus.is_valid is True
    assert res_plus.difference == Decimal("0.05")
    assert res_plus.rounding_within_tolerance is True
    assert res_plus.error == ""

    # Exact -0.05 boundary (must PASS)
    res_minus = evaluate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("119.95"))
    assert res_minus.is_valid is True
    assert res_minus.difference == Decimal("0.05")
    assert res_minus.rounding_within_tolerance is True

    # Zero-tax reverse-charge / exempt invoice (0.00 tax)
    res_zero_tax = evaluate_invoice_total(Decimal("1250.00"), Decimal("0.00"), Decimal("1250.00"))
    assert res_zero_tax.is_valid is True
    assert res_zero_tax.rounding_within_tolerance is False

    # Zero-dollar invoice
    res_zero = evaluate_invoice_total(Decimal("0.00"), Decimal("0.00"), Decimal("0.00"))
    assert res_zero.is_valid is True
    assert res_zero.expected_total == Decimal("0.00")


def test_validate_invoice_total_fails_outside_tolerance_with_lld_error_message() -> None:
    """Tests: FR-06 — Discrepancies > ±0.05 (including sub-cent +0.051) fail with descriptive LLD message."""
    # +0.06 above expected
    ok_plus, err_plus = validate_invoice_total(
        Decimal("1000.00"), Decimal("240.00"), Decimal("1240.06")
    )
    assert ok_plus is False
    assert "Subtotal (1000.00)" in err_plus
    assert "Tax (240.00)" in err_plus
    assert "1240.00" in err_plus
    assert "1240.06" in err_plus
    assert "0.06" in err_plus

    # -0.06 below expected
    ok_minus, err_minus = validate_invoice_total(
        Decimal("1000.00"), Decimal("240.00"), Decimal("1239.94")
    )
    assert ok_minus is False
    assert "0.06" in err_minus

    # Sub-cent overrun +0.051 MUST FAIL (must never silently round down to 0.05!)
    res_subcent = evaluate_invoice_total(Decimal("100.00"), Decimal("0.00"), Decimal("100.051"))
    assert res_subcent.is_valid is False
    assert res_subcent.difference == Decimal("0.051")
    assert "0.051" in res_subcent.error


def test_validate_invoice_total_credit_note_negatives_and_sign_mismatch() -> None:
    """Tests: FR-06 & FR-11 — Negative credit-note totals balance cleanly and catch sign errors."""
    ok_cn, err_cn = validate_invoice_total(
        Decimal("-1000.00"), Decimal("-190.00"), Decimal("-1190.00")
    )
    assert ok_cn is True
    assert err_cn == ""

    # Sign mismatch (positive subtotal + tax vs negative grand total) MUST fail
    ok_flip, err_flip = validate_invoice_total(
        Decimal("1000.00"), Decimal("190.00"), Decimal("-1190.00")
    )
    assert ok_flip is False
    assert "2380.00" in err_flip


# ---------------------------------------------------------------------------
# 2. Config Threshold Integration (CLAUDE.md §11.1, §16 Rule 8)
# ---------------------------------------------------------------------------


def test_invoice_tolerance_loaded_from_settings_not_hardcoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests: FR-06 & CLAUDE.md §16 Rule 8 — INVOICE_ROUNDING_TOLERANCE read from get_settings()."""
    # Diff = 0.08 fails default 0.05
    ok_default, _ = validate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("120.08"))
    assert ok_default is False

    # Updating env INVOICE_ROUNDING_TOLERANCE=0.10 dynamically allows diff=0.08
    monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", "0.10")
    get_settings.cache_clear()
    try:
        res_relaxed = evaluate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("120.08"))
        assert res_relaxed.tolerance == Decimal("0.10")
        assert res_relaxed.is_valid is True
        assert res_relaxed.rounding_within_tolerance is True
    finally:
        monkeypatch.delenv("INVOICE_ROUNDING_TOLERANCE", raising=False)
        get_settings.cache_clear()

    # Explicit tolerance override works cleanly
    ok_override, _ = validate_invoice_total(
        Decimal("100.00"), Decimal("20.00"), Decimal("120.08"), tolerance=Decimal("0.08")
    )
    assert ok_override is True


# ---------------------------------------------------------------------------
# 3. Ground-Truth 300 Invoices, INV-2026-1030, ORM & Optional Line-Sum Cross-Check
# ---------------------------------------------------------------------------


def test_validate_all_300_ground_truth_invoices_including_rounding_within_tolerance() -> None:
    """Tests: FR-06 — All 300 ground-truth invoices pass, and INV-2026-1030 flags rounding_within_tolerance."""
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    rounding_flagged: list[str] = []
    for path in gt_files:
        gt = json.loads(path.read_text(encoding="utf-8"))
        schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
        res = validate_extraction_invoice_total(schema, check_lines_subtotal=True)
        assert res.is_valid is True, f"Invoice total failed on {path.name}: {res.error}"
        assert res.subtotal_matches_lines is True
        if res.rounding_within_tolerance:
            rounding_flagged.append(gt["header"]["invoice_number"])

    # INV-2026-1030 (967.50 + 77.40 = 1044.90 vs 1044.94, diff=0.04 <= 0.05)
    assert rounding_flagged == ["INV-2026-1030"]


def test_lines_subtotal_cross_check_and_orm_invoice_record_support() -> None:
    """Tests: FR-06 — Optional header-subtotal vs line-item-sum cross-check and ORM Invoice support."""
    # Header math balances (1000 + 200 = 1200) but lines only sum to 900 -> caught when cross-checked!
    res_tampered = evaluate_invoice_total(
        Decimal("1000.00"),
        Decimal("200.00"),
        Decimal("1200.00"),
        lines_subtotal=Decimal("900.00"),
    )
    assert res_tampered.is_valid is False
    assert res_tampered.subtotal_matches_lines is False
    assert res_tampered.subtotal_lines_difference == Decimal("100.00")
    assert "Line items sum" in res_tampered.error

    # SQLAlchemy Invoice ORM record support (P2-1)
    orm_inv = Invoice(
        vendor_tax_id="ESA98765432",
        invoice_number="INV-2026-9001",
        subtotal=Decimal("500.00"),
        total_tax_amount=Decimal("105.00"),
        total_amount=Decimal("605.00"),
        currency="EUR",
        status="EXTRACTING",
        composite_hash="0" * 64,
    )
    res_orm = evaluate_invoice_record(orm_inv)
    assert res_orm.is_valid is True
    assert res_orm.expected_total == Decimal("605.00")

    # Missing subtotal/tax on unextracted ORM Invoice raises explicit ValueError (never silently passes!)
    unextracted = Invoice(
        vendor_tax_id="ESA98765432",
        invoice_number="INV-2026-9002",
        subtotal=None,
        total_tax_amount=None,
        total_amount=Decimal("605.00"),
        currency="EUR",
        status="UPLOADED",
        composite_hash="1" * 64,
    )
    with pytest.raises(ValueError, match="subtotal"):
        evaluate_invoice_record(unextracted)


# ---------------------------------------------------------------------------
# 4. Security, Input Hardening & Layer Isolation (CLAUDE.md §4.2, §7.2)
# ---------------------------------------------------------------------------


def test_security_input_hardening_overflow_bounds_and_layer_isolation() -> None:
    """Tests: FR-06 & CLAUDE.md §4.2 — Rejects NaN/Inf/bool/bombs/overflow/extra fields & keeps layers clean."""
    for bad in (True, False, "NaN", "Infinity", "-Infinity", "1E-5000000", "1E500"):
        with pytest.raises(ValidationError):
            InvoiceTotalInput(
                subtotal=bad,  # type: ignore[arg-type]
                tax_amount=Decimal("0.00"),
                total_amount=Decimal("0.00"),
            )

    # Extra injected fields rejected (CWE-915)
    with pytest.raises(ValidationError):
        InvoiceTotalInput(
            subtotal=Decimal("100.00"),
            tax_amount=Decimal("10.00"),
            total_amount=Decimal("110.00"),
            status="APPROVED_CLERK",  # type: ignore[call-arg]
        )

    # Sum overflow exceeding SQL DECIMAL(18, 2) ceiling rejected (CWE-190)
    with pytest.raises(ValueError, match="exceeds maximum allowed bound"):
        evaluate_invoice_total(
            Decimal("800000000000.00"),
            Decimal("800000000000.00"),
            Decimal("100.00"),
        )

    # Layer isolation check (CLAUDE.md §4.2): zero LLM/SQLAlchemy/API/UI/storage imports
    src_code = Path("src/validation/invoice_total.py").read_text(encoding="utf-8")
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


def test_pentest_opposite_sign_tax_threshold_evasion_blocked() -> None:
    """Security (SEC-146 · CWE-840/CWE-682): Negative tax on positive subtotal cannot drop total below $10k."""
    # +10,000 subtotal + (-100) tax = 9,900 balances arithmetically but attempts approval threshold evasion
    res_pos_sub_neg_tax = evaluate_invoice_total(
        Decimal("10000.00"), Decimal("-100.00"), Decimal("9900.00")
    )
    assert res_pos_sub_neg_tax.is_valid is False
    assert res_pos_sub_neg_tax.sign_consistent is False
    assert "opposite sign" in res_pos_sub_neg_tax.error

    # Reverse: negative credit subtotal with positive tax also blocked
    res_neg_sub_pos_tax = evaluate_invoice_total(
        Decimal("-1000.00"), Decimal("100.00"), Decimal("-900.00")
    )
    assert res_neg_sub_pos_tax.is_valid is False
    assert res_neg_sub_pos_tax.sign_consistent is False


def test_pentest_non_ascii_digits_underscores_and_crlf_strings_rejected() -> None:
    """Security (SEC-147 · CWE-20/CWE-117/CWE-436): Block underscores, Arabic-Indic digits, and CRLF."""
    for bad_str in ("1_000.00", "١٠٠.٠٠", "100.00\r\n", "\x00100.00", "100.00\nINJECT"):
        with pytest.raises(ValidationError):
            InvoiceTotalInput(
                subtotal=bad_str,  # type: ignore[arg-type]
                tax_amount=Decimal("0.00"),
                total_amount=Decimal("100.00"),
            )


def test_pentest_misconfigured_env_tolerance_and_result_immutability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security (SEC-148/SEC-149 · CWE-20/CWE-703/CWE-754/CWE-863): Env tolerance bounds & frozen result."""
    for bad_env in ("-0.05", "5000.00"):
        monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", bad_env)
        get_settings.cache_clear()
        try:
            with pytest.raises(ValueError):
                validate_invoice_total(Decimal("10.00"), Decimal("0.00"), Decimal("10.00"))
        finally:
            monkeypatch.delenv("INVOICE_ROUNDING_TOLERANCE", raising=False)
            get_settings.cache_clear()

    for bad_tol in (Decimal("-0.01"), True, "NaN", "Infinity", Decimal("1000.00")):
        with pytest.raises(ValueError):
            validate_invoice_total(
                Decimal("10.00"),
                Decimal("0.00"),
                Decimal("10.00"),
                tolerance=bad_tol,  # type: ignore[arg-type]
            )

    # Frozen result cannot be mutated into is_valid=True after failing validation
    failed = evaluate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("200.00"))
    assert failed.is_valid is False
    with pytest.raises(ValidationError):
        failed.is_valid = True  # type: ignore[misc]

    # Unsupported record type fails closed
    with pytest.raises(ValueError, match="Unsupported invoice record type"):
        evaluate_invoice_record({"subtotal": 100})  # type: ignore[arg-type]
