"""
Unit tests for P7-2 · Line-Item Arithmetic Validator (src/validation/line_arithmetic.py).

Tests: FR-05
Requirements: BR-009, Q-05, LLD §5.1, CLAUDE.md §4.2, §7.1, §7.2, §11.1, §16 Rule 8.
Strict offline isolation: zero external network or Azure calls.
"""

import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.core.config import get_settings
from src.database.models import InvoiceLine
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.line_arithmetic import (
    MAX_LINE_ITEMS,
    LineItemArithmeticInput,
    evaluate_line_items,
    validate_extraction_line_items,
    validate_line_items,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")


# ---------------------------------------------------------------------------
# 1. FR-05: Exact & Within-Tolerance Line Arithmetic (BR-009, LLD §5.1)
# ---------------------------------------------------------------------------


def test_validate_line_items_exact_and_within_tolerance_boundaries() -> None:
    """Tests: FR-05 — Exact matches and boundary rounding diffs (±0.02) pass cleanly."""
    lines = [
        # Exact integer math
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("10"),
            unit_price=Decimal("125.00"),
            line_total=Decimal("1250.00"),
        ),
        # Fractional qty & price with ROUND_HALF_UP: 2.5 * 33.33 = 83.325 -> 83.33
        LineItemArithmeticInput(
            line_number=2,
            quantity=Decimal("2.5"),
            unit_price=Decimal("33.33"),
            line_total=Decimal("83.33"),
        ),
        # IEEE 754 float precision trap: 3 * 0.10 = 0.30
        LineItemArithmeticInput(
            line_number=3,
            quantity="3",
            unit_price="0.10",
            line_total="0.30",
        ),
        # Exact +0.02 boundary (must PASS)
        LineItemArithmeticInput(
            line_number=4,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.02"),
        ),
        # Exact -0.02 boundary (must PASS)
        LineItemArithmeticInput(
            line_number=5,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("9.98"),
        ),
        # Zero quantity line (0 * 100 = 0.00)
        LineItemArithmeticInput(
            line_number=6,
            quantity=Decimal("0"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("0.00"),
        ),
    ]

    is_valid, errors = validate_line_items(lines)
    assert is_valid is True
    assert errors == []

    res = evaluate_line_items(lines)
    assert res.is_valid is True
    assert res.tolerance == Decimal("0.02")
    assert res.total_lines_checked == 6
    assert res.passed_count == 6
    assert res.failed_count == 0
    assert res.computed_subtotal == Decimal("1353.63")
    assert res.expected_subtotal == Decimal("1353.63")


def test_validate_line_items_fails_outside_tolerance_with_lld_error_details() -> None:
    """Tests: FR-05 — Discrepancies > ±0.02 fail and report exact line number, expected, and diff."""
    lines = [
        # Line 1: valid
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("4"),
            unit_price=Decimal("50.00"),
            line_total=Decimal("200.00"),
        ),
        # Line 2: +0.03 above expected (fails ±0.02)
        LineItemArithmeticInput(
            line_number=2,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.03"),
        ),
        # Line 3: -0.03 below expected (fails ±0.02)
        LineItemArithmeticInput(
            line_number=3,
            quantity=Decimal("2"),
            unit_price=Decimal("25.00"),
            line_total=Decimal("49.97"),
        ),
        # Line 4: +0.021 (sub-cent exceeding 0.02 tolerance — must FAIL, never round away!)
        LineItemArithmeticInput(
            line_number=4,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.021"),
        ),
    ]

    is_valid, errors = validate_line_items(lines)
    assert is_valid is False
    assert len(errors) == 3
    assert "Line 2:" in errors[0]
    assert "10.03" in errors[0]
    assert "10.00" in errors[0]
    assert "0.03" in errors[0]
    assert "Line 3:" in errors[1]
    assert "49.97" in errors[1]
    assert "50.00" in errors[1]
    assert "Line 4:" in errors[2]

    res = evaluate_line_items(lines)
    assert res.passed_count == 1
    assert res.failed_count == 3
    assert res.line_results[0].is_valid is True
    assert res.line_results[1].is_valid is False
    assert res.line_results[1].difference == Decimal("0.03")
    assert res.line_results[3].is_valid is False


def test_validate_line_items_credit_note_negative_values_and_sign_mismatch() -> None:
    """Tests: FR-05 — Negative credit-note line math validates accurately and catches sign flips."""
    valid_credit_lines = [
        # Negative qty * positive price = negative line_total
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("-2"),
            unit_price=Decimal("85.50"),
            line_total=Decimal("-171.00"),
        ),
        # Positive qty * negative price = negative line_total
        LineItemArithmeticInput(
            line_number=2,
            quantity=Decimal("1"),
            unit_price=Decimal("-171.00"),
            line_total=Decimal("-171.00"),
        ),
    ]
    ok, errs = validate_line_items(valid_credit_lines)
    assert ok is True
    assert errs == []

    # Sign mismatch (2 * 85.50 = +171.00 != -171.00) must fail
    sign_mismatch = [
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("2"),
            unit_price=Decimal("85.50"),
            line_total=Decimal("-171.00"),
        )
    ]
    ok2, errs2 = validate_line_items(sign_mismatch)
    assert ok2 is False
    assert len(errs2) == 1
    assert "342.00" in errs2[0]


def test_validate_line_items_empty_sequence_returns_valid() -> None:
    """Tests: FR-05 — Empty line list returns valid with zero totals and zero errors (LLD §5.1)."""
    is_valid, errors = validate_line_items([])
    assert is_valid is True
    assert errors == []

    res = evaluate_line_items([])
    assert res.total_lines_checked == 0
    assert res.computed_subtotal == Decimal("0.00")
    assert res.expected_subtotal == Decimal("0.00")


# ---------------------------------------------------------------------------
# 2. Config Threshold Integration (CLAUDE.md §11.1, §16 Rule 8)
# ---------------------------------------------------------------------------


def test_tolerance_loaded_from_settings_not_hardcoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests: FR-05 & CLAUDE.md §16 Rule 8 — LINE_ROUNDING_TOLERANCE read from get_settings()."""
    line = [
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.04"),
        )
    ]

    # Default 0.02 fails diff=0.04
    ok_default, _ = validate_line_items(line)
    assert ok_default is False

    # Updating env LINE_ROUNDING_TOLERANCE=0.05 dynamically allows diff=0.04
    monkeypatch.setenv("LINE_ROUNDING_TOLERANCE", "0.05")
    get_settings.cache_clear()
    try:
        res_relaxed = evaluate_line_items(line)
        assert res_relaxed.tolerance == Decimal("0.05")
        assert res_relaxed.is_valid is True
    finally:
        monkeypatch.delenv("LINE_ROUNDING_TOLERANCE", raising=False)
        get_settings.cache_clear()

    # Explicit tolerance argument also works
    ok_override, _ = validate_line_items(line, tolerance=Decimal("0.04"))
    assert ok_override is True


# ---------------------------------------------------------------------------
# 3. Polymorphic Contracts: SQLAlchemy ORM, P6-3 Extraction Schema, Dicts, 300 GT Files
# ---------------------------------------------------------------------------


def test_validate_line_items_supports_orm_extraction_schema_dicts_and_all_300_ground_truths() -> (
    None
):
    """Tests: FR-05 — Accepts InvoiceLine ORM, InvoiceLineItemExtraction, dicts, and all 300 GT files."""
    # 1. SQLAlchemy InvoiceLine ORM instance (P2-1)
    orm_line = InvoiceLine(
        invoice_id="inv-001",
        line_number=7,
        description="Consulting hours",
        quantity=Decimal("8.0000"),
        unit_price=Decimal("150.0000"),
        line_total=Decimal("1200.00"),
        line_tax_rate=Decimal("0.2000"),
    )
    ok_orm, errs_orm = validate_line_items([orm_line])
    assert ok_orm is True
    assert errs_orm == []

    # 2. Plain dict payload (e.g. from P9-1 /revalidate API)
    dict_lines = [
        {"line_number": 1, "quantity": 10, "unit_price": 12.50, "line_total": 125.00},
        {"quantity": 3, "unit_price": 20.00, "line_total": 61.00},  # defaults to line_number=2
    ]
    res_dict = evaluate_line_items(dict_lines)
    assert res_dict.is_valid is False
    assert res_dict.line_results[1].line_number == 2
    assert res_dict.line_results[1].difference == Decimal("1.00")

    # 3. All 300 sample_data/ground_truth/ invoices (1,068 line items) via P6-3 InvoiceExtractionSchema
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300
    total_checked = 0
    for path in gt_files:
        gt = json.loads(path.read_text(encoding="utf-8"))
        schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
        res = validate_extraction_line_items(schema)
        assert res.is_valid is True, f"Line arithmetic failed on {path.name}: {res.errors}"
        total_checked += res.total_lines_checked
    assert total_checked == 1068


# ---------------------------------------------------------------------------
# 4. Security, Input Hardening & Layer Isolation (CLAUDE.md §4.2, §7.2)
# ---------------------------------------------------------------------------


def test_security_input_hardening_bounds_and_layer_isolation() -> None:
    """Tests: FR-05 & CLAUDE.md §4.2 — Rejects NaN/Inf/bool/bombs/overflow/DoS and keeps layers clean."""
    # Reject booleans, NaN, Infinity, exponent bombs on numeric fields
    for bad in (True, False, "NaN", "Infinity", "-Infinity", "1E-5000000", "1E500"):
        with pytest.raises(ValidationError):
            LineItemArithmeticInput(
                line_number=1,
                quantity=bad,  # type: ignore[arg-type]
                unit_price=Decimal("10.00"),
                line_total=Decimal("10.00"),
            )

    # Reject invalid line_number (<= 0 or bool)
    with pytest.raises(ValidationError):
        LineItemArithmeticInput(
            line_number=0,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.00"),
        )
    with pytest.raises(ValidationError):
        LineItemArithmeticInput(
            line_number=True,  # type: ignore[arg-type]
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.00"),
        )

    # Reject extra injected fields (CWE-915)
    with pytest.raises(ValidationError):
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.00"),
            status="APPROVED_CLERK",  # type: ignore[call-arg]
        )

    # Reject product overflow exceeding SQL DECIMAL(18, 2) ceiling (CWE-190)
    overflow_line = LineItemArithmeticInput(
        line_number=1,
        quantity=Decimal("100000000"),
        unit_price=Decimal("100000000"),
        line_total=Decimal("0.00"),
    )
    with pytest.raises(ValueError, match="exceeds maximum allowed bound"):
        evaluate_line_items([overflow_line])

    # Reject negative, bool, NaN, Infinity, or absurdly large tolerance overrides
    for bad_tol in (Decimal("-0.01"), True, "NaN", "Infinity", Decimal("1000.00")):
        with pytest.raises(ValueError):
            validate_line_items([], tolerance=bad_tol)  # type: ignore[arg-type]

    # Reject unbounded line counts > MAX_LINE_ITEMS (CWE-400)
    one_line = LineItemArithmeticInput(
        line_number=1,
        quantity=Decimal("1"),
        unit_price=Decimal("1.00"),
        line_total=Decimal("1.00"),
    )
    with pytest.raises(ValueError, match="maximum allowed count"):
        validate_line_items([one_line] * (MAX_LINE_ITEMS + 1))

    # Reject raw str/bytes passed instead of a sequence of lines
    with pytest.raises(ValueError, match="sequence"):
        validate_line_items("not-a-line-list")  # type: ignore[arg-type]

    # Layer isolation check (CLAUDE.md §4.2): zero LLM/SQLAlchemy/API/UI/storage imports
    src_code = Path("src/validation/line_arithmetic.py").read_text(encoding="utf-8")
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


def test_pentest_duplicate_line_number_and_salami_slicing_drift_visibility() -> None:
    """Security (SEC-142/SEC-145 · CWE-20/CWE-345/CWE-682): Reject duplicate line numbers and expose cumulative drift."""
    dup_lines = [
        {"line_number": 1, "quantity": 1, "unit_price": 100.00, "line_total": 100.00},
        {"line_number": 1, "quantity": 1, "unit_price": 500.00, "line_total": 500.00},
    ]
    with pytest.raises(ValueError, match="Duplicate line_number"):
        evaluate_line_items(dup_lines)

    # Salami-slicing: 100 lines each inflated by +0.02 pass per-line FR-05 but expose exact $2.00 drift
    sliced_lines = [
        LineItemArithmeticInput(
            line_number=i,
            quantity=Decimal("1"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.02"),
        )
        for i in range(1, 101)
    ]
    res = evaluate_line_items(sliced_lines)
    assert res.is_valid is True
    assert res.computed_subtotal == Decimal("1002.00")
    assert res.expected_subtotal == Decimal("1000.00")
    assert res.cumulative_rounding_drift == Decimal("2.00")


def test_pentest_non_ascii_digits_underscores_and_crlf_numeric_strings_rejected() -> None:
    """Security (SEC-143 · CWE-20/CWE-117/CWE-436): Block Python underscores, Arabic-Indic digits, and CRLF."""
    for bad_str in ("1_000.00", "١٠.٠٠", "10.00\r\n", "\x0010.00", "10.00\nFAKE"):
        with pytest.raises(ValidationError):
            LineItemArithmeticInput(
                line_number=1,
                quantity=Decimal("1"),
                unit_price=bad_str,  # type: ignore[arg-type]
                line_total=Decimal("10.00"),
            )


def test_pentest_misconfigured_env_tolerance_and_dict_mass_assignment_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security (SEC-144 · CWE-20/CWE-703/CWE-915): Invalid env tolerance and injected dict keys fail closed."""
    # Negative or absurdly large env tolerance must fail closed instead of silently disabling checks
    for bad_env in ("-0.05", "5000.00"):
        monkeypatch.setenv("LINE_ROUNDING_TOLERANCE", bad_env)
        get_settings.cache_clear()
        try:
            with pytest.raises(ValueError):
                validate_line_items([])
        finally:
            monkeypatch.delenv("LINE_ROUNDING_TOLERANCE", raising=False)
            get_settings.cache_clear()

    # Injected dict keys (CWE-915 mass assignment) rejected cleanly
    with pytest.raises(ValueError, match="Disallowed fields"):
        validate_line_items(
            [
                {
                    "line_number": 1,
                    "quantity": 1,
                    "unit_price": 10.00,
                    "line_total": 10.00,
                    "approved_by": "attacker",
                }
            ]
        )
