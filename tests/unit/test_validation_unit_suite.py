"""
Consolidated Validation & Reason-Code Unit Test Suite (P12-1).

Tests: FR-04, FR-05, FR-06, FR-07, FR-08, FR-09, FR-10, FR-11, FR-12
Requirements: CLAUDE.md §3, §4.2, §5, §7.1, §7.2, §13, §16 Rules 3/7/8/9,
BR-007, BR-009, BR-010, BR-011, BR-012, BR-013, BR-017.

Covers all 7 P12-1 unit-validation pillars in a fast, strictly offline suite:
1. Line-item arithmetic (FR-05)
2. Invoice total arithmetic (FR-06)
3. Multi-country tax validation + reverse-charge / exempt (FR-07)
4. Vendor-locale date normalization & disambiguation (FR-08)
5. SHA-256 duplicate hash, revision detection, and credit-note classification (FR-09..FR-11)
6. Tri-tier confidence routing & Rules-First precedence (FR-04)
7. ReasonCode enum validation, cross-layer parity & AuditLogger enforcement (FR-12)
8. Layering & determinism invariants across src/validation/ and src/core/audit.py
"""

import ast
import asyncio
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import src.core.audit as audit_mod
from src.api.schemas.invoices import InvoiceHeaderEdits, InvoiceRevalidateRequest
from src.core.audit import (
    AuditActionType,
    AuditLogger,
    ReasonCode,
    parse_reason_code,
    validate_reason_code,
)
from src.core.config import get_settings
from src.database.repositories import (
    compute_composite_hash as repo_compute_composite_hash,
)
from src.ui.review_workbench import REASON_CODE_LABELS
from src.validation.confidence_router import (
    ConfidenceColor,
    ConfidenceTier,
    classify_confidence_score,
    route_confidence_scores,
)
from src.validation.date_normalizer import (
    AmbiguousDateError,
    normalize_invoice_dates,
    parse_invoice_date,
    resolve_date_locale,
)
from src.validation.duplicate_detector import (
    DuplicateCheckInput,
    DuplicateOutcome,
    compute_composite_hash,
    evaluate_duplicate_rules,
)
from src.validation.invoice_total import evaluate_invoice_total, validate_invoice_total
from src.validation.line_arithmetic import (
    LineItemArithmeticInput,
    evaluate_line_items,
    validate_line_items,
)
from src.validation.tax_validator import TaxLineInput, evaluate_tax_rate, validate_tax_rate

# ---------------------------------------------------------------------------
# 1. Line-Item Arithmetic (FR-05)
# ---------------------------------------------------------------------------


def test_p12_1_line_arithmetic_exact_tolerance_credit_notes_and_dynamic_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-05 — Line arithmetic (Qty * Price = Total ± LINE_ROUNDING_TOLERANCE)."""
    # Exact match, fractional ROUND_HALF_UP, ±0.02 boundary, and negative credit-note line
    passing_lines = [
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("10"),
            unit_price=Decimal("125.00"),
            line_total=Decimal("1250.00"),
        ),
        LineItemArithmeticInput(
            line_number=2,
            quantity=Decimal("3"),
            unit_price=Decimal("0.335"),
            line_total=Decimal("1.01"),
        ),
        LineItemArithmeticInput(
            line_number=3,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.02"),
        ),
        LineItemArithmeticInput(
            line_number=4,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("99.98"),
        ),
        LineItemArithmeticInput(
            line_number=5,
            quantity=Decimal("-2"),
            unit_price=Decimal("50.00"),
            line_total=Decimal("-100.00"),
        ),
    ]
    ok, errors = validate_line_items(passing_lines)
    assert ok is True
    assert errors == []

    # Out-of-tolerance ±0.03 fails deterministically
    failing_lines = [
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.03"),
        ),
        LineItemArithmeticInput(
            line_number=2,
            quantity=Decimal("1"),
            unit_price=Decimal("100.00"),
            line_total=Decimal("99.97"),
        ),
    ]
    res_fail = evaluate_line_items(failing_lines)
    assert res_fail.is_valid is False
    assert len(res_fail.errors) == 2

    # Thresholds come from get_settings(), not hardcoded constants (CLAUDE.md §16 Rule 8)
    monkeypatch.setenv("LINE_ROUNDING_TOLERANCE", "0.05")
    get_settings.cache_clear()
    try:
        res_wider = evaluate_line_items(failing_lines)
        assert res_wider.is_valid is True
    finally:
        monkeypatch.delenv("LINE_ROUNDING_TOLERANCE", raising=False)
        get_settings.cache_clear()

    # Rejects boolean / NaN inputs
    with pytest.raises(ValidationError):
        LineItemArithmeticInput(
            line_number=1, quantity=True, unit_price=Decimal("10.00"), line_total=Decimal("10.00")
        )
    with pytest.raises(ValidationError):
        LineItemArithmeticInput(
            line_number=1,
            quantity=Decimal("NaN"),
            unit_price=Decimal("10.00"),
            line_total=Decimal("10.00"),
        )


# ---------------------------------------------------------------------------
# 2. Invoice Total Arithmetic (FR-06)
# ---------------------------------------------------------------------------


def test_p12_1_invoice_total_exact_tolerance_line_sum_and_dynamic_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-06 — Invoice total (Subtotal + Tax = Total ± INVOICE_ROUNDING_TOLERANCE)."""
    # Exact, ±0.05 boundaries, zero-tax reverse-charge, and negative credit note
    assert validate_invoice_total(Decimal("1000.00"), Decimal("190.00"), Decimal("1190.00"))[0]
    assert validate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("120.05"))[0]
    assert validate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("119.95"))[0]
    assert validate_invoice_total(Decimal("500.00"), Decimal("0.00"), Decimal("500.00"))[0]
    assert validate_invoice_total(Decimal("-100.00"), Decimal("-20.00"), Decimal("-120.00"))[0]

    # Out-of-tolerance ±0.06 fails
    ok_plus, err_plus = validate_invoice_total(
        Decimal("100.00"), Decimal("20.00"), Decimal("120.06")
    )
    assert ok_plus is False
    assert err_plus != ""

    ok_minus, err_minus = validate_invoice_total(
        Decimal("100.00"), Decimal("20.00"), Decimal("119.94")
    )
    assert ok_minus is False
    assert err_minus != ""

    # Line-sum cross-check catches subtotal mismatch
    res_lines_mismatch = evaluate_invoice_total(
        Decimal("200.00"),
        Decimal("40.00"),
        Decimal("240.00"),
        lines_subtotal=Decimal("150.00"),
    )
    assert res_lines_mismatch.is_valid is False

    # Dynamic tolerance from get_settings()
    monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", "0.10")
    get_settings.cache_clear()
    try:
        res_wider = evaluate_invoice_total(Decimal("100.00"), Decimal("20.00"), Decimal("120.08"))
        assert res_wider.is_valid is True
    finally:
        monkeypatch.delenv("INVOICE_ROUNDING_TOLERANCE", raising=False)
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 3. Tax Validation — All Countries + Reverse-Charge / Exempt (FR-07)
# ---------------------------------------------------------------------------


def test_p12_1_tax_validation_all_countries() -> None:
    """# Tests: FR-07 — Country statutory tax rates across US, GB/UK, DE, ES + fail-closed unknown."""
    cases = [
        # US sales tax: 0% to 15% allowed; >15% rejected
        ("US", Decimal("1000.00"), Decimal("0.00"), True),
        ("US", Decimal("1000.00"), Decimal("82.50"), True),
        ("US", Decimal("1000.00"), Decimal("100.00"), True),
        ("US", Decimal("1000.00"), Decimal("250.00"), False),
        # UK VAT (GB and UK alias): 20%, 5%, 0%; 15% invalid
        ("GB", Decimal("1000.00"), Decimal("200.00"), True),
        ("UK", Decimal("1000.00"), Decimal("200.00"), True),
        ("GB", Decimal("1000.00"), Decimal("50.00"), True),
        ("GB", Decimal("1000.00"), Decimal("0.00"), True),
        ("GB", Decimal("1000.00"), Decimal("150.00"), False),
        # Germany MwSt: 19%, 7%, 0%; 12% invalid
        ("DE", Decimal("1000.00"), Decimal("190.00"), True),
        ("DE", Decimal("1000.00"), Decimal("70.00"), True),
        ("DE", Decimal("1000.00"), Decimal("0.00"), True),
        ("DE", Decimal("1000.00"), Decimal("120.00"), False),
        # Spain IVA: 21%, 10%, 4%, 0%; 15% invalid
        ("ES", Decimal("1000.00"), Decimal("210.00"), True),
        ("ES", Decimal("1000.00"), Decimal("100.00"), True),
        ("ES", Decimal("1000.00"), Decimal("40.00"), True),
        ("ES", Decimal("1000.00"), Decimal("0.00"), True),
        ("ES", Decimal("1000.00"), Decimal("150.00"), False),
    ]
    for country, subtotal, tax, expected_valid in cases:
        ok, _err = validate_tax_rate(country, subtotal, tax, False, False)
        assert ok is expected_valid, (
            f"Unexpected tax validation result for {country} {tax}/{subtotal}"
        )

    # Unsupported country fails closed with ValueError
    with pytest.raises(ValueError, match="Unsupported country_code"):
        validate_tax_rate("FR", Decimal("1000.00"), Decimal("200.00"), False, False)


def test_p12_1_tax_validation_reverse_charge_exempt_and_mixed_lines() -> None:
    """# Tests: FR-07 — Reverse-charge, exempt bypasses, non-zero override guard, mixed lines."""
    # Reverse-charge with 0.00 tax passes across EU/UK jurisdictions
    for country in ("DE", "ES", "GB"):
        res_rc = evaluate_tax_rate(
            country, Decimal("2000.00"), Decimal("0.00"), is_reverse_charge=True
        )
        assert res_rc.is_valid is True
        assert res_rc.is_reverse_charge is True

    # Exempt with 0.00 tax passes
    res_ex = evaluate_tax_rate("US", Decimal("1500.00"), Decimal("0.00"), is_exempt=True)
    assert res_ex.is_valid is True
    assert res_ex.is_exempt is True

    # Reverse-charge / exempt MUST reject non-zero stated tax (prevents silent tax bypass)
    res_rc_nonzero = evaluate_tax_rate(
        "DE", Decimal("1000.00"), Decimal("190.00"), is_reverse_charge=True
    )
    assert res_rc_nonzero.is_valid is False

    res_ex_nonzero = evaluate_tax_rate("GB", Decimal("1000.00"), Decimal("50.00"), is_exempt=True)
    assert res_ex_nonzero.is_valid is False

    # Mixed-rate lines (DE 19% + 7%) validate accurately
    mixed_lines = [
        TaxLineInput(line_total=Decimal("1000.00"), tax_rate=Decimal("0.19")),
        TaxLineInput(line_total=Decimal("500.00"), tax_rate=Decimal("0.07")),
    ]
    res_mixed = evaluate_tax_rate(
        "DE", Decimal("1500.00"), Decimal("225.00"), line_items=mixed_lines
    )
    assert res_mixed.is_valid is True


# ---------------------------------------------------------------------------
# 4. Date Locale Parser (FR-08)
# ---------------------------------------------------------------------------


def test_p12_1_date_locale_disambiguation_iso_ambiguous_and_chronology() -> None:
    """# Tests: FR-08 — Vendor Master locale disambiguation (US MM/DD/YYYY vs EU DD/MM/YYYY)."""
    assert resolve_date_locale("US") == "US"
    assert resolve_date_locale("MM/DD/YYYY") == "US"
    assert resolve_date_locale("DE") == "EU"
    assert resolve_date_locale("DD/MM/YYYY") == "EU"
    assert resolve_date_locale(None) is None

    # Ambiguous 05/06/2026 disambiguated by Vendor Master locale
    assert parse_invoice_date("05/06/2026", "US") == date(2026, 5, 6)
    assert parse_invoice_date("05/06/2026", "MM/DD/YYYY") == date(2026, 5, 6)
    assert parse_invoice_date("05/06/2026", "DE") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "ES") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "GB") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "DD/MM/YYYY") == date(2026, 6, 5)

    # ISO-8601 always parses identically regardless of locale
    assert parse_invoice_date("2026-06-05", None) == date(2026, 6, 5)

    # Unambiguous day > 12 succeeds under EU and rejects under US
    assert parse_invoice_date("25/06/2026", "DE") == date(2026, 6, 25)
    with pytest.raises((ValueError, AmbiguousDateError)):
        parse_invoice_date("25/06/2026", "US")

    # Unknown / missing locale flags ambiguous 05/06/2026
    with pytest.raises(AmbiguousDateError):
        parse_invoice_date("05/06/2026", None)

    # Chronological check: due_date < invoice_date fails
    chron_res = normalize_invoice_dates("15/06/2026", "01/06/2026", locale="DE")
    assert chron_res.is_valid is False


# ---------------------------------------------------------------------------
# 5. Duplicate SHA-256 Composite Hash, Revision & Credit Note (FR-09, FR-10, FR-11)
# ---------------------------------------------------------------------------


@dataclass
class _StubExistingInvoice:
    invoice_id: str
    vendor_tax_id: str
    invoice_number: str
    total_amount: Decimal
    status: str
    composite_hash: str


def test_p12_1_duplicate_hash_parity_revisions_and_credit_notes() -> None:
    """# Tests: FR-09, FR-10, FR-11 — Composite hash parity, duplicates, revisions, credit notes."""
    # Cross-module SHA-256 parity and whitespace/scale normalization stability
    h_val = compute_composite_hash(" US-12-3456789 ", " INV-2026-001 ", Decimal("100"))
    h_repo = repo_compute_composite_hash("US-12-3456789", "INV-2026-001", Decimal("100.00"))
    assert h_val == h_repo
    assert len(h_val) == 64

    existing_active = _StubExistingInvoice(
        invoice_id="inv-existing-1",
        vendor_tax_id="US-12-3456789",
        invoice_number="INV-2026-001",
        total_amount=Decimal("100.00"),
        status="APPROVED_CLERK",
        composite_hash=h_val,
    )
    existing_void = _StubExistingInvoice(
        invoice_id="inv-existing-void",
        vendor_tax_id="US-12-3456789",
        invoice_number="INV-2026-001",
        total_amount=Decimal("100.00"),
        status="VOID",
        composite_hash=h_val,
    )

    # FR-09: Exact duplicate against active invoice -> DUPLICATE_INVOICE
    dup_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="INV-2026-001",
            total_amount=Decimal("100.00"),
        ),
        existing_vendor_invoices=[existing_active],
    )
    assert dup_res.outcome is DuplicateOutcome.DUPLICATE_INVOICE
    assert dup_res.target_status == "DUPLICATE_INVOICE"

    # VOID record is excluded from duplicate blocking
    void_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="INV-2026-001",
            total_amount=Decimal("100.00"),
        ),
        existing_vendor_invoices=[existing_void],
    )
    assert void_res.outcome is DuplicateOutcome.PROCEED

    # FR-10: -REV suffix or same invoice number with different total -> FLAGGED_POTENTIAL_REVISION
    rev_suffix_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="INV-2026-001-REV",
            total_amount=Decimal("120.00"),
        ),
        existing_vendor_invoices=[existing_active],
    )
    assert rev_suffix_res.outcome is DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
    assert rev_suffix_res.target_status == "FLAGGED_POTENTIAL_REVISION"

    rev_amount_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="INV-2026-001",
            total_amount=Decimal("125.00"),
        ),
        existing_vendor_invoices=[existing_active],
    )
    assert rev_amount_res.outcome is DuplicateOutcome.FLAGGED_POTENTIAL_REVISION

    # FR-11: Negative grand total or negative line total -> CREDIT_NOTE
    cn_total_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="CN-2026-001",
            total_amount=Decimal("-250.00"),
        ),
        existing_vendor_invoices=[],
    )
    assert cn_total_res.outcome is DuplicateOutcome.CREDIT_NOTE
    assert cn_total_res.target_status == "CREDIT_NOTE"

    cn_line_res = evaluate_duplicate_rules(
        DuplicateCheckInput(
            vendor_tax_id="US-12-3456789",
            invoice_number="INV-2026-002",
            total_amount=Decimal("50.00"),
            line_totals=[Decimal("100.00"), Decimal("-50.00")],
        ),
        existing_vendor_invoices=[],
    )
    assert cn_line_res.outcome is DuplicateOutcome.CREDIT_NOTE


# ---------------------------------------------------------------------------
# 6. Confidence Router Thresholds & Rules-First Precedence (FR-04)
# ---------------------------------------------------------------------------


def test_p12_1_confidence_router_boundaries_worst_field_and_dynamic_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-04 — Tri-tier thresholds (>=90, 80-89.99, <80), worst-field-wins, config-driven."""
    # Exact tier & colour boundaries
    assert classify_confidence_score(Decimal("100.00")) is ConfidenceTier.HIGH
    assert classify_confidence_score(Decimal("90.00")) is ConfidenceTier.HIGH
    assert classify_confidence_score(Decimal("89.99")) is ConfidenceTier.MEDIUM
    assert classify_confidence_score(Decimal("80.00")) is ConfidenceTier.MEDIUM
    assert classify_confidence_score(Decimal("79.99")) is ConfidenceTier.LOW
    assert classify_confidence_score(Decimal("0.00")) is ConfidenceTier.LOW

    # Routing outcomes & colour codes
    high_res = route_confidence_scores(
        {"invoice_number": Decimal("95.00"), "total_amount": Decimal("90.00")}
    )
    assert high_res.target_status == "VALIDATED"
    assert high_res.color_hex == ConfidenceColor.GREEN.value

    med_res = route_confidence_scores(
        {"invoice_number": Decimal("98.00"), "total_amount": Decimal("85.00")}
    )
    assert med_res.target_status == "REQUIRES_REVIEW"
    assert med_res.color_hex == ConfidenceColor.LIGHT_YELLOW.value

    # Worst-field-wins: one low-confidence line pulls overall route to REQUIRES_APPROVAL
    low_res = route_confidence_scores(
        {"invoice_number": Decimal("99.00"), "line[1].unit_price": Decimal("79.99")}
    )
    assert low_res.target_status == "REQUIRES_APPROVAL"
    assert low_res.color_hex == ConfidenceColor.AMBER_RED.value
    assert "line[1].unit_price" in low_res.low_confidence_fields

    # Dynamic thresholds from get_settings() (CLAUDE.md §16 Rule 8)
    monkeypatch.setenv("CONFIDENCE_HIGH_THRESHOLD", "95.00")
    monkeypatch.setenv("CONFIDENCE_MEDIUM_THRESHOLD", "85.00")
    get_settings.cache_clear()
    try:
        stricter = route_confidence_scores({"total_amount": Decimal("92.00")})
        assert stricter.target_status == "REQUIRES_REVIEW"
    finally:
        monkeypatch.delenv("CONFIDENCE_HIGH_THRESHOLD", raising=False)
        monkeypatch.delenv("CONFIDENCE_MEDIUM_THRESHOLD", raising=False)
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 7. Reason Code Enum Validation & Cross-Layer Parity (FR-12)
# ---------------------------------------------------------------------------


def test_p12_1_reason_code_enum_members_cross_layer_parity_and_strict_parsing() -> None:
    """# Tests: FR-12 — Exact 5 ReasonCode members, UI parity, strict ASCII parsing & OTHER comment."""
    expected_codes = {
        "OCR_MISREAD",
        "VENDOR_ROUNDING",
        "TAX_CODE_OVERRIDE",
        "VENDOR_DISCOUNT",
        "OTHER",
    }
    assert {r.value for r in ReasonCode} == expected_codes
    assert len(ReasonCode) == 5

    # UI Review Workbench dropdown options match canonical ReasonCode enum 1:1
    ui_codes = {code.value for code, _label in REASON_CODE_LABELS}
    assert ui_codes == expected_codes

    # Valid parsing for every canonical ReasonCode (enum + string)
    for code in ReasonCode:
        assert parse_reason_code(code) is code
        assert parse_reason_code(code.value) is code
        if code is not ReasonCode.OTHER:
            assert validate_reason_code(code.value) is code

    # Valid OTHER with real explanatory comment
    assert (
        validate_reason_code("OTHER", comment="Approved per vendor credit memo #99")
        is ReasonCode.OTHER
    )

    # Invalid / unknown / spoofed / non-string reason codes rejected
    for bad_code in (
        "",
        "   ",
        "UNKNOWN_CODE",
        "DELETE_ALL",
        "OCR_MISREAD\r\n",
        "OCR_MI\u017fREAD",  # Unicode Long-S uppercases to 'S' in Python — must fail!
        "VENDOR_DI\u017fCOUNT",
        "other_fake",
        123,
        True,
    ):
        with pytest.raises(ValueError):
            parse_reason_code(bad_code)  # type: ignore[arg-type]

    # ReasonCode.OTHER rejects missing, whitespace, control-char-only, and invisible-char comments
    for bad_comment in (None, "", "   ", "\x00\x07\r\n", "\u200b\u202e\ufeff"):
        with pytest.raises(ValueError, match="comment"):
            validate_reason_code(ReasonCode.OTHER, comment=bad_comment)

    # API schema InvoiceRevalidateRequest enforces ReasonCode enum + OTHER comment + tax override codes
    valid_req = InvoiceRevalidateRequest(
        reason_code=ReasonCode.TAX_CODE_OVERRIDE,
        is_reverse_charge=True,
        header_edits=InvoiceHeaderEdits(total_tax_amount=Decimal("0.00")),
    )
    assert valid_req.reason_code is ReasonCode.TAX_CODE_OVERRIDE

    with pytest.raises(ValidationError):
        InvoiceRevalidateRequest(
            reason_code="NOT_A_REASON",  # type: ignore[arg-type]
            header_edits=InvoiceHeaderEdits(subtotal=Decimal("100.00")),
        )

    with pytest.raises(ValidationError):
        InvoiceRevalidateRequest(
            reason_code=ReasonCode.OTHER,
            comment="   ",
            header_edits=InvoiceHeaderEdits(subtotal=Decimal("100.00")),
        )

    with pytest.raises(ValidationError):
        InvoiceRevalidateRequest(
            reason_code=ReasonCode.OCR_MISREAD,
            is_reverse_charge=True,
            header_edits=InvoiceHeaderEdits(total_tax_amount=Decimal("0.00")),
        )


def test_p12_1_audit_logger_enforces_reason_code_on_dotted_financial_fields_and_other_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-12 — AuditLogger blocks dotted financial edits without reason_code & spoofed OTHER comments."""
    recorded_entries: list[Any] = []

    class _FakeSession:
        async def __aenter__(self) -> "_FakeSession":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    class _FakeAuditRepo:
        def __init__(self, _session: Any) -> None:
            pass

        async def create(self, entry: Any) -> Any:
            entry.audit_id = f"aud-{len(recorded_entries) + 1}"
            recorded_entries.append(entry)
            return entry

    monkeypatch.setattr(audit_mod, "AuditLogRepository", _FakeAuditRepo)

    async def _run() -> None:
        audit_logger = AuditLogger(lambda: _FakeSession())  # type: ignore[arg-type]
        invoice_id = "inv-p12-rc-1"

        # Dotted line-item financial fields MUST require reason_code (prevents CWE-863 bypass)
        for dotted_field in (
            "line[1].line_total",
            "line[2].unit_price",
            "line[1].quantity",
            "line[1].line_tax_rate",
        ):
            with pytest.raises(ValueError, match="reason_code"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name=dotted_field,
                    previous_value="100.00",
                    new_value="90.00",
                    reason_code=None,
                )

        # Control-char-only and invisible zero-width/bidi OTHER comments MUST be rejected
        for bad_comment in ("\x00\x07\r\n", "\u200b\u202e\ufeff"):
            with pytest.raises(ValueError, match="comment"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="po_number",
                    previous_value="PO-1",
                    new_value="PO-2",
                    reason_code=ReasonCode.OTHER,
                    comment=bad_comment,
                )

        # Unicode Long-S spoofed reason_code rejected
        with pytest.raises(ValueError, match="reason_code"):
            await audit_logger.record(
                invoice_id=invoice_id,
                user_id="sarah.clerk",
                action_type=AuditActionType.EDIT,
                field_name="total_amount",
                previous_value="108.00",
                new_value="100.00",
                reason_code="OCR_MI\u017fREAD",
            )

        # Valid dotted line edit with canonical ReasonCode persists cleanly
        persisted = await audit_logger.record(
            invoice_id=invoice_id,
            user_id="sarah.clerk",
            action_type=AuditActionType.EDIT,
            field_name="line[1].line_total",
            previous_value="100.00",
            new_value="90.00",
            reason_code=ReasonCode.VENDOR_DISCOUNT,
            comment="Applied 10% loyalty discount",
        )
        assert persisted.reason_code == "VENDOR_DISCOUNT"
        assert persisted.field_name == "line[1].line_total"
        assert len(recorded_entries) == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 8. Layering & Determinism Audit (CLAUDE.md §4.2, §7.2)
# ---------------------------------------------------------------------------


def test_p12_1_validation_layer_obeys_zero_llm_and_zero_http_imports() -> None:
    """# Tests: FR-04, FR-05, FR-06, FR-07, FR-08, FR-09, FR-10, FR-11, FR-12 — Pure deterministic validation layer."""
    forbidden_prefixes = (
        "openai",
        "httpx",
        "aiohttp",
        "requests",
        "azure.",
        "src.ui",
        "src.api",
        "src.storage",
        "src.extraction.model_gateway",
        "src.extraction.extract_engine",
    )
    validation_dir = Path("src/validation")
    py_files = sorted(validation_dir.glob("*.py"))
    assert len(py_files) >= 9

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"Forbidden import {alias.name!r} in {py_file}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_prefixes), (
                    f"Forbidden import from {node.module!r} in {py_file}"
                )
