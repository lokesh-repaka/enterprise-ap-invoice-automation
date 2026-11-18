"""
Unit tests for P7-6 · Rules Engine Orchestrator (src/validation/rules_engine.py).

Tests: FR-05, FR-06, FR-07, FR-08, FR-09, FR-10, FR-11
Requirements: CLAUDE.md §4.1, §4.2, §7.1, §7.2, §7.4, §10, §16.1, LLD §2.2, §4, §5.
Strict offline isolation: zero external network or Azure calls (in-memory SQLite + pure rules).
"""

import asyncio
import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.database.models import Base, Invoice, Vendor
from src.database.repositories import InvoiceRepository, VendorRepository, compute_composite_hash
from src.database.session import create_db_engine, create_session_factory
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.rules_engine import (
    RuleName,
    RulesEngine,
    RulesEngineResult,
    VendorRuleContext,
    parse_invoice_date,
    validate_invoice_total,
    validate_line_items,
    validate_tax_rate,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")
VENDOR_MASTER_PATH = Path("./sample_data/vendor_master.json")


def _load_gt_schema(invoice_number: str) -> InvoiceExtractionSchema:
    gt = json.loads(
        (GROUND_TRUTH_DIR / f"{invoice_number}_ground_truth.json").read_text(encoding="utf-8")
    )
    return InvoiceExtractionSchema.from_ground_truth_dict(gt)


def _load_vendor_contexts() -> dict[str, VendorRuleContext]:
    vendors = json.loads(VENDOR_MASTER_PATH.read_text(encoding="utf-8"))
    return {v["TaxID_VAT"]: VendorRuleContext.from_vendor(v) for v in vendors}


# ---------------------------------------------------------------------------
# 1. CLAUDE.md Direct Re-Exports & Clean All-Pass Flow
# ---------------------------------------------------------------------------


def test_rules_engine_reexports_claude_md_contracts_and_passes_clean_invoice() -> None:
    """Tests: FR-05..FR-09 — Re-exports validate_line_items/validate_invoice_total and passes clean invoice."""
    # CLAUDE.md FR-05 / FR-06 explicit module locations
    assert callable(validate_line_items)
    assert callable(validate_invoice_total)
    assert callable(validate_tax_rate)
    assert callable(parse_invoice_date)

    contexts = _load_vendor_contexts()
    schema = _load_gt_schema("INV-2026-1001")
    vctx = contexts[schema.header.vendor_tax_id.value]

    engine = RulesEngine(repository=None)
    res = asyncio.run(engine.validate_extraction(schema, vendor_context=vctx))

    assert res.all_passed is True
    assert res.recommended_status is None
    assert res.failed_rules == ()
    assert res.errors == ()
    assert len(res.rule_outcomes) == 5
    assert [o.rule for o in res.rule_outcomes] == [
        RuleName.DUPLICATE_CHECK,
        RuleName.LINE_ARITHMETIC,
        RuleName.INVOICE_TOTAL,
        RuleName.TAX_VALIDATION,
        RuleName.DATE_NORMALIZATION,
    ]
    assert all(o.passed for o in res.rule_outcomes)
    assert res.duplicate_passed is True
    assert res.line_arithmetic_valid is True
    assert res.invoice_total_valid is True
    assert res.tax_valid is True
    assert res.date_valid is True

    summary = res.to_validation_summary()
    assert summary["line_arithmetic_valid"] is True
    assert summary["invoice_total_valid"] is True
    assert summary["tax_valid"] is True
    assert summary["active_exceptions"] == []


# ---------------------------------------------------------------------------
# 2. All 300 Ground-Truth Pilot Invoices Batch Stability & Exact Problem Routing
# ---------------------------------------------------------------------------


def test_rules_engine_chains_all_300_ground_truth_invoices_with_zero_crashes() -> None:
    """Tests: FR-05..FR-11 & AC-005 — Chains all 5 validators across all 300 GT files with exact routing."""
    contexts = _load_vendor_contexts()
    engine = RulesEngine(repository=None)
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    routed_exceptions: dict[str, str | None] = {}
    rounding_detected: list[str] = []

    async def _run():
        for path in gt_files:
            gt = json.loads(path.read_text(encoding="utf-8"))
            schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
            vctx = contexts[schema.header.vendor_tax_id.value]
            res = await engine.validate_extraction(schema, vendor_context=vctx)
            inv_num = schema.header.invoice_number.value
            if not res.all_passed:
                routed_exceptions[inv_num] = res.recommended_status
            if res.total_result is not None and res.total_result.rounding_within_tolerance:
                rounding_detected.append(inv_num)

    asyncio.run(_run())

    # Exact 4 Phase-7 problem cases routed cleanly to their canonical statuses
    assert routed_exceptions == {
        "INV-2026-1002-REV": "FLAGGED_POTENTIAL_REVISION",
        "INV-2026-1005": "REQUIRES_REVIEW",
        "INV-2026-1010": "REJECTED_TAX_MISMATCH",
        "INV-2026-1025": "CREDIT_NOTE",
    }
    # INV-2026-1030 passes within ±0.05 tolerance while surfacing rounding telemetry
    assert rounding_detected == ["INV-2026-1030"]


# ---------------------------------------------------------------------------
# 3. Async SQLite Duplicate Integration & Multi-Failure Status Precedence
# ---------------------------------------------------------------------------


def test_rules_engine_detects_sqlite_duplicate_and_enforces_status_precedence() -> None:
    """Tests: FR-05..FR-11 — Exact DB duplicate, multi-rule failures, and deterministic status precedence."""

    async def _run():
        db_engine = create_db_engine("sqlite+aiosqlite:///:memory:")
        async with db_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(db_engine)
        try:
            async with session_factory() as session:
                vrepo = VendorRepository(session)
                vendor = await vrepo.create(
                    Vendor(
                        vendor_tax_id="ESA98765432",
                        vendor_id="VEND-3002",
                        vendor_name="Mediterraneo Quimica SA",
                        country_code="ES",
                        date_format_locale="DD/MM/YYYY",
                        default_currency="EUR",
                        standard_tax_rate=Decimal("0.2100"),
                    )
                )
                irepo = InvoiceRepository(session)
                schema = _load_gt_schema("INV-2026-1001")
                dup_hash = compute_composite_hash(
                    schema.header.vendor_tax_id.value,
                    schema.header.invoice_number.value,
                    schema.header.total_amount.value,
                )
                await irepo.create(
                    Invoice(
                        vendor_tax_id=vendor.vendor_tax_id,
                        invoice_number=schema.header.invoice_number.value,
                        total_amount=schema.header.total_amount.value,
                        currency="EUR",
                        status="VALIDATED",
                        composite_hash=dup_hash,
                    )
                )

                rules_engine = RulesEngine(repository=irepo)
                vctx = VendorRuleContext.from_vendor(vendor)

                # Duplicate submission against SQLite -> DUPLICATE_INVOICE
                dup_res = await rules_engine.validate_extraction(
                    schema, vendor_context=vctx, current_invoice_id="inv-dup-new"
                )
                assert dup_res.all_passed is False
                assert dup_res.duplicate_passed is False
                assert dup_res.recommended_status == "DUPLICATE_INVOICE"
                assert RuleName.DUPLICATE_CHECK in dup_res.failed_rules
        finally:
            await db_engine.dispose()

    asyncio.run(_run())

    # Multi-rule failure precedence: Tax mismatch + Line math error + Bad date -> REJECTED_TAX_MISMATCH wins
    engine = RulesEngine(repository=None)
    vctx_de = VendorRuleContext(country_code="DE", date_locale="DD/MM/YYYY")
    multi_fail = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": 2, "unit_price": 500.00, "line_total": 990.00}],
        subtotal=Decimal("1000.00"),
        tax_amount=Decimal("150.00"),  # 15% invalid in DE
        total_amount=Decimal("1200.00"),  # 1000 + 150 != 1200
        vendor_context=vctx_de,
        invoice_date="05/06/2026",
        due_date="06/05/2026",  # chronological conflict under EU
    )
    assert multi_fail.all_passed is False
    assert multi_fail.line_arithmetic_valid is False
    assert multi_fail.invoice_total_valid is False
    assert multi_fail.tax_valid is False
    assert multi_fail.date_valid is False
    assert len(multi_fail.failed_rules) == 4
    assert multi_fail.recommended_status == "REJECTED_TAX_MISMATCH"


# ---------------------------------------------------------------------------
# 4. CLAUDE.md §7.4 Re-Validation Workflow & Malformed OCR Stability
# ---------------------------------------------------------------------------


def test_revalidation_workflow_and_malformed_ocr_date_fails_closed_without_crashing() -> None:
    """Tests: FR-12 & CLAUDE.md §7.4 — Re-validation passes after clerk tax override; bad OCR fails closed."""
    engine = RulesEngine(repository=None)
    vctx_de = VendorRuleContext(
        country_code="DE",
        date_locale="DD/MM/YYYY",
        standard_tax_rate=Decimal("0.19"),
        require_exemption_for_zero_tax=True,
    )

    # Before clerk edit: 0% tax without reverse-charge flag -> REJECTED_TAX_MISMATCH
    before = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": 10, "unit_price": 125.00, "line_total": 1250.00}],
        subtotal=Decimal("1250.00"),
        tax_amount=Decimal("0.00"),
        total_amount=Decimal("1250.00"),
        vendor_context=vctx_de,
        is_reverse_charge=False,
    )
    assert before.all_passed is False
    assert before.tax_valid is False
    assert before.recommended_status == "REJECTED_TAX_MISMATCH"

    # After clerk enables reverse charge -> all rules pass!
    after = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": 10, "unit_price": 125.00, "line_total": 1250.00}],
        subtotal=Decimal("1250.00"),
        tax_amount=Decimal("0.00"),
        total_amount=Decimal("1250.00"),
        vendor_context=vctx_de,
        is_reverse_charge=True,
    )
    assert after.all_passed is True
    assert after.recommended_status is None
    assert after.errors == ()

    # Malformed OCR date string (e.g. "99/99/2026") MUST fail closed without crashing batch
    bad_ocr = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": 1, "unit_price": 100.00, "line_total": 100.00}],
        subtotal=Decimal("100.00"),
        tax_amount=Decimal("19.00"),
        total_amount=Decimal("119.00"),
        vendor_context=vctx_de,
        invoice_date="99/99/2026",
    )
    assert bad_ocr.all_passed is False
    assert bad_ocr.date_valid is False
    assert bad_ocr.recommended_status == "REQUIRES_REVIEW"
    assert RuleName.DATE_NORMALIZATION in bad_ocr.failed_rules


# ---------------------------------------------------------------------------
# 5. Security, Self-Approval Prevention & Layer Isolation (CLAUDE.md §4.2, §16.1)
# ---------------------------------------------------------------------------


def test_security_never_approves_frozen_results_and_layer_isolation() -> None:
    """Tests: CLAUDE.md §4.2, §16.1 — Never emits approval status, blocks mutation, zero LLM/SQL imports."""
    # Forbidden approval statuses cannot be assigned to RulesEngineResult
    for forbidden_status in ("APPROVED_CLERK", "APPROVED_MANAGER", "STAGED_FOR_EXPORT"):
        with pytest.raises(ValidationError):
            RulesEngineResult(
                all_passed=True,
                rule_outcomes=(),
                failed_rules=(),
                errors=(),
                recommended_status=forbidden_status,  # type: ignore[arg-type]
                duplicate_passed=True,
                line_arithmetic_valid=True,
                invoice_total_valid=True,
                tax_valid=True,
                date_valid=True,
            )

    # Extra injected fields rejected on VendorRuleContext
    with pytest.raises(ValidationError):
        VendorRuleContext(
            country_code="US",
            skip_validation=True,  # type: ignore[call-arg]
        )

    # Layer isolation check (CLAUDE.md §4.2): zero LLM/SQLAlchemy/API/UI/storage imports
    src_code = Path("src/validation/rules_engine.py").read_text(encoding="utf-8")
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


def test_pentest_credit_note_never_passes_as_regular_even_when_duplicate_check_skipped() -> None:
    """Security (SEC-157 · CWE-840 / CLAUDE.md §16.1): Credit notes cannot bypass routing when duplicate check is skipped."""
    contexts = _load_vendor_contexts()
    engine = RulesEngine(repository=None)

    # 1. Extraction with run_duplicate_check=False on INV-2026-1025 (negative line item -171.00)
    cn_schema = _load_gt_schema("INV-2026-1025")
    vctx = contexts[cn_schema.header.vendor_tax_id.value]
    res_skip_dup = asyncio.run(
        engine.validate_extraction(cn_schema, vendor_context=vctx, run_duplicate_check=False)
    )
    assert res_skip_dup.all_passed is False
    assert res_skip_dup.recommended_status == "CREDIT_NOTE"

    # 2. Re-validation with clerk-edited negative total MUST also route to CREDIT_NOTE
    res_reval_cn = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": -1, "unit_price": 500.00, "line_total": -500.00}],
        subtotal=Decimal("-500.00"),
        tax_amount=Decimal("-95.00"),
        total_amount=Decimal("-595.00"),
        vendor_context=vctx,
    )
    assert res_reval_cn.all_passed is False
    assert res_reval_cn.recommended_status == "CREDIT_NOTE"


def test_pentest_partial_line_tax_rate_omission_and_vendor_context_hardening() -> None:
    """Security (SEC-158/159/160 · CWE-20/400/704/840): Block partial line tax omission, exponent bombs, and non-bool flags."""
    engine = RulesEngine(repository=None)
    vctx_gb = VendorRuleContext(country_code="GB", date_locale="DD/MM/YYYY")

    # 1. Partial line tax_rate omission cannot silently drop non-statutory 15% UK rate on Line 1
    with pytest.raises(ValueError, match="Partial per-line tax_rate"):
        engine.validate_revalidation(
            lines=[
                {
                    "line_number": 1,
                    "quantity": 1,
                    "unit_price": 1000.00,
                    "line_total": 1000.00,
                    "tax_rate": 0.15,
                },
                {
                    "line_number": 2,
                    "quantity": 1,
                    "unit_price": 1000.00,
                    "line_total": 1000.00,
                },
            ],
            subtotal=Decimal("2000.00"),
            tax_amount=Decimal("100.00"),
            total_amount=Decimal("2100.00"),
            vendor_context=vctx_gb,
        )

    # 2. Exponent bombs, NaN, underscores, and booleans rejected on VendorRuleContext.standard_tax_rate
    for bad_rate in ("1E-5000000", "NaN", "0_20", True, Decimal("-0.05"), Decimal("1.5")):
        with pytest.raises(ValidationError):
            VendorRuleContext(country_code="US", standard_tax_rate=bad_rate)  # type: ignore[arg-type]

    # 3. Non-boolean flags rejected fail-closed (CWE-704)
    schema = _load_gt_schema("INV-2026-1001")
    with pytest.raises(ValueError, match="boolean"):
        asyncio.run(
            engine.validate_extraction(
                schema,
                vendor_context=vctx_gb,
                run_duplicate_check="false",  # type: ignore[arg-type]
            )
        )

    with pytest.raises(ValueError, match="boolean"):
        engine.validate_revalidation(
            lines=[],
            subtotal=Decimal("0.00"),
            tax_amount=Decimal("0.00"),
            total_amount=Decimal("0.00"),
            vendor_context=vctx_gb,
            is_reverse_charge="false",  # type: ignore[arg-type]
        )

    # 4. Frozen RulesEngineResult cannot be mutated after failure
    failed = engine.validate_revalidation(
        lines=[{"line_number": 1, "quantity": 1, "unit_price": 100.00, "line_total": 999.00}],
        subtotal=Decimal("100.00"),
        tax_amount=Decimal("20.00"),
        total_amount=Decimal("120.00"),
        vendor_context=vctx_gb,
    )
    assert failed.all_passed is False
    with pytest.raises(ValidationError):
        failed.all_passed = True  # type: ignore[misc]
