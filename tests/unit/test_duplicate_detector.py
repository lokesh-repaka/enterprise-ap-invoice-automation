"""
Unit tests for P7-1 · Duplicate, Revision, and Credit Note Detector (src/validation/duplicate_detector.py).

Tests: FR-09, FR-10, FR-11
Requirements: BR-013, BR-013a, BR-013b, ADR-006, CLAUDE.md §4.2, §6, §7.1, §8, §16.1, N3, N8.
Strict offline isolation: zero external network or Azure calls (in-memory SQLite + pure unit checks).
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.database.models import Base, Invoice, Vendor
from src.database.repositories import (
    InvoiceRepository,
    VendorRepository,
)
from src.database.repositories import (
    compute_composite_hash as repo_compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory
from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.duplicate_detector import (
    MAX_EXISTING_LOOKUP_RECORDS,
    MAX_LINE_ITEMS,
    DuplicateCheckInput,
    DuplicateDetectionResult,
    DuplicateDetector,
    DuplicateOutcome,
    compute_composite_hash,
    detect_credit_note,
    detect_revision_suffix,
    evaluate_duplicate_rules,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")


@dataclass
class _StubInvoiceRecord:
    invoice_id: str
    vendor_tax_id: str
    invoice_number: str
    total_amount: Decimal
    status: str
    composite_hash: str


async def _setup_db_with_vendors():
    """Initialize an isolated in-memory async SQLite database with test vendors."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    async with session_factory() as session:
        vrepo = VendorRepository(session)
        await vrepo.create(
            Vendor(
                vendor_tax_id="ESA98765432",
                vendor_id="VEND-3002",
                vendor_name="Mediterraneo Quimica SA",
                country_code="ES",
                date_format_locale="DD/MM/YYYY",
                default_currency="EUR",
            )
        )
        await vrepo.create(
            Vendor(
                vendor_tax_id="DE987654321",
                vendor_id="VEND-2002",
                vendor_name="Munich Tech GmbH",
                country_code="DE",
                date_format_locale="DD/MM/YYYY",
                default_currency="EUR",
            )
        )
        await vrepo.create(
            Vendor(
                vendor_tax_id="DE123456789",
                vendor_id="VEND-2001",
                vendor_name="Berlin Systems GmbH",
                country_code="DE",
                date_format_locale="DD/MM/YYYY",
                default_currency="EUR",
            )
        )
    return engine, session_factory


# ---------------------------------------------------------------------------
# 1. FR-09: SHA-256 Composite Key Parity & Input Hardening
# ---------------------------------------------------------------------------


def test_composite_hash_matches_all_300_ground_truth_files_and_repository() -> None:
    """Tests: FR-09 — 100% SHA-256 composite key parity with sample_data/ground_truth/ and repo."""
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    for path in gt_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        hdr = data["header"]
        expected = data["invoice_metadata"]["composite_hash"]
        computed = compute_composite_hash(
            vendor_tax_id=hdr["vendor_tax_id"],
            invoice_number=hdr["invoice_number"],
            total_amount=hdr["total_amount"],
        )
        assert computed == expected, f"Hash mismatch on {path.name}"
        assert computed == repo_compute_composite_hash(
            hdr["vendor_tax_id"], hdr["invoice_number"], hdr["total_amount"]
        )


def test_composite_hash_normalization_and_security_guards() -> None:
    """Tests: FR-09 — Normalization equivalence and anti-spoofing/DoS guards (CWE-20/74/451)."""
    base_hash = compute_composite_hash("ESA98765432", "INV-2026-1001", Decimal("3449.71"))
    assert base_hash == compute_composite_hash(" ESA98765432 ", " INV-2026-1001 ", "3449.710")
    assert base_hash == compute_composite_hash("ESA98765432", "INV-2026-1001", 3449.71)

    # Signed zero canonicalization (-0.00 == 0.00) defeats signed-zero hash bypass
    assert compute_composite_hash("ESA98765432", "INV-ZERO", Decimal("-0.00")) == (
        compute_composite_hash("ESA98765432", "INV-ZERO", Decimal("0.00"))
    )

    # Reject empty/whitespace identifiers
    with pytest.raises(ValueError, match="vendor_tax_id"):
        compute_composite_hash("   ", "INV-1", Decimal("10.00"))
    with pytest.raises(ValueError, match="invoice_number"):
        compute_composite_hash("US-12-3456789", "", Decimal("10.00"))

    # Reject invisible Unicode bidi/zero-width characters that attempt composite_hash bypass
    for spoofed in ("INV-2026-1001\u200b", "INV-2026\u202e-1001", "\ufeffINV-2026-1001"):
        with pytest.raises(ValueError, match="bidi/zero-width"):
            compute_composite_hash("ESA98765432", spoofed, Decimal("100.00"))

    # Reject control characters
    with pytest.raises(ValueError, match="control characters"):
        compute_composite_hash("ESA98765432\n", "INV-1", Decimal("100.00"))

    # Reject booleans, NaN, Infinity, and scientific-notation exponent bombs (CWE-20/400)
    for bad_amount in (True, False, "NaN", "Infinity", "-Infinity", "1E-5000000", "1E500"):
        with pytest.raises(ValueError):
            compute_composite_hash("ESA98765432", "INV-1", bad_amount)


# ---------------------------------------------------------------------------
# 2. FR-09: Exact Duplicate Detection with Async SQLite InvoiceRepository
# ---------------------------------------------------------------------------


def test_exact_duplicate_detection_against_sqlite_repository() -> None:
    """Tests: FR-09 — Exact SHA-256 hash match flags DUPLICATE_INVOICE; VOID/self excluded."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendors()
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                detector = DuplicateDetector(repo)

                # First submission — unique, proceeds to rules engine
                first_res = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                )
                assert first_res.outcome == DuplicateOutcome.PROCEED
                assert first_res.target_status is None
                assert first_res.should_proceed is True
                assert first_res.is_duplicate is False
                assert first_res.matched_invoice_id is None

                # Persist original invoice as VALIDATED
                original = await repo.create(
                    Invoice(
                        vendor_tax_id="ESA98765432",
                        invoice_number="INV-2026-1001",
                        total_amount=Decimal("3449.71"),
                        currency="EUR",
                        status="VALIDATED",
                        composite_hash=first_res.composite_hash,
                    )
                )

                # Self-check (same current_invoice_id) MUST NOT flag itself
                self_res = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                    current_invoice_id=original.invoice_id,
                )
                assert self_res.outcome == DuplicateOutcome.PROCEED
                assert self_res.should_proceed is True

                # Second submission with new invoice_id -> DUPLICATE_INVOICE
                dup_res = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount="3449.710",
                    current_invoice_id="inv-new-duplicate-002",
                )
                assert dup_res.outcome == DuplicateOutcome.DUPLICATE_INVOICE
                assert dup_res.target_status == "DUPLICATE_INVOICE"
                assert dup_res.should_proceed is False
                assert dup_res.is_duplicate is True
                assert dup_res.matched_invoice_id == original.invoice_id
                assert dup_res.matched_invoice_number == "INV-2026-1001"
                assert dup_res.matched_total_amount == Decimal("3449.71")
                assert dup_res.amount_difference == Decimal("0.00")

                # If original is VOID or REJECTED_DUPLICATE, resubmission is allowed
                await repo.update_status(original.invoice_id, "VOID")
                after_void = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                    current_invoice_id="inv-resubmitted-003",
                )
                assert after_void.outcome == DuplicateOutcome.PROCEED
                assert after_void.should_proceed is True

                await repo.update_status(original.invoice_id, "REJECTED_DUPLICATE")
                after_rejected_dup = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                    current_invoice_id="inv-resubmitted-004",
                )
                assert after_rejected_dup.outcome == DuplicateOutcome.PROCEED
                assert after_rejected_dup.should_proceed is True
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_exact_duplicate_fallback_on_vendor_number_and_equal_total() -> None:
    """Tests: FR-09 — Even if stored composite_hash was stale, matching (vendor, number, total) flags duplicate."""
    candidate = DuplicateCheckInput(
        vendor_tax_id="ESA98765432",
        invoice_number="INV-2026-9999",
        total_amount=Decimal("750.00"),
        current_invoice_id="inv-new",
    )
    existing = _StubInvoiceRecord(
        invoice_id="inv-old",
        vendor_tax_id="ESA98765432",
        invoice_number="inv-2026-9999",  # differing case (Azure SQL CI collation parity)
        total_amount=Decimal("750.00"),
        status="APPROVED_CLERK",
        composite_hash="stale-placeholder-hash",
    )
    result = evaluate_duplicate_rules(candidate, existing_vendor_invoices=[existing])
    assert result.outcome == DuplicateOutcome.DUPLICATE_INVOICE
    assert result.target_status == "DUPLICATE_INVOICE"
    assert result.matched_invoice_id == "inv-old"
    assert result.amount_difference == Decimal("0.00")


# ---------------------------------------------------------------------------
# 3. FR-10: Revision Suffix & Amount-Difference Revision Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_value", "expected_base", "expected_suffix"),
    [
        ("INV-2026-1002-REV", "INV-2026-1002", "-REV"),
        ("INV-2026-1002-rev", "INV-2026-1002", "-rev"),
        ("INV-2026-1002_REV", "INV-2026-1002", "_REV"),
        ("INV-2026-1002 REV", "INV-2026-1002", " REV"),
        ("INV-2026-1002.REV", "INV-2026-1002", ".REV"),
        ("INV-2026-1002-REV1", "INV-2026-1002", "-REV1"),
        ("INV-2026-1002-REV2", "INV-2026-1002", "-REV2"),
        ("INV-2026-1002-REV-02", "INV-2026-1002", "-REV-02"),
        ("INV-2026-1002 Rev 2", "INV-2026-1002", " Rev 2"),
        ("INV-2026-1002-Rev.3", "INV-2026-1002", "-Rev.3"),
        ("INV-2026-1002-RevA", "INV-2026-1002", "-RevA"),
        ("INV-2026-1002-REVISION", "INV-2026-1002", "-REVISION"),
        ("INV-2026-1002-REVISION-2", "INV-2026-1002", "-REVISION-2"),
        ("INV-2026-1002-v2", "INV-2026-1002", "-v2"),
        ("INV-2026-1002_V3", "INV-2026-1002", "_V3"),
        ("INV-2026-1002 v2.1", "INV-2026-1002", " v2.1"),
        ("INV-2026-1002-ver2", "INV-2026-1002", "-ver2"),
        ("INV-2026-1002-v10", "INV-2026-1002", "-v10"),
        ("INV-2026-1002_version_2", "INV-2026-1002", "_version_2"),
        ("INV-2026-1002-REV-v2", "INV-2026-1002", "-REV-v2"),
    ],
)
def test_detect_revision_suffix_positive_cases(
    raw_value: str, expected_base: str, expected_suffix: str
) -> None:
    """Tests: FR-10 — Recognizes all documented revision suffixes (-REV, Rev, v2, etc.)."""
    has_rev, base, suffix = detect_revision_suffix(raw_value)
    assert has_rev is True
    assert base == expected_base
    assert suffix == expected_suffix


@pytest.mark.parametrize(
    "clean_value",
    [
        "INV-2026-1001",
        "INV-2026-1002",
        "REVENUE-2026-001",
        "REV-2026-001",
        "INV-2026-PREV",
        "INV-2026-1001-V1",
        "INV-2026-1001-V0",
        "INV-2026-VEND2",
        "INV-2026-1001-REVIEW",
        "INV-2026-1001-REVENUE",
        "-REV",
    ],
)
def test_detect_revision_suffix_zero_false_positives(clean_value: str) -> None:
    """Tests: FR-10 — Standard invoice numbers and prefixes never trigger false revision flags."""
    has_rev, base, suffix = detect_revision_suffix(clean_value)
    assert has_rev is False
    assert base == clean_value
    assert suffix is None


def test_revision_detection_links_base_invoice_and_detects_amount_diff_and_filename_suffix() -> (
    None
):
    """Tests: FR-10 — Links -REV to base invoice, flags differing totals, and inspects filenames."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendors()
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                detector = DuplicateDetector(repo)

                # Seed original invoice INV-2026-1002 for DE987654321
                orig_hash = compute_composite_hash(
                    "DE987654321", "INV-2026-1002", Decimal("1500.00")
                )
                orig = await repo.create(
                    Invoice(
                        vendor_tax_id="DE987654321",
                        invoice_number="INV-2026-1002",
                        total_amount=Decimal("1500.00"),
                        currency="EUR",
                        status="APPROVED_CLERK",
                        composite_hash=orig_hash,
                    )
                )

                # Case A: -REV suffix with updated total -> links to original & computes diff
                rev_res = await detector.check_invoice(
                    vendor_tax_id="DE987654321",
                    invoice_number="INV-2026-1002-REV",
                    total_amount=Decimal("1722.17"),
                    filename="INV-2026-1002-REV.pdf",
                )
                assert rev_res.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
                assert rev_res.target_status == "FLAGGED_POTENTIAL_REVISION"
                assert rev_res.should_proceed is False
                assert rev_res.is_potential_revision is True
                assert rev_res.revision_suffix_detected is True
                assert rev_res.detected_revision_suffix == "-REV"
                assert rev_res.revision_detected_in == "both"
                assert rev_res.base_invoice_number == "INV-2026-1002"
                assert rev_res.matched_invoice_id == orig.invoice_id
                assert rev_res.matched_total_amount == Decimal("1500.00")
                assert rev_res.amount_difference == Decimal("222.17")

                # Case B: Same invoice number, NO -REV suffix, DIFFERENT total -> revision
                diff_total_res = await detector.check_invoice(
                    vendor_tax_id="DE987654321",
                    invoice_number="INV-2026-1002",
                    total_amount=Decimal("1425.50"),
                )
                assert diff_total_res.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
                assert diff_total_res.target_status == "FLAGGED_POTENTIAL_REVISION"
                assert diff_total_res.revision_suffix_detected is False
                assert diff_total_res.matched_invoice_id == orig.invoice_id
                assert diff_total_res.amount_difference == Decimal("-74.50")

                # Case C: Filename-only revision suffix (even with path traversal prefix: CWE-22)
                file_only_res = await detector.check_invoice(
                    vendor_tax_id="DE987654321",
                    invoice_number="INV-2026-8888",
                    total_amount=Decimal("400.00"),
                    filename="../../uploads/INV-2026-8888_v2.xlsx",
                )
                assert file_only_res.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
                assert file_only_res.revision_suffix_detected is True
                assert file_only_res.detected_revision_suffix == "_v2"
                assert file_only_res.revision_detected_in == "filename"
                assert file_only_res.matched_invoice_id is None

                # Case D: -REV suffix with SAME total (metadata/line-item revision) -> revision
                same_total_rev = await detector.check_invoice(
                    vendor_tax_id="DE987654321",
                    invoice_number="INV-2026-1002-REV",
                    total_amount=Decimal("1500.00"),
                )
                assert same_total_rev.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
                assert same_total_rev.matched_invoice_id == orig.invoice_id
                assert same_total_rev.amount_difference == Decimal("0.00")

                # Case E: Persisting the revision and re-submitting the EXACT SAME revision -> DUPLICATE
                rev_record = await repo.create(
                    Invoice(
                        vendor_tax_id="DE987654321",
                        invoice_number="INV-2026-1002-REV",
                        total_amount=Decimal("1722.17"),
                        currency="EUR",
                        status="FLAGGED_POTENTIAL_REVISION",
                        composite_hash=rev_res.composite_hash,
                    )
                )
                dup_rev = await detector.check_invoice(
                    vendor_tax_id="DE987654321",
                    invoice_number="INV-2026-1002-REV",
                    total_amount=Decimal("1722.17"),
                )
                assert dup_rev.outcome == DuplicateOutcome.DUPLICATE_INVOICE
                assert dup_rev.target_status == "DUPLICATE_INVOICE"
                assert dup_rev.matched_invoice_id == rev_record.invoice_id
        finally:
            await engine.dispose()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. FR-11: Credit Note Detection (Negative Total / Negative Line Items)
# ---------------------------------------------------------------------------


def test_credit_note_detection_negative_total_subtotal_and_line_items() -> None:
    """Tests: FR-11 — Negative grand total, subtotal, or line items classify as CREDIT_NOTE."""
    # Negative grand total
    is_cn, neg_tot, neg_lines = detect_credit_note(
        Decimal("-1250.00"), line_totals=[Decimal("-1000.00"), Decimal("-250.00")]
    )
    assert is_cn is True
    assert neg_tot is True
    assert neg_lines == (1, 2)

    # Positive grand total with a single negative credit line item (mirrors INV-2026-1025)
    is_cn2, neg_tot2, neg_lines2 = detect_credit_note(
        Decimal("5228.86"),
        subtotal=Decimal("4394.00"),
        line_totals=[Decimal("-171.00"), Decimal("25.00"), Decimal("3400.00")],
    )
    assert is_cn2 is True
    assert neg_tot2 is False
    assert neg_lines2 == (1,)

    # Negative subtotal with zero total
    is_cn3, neg_tot3, neg_lines3 = detect_credit_note(
        Decimal("0.00"), subtotal=Decimal("-50.00"), line_totals=[]
    )
    assert is_cn3 is True
    assert neg_tot3 is False
    assert neg_lines3 == ()

    # Zero-dollar regular invoice with non-negative lines is NOT a credit note
    is_cn4, neg_tot4, neg_lines4 = detect_credit_note(
        Decimal("0.00"), subtotal=Decimal("0.00"), line_totals=[Decimal("0.00")]
    )
    assert is_cn4 is False
    assert neg_tot4 is False
    assert neg_lines4 == ()


def test_credit_note_precedence_over_revision_and_duplicate_credit_note_blocked() -> None:
    """Tests: FR-11 & FR-09 — Negative invoice referencing original -> CREDIT_NOTE; exact dup -> DUPLICATE."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendors()
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                detector = DuplicateDetector(repo)

                orig_hash = compute_composite_hash(
                    "DE123456789", "INV-2026-500", Decimal("1000.00")
                )
                orig = await repo.create(
                    Invoice(
                        vendor_tax_id="DE123456789",
                        invoice_number="INV-2026-500",
                        total_amount=Decimal("1000.00"),
                        currency="EUR",
                        status="APPROVED_CLERK",
                        composite_hash=orig_hash,
                    )
                )

                # Credit note referencing same invoice number with negative total -> CREDIT_NOTE (never regular/revision)
                cn_res = await detector.check_invoice(
                    vendor_tax_id="DE123456789",
                    invoice_number="INV-2026-500",
                    total_amount=Decimal("-1000.00"),
                    line_totals=[Decimal("-1000.00")],
                )
                assert cn_res.outcome == DuplicateOutcome.CREDIT_NOTE
                assert cn_res.target_status == "CREDIT_NOTE"
                assert cn_res.should_proceed is False
                assert cn_res.is_credit_note is True
                assert cn_res.negative_total_detected is True
                assert cn_res.matched_invoice_id == orig.invoice_id
                assert cn_res.amount_difference == Decimal("-2000.00")

                # Persist credit note, then re-submit identical credit note -> DUPLICATE_INVOICE (prevents double credit)
                cn_row = await repo.create(
                    Invoice(
                        vendor_tax_id="DE123456789",
                        invoice_number="INV-2026-500",
                        total_amount=Decimal("-1000.00"),
                        currency="EUR",
                        status="CREDIT_NOTE",
                        composite_hash=cn_res.composite_hash,
                    )
                )
                dup_cn = await detector.check_invoice(
                    vendor_tax_id="DE123456789",
                    invoice_number="INV-2026-500",
                    total_amount=Decimal("-1000.00"),
                    line_totals=[Decimal("-1000.00")],
                )
                assert dup_cn.outcome == DuplicateOutcome.DUPLICATE_INVOICE
                assert dup_cn.target_status == "DUPLICATE_INVOICE"
                assert dup_cn.matched_invoice_id == cn_row.invoice_id
        finally:
            await engine.dispose()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Ground-Truth Sample Dataset & P6-3 InvoiceExtractionSchema Integration
# ---------------------------------------------------------------------------


def test_detect_from_extraction_matches_ground_truth_problem_cases() -> None:
    """Tests: FR-09, FR-10, FR-11 — End-to-end compatibility with P6-3 InvoiceExtractionSchema."""

    async def _run():
        detector = DuplicateDetector(repository=None)

        # Standard invoice -> PROCEED
        gt_std = json.loads(
            (GROUND_TRUTH_DIR / "INV-2026-1001_ground_truth.json").read_text(encoding="utf-8")
        )
        schema_std = InvoiceExtractionSchema.from_ground_truth_dict(gt_std)
        res_std = await detector.detect_from_extraction(schema_std)
        assert res_std.outcome == DuplicateOutcome.PROCEED
        assert res_std.should_proceed is True
        assert res_std.composite_hash == gt_std["invoice_metadata"]["composite_hash"]

        # Potential revision sample (INV-2026-1002-REV) -> FLAGGED_POTENTIAL_REVISION
        gt_rev = json.loads(
            (GROUND_TRUTH_DIR / "INV-2026-1002-REV_ground_truth.json").read_text(encoding="utf-8")
        )
        schema_rev = InvoiceExtractionSchema.from_ground_truth_dict(gt_rev)
        res_rev = await detector.detect_from_extraction(schema_rev)
        assert res_rev.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
        assert res_rev.target_status == "FLAGGED_POTENTIAL_REVISION"
        assert res_rev.base_invoice_number == "INV-2026-1002"
        assert res_rev.composite_hash == gt_rev["invoice_metadata"]["composite_hash"]

        # Credit note sample (INV-2026-1025 with negative line item -171.00) -> CREDIT_NOTE
        gt_cn = json.loads(
            (GROUND_TRUTH_DIR / "INV-2026-1025_ground_truth.json").read_text(encoding="utf-8")
        )
        schema_cn = InvoiceExtractionSchema.from_ground_truth_dict(gt_cn)
        res_cn = await detector.detect_from_extraction(schema_cn)
        assert res_cn.outcome == DuplicateOutcome.CREDIT_NOTE
        assert res_cn.target_status == "CREDIT_NOTE"
        assert res_cn.negative_line_numbers == (1,)
        assert res_cn.composite_hash == gt_cn["invoice_metadata"]["composite_hash"]

        # Verify zero false positives on all 298 non-revision, non-credit-note sample invoices
        for path in sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json")):
            gt = json.loads(path.read_text(encoding="utf-8"))
            case_type = gt["invoice_metadata"]["test_case_type"]
            schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
            res = await detector.detect_from_extraction(schema)
            if case_type == "potential_revision":
                assert res.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
            elif case_type == "credit_note":
                assert res.outcome == DuplicateOutcome.CREDIT_NOTE
            else:
                assert res.outcome == DuplicateOutcome.PROCEED, f"Unexpected flag on {path.name}"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Security, Guardrails, PII Masking & Layer Isolation (CLAUDE.md §4.2, §8, §16.1)
# ---------------------------------------------------------------------------


def test_pii_masking_bounds_and_layer_isolation(caplog: pytest.LogCaptureFixture) -> None:
    """Tests: N3, N8, CLAUDE.md §4.2, §8, §16.1 — Zero raw Tax ID leaks, bounded DoS, zero LLM/SQL imports."""
    raw_tax_id = "US-99-8877665"

    # 1. Input repr and log output MUST mask vendor_tax_id as ***-**-XXXX
    candidate = DuplicateCheckInput(
        vendor_tax_id=raw_tax_id,
        invoice_number="INV-2026-777-REV",
        total_amount=Decimal("250.00"),
    )
    assert raw_tax_id not in repr(candidate)
    assert "***-**-7665" in repr(candidate)

    detector = DuplicateDetector(repository=None)
    with caplog.at_level(logging.INFO, logger="ap.validation.duplicate_detector"):
        result = asyncio.run(detector.detect(candidate))

    assert raw_tax_id not in result.reason
    assert raw_tax_id not in repr(result)
    for record in caplog.records:
        assert raw_tax_id not in record.getMessage()
        assert getattr(record, "vendor_tax_id_masked", "") == "***-**-7665"

    # 2. Never emits approval statuses (CLAUDE.md §16.1)
    forbidden_statuses = {"APPROVED_CLERK", "APPROVED_MANAGER", "STAGED_FOR_EXPORT"}
    assert {o.value for o in DuplicateOutcome}.isdisjoint(forbidden_statuses)

    # 3. Extra injected fields & oversized line_totals blocked (CWE-915 / CWE-400)
    with pytest.raises(ValidationError):
        DuplicateCheckInput(
            vendor_tax_id=raw_tax_id,
            invoice_number="INV-1",
            total_amount=Decimal("10.00"),
            status="APPROVED_CLERK",  # type: ignore[call-arg]
        )

    with pytest.raises(ValueError, match="maximum allowed count"):
        detect_credit_note(Decimal("100.00"), line_totals=[Decimal("1.00")] * (MAX_LINE_ITEMS + 1))

    # 4. Layering check (CLAUDE.md §4.2): src/validation/ MUST NOT call LLMs or import SQLAlchemy/API/UI
    src_code = Path("src/validation/duplicate_detector.py").read_text(encoding="utf-8")
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
        assert forbidden not in src_code, f"Forbidden import/token '{forbidden}' found in validator"


def test_pentest_unicode_soft_hyphen_nbsp_and_fullwidth_hash_bypass_blocked() -> None:
    """Security (SEC-137 · CWE-172/CWE-451): Block soft-hyphen, NBSP, and fullwidth spoofing."""
    for spoofed in (
        "INV-2026\u00ad-1001",  # invisible soft hyphen (Unicode Cf)
        "INV\u00a02026-1001",  # non-breaking space (Unicode Zs)
        "INV-2026-100\uff11",  # fullwidth digit '１' (NFKC spoofing)
        "INV\uff0d2026-1001",  # fullwidth hyphen '－' (NFKC spoofing)
        "INV-2026\u2060-1001",  # word joiner (Unicode Cf)
    ):
        with pytest.raises(ValueError):
            compute_composite_hash("ESA98765432", spoofed, Decimal("100.00"))


def test_pentest_mixed_case_duplicate_and_revision_bypass_blocked_on_sqlite() -> None:
    """Security (SEC-138 · CWE-178): Lowercase 'inv-2026-1001' cannot bypass uppercase DB record on SQLite."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendors()
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                detector = DuplicateDetector(repo)

                orig_hash = compute_composite_hash(
                    "ESA98765432", "INV-2026-1001", Decimal("3449.71")
                )
                orig = await repo.create(
                    Invoice(
                        vendor_tax_id="ESA98765432",
                        invoice_number="INV-2026-1001",
                        total_amount=Decimal("3449.71"),
                        currency="EUR",
                        status="VALIDATED",
                        composite_hash=orig_hash,
                    )
                )

                # Lowercase exact duplicate MUST still be caught as DUPLICATE_INVOICE
                dup_lower = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="inv-2026-1001",
                    total_amount=Decimal("3449.71"),
                    current_invoice_id="inv-attacker-lower",
                )
                assert dup_lower.outcome == DuplicateOutcome.DUPLICATE_INVOICE
                assert dup_lower.matched_invoice_id == orig.invoice_id

                # Lowercase revision MUST link to original uppercase invoice
                rev_lower = await detector.check_invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="inv-2026-1001-rev",
                    total_amount=Decimal("3999.00"),
                    current_invoice_id="inv-attacker-rev-lower",
                )
                assert rev_lower.outcome == DuplicateOutcome.FLAGGED_POTENTIAL_REVISION
                assert rev_lower.matched_invoice_id == orig.invoice_id
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_pentest_cross_vendor_isolation_log_injection_dos_and_status_tampering() -> None:
    """Security (SEC-139/140/141 · CWE-284/117/400/863/1333): Cross-vendor, CRLF, DoS, and approval guards."""
    # 1. Cross-vendor isolation: a mismatched vendor_tax_id hash record MUST NOT link or leak invoice_id
    cand = DuplicateCheckInput(
        vendor_tax_id="ESA98765432",
        invoice_number="INV-2026-1001",
        total_amount=Decimal("100.00"),
    )
    other_vendor_rec = _StubInvoiceRecord(
        invoice_id="secret-other-vendor-inv",
        vendor_tax_id="DE987654321",
        invoice_number="INV-2026-1001",
        total_amount=Decimal("100.00"),
        status="VALIDATED",
        composite_hash=compute_composite_hash("ESA98765432", "INV-2026-1001", Decimal("100.00")),
    )
    iso_res = evaluate_duplicate_rules(
        cand, existing_by_hash=other_vendor_rec, existing_vendor_invoices=[other_vendor_rec]
    )
    assert iso_res.outcome == DuplicateOutcome.PROCEED
    assert iso_res.matched_invoice_id is None

    # 2. Log/audit injection defense (CWE-117): CRLF in persisted invoice_number is stripped from reason
    crlf_rec = _StubInvoiceRecord(
        invoice_id="inv-old\r\nFAKE_AUDIT=APPROVED",
        vendor_tax_id="ESA98765432",
        invoice_number="INV-2026-1001\r\nINJECTED",
        total_amount=Decimal("200.00"),
        status="VALIDATED",
        composite_hash="other-hash",
    )
    crlf_res = evaluate_duplicate_rules(cand, existing_vendor_invoices=[crlf_rec])
    assert "\r" not in crlf_res.reason
    assert "\n" not in crlf_res.reason

    # 3. Unbounded lookup DoS rejected (CWE-400)
    oversized = [crlf_rec] * (MAX_EXISTING_LOOKUP_RECORDS + 1)
    with pytest.raises(ValueError, match="maximum allowed count"):
        evaluate_duplicate_rules(cand, existing_vendor_invoices=oversized)

    # 4. Pathological revision-suffix inputs execute in linear time without ReDoS (CWE-1333)
    for stress in ("-" * 100, "A" + "-rev" * 20, "A" + "_v2" * 25):
        detect_revision_suffix(stress)

    # 5. Status tampering / self-approval hard-blocked by Pydantic Literal + frozen=True (CWE-863)
    with pytest.raises(ValidationError):
        DuplicateDetectionResult(
            outcome=DuplicateOutcome.PROCEED,
            target_status="APPROVED_CLERK",  # type: ignore[arg-type]
            should_proceed=True,
            composite_hash="0" * 64,
            normalized_invoice_number="INV-1",
            base_invoice_number="INV-1",
            reason="tampered",
        )
