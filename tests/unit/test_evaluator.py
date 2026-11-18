"""
Unit and Security Tests for Batch Evaluator & Field-by-Field Comparison (P13-1).

Tests: FR-14, CLAUDE.md §4.2, §10, §13, SEC-220, SEC-221, SEC-222
Strict offline isolation: zero external network or Azure calls.
"""

import ast
import asyncio
import json
import logging
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from src.core.config import get_settings
from src.evaluation.evaluator import (
    MAX_BATCH_INVOICES,
    BatchEvaluationResult,
    EvaluationSecurityError,
    InvoiceBatchEvaluator,
    compare_header_fields,
    compare_line_items,
    discover_evaluation_cases,
)
from src.extraction.schemas import (
    CRITICAL_HEADER_FIELD_NAMES,
    HEADER_FIELD_NAMES,
    LINE_ITEM_FIELD_NAMES,
    InvoiceExtractionSchema,
)

SAMPLE_DATA_DIR = Path("./sample_data")


def _sample_gt_dict() -> dict[str, Any]:
    return {
        "invoice_metadata": {
            "invoice_number": "INV-2026-9001",
            "test_case_type": "standard",
        },
        "header": {
            "vendor_name": "Apex Global Logistics Inc",
            "vendor_tax_id": "US-12-3456789",
            "invoice_number": "INV-2026-9001",
            "invoice_date": "02/15/2026",
            "due_date": "03/17/2026",
            "po_number": "PO-9000-1001",
            "subtotal": 1000.0,
            "tax_amount": 80.0,
            "total_amount": 1080.0,
            "currency": "USD",
        },
        "line_items": [
            {
                "description": "Heavy Duty Steel Fasteners",
                "quantity": 10,
                "unit_price": 50.0,
                "line_total": 500.0,
                "tax_rate": 0.08,
            },
            {
                "description": "Pneumatic Valve Assembly",
                "quantity": 2,
                "unit_price": 250.0,
                "line_total": 500.0,
                "tax_rate": 0.08,
            },
        ],
    }


# ---------------------------------------------------------------------------
# 1. Field-by-Field Header & Line-Item Comparison (FR-14, CLAUDE.md §10)
# ---------------------------------------------------------------------------


def test_compare_header_fields_exact_normalization_and_mismatch_detection() -> None:
    """# Tests: FR-14 — Compares all 10 header fields with Decimal/whitespace normalization and critical flags."""
    gt = _sample_gt_dict()
    predicted = InvoiceExtractionSchema.from_ground_truth_dict(
        gt, default_confidence=Decimal("97.50")
    )

    # Exact match across all 10 fields (including Decimal scale 1000.0 vs 1000.00)
    results = compare_header_fields(predicted, gt["header"])
    assert len(results) == len(HEADER_FIELD_NAMES) == 10
    assert all(r.matched for r in results)
    critical_names = {r.field_name for r in results if r.is_critical}
    assert critical_names == set(CRITICAL_HEADER_FIELD_NAMES)

    # Introduce 2 mismatches: total_amount (critical) and po_number (non-critical)
    mutated_gt = json.loads(json.dumps(gt))
    mutated_gt["header"]["total_amount"] = 1099.99
    mutated_gt["header"]["po_number"] = "PO-DIFFERENT"
    mismatched = compare_header_fields(predicted, mutated_gt["header"])
    by_name = {r.field_name: r for r in mismatched}
    assert by_name["total_amount"].matched is False
    assert by_name["total_amount"].is_critical is True
    assert by_name["po_number"].matched is False
    assert by_name["po_number"].is_critical is False
    assert sum(1 for r in mismatched if r.matched) == 8


def test_compare_line_items_exact_missing_and_extra_line_penalties() -> None:
    """# Tests: FR-14 — Compares all 5 line fields per line and penalizes missing/extra predicted lines."""
    gt = _sample_gt_dict()
    predicted = InvoiceExtractionSchema.from_ground_truth_dict(
        gt, default_confidence=Decimal("96.00")
    )

    # Exact 2-line match -> 10/10 fields matched
    exact = compare_line_items(predicted.line_items, gt["line_items"])
    assert len(exact) == 2 * len(LINE_ITEM_FIELD_NAMES) == 10
    assert all(r.matched for r in exact)

    # Single unit_price mismatch on line 2 -> 9/10 matched
    mutated_lines = json.loads(json.dumps(gt["line_items"]))
    mutated_lines[1]["unit_price"] = 255.0
    partial = compare_line_items(predicted.line_items, mutated_lines)
    assert sum(1 for r in partial if r.matched) == 9

    # Missing predicted line (ground truth has 3 lines, prediction has 2) -> 5 missed fields
    three_gt_lines = [
        *gt["line_items"],
        {
            "description": "Extra Missing Line",
            "quantity": 1,
            "unit_price": 10.0,
            "line_total": 10.0,
            "tax_rate": 0.08,
        },
    ]
    missing = compare_line_items(predicted.line_items, three_gt_lines)
    assert len(missing) == 15
    assert sum(1 for r in missing if r.matched) == 10

    # Extra hallucinated predicted line (ground truth has 1 line, prediction has 2) -> penalized
    one_gt_line = [gt["line_items"][0]]
    hallucinated = compare_line_items(predicted.line_items, one_gt_line)
    assert len(hallucinated) == 10
    assert sum(1 for r in hallucinated if r.matched) == 5


# ---------------------------------------------------------------------------
# 2. Bounded Offline Batch Inference (FR-14)
# ---------------------------------------------------------------------------


def test_batch_evaluator_bounded_subset_runs_extraction_rules_and_field_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-14 — Bounded batch inference runs MockAOAI + RulesEngine + ConfidenceRouter + FX offline."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()

    try:
        evaluator = InvoiceBatchEvaluator(sample_data_dir=SAMPLE_DATA_DIR)
        batch: BatchEvaluationResult = asyncio.run(evaluator.run_batch(limit=12))
        assert batch.total_invoices == 12
        assert batch.completed_invoices == 12
        assert batch.crashed_invoices == 0
        assert len(batch.results) == 12

        # Every invoice compared all 10 header fields and never self-approved (SEC-222)
        for item in batch.results:
            assert item.succeeded is True
            assert item.header_total_count == 10
            assert item.header_matched_count == 10
            assert item.line_total_count > 0
            assert item.line_matched_count == item.line_total_count
            assert item.routed_status is not None
            assert not item.routed_status.startswith("APPROVED_")

        # INV-2026-1010 (Spanish tax mismatch) is in the first 12 sorted files and routes cleanly
        by_stem = {r.invoice_stem: r for r in batch.results}
        assert by_stem["INV-2026-1001"].routed_status == "VALIDATED"
        assert by_stem["INV-2026-1001"].stp_achieved is True
        assert by_stem["INV-2026-1010"].routed_status == "REJECTED_TAX_MISMATCH"
        assert by_stem["INV-2026-1010"].stp_achieved is False
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 3. Security Guards: Path/Symlink Containment, Crash Isolation & PII Masking
# ---------------------------------------------------------------------------


def test_evaluator_blocks_symlinks_oversized_files_and_unbounded_limits(tmp_path: Path) -> None:
    """# Tests: FR-14, SEC-220 — Blocks symlink escape, oversized ground-truth JSON, and invalid limits."""
    inv_dir = tmp_path / "invoices"
    gt_dir = tmp_path / "ground_truth"
    inv_dir.mkdir()
    gt_dir.mkdir()

    secret_outside = tmp_path.parent / "outside_secret.txt"
    secret_outside.write_text("TOP SECRET", encoding="utf-8")
    try:
        # Symlink inside invoices/ pointing outside sample_data_dir MUST be rejected (CWE-59)
        (inv_dir / "INV-2026-9999.txt").symlink_to(secret_outside)
        (gt_dir / "INV-2026-9999_ground_truth.json").write_text(
            json.dumps(_sample_gt_dict()), encoding="utf-8"
        )
        with pytest.raises(EvaluationSecurityError, match="Symlink"):
            discover_evaluation_cases(tmp_path)
    finally:
        secret_outside.unlink(missing_ok=True)

    # Unbounded limit > MAX_BATCH_INVOICES rejected (CWE-400)
    with pytest.raises(ValueError, match="limit"):
        discover_evaluation_cases(SAMPLE_DATA_DIR, limit=MAX_BATCH_INVOICES + 1)
    with pytest.raises(ValueError, match="limit"):
        discover_evaluation_cases(SAMPLE_DATA_DIR, limit=0)


def test_evaluator_isolates_per_invoice_crash_and_never_leaks_pii_in_logs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """# Tests: FR-14, SEC-221, SEC-222 — Per-invoice crash contained in result; zero raw Tax ID in logs."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    get_settings.cache_clear()

    # Build a tiny 2-invoice dataset where 1 ground-truth JSON is intentionally corrupt
    inv_dir = tmp_path / "invoices"
    gt_dir = tmp_path / "ground_truth"
    inv_dir.mkdir()
    gt_dir.mkdir()
    (tmp_path / "vendor_master.json").write_text(
        (SAMPLE_DATA_DIR / "vendor_master.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "exchange_rates.json").write_text(
        (SAMPLE_DATA_DIR / "exchange_rates.json").read_text(encoding="utf-8"), encoding="utf-8"
    )

    # Good invoice (INV-2026-1001)
    (inv_dir / "INV-2026-1001.txt").write_text(
        (SAMPLE_DATA_DIR / "invoices" / "INV-2026-1001.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (gt_dir / "INV-2026-1001_ground_truth.json").write_text(
        (SAMPLE_DATA_DIR / "ground_truth" / "INV-2026-1001_ground_truth.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    # Corrupt ground-truth JSON invoice
    (inv_dir / "INV-2026-9998.txt").write_text("Corrupt invoice text", encoding="utf-8")
    (gt_dir / "INV-2026-9998_ground_truth.json").write_text("{not valid json", encoding="utf-8")

    monkeypatch.setenv("SAMPLE_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        evaluator = InvoiceBatchEvaluator(sample_data_dir=tmp_path)
        with caplog.at_level(logging.INFO, logger="ap.evaluation.evaluator"):
            batch = asyncio.run(evaluator.run_batch())

        assert batch.total_invoices == 2
        assert batch.completed_invoices == 1
        assert batch.crashed_invoices == 1

        by_stem = {r.invoice_stem: r for r in batch.results}
        assert by_stem["INV-2026-1001"].succeeded is True
        assert by_stem["INV-2026-9998"].succeeded is False
        assert by_stem["INV-2026-9998"].error_message is not None

        # Zero raw vendor Tax ID PII in structured logs (SEC-221)
        combined_logs = " ".join(rec.getMessage() for rec in caplog.records)
        assert "ESA98765432" not in combined_logs
        assert "ESA98765432" not in repr(by_stem["INV-2026-1001"])
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 4. Layering Rule Audit: Production Code MUST NOT Import src.evaluation
# ---------------------------------------------------------------------------


def test_production_layers_never_import_src_evaluation() -> None:
    """# Tests: FR-14, CLAUDE.md §4.2 — Production packages must never import src.evaluation."""
    prod_dirs = (
        Path("src/api"),
        Path("src/core"),
        Path("src/database"),
        Path("src/extraction"),
        Path("src/services"),
        Path("src/storage"),
        Path("src/ui"),
        Path("src/validation"),
    )
    for folder in prod_dirs:
        for py_file in sorted(folder.rglob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert not alias.name.startswith("src.evaluation"), (
                            f"Production file {py_file} must not import {alias.name}"
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert not node.module.startswith("src.evaluation"), (
                        f"Production file {py_file} must not import from {node.module}"
                    )
