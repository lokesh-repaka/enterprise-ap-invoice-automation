"""
Integration test for P13-2: 300-invoice pilot metric reporting and contractual threshold gates.

Maps to FR-14, CLAUDE.md §10, BRD AC-001/AC-002/AC-004/AC-007.
Runs offline against sample_data/ with USE_MOCK_AOAI=true.
"""

import asyncio
import json
from decimal import Decimal
from pathlib import Path

import pytest

from src.core.config import get_settings
from src.evaluation.evaluator import InvoiceBatchEvaluator
from src.evaluation.metrics import compute_evaluation_metrics, format_metrics_summary

SAMPLE_DATA_DIR = Path(__file__).resolve().parents[2] / "sample_data"


def test_full_300_invoice_pilot_metric_reporting_passes_all_contractual_thresholds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-14, AC-001, AC-002, AC-004, AC-007 — 300-invoice metrics meet all pilot gates."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()

    try:
        evaluator = InvoiceBatchEvaluator(sample_data_dir=SAMPLE_DATA_DIR)
        batch = asyncio.run(evaluator.run_batch())
        report = compute_evaluation_metrics(batch)

        assert report.total_invoices == 300
        assert report.completed_invoices == 300
        assert report.crashed_invoices == 0

        # Contractual acceptance thresholds (CLAUDE.md §10)
        assert report.header_macro_accuracy_pct >= Decimal("95.00")
        assert report.critical_field_min_accuracy_pct >= Decimal("92.00")
        assert report.line_item_accuracy_pct >= Decimal("90.00")
        assert report.stp_rate_pct >= Decimal("65.00")
        assert report.all_thresholds_passed is True
        assert report.failed_gates == ()

        # Precision / Recall / F1 reported and bounded within [0, 100]
        assert Decimal("95.00") <= report.overall_precision_pct <= Decimal("100.00")
        assert Decimal("95.00") <= report.overall_recall_pct <= Decimal("100.00")
        assert Decimal("95.00") <= report.overall_f1_pct <= Decimal("100.00")

        # Safe JSON and formatted text report omit host filesystem paths & raw Tax IDs
        safe_json = report.to_safe_json()
        summary = format_metrics_summary(report)
        assert str(SAMPLE_DATA_DIR.parent) not in safe_json
        assert str(SAMPLE_DATA_DIR.parent) not in summary
        assert "ESA98765432" not in safe_json
        assert "ESA98765432" not in summary

        parsed = json.loads(safe_json)
        assert parsed["all_thresholds_passed"] is True
        assert parsed["total_invoices"] == 300
        assert "standard" in parsed["by_test_case_type"]
        assert "PASS" in summary
    finally:
        get_settings.cache_clear()
