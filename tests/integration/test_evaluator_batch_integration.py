"""
End-to-End Offline Integration Test: Full 300-Invoice Pilot Batch Evaluation (P13-1).

Tests: FR-14, CLAUDE.md §10, §13
Runs all 300 synthetic invoices in sample_data/invoices/ through InvoiceBatchEvaluator
(ExtractionEngine + MockAOAIClient + RulesEngine + ConfidenceRouter + EscalationEvaluator)
and verifies zero unhandled crashes, full 10-header & line-item comparison coverage, and
deterministic problem-case routing across the entire 300-invoice corpus.
"""

import asyncio
from pathlib import Path

import pytest

from src.core.config import get_settings
from src.evaluation.evaluator import InvoiceBatchEvaluator

SAMPLE_DATA_DIR = Path("./sample_data")


def test_p13_1_full_300_invoice_pilot_batch_inference_and_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-14, CLAUDE.md §10 — Run all 300 pilot invoices offline with zero crashes."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()

    try:
        evaluator = InvoiceBatchEvaluator(sample_data_dir=SAMPLE_DATA_DIR)
        batch = asyncio.run(evaluator.run_batch())

        # Batch Stability = Zero unhandled crashes across all 300 pilot invoices (CLAUDE.md §10)
        assert batch.total_invoices == 300
        assert batch.completed_invoices == 300
        assert batch.crashed_invoices == 0
        assert len(batch.results) == 300

        # Every single invoice evaluated all 10 header fields and its line-item fields
        assert sum(r.header_total_count for r in batch.results) == 3000
        assert batch.total_line_fields_expected > 0
        assert batch.total_line_fields_matched == batch.total_line_fields_expected

        # Zero self-approval anywhere in the 300-invoice batch (CLAUDE.md §16.1)
        for status_name in batch.status_distribution:
            assert not status_name.startswith("APPROVED_")

        # STP rate across the 300-invoice corpus meets >= 65% pilot acceptance bar
        stp_rate = batch.stp_count / batch.total_invoices
        assert stp_rate >= 0.65
    finally:
        get_settings.cache_clear()
