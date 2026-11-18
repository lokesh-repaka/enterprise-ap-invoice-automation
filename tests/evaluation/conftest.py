"""
Offline evaluation fixtures for tests/evaluation/ (P13-3).

Runs the full 300-invoice pilot corpus once per test module in strict offline mode
(USE_LOCAL_SQLITE=true, USE_FAKE_REDIS=true, USE_MOCK_AOAI=true) so individual
threshold gate tests execute instantaneously without redundant inference.
"""

import asyncio
from collections.abc import Generator
from pathlib import Path

import pytest

from src.core.config import get_settings
from src.evaluation.evaluator import BatchEvaluationResult, InvoiceBatchEvaluator
from src.evaluation.metrics import EvaluationMetricsReport, compute_evaluation_metrics

SAMPLE_DATA_DIR = Path(__file__).resolve().parents[2] / "sample_data"


@pytest.fixture(scope="module")
def pilot_batch_result() -> Generator[BatchEvaluationResult, None, None]:
    """Execute the 300-invoice offline pilot evaluation once per module."""
    mp = pytest.MonkeyPatch()
    mp.setenv("APP_ENV", "test")
    mp.setenv("USE_LOCAL_SQLITE", "true")
    mp.setenv("USE_FAKE_REDIS", "true")
    mp.setenv("USE_MOCK_AOAI", "true")
    mp.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()
    try:
        evaluator = InvoiceBatchEvaluator(sample_data_dir=SAMPLE_DATA_DIR)
        batch = asyncio.run(evaluator.run_batch())
        yield batch
    finally:
        mp.undo()
        get_settings.cache_clear()


@pytest.fixture(scope="module")
def pilot_evaluation_report(
    pilot_batch_result: BatchEvaluationResult,
) -> EvaluationMetricsReport:
    """Compute contractual evaluation metrics and threshold checks for the 300-invoice pilot."""
    return compute_evaluation_metrics(pilot_batch_result)
