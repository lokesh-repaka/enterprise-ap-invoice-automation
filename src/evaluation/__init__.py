"""
Offline batch evaluation harness: benchmarks accuracy and STP against ground-truth JSON files.
MUST NOT be imported by production code paths (CLAUDE.md §4.2).

Uses PEP 562 lazy attribute loading so ``python -m src.evaluation.evaluator --report`` executes
with zero ``runpy`` RuntimeWarning while preserving all public ``from src.evaluation import ...``
exports cleanly.
"""

from importlib import import_module
from typing import Any

_EXPORT_MAP: dict[str, str] = {
    # cli.py
    "build_argument_parser": "src.evaluation.cli",
    "run_cli": "src.evaluation.cli",
    # evaluator.py
    "BatchEvaluationResult": "src.evaluation.evaluator",
    "EvaluationCase": "src.evaluation.evaluator",
    "EvaluationSecurityError": "src.evaluation.evaluator",
    "FieldComparisonResult": "src.evaluation.evaluator",
    "InvoiceBatchEvaluator": "src.evaluation.evaluator",
    "InvoiceEvaluationResult": "src.evaluation.evaluator",
    "LineFieldComparisonResult": "src.evaluation.evaluator",
    "MAX_BATCH_INVOICES": "src.evaluation.evaluator",
    "MAX_EVAL_GROUND_TRUTH_BYTES": "src.evaluation.evaluator",
    "MAX_EVAL_INVOICE_BYTES": "src.evaluation.evaluator",
    "SUPPORTED_INVOICE_EXTENSIONS": "src.evaluation.evaluator",
    "compare_header_fields": "src.evaluation.evaluator",
    "compare_line_items": "src.evaluation.evaluator",
    "discover_evaluation_cases": "src.evaluation.evaluator",
    "main": "src.evaluation.evaluator",
    # metrics.py
    "DEFAULT_THRESHOLDS": "src.evaluation.metrics",
    "EvaluationIntegrityError": "src.evaluation.metrics",
    "EvaluationMetricsReport": "src.evaluation.metrics",
    "EvaluationThresholdError": "src.evaluation.metrics",
    "EvaluationThresholds": "src.evaluation.metrics",
    "FieldMetricSummary": "src.evaluation.metrics",
    "LONG_TERM_STP_OBJECTIVE_PCT": "src.evaluation.metrics",
    "TestCaseTypeSummary": "src.evaluation.metrics",
    "ThresholdCheckResult": "src.evaluation.metrics",
    "assert_evaluation_thresholds": "src.evaluation.metrics",
    "compute_evaluation_metrics": "src.evaluation.metrics",
    "format_metrics_summary": "src.evaluation.metrics",
}

__all__ = sorted(_EXPORT_MAP.keys())


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MAP.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_name)
    return getattr(module, name)
