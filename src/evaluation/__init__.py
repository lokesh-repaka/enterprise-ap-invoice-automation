"""
Offline batch evaluation harness: benchmarks accuracy and STP against ground-truth JSON files.
MUST NOT be imported by production code paths (CLAUDE.md §4.2).
"""

from src.evaluation.evaluator import (
    MAX_BATCH_INVOICES,
    MAX_EVAL_GROUND_TRUTH_BYTES,
    MAX_EVAL_INVOICE_BYTES,
    SUPPORTED_INVOICE_EXTENSIONS,
    BatchEvaluationResult,
    EvaluationCase,
    EvaluationSecurityError,
    FieldComparisonResult,
    InvoiceBatchEvaluator,
    InvoiceEvaluationResult,
    LineFieldComparisonResult,
    compare_header_fields,
    compare_line_items,
    discover_evaluation_cases,
)
from src.evaluation.metrics import (
    DEFAULT_THRESHOLDS,
    LONG_TERM_STP_OBJECTIVE_PCT,
    EvaluationIntegrityError,
    EvaluationMetricsReport,
    EvaluationThresholds,
    FieldMetricSummary,
    TestCaseTypeSummary,
    ThresholdCheckResult,
    compute_evaluation_metrics,
    format_metrics_summary,
)

__all__ = [
    "BatchEvaluationResult",
    "DEFAULT_THRESHOLDS",
    "EvaluationCase",
    "EvaluationIntegrityError",
    "EvaluationMetricsReport",
    "EvaluationSecurityError",
    "EvaluationThresholds",
    "FieldComparisonResult",
    "FieldMetricSummary",
    "InvoiceBatchEvaluator",
    "InvoiceEvaluationResult",
    "LONG_TERM_STP_OBJECTIVE_PCT",
    "LineFieldComparisonResult",
    "MAX_BATCH_INVOICES",
    "MAX_EVAL_GROUND_TRUTH_BYTES",
    "MAX_EVAL_INVOICE_BYTES",
    "SUPPORTED_INVOICE_EXTENSIONS",
    "TestCaseTypeSummary",
    "ThresholdCheckResult",
    "compare_header_fields",
    "compare_line_items",
    "compute_evaluation_metrics",
    "discover_evaluation_cases",
    "format_metrics_summary",
]
