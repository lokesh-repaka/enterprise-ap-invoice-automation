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

__all__ = [
    "BatchEvaluationResult",
    "EvaluationCase",
    "EvaluationSecurityError",
    "FieldComparisonResult",
    "InvoiceBatchEvaluator",
    "InvoiceEvaluationResult",
    "LineFieldComparisonResult",
    "MAX_BATCH_INVOICES",
    "MAX_EVAL_GROUND_TRUTH_BYTES",
    "MAX_EVAL_INVOICE_BYTES",
    "SUPPORTED_INVOICE_EXTENSIONS",
    "compare_header_fields",
    "compare_line_items",
    "discover_evaluation_cases",
]
