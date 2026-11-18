"""
Deterministic validation rules engine (Phase 7 & Phase 8).

Owns duplicate/revision/credit-note detection, line-item and invoice-total arithmetic,
multi-country tax validation, vendor-locale date normalization, confidence routing,
and the 10-state invoice FSM.
MUST NOT call LLMs (CLAUDE.md §4.2, §7.2).
"""

from src.validation.duplicate_detector import (
    IGNORED_DUPLICATE_STATUSES,
    MAX_EXISTING_LOOKUP_RECORDS,
    MAX_FILENAME_CHARS,
    MAX_INVOICE_NUMBER_CHARS,
    MAX_LINE_ITEMS,
    MAX_MONETARY_AMOUNT,
    MAX_VENDOR_TAX_ID_CHARS,
    DuplicateCheckInput,
    DuplicateDetectionResult,
    DuplicateDetector,
    DuplicateOutcome,
    ExistingInvoiceRecord,
    InvoiceLookupProtocol,
    TargetDuplicateStatus,
    compute_composite_hash,
    detect_credit_note,
    detect_revision_suffix,
    evaluate_duplicate_rules,
)

__all__ = [
    "DuplicateCheckInput",
    "DuplicateDetectionResult",
    "DuplicateDetector",
    "DuplicateOutcome",
    "ExistingInvoiceRecord",
    "IGNORED_DUPLICATE_STATUSES",
    "InvoiceLookupProtocol",
    "MAX_EXISTING_LOOKUP_RECORDS",
    "MAX_FILENAME_CHARS",
    "MAX_INVOICE_NUMBER_CHARS",
    "MAX_LINE_ITEMS",
    "MAX_MONETARY_AMOUNT",
    "MAX_VENDOR_TAX_ID_CHARS",
    "TargetDuplicateStatus",
    "compute_composite_hash",
    "detect_credit_note",
    "detect_revision_suffix",
    "evaluate_duplicate_rules",
]
