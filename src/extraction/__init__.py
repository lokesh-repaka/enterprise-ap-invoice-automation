"""
Extraction Engine & Model Gateway package (Phase 6).

Owns document classification, Azure OpenAI East US 2 Model Gateway routing,
Pydantic extraction schemas, prompt assembly with ``<invoice_text>`` delimiters,
and offline mock AOAI client.
MUST NOT execute business rules or write to SQL directly (CLAUDE.md §4.2).
"""

from src.extraction.document_classifier import (
    DEFAULT_MIN_CHARS_PER_PAGE,
    DEFAULT_MIN_DENSE_PAGE_RATIO,
    MAX_CLASSIFIER_PDF_PAGES,
    MAX_CLASSIFIER_SIZE_BYTES,
    MAX_EXTRACTED_TEXT_CHARS,
    DocumentClassificationError,
    DocumentClassificationResult,
    DocumentType,
    UnsupportedDocumentError,
    classify_document,
)

__all__ = [
    "DEFAULT_MIN_CHARS_PER_PAGE",
    "DEFAULT_MIN_DENSE_PAGE_RATIO",
    "DocumentClassificationError",
    "DocumentClassificationResult",
    "DocumentType",
    "MAX_CLASSIFIER_PDF_PAGES",
    "MAX_CLASSIFIER_SIZE_BYTES",
    "MAX_EXTRACTED_TEXT_CHARS",
    "UnsupportedDocumentError",
    "classify_document",
]
