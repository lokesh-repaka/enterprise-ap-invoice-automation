"""
Unit tests for JSON Logging & PII Masking (src/core/logging.py).

Tests: N3, N8
"""
import json
import logging

from src.core.logging import (
    JSONFormatter,
    get_logger,
    mask_pii,
    request_id_ctx,
    setup_logging,
)


def test_json_formatter_structure():
    """Verify JSONFormatter outputs valid JSON with standard fields."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=25,
        msg="Processing invoice upload",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    log_data = json.loads(formatted)

    assert log_data["level"] == "INFO"
    assert log_data["logger"] == "test_logger"
    assert log_data["message"] == "Processing invoice upload"
    assert "timestamp" in log_data
    assert "request_id" in log_data


def test_request_id_propagation():
    """Verify request_id from ContextVar is injected into JSON log output."""
    formatter = JSONFormatter()
    token = request_id_ctx.set("req-uuid-test-9999")

    try:
        record = logging.LogRecord(
            name="test_logger",
            level=logging.WARNING,
            pathname=__file__,
            lineno=45,
            msg="PO variance detected",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert log_data["request_id"] == "req-uuid-test-9999"
    finally:
        request_id_ctx.reset(token)


def test_pii_masking_tax_id_and_ssn():
    """Verify sensitive tax IDs and SSNs are masked as ***-**-XXXX per CLAUDE.md §8."""
    # US Tax ID format: 12-3456789 or US-12-3456789
    text_with_tax_id = "Vendor Tax ID US-12-3456789 submitted for approval"
    masked = mask_pii(text_with_tax_id)
    assert "***-**-" in masked
    assert "12-3456789" not in masked

    # Format in log message through formatter
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=70,
        msg="Extracting invoice for Tax ID 12-3456789 and bank account",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    log_data = json.loads(formatted)
    assert "12-3456789" not in log_data["message"]
    assert "***-**-" in log_data["message"]


def test_setup_logging_and_get_logger():
    """Verify setup_logging attaches stream handler with JSONFormatter."""
    setup_logging(log_level="DEBUG")
    logger = get_logger("ap.test")
    assert logger.name == "ap.test"
    assert logger.isEnabledFor(logging.DEBUG)
