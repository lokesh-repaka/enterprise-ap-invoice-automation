"""
Structured JSON Logging and PII Masking.

Provides ISO 8601 timestamps, request_id propagation, and automatic masking
of sensitive financial identifiers (Tax IDs, SSNs) per CLAUDE.md §8 and N3.
"""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# ContextVars for request tracing and verified audit actor propagation across async calls
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
audit_actor_ctx: ContextVar[str] = ContextVar("audit_actor", default="anonymous")

# Regular expressions for sensitive financial identifiers to mask
# Matches Tax IDs (e.g. US-12-3456789, 12-3456789, DE123456789, ESB12345678, GB123456789)
TAX_ID_PATTERN = re.compile(
    r"\b(?:[A-Z]{2}-?)?(\d{2})[- ]?(\d{5,7})\b|\b([A-Z]{2,3}[0-9A-Z]{8,10})\b"
)
SSN_PATTERN = re.compile(r"\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b")


def mask_pii(text: str) -> str:
    """Mask sensitive financial identifiers (Tax IDs, SSNs, account numbers) to ***-**-XXXX."""
    if not isinstance(text, str):
        return text

    # Mask standard SSN format
    text = SSN_PATTERN.sub(r"***-**-\3", text)

    # Mask US and international Tax IDs / VAT numbers
    def _mask_tax(match: re.Match) -> str:
        matched_str = match.group(0)
        # Preserve prefix if present, mask the digits
        if len(matched_str) > 4:
            return f"***-**-{matched_str[-4:]}"
        return "***-**-XXXX"

    return TAX_ID_PATTERN.sub(_mask_tax, text)


class JSONFormatter(logging.Formatter):
    """Custom logging formatter that outputs newline-delimited JSON objects with PII masking."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).isoformat()
        req_id = request_id_ctx.get() or getattr(record, "request_id", "")

        # Format original log message and apply PII masking
        raw_message = record.getMessage()
        masked_message = mask_pii(raw_message)

        log_payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": masked_message,
            "request_id": req_id,
            "module": record.module,
            "line": record.lineno,
        }

        # Include exception trace if present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        # Include custom extra fields if passed
        for key, val in record.__dict__.items():
            if key not in (
                "args",
                "asctime",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "request_id",
            ):
                log_payload[key] = val

        return json.dumps(log_payload, default=str)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure root logger with JSON formatting and stream handler."""
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicate log outputs
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Convenience getter for namespaced logger."""
    return logging.getLogger(name)
