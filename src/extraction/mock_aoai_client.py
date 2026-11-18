"""
Offline Mock Azure OpenAI Client Returning Schema-Valid Fixture JSON (P6-5).

Implements ``AOAIChatClientProtocol`` for 100% offline, zero-network development, CI,
and 300-invoice evaluation (FR-03, FR-14, CLAUDE.md §13, ADR-007):
- Resolves matching pilot fixtures from ``sample_data/ground_truth/<INV>_ground_truth.json``
  with strict allowlist regex, symlink rejection, path-containment verification (CWE-22/59),
  and 1 MB file-size ceiling (CWE-400).
- Supports explicit custom fixtures, per-field confidence overrides (for tri-tier routing
  tests), and FIFO scripted error injection (for HTTP 429 backoff/retry tests).
- Simulates Azure OpenAI Prompt Caching telemetry (``cached_tokens > 0`` on repeated
  static system prompts).
- Enforces production/staging isolation (blocks instantiation outside ``dev``/``local``/``test``
  or whenever ``USE_LOCAL_SQLITE=False``: CWE-489).
- Zero imports from ``src/database/`` or ``src/validation/`` and zero PII in logs (CLAUDE.md §4.2, §8).
"""

import hashlib
import json
import os
import re
import stat
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.extraction.model_gateway import (
    MOCK_AOAI_ALLOWED_ENVS,
    ModelGatewayConfigurationError,
)
from src.extraction.schemas import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    HEADER_FIELD_NAMES,
    InvoiceExtractionSchema,
)

logger = get_logger("ap.extraction.mock_aoai_client")

DEFAULT_MOCK_CONFIDENCE: Decimal = Decimal("97.50")
MAX_FIXTURE_FILE_BYTES: int = 1 * 1024 * 1024
MAX_RECORDED_CALLS: int = 10_000
MAX_CACHED_SYSTEM_HASHES: int = 128

# Strictly allowlisted canonical pilot invoice token (blocks any path traversal characters)
_SAFE_INVOICE_TOKEN_RE = re.compile(r"\b(INV-\d{4}-\d{4}(?:-REV)?)\b")


@dataclass(frozen=True)
class MockPromptTokensDetails:
    """OpenAI SDK-compatible ``usage.prompt_tokens_details`` shape."""

    cached_tokens: int = 0


@dataclass(frozen=True)
class MockCompletionUsage:
    """OpenAI SDK-compatible ``usage`` shape."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    prompt_tokens_details: MockPromptTokensDetails


@dataclass(frozen=True)
class MockChatMessage:
    """OpenAI SDK-compatible ``choices[0].message`` shape."""

    content: str
    role: str = "assistant"


@dataclass(frozen=True)
class MockChatChoice:
    """OpenAI SDK-compatible ``choices[0]`` shape."""

    index: int
    message: MockChatMessage
    finish_reason: str = "stop"


@dataclass(frozen=True)
class MockChatCompletion:
    """OpenAI SDK-compatible chat completion response emitted by ``MockAOAIClient``."""

    id: str
    model: str
    choices: list[MockChatChoice]
    usage: MockCompletionUsage


def _validate_confidence_decimal(val: Any, *, label: str) -> Decimal:
    if isinstance(val, bool) or not isinstance(val, (Decimal, int, float, str)):
        raise ValueError(f"{label} must be a finite Decimal within [0.00, 100.00]")
    try:
        dec = val if isinstance(val, Decimal) else Decimal(str(val))
    except InvalidOperation:
        raise ValueError(f"{label} must be a finite Decimal within [0.00, 100.00]") from None
    if not dec.is_finite() or dec < CONFIDENCE_MIN or dec > CONFIDENCE_MAX:
        raise ValueError(f"{label} must be a finite Decimal within [0.00, 100.00]")
    return dec


def _infer_language(vendor_tax_id: str) -> Literal["en", "de", "es"]:
    prefix = vendor_tax_id.strip().upper()[:2]
    if prefix == "DE":
        return "de"
    if prefix == "ES":
        return "es"
    return "en"


def build_default_fixture_schema(
    *,
    default_confidence: Decimal = DEFAULT_MOCK_CONFIDENCE,
) -> InvoiceExtractionSchema:
    """
    Construct a deterministic, mathematically consistent ``InvoiceExtractionSchema`` fixture
    used when no matching ground-truth file exists (e.g. generic synthetic PDFs or PNG scans).
    """
    conf = _validate_confidence_decimal(default_confidence, label="default_confidence")
    return InvoiceExtractionSchema.from_ground_truth_dict(
        {
            "header": {
                "vendor_name": "Apex Global Logistics Inc",
                "vendor_tax_id": "US-12-3456789",
                "invoice_number": "INV-2026-0000",
                "invoice_date": "02/05/2026",
                "due_date": "03/07/2026",
                "po_number": "PO-9000-0001",
                "subtotal": 1250.00,
                "tax_amount": 100.00,
                "total_amount": 1350.00,
                "currency": "USD",
            },
            "line_items": [
                {
                    "description": "Heavy Duty Steel Fasteners",
                    "quantity": 10,
                    "unit_price": 75.00,
                    "line_total": 750.00,
                    "tax_rate": 0.08,
                },
                {
                    "description": "Precision Calibration Kit",
                    "quantity": 5,
                    "unit_price": 100.00,
                    "line_total": 500.00,
                    "tax_rate": 0.08,
                },
            ],
        },
        default_confidence=conf,
        detected_language="en",
    )


def _apply_confidence_overrides(
    schema: InvoiceExtractionSchema,
    overrides: dict[str, Decimal],
) -> InvoiceExtractionSchema:
    """Return a validated copy of ``schema`` with header per-field confidence overrides applied."""
    if not overrides:
        return schema
    dumped = schema.model_dump(mode="python")
    for field_name, conf in overrides.items():
        dumped["header"][field_name]["confidence"] = conf
    return InvoiceExtractionSchema.model_validate(dumped)


def _extract_prompt_text(messages: list[dict[str, Any]]) -> tuple[str, str]:
    """Return (system_text, combined_user_text) safely from chat completion messages."""
    system_parts: list[str] = []
    user_parts: list[str] = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content")
        text_chunks: list[str] = []
        if isinstance(content, str):
            text_chunks.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    t_val = part.get("text")
                    if isinstance(t_val, str):
                        text_chunks.append(t_val)
        joined = "\n".join(text_chunks)
        if role == "system":
            system_parts.append(joined)
        elif role == "user":
            user_parts.append(joined)
    return "\n".join(system_parts), "\n".join(user_parts)


class MockAOAIClient:
    """
    Zero-network offline Azure OpenAI client implementing ``AOAIChatClientProtocol`` (P6-5).

    Always returns JSON conforming strictly to ``InvoiceExtractionSchema`` (P6-3).
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        fixture: InvoiceExtractionSchema | dict[str, Any] | None = None,
        default_confidence: Decimal = DEFAULT_MOCK_CONFIDENCE,
        confidence_overrides: dict[str, Decimal] | None = None,
        scripted_errors: Sequence[BaseException] | None = None,
    ) -> None:
        cfg = settings or get_settings()
        env_name = cfg.APP_ENV.strip().lower()
        if env_name not in MOCK_AOAI_ALLOWED_ENVS:
            raise ModelGatewayConfigurationError(
                f"MockAOAIClient is strictly prohibited in environment '{env_name}'"
            )
        if not cfg.USE_LOCAL_SQLITE:
            raise ModelGatewayConfigurationError(
                "MockAOAIClient requires USE_LOCAL_SQLITE=true (cannot pair mock AI with Azure SQL)"
            )

        self._default_confidence = _validate_confidence_decimal(
            default_confidence, label="default_confidence"
        )
        self._confidence_overrides: dict[str, Decimal] = {}
        if confidence_overrides:
            for field_name, conf_val in confidence_overrides.items():
                if field_name not in HEADER_FIELD_NAMES:
                    raise ValueError(
                        f"Unknown header field in confidence_overrides: {field_name!r}"
                    )
                self._confidence_overrides[field_name] = _validate_confidence_decimal(
                    conf_val, label=f"confidence_overrides[{field_name}]"
                )

        if isinstance(fixture, InvoiceExtractionSchema):
            self._explicit_fixture: InvoiceExtractionSchema | None = fixture
        elif isinstance(fixture, dict):
            self._explicit_fixture = InvoiceExtractionSchema.model_validate(fixture)
        elif fixture is None:
            self._explicit_fixture = None
        else:
            raise TypeError("fixture must be an InvoiceExtractionSchema, dict, or None")

        self._ground_truth_dir = (Path(cfg.SAMPLE_DATA_DIR) / "ground_truth").resolve()
        self._scripted_errors: deque[BaseException] = deque(scripted_errors or ())
        self._seen_system_hashes: deque[str] = deque(maxlen=MAX_CACHED_SYSTEM_HASHES)
        self._call_count: int = 0
        self._recorded_models: deque[str] = deque(maxlen=MAX_RECORDED_CALLS)

    @property
    def call_count(self) -> int:
        """Total number of chat-completion calls handled by this mock client."""
        return self._call_count

    @property
    def recorded_models(self) -> list[str]:
        """List of deployment/model names invoked (sanitized; zero prompt PII)."""
        return list(self._recorded_models)

    def _load_ground_truth_fixture(
        self,
        invoice_token: str,
        *,
        user_text: str,
    ) -> InvoiceExtractionSchema | None:
        """
        Safely resolve ``<ground_truth_dir>/<invoice_token>_ground_truth.json`` using
        ``O_NOFOLLOW`` + ``fstat`` regular-file verification + bounded fd read (CWE-22/59/367/400).
        """
        if not self._ground_truth_dir.is_dir():
            return None

        candidate = self._ground_truth_dir / f"{invoice_token}_ground_truth.json"
        if candidate.is_symlink():
            return None

        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None

        if not resolved.is_relative_to(self._ground_truth_dir):
            return None

        open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(candidate, open_flags)
        except OSError:
            return None

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FIXTURE_FILE_BYTES:
                return None
            with os.fdopen(fd, "rb") as handle:
                fd = -1  # Ownership transferred to file object
                raw_bytes = handle.read(MAX_FIXTURE_FILE_BYTES + 1)
        except OSError:
            return None
        finally:
            if fd >= 0:
                os.close(fd)

        if len(raw_bytes) > MAX_FIXTURE_FILE_BYTES:
            return None

        try:
            raw_data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(raw_data, dict):
            return None
        raw_header = raw_data.get("header")
        if not isinstance(raw_header, dict):
            return None

        tax_id = str(raw_header.get("vendor_tax_id", ""))
        try:
            tax_amt = Decimal(str(raw_header.get("tax_amount", "0")))
        except (InvalidOperation, ValueError):
            return None

        lowered_text = user_text.lower()
        is_reverse_charge = tax_amt == 0 and (
            "reverse charge" in lowered_text or "steuerschuldnerschaft" in lowered_text
        )
        is_exempt = tax_amt == 0 and not is_reverse_charge and "exempt" in lowered_text

        try:
            return InvoiceExtractionSchema.from_ground_truth_dict(
                raw_data,
                default_confidence=self._default_confidence,
                is_reverse_charge=is_reverse_charge,
                is_exempt=is_exempt,
                detected_language=_infer_language(tax_id),
            )
        except ValueError:
            return None

    def _resolve_fixture(self, user_text: str) -> tuple[InvoiceExtractionSchema, str]:
        """Resolve explicit fixture -> ground-truth match -> deterministic default fixture."""
        if self._explicit_fixture is not None:
            return (
                _apply_confidence_overrides(self._explicit_fixture, self._confidence_overrides),
                "explicit_fixture",
            )

        match = _SAFE_INVOICE_TOKEN_RE.search(user_text)
        if match is not None:
            loaded = self._load_ground_truth_fixture(match.group(1), user_text=user_text)
            if loaded is not None:
                return (
                    _apply_confidence_overrides(loaded, self._confidence_overrides),
                    "ground_truth_file",
                )

        default_schema = build_default_fixture_schema(default_confidence=self._default_confidence)
        return (
            _apply_confidence_overrides(default_schema, self._confidence_overrides),
            "default_fallback",
        )

    async def create_chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        temperature: float,
        response_format: dict[str, str],
        timeout: float,
    ) -> MockChatCompletion:
        """Return a schema-valid offline completion object with realistic prompt-caching metrics."""
        self._call_count += 1
        self._recorded_models.append(model)

        if self._scripted_errors:
            raise self._scripted_errors.popleft()

        system_text, user_text = _extract_prompt_text(messages)
        schema_obj, source = self._resolve_fixture(user_text)
        json_content = schema_obj.model_dump_json()

        # Estimate token telemetry and simulate Azure Prompt Caching hits on repeated system prompt
        sys_tokens = max(len(system_text) // 4, 1)
        usr_tokens = max(len(user_text) // 4, 1)
        prompt_tokens = sys_tokens + usr_tokens
        completion_tokens = min(max(len(json_content) // 4, 1), max(int(max_tokens), 1))

        sys_hash = hashlib.sha256(system_text.encode("utf-8")).hexdigest()
        cached_tokens = sys_tokens if sys_hash in self._seen_system_hashes else 0
        if sys_hash not in self._seen_system_hashes:
            self._seen_system_hashes.append(sys_hash)

        logger.info(
            "MockAOAIClient returned offline extraction fixture",
            extra={
                "model": model,
                "fixture_source": source,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cached_tokens": cached_tokens,
            },
        )
        return MockChatCompletion(
            id=f"chatcmpl-mock-{self._call_count}",
            model=f"{model}-offline-mock",
            choices=[
                MockChatChoice(
                    index=0,
                    message=MockChatMessage(content=json_content),
                )
            ],
            usage=MockCompletionUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                prompt_tokens_details=MockPromptTokensDetails(cached_tokens=cached_tokens),
            ),
        )


__all__ = [
    "DEFAULT_MOCK_CONFIDENCE",
    "MAX_FIXTURE_FILE_BYTES",
    "MockAOAIClient",
    "MockChatChoice",
    "MockChatCompletion",
    "MockChatMessage",
    "MockCompletionUsage",
    "MockPromptTokensDetails",
    "build_default_fixture_schema",
]
