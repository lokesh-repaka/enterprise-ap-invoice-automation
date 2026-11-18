"""
Azure OpenAI Model Gateway with Hybrid Text vs. Vision Routing (P6-2).

Implements ADR-001, ADR-004, ADR-007, HLD §7.1, LLD §6.2, and CLAUDE.md §7.3:
- Hybrid routing based on P6-1 Document Classifier output:
  - ``searchable_pdf`` / ``xlsx`` -> **GPT-4o-mini** (~80% token savings)
  - ``scanned_image`` (or ``force_vision=True``) -> **GPT-4o Vision**
- 100% Keyless Entra ID Managed Identity authentication (``DefaultAzureCredential`` +
  ``get_bearer_token_provider``) pinned strictly to ``https://<resource>.openai.azure.com/``
  (prevents Managed Identity Bearer token exfiltration / SSRF: CWE-918 / CWE-522).
- Enforces Azure Prompt Caching message order (static ``system`` message first),
  JSON object output mode (``response_format={"type": "json_object"}``),
  deterministic ``temperature=0.0``, and hard ``<= 2,000`` output token ceiling (HLD §243).
- Exponential backoff with jitter on HTTP 429 / transient 5xx / timeout errors:
  ``2**attempt + Uniform(0, 1)`` seconds, max 4 total attempts (LLD §6.2).
- Zero imports from ``src/database/`` or ``src/validation/`` (CLAUDE.md §4.2).
"""

import asyncio
import json
import random
import re
import threading
import time
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncAzureOpenAI,
    RateLimitError,
)
from pydantic import BaseModel, ConfigDict

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.extraction.document_classifier import (
    DocumentClassificationResult,
    DocumentType,
    classify_document,
)

logger = get_logger("ap.extraction.model_gateway")

# Azure Cognitive Services Entra ID OAuth2 scope for keyless Managed Identity auth (ADR-007)
AZURE_COGNITIVE_SERVICES_SCOPE: str = "https://cognitiveservices.azure.com/.default"

# Hard operational ceilings (HLD §7.1, LLD §6.2, CWE-400)
MAX_OUTPUT_TOKENS: int = 2000
DEFAULT_MAX_OUTPUT_TOKENS: int = 2000
MAX_RETRY_ATTEMPTS: int = 4
DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 45.0
MAX_PROMPT_CHARS: int = 250_000
MAX_RESPONSE_CHARS: int = 128 * 1024
MAX_JSON_NESTING_DEPTH: int = 32
MAX_VISION_IMAGES: int = 10
MAX_SINGLE_IMAGE_DATA_URL_CHARS: int = 10 * 1024 * 1024
MAX_TOTAL_VISION_DATA_URL_CHARS: int = 25 * 1024 * 1024

MOCK_AOAI_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})
ALLOWED_VISION_DETAIL_LEVELS: frozenset[str] = frozenset({"auto", "low", "high"})

# Strict Azure OpenAI HTTPS endpoint, deployment, & API version pins (prevents SSRF & injection)
AOAI_ENDPOINT_PATTERN = re.compile(
    r"^https://([a-z0-9][a-z0-9-]{0,62}[a-z0-9])\.openai\.azure\.com/?$"
)
AOAI_DEPLOYMENT_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AOAI_API_VERSION_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:-(?:preview|alpha|beta))?$")
SAFE_VISION_DATA_URL_PATTERN = re.compile(r"^data:image/(?:png|jpeg);base64,[A-Za-z0-9+/=]+$")
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


class ModelRoute(StrEnum):
    """Canonical Azure OpenAI model routing targets (ADR-004)."""

    GPT4O_MINI = "gpt-4o-mini"
    GPT4O_VISION = "gpt-4o-vision"


class ModelGatewayError(RuntimeError):
    """Base error raised when an Azure OpenAI Model Gateway invocation fails."""


class ModelGatewayConfigurationError(ModelGatewayError):
    """Raised when Model Gateway configuration violates keyless, endpoint, or mock-isolation rules."""


class ModelRateLimitError(ModelGatewayError):
    """Raised when Azure OpenAI HTTP 429 rate-limit retries are exhausted."""


class ModelResponseParseError(ModelGatewayError):
    """Raised when the model response is empty, malformed JSON, or not a JSON object."""


class RoutingDecision(BaseModel):
    """Immutable deterministic routing decision emitted by Model Gateway."""

    model_config = ConfigDict(frozen=True)

    document_type: DocumentType
    route: ModelRoute
    deployment_name: str
    requires_vision: bool
    max_output_tokens: int
    reason: str


class ModelUsageMetrics(BaseModel):
    """Immutable token accounting and latency telemetry (zero PII)."""

    model_config = ConfigDict(frozen=True)

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cached_prompt_tokens: int = 0
    latency_ms: int = 0


class ModelGatewayResponse(BaseModel):
    """Immutable validated JSON completion returned by Model Gateway."""

    model_config = ConfigDict(frozen=True)

    routing: RoutingDecision
    parsed_json: dict[str, Any]
    raw_content: str
    model_version: str
    usage: ModelUsageMetrics
    attempts: int


@runtime_checkable
class AOAIChatClientProtocol(Protocol):
    """Injectable async Azure OpenAI chat-completion client protocol (real or offline mock)."""

    async def create_chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        temperature: float,
        response_format: dict[str, str],
        timeout: float,
    ) -> Any: ...


def validate_azure_openai_endpoint(url: str) -> str:
    """
    Validate and normalize an Azure OpenAI HTTPS endpoint URL.

    Strictly pins to ``https://<resource>.openai.azure.com/`` to block plaintext HTTP,
    embedded credentials, leaked query strings, and SSRF token exfiltration (CWE-918/522).
    """
    if not isinstance(url, str) or _CONTROL_CHAR_RE.search(url):
        raise ModelGatewayConfigurationError(
            "Invalid Azure OpenAI endpoint URL; expected https://<resource>.openai.azure.com/"
        )
    stripped = url.strip()
    if not AOAI_ENDPOINT_PATTERN.match(stripped):
        raise ModelGatewayConfigurationError(
            "Invalid Azure OpenAI endpoint URL; expected https://<resource>.openai.azure.com/"
        )
    return stripped if stripped.endswith("/") else f"{stripped}/"


def validate_deployment_name(name: str) -> str:
    """Validate an Azure OpenAI deployment name against safe path-segment characters."""
    if not isinstance(name, str) or not AOAI_DEPLOYMENT_PATTERN.match(name.strip()):
        raise ModelGatewayConfigurationError("Invalid Azure OpenAI deployment name")
    return name.strip()


def validate_api_version(api_version: str) -> str:
    """Validate an Azure OpenAI API version string to prevent query-parameter injection (CWE-20)."""
    if not isinstance(api_version, str) or not AOAI_API_VERSION_PATTERN.match(api_version.strip()):
        raise ModelGatewayConfigurationError("Invalid AZURE_OPENAI_API_VERSION")
    return api_version.strip()


def _validate_user_content(
    user_content: str | list[dict[str, Any]],
    *,
    requires_vision: bool,
) -> None:
    """Enforce prompt/image size limits, strict part schemas, and base64 Vision data URIs (CWE-20/400/918)."""
    if isinstance(user_content, str):
        if not user_content.strip():
            raise ValueError("user_content must be non-empty")
        if len(user_content) > MAX_PROMPT_CHARS:
            raise ValueError(
                f"user_content length exceeds maximum of {MAX_PROMPT_CHARS} characters"
            )
        return

    if not isinstance(user_content, list) or len(user_content) == 0:
        raise ValueError("user_content must be a non-empty string or multimodal content list")

    image_count = 0
    total_text_chars = 0
    total_image_chars = 0
    for part in user_content:
        if not isinstance(part, dict):
            raise ValueError("Each multimodal user_content item must be a dict")
        part_type = part.get("type")
        if part_type == "text":
            if set(part.keys()) != {"type", "text"}:
                raise ValueError("Multimodal text part contains unexpected keys")
            text_val = part.get("text")
            if not isinstance(text_val, str):
                raise ValueError("Multimodal text part must contain a string 'text' field")
            total_text_chars += len(text_val)
            if total_text_chars > MAX_PROMPT_CHARS:
                raise ValueError(f"Prompt text length exceeds maximum of {MAX_PROMPT_CHARS} chars")
        elif part_type == "image_url":
            if set(part.keys()) != {"type", "image_url"}:
                raise ValueError("Multimodal image_url part contains unexpected keys")
            image_count += 1
            if image_count > MAX_VISION_IMAGES:
                raise ValueError(
                    f"Vision request exceeds maximum of {MAX_VISION_IMAGES} images per invoice"
                )
            img_obj = part.get("image_url")
            if not isinstance(img_obj, dict):
                raise ValueError("Invalid image_url: expected object with 'url' field")
            extra_img_keys = set(img_obj.keys()) - {"url", "detail"}
            if extra_img_keys or "url" not in img_obj:
                raise ValueError("Invalid image_url: only 'url' and optional 'detail' keys allowed")
            if "detail" in img_obj and img_obj["detail"] not in ALLOWED_VISION_DETAIL_LEVELS:
                raise ValueError(
                    "Invalid image_url detail: must be one of 'auto', 'low', or 'high'"
                )
            url_val = img_obj.get("url")
            if (
                not isinstance(url_val, str)
                or len(url_val) > MAX_SINGLE_IMAGE_DATA_URL_CHARS
                or not SAFE_VISION_DATA_URL_PATTERN.match(url_val)
            ):
                raise ValueError(
                    "Invalid image_url: only base64 data:image/png or data:image/jpeg URIs are permitted"
                )
            total_image_chars += len(url_val)
            if total_image_chars > MAX_TOTAL_VISION_DATA_URL_CHARS:
                raise ValueError(
                    f"Cumulative Vision image payload exceeds maximum of {MAX_TOTAL_VISION_DATA_URL_CHARS} chars"
                )
        else:
            raise ValueError(f"Unsupported multimodal content part type: {part_type!r}")

    if image_count > 0 and not requires_vision:
        raise ValueError("Image content parts require a Vision-capable route (GPT-4o Vision)")


def _enforce_max_json_depth(obj: Any, *, max_depth: int = MAX_JSON_NESTING_DEPTH) -> None:
    """Iteratively verify parsed JSON nesting depth does not exceed ceiling (CWE-674)."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ModelResponseParseError(
                f"Azure OpenAI JSON output exceeds maximum nesting depth of {max_depth}"
            )
        if isinstance(current, dict):
            for val in current.values():
                if isinstance(val, (dict, list)):
                    stack.append((val, depth + 1))
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))


def _is_retryable_aoai_error(exc: Exception) -> bool:
    """Return True for transient Azure OpenAI 429, timeout, connection, or 5xx errors."""
    if isinstance(exc, (RateLimitError, APITimeoutError, APIConnectionError)):
        return True
    if isinstance(exc, APIStatusError):
        status_code = getattr(exc, "status_code", None)
        return isinstance(status_code, int) and (status_code == 429 or 500 <= status_code < 600)
    return False


def _extract_usage_metrics(raw_response: Any, *, latency_ms: int) -> ModelUsageMetrics:
    """Safely extract token usage & prompt-cache hit counters from an OpenAI completion response."""
    usage = getattr(raw_response, "usage", None)
    if usage is None:
        return ModelUsageMetrics(latency_ms=latency_ms)

    prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
    total_tokens = int(getattr(usage, "total_tokens", prompt_tokens + completion_tokens) or 0)
    details = getattr(usage, "prompt_tokens_details", None)
    cached_tokens = int(getattr(details, "cached_tokens", 0) or 0) if details is not None else 0

    return ModelUsageMetrics(
        prompt_tokens=max(prompt_tokens, 0),
        completion_tokens=max(completion_tokens, 0),
        total_tokens=max(total_tokens, 0),
        cached_prompt_tokens=max(cached_tokens, 0),
        latency_ms=max(latency_ms, 0),
    )


class KeylessAzureOpenAIClient:
    """
    Production Azure OpenAI async client using keyless Microsoft Entra ID Managed Identity (ADR-007).
    """

    def __init__(
        self,
        *,
        endpoint: str,
        api_version: str,
        credential: Any | None = None,
    ) -> None:
        self._endpoint = validate_azure_openai_endpoint(endpoint)
        self._api_version = validate_api_version(api_version)
        self._credential = credential
        self._client: AsyncAzureOpenAI | None = None
        self._lock = threading.Lock()

    def _get_client(self) -> AsyncAzureOpenAI:
        with self._lock:
            if self._client is not None:
                return self._client

            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            cred = self._credential or DefaultAzureCredential()
            token_provider = get_bearer_token_provider(cred, AZURE_COGNITIVE_SERVICES_SCOPE)
            self._client = AsyncAzureOpenAI(
                azure_endpoint=self._endpoint,
                azure_ad_token_provider=token_provider,
                api_version=self._api_version,
                max_retries=0,  # ModelGateway owns deterministic LLD §6.2 retry & jitter
            )
            return self._client

    async def create_chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        temperature: float,
        response_format: dict[str, str],
        timeout: float,
    ) -> Any:
        client = self._get_client()
        return await client.chat.completions.create(
            model=model,
            messages=messages,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=temperature,
            response_format=response_format,  # type: ignore[arg-type]
            timeout=timeout,
        )


class ModelGateway:
    """
    Hybrid Azure OpenAI Model Gateway routing invoices to GPT-4o-mini or GPT-4o Vision (ADR-004).
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        chat_client: AOAIChatClientProtocol,
        max_attempts: int = MAX_RETRY_ATTEMPTS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter_fn: Callable[[], float] | None = None,
    ) -> None:
        cfg = settings or get_settings()
        self._mini_deployment = validate_deployment_name(cfg.AZURE_OPENAI_MINI_DEPLOYMENT)
        self._vision_deployment = validate_deployment_name(cfg.AZURE_OPENAI_GPT4O_DEPLOYMENT)
        self._chat_client = chat_client
        self._max_attempts = max(1, min(int(max_attempts), MAX_RETRY_ATTEMPTS))
        self._timeout = max(1.0, min(float(request_timeout_seconds), 120.0))
        self._sleep_fn = sleep_fn
        self._jitter_fn = jitter_fn or (lambda: random.uniform(0.0, 1.0))

    def select_route(
        self,
        classification: DocumentClassificationResult | DocumentType,
        *,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        force_vision: bool = False,
    ) -> RoutingDecision:
        """Select cheapest capable Azure OpenAI deployment for the classified document (ADR-004)."""
        if (
            isinstance(max_output_tokens, bool)
            or not isinstance(max_output_tokens, int)
            or not (1 <= max_output_tokens <= MAX_OUTPUT_TOKENS)
        ):
            raise ValueError(
                f"max_output_tokens must be an integer within [1, {MAX_OUTPUT_TOKENS}]"
            )

        doc_type = (
            classification.document_type
            if isinstance(classification, DocumentClassificationResult)
            else classification
        )
        if not isinstance(doc_type, DocumentType):
            raise ValueError(f"Unsupported document classification type: {doc_type!r}")

        if force_vision:
            return RoutingDecision(
                document_type=doc_type,
                route=ModelRoute.GPT4O_VISION,
                deployment_name=self._vision_deployment,
                requires_vision=True,
                max_output_tokens=max_output_tokens,
                reason="escalated_to_vision_override",
            )

        if doc_type == DocumentType.SCANNED_IMAGE:
            return RoutingDecision(
                document_type=doc_type,
                route=ModelRoute.GPT4O_VISION,
                deployment_name=self._vision_deployment,
                requires_vision=True,
                max_output_tokens=max_output_tokens,
                reason="scanned_or_raster_vision_route",
            )

        # SEARCHABLE_PDF and XLSX route to fast, low-cost GPT-4o-mini (ADR-004)
        return RoutingDecision(
            document_type=doc_type,
            route=ModelRoute.GPT4O_MINI,
            deployment_name=self._mini_deployment,
            requires_vision=False,
            max_output_tokens=max_output_tokens,
            reason=f"{doc_type.value}_text_mini_route",
        )

    async def invoke(
        self,
        *,
        classification: DocumentClassificationResult | DocumentType,
        system_prompt: str,
        user_content: str | list[dict[str, Any]],
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        force_vision: bool = False,
    ) -> ModelGatewayResponse:
        """
        Invoke the routed Azure OpenAI deployment with prompt-caching order, JSON mode,
        strict 2,000-token output ceiling, and LLD §6.2 exponential backoff + jitter.
        """
        if not isinstance(system_prompt, str) or not system_prompt.strip():
            raise ValueError("system_prompt must be a non-empty string")
        if len(system_prompt) > MAX_PROMPT_CHARS:
            raise ValueError(
                f"system_prompt length exceeds maximum of {MAX_PROMPT_CHARS} characters"
            )

        routing = self.select_route(
            classification,
            max_output_tokens=max_output_tokens,
            force_vision=force_vision,
        )
        _validate_user_content(user_content, requires_vision=routing.requires_vision)

        # Static system prompt ALWAYS precedes variable user content to trigger Azure Prompt Caching
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        start_monotonic = time.monotonic()
        last_exc: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            try:
                raw_response = await self._chat_client.create_chat_completion(
                    model=routing.deployment_name,
                    messages=messages,
                    max_tokens=routing.max_output_tokens,
                    temperature=0.0,
                    response_format={"type": "json_object"},
                    timeout=self._timeout,
                )
                latency_ms = int((time.monotonic() - start_monotonic) * 1000)
                return self._parse_completion(
                    raw_response,
                    routing=routing,
                    latency_ms=latency_ms,
                    attempts=attempt,
                )
            except ModelResponseParseError:
                raise
            except Exception as exc:
                last_exc = exc
                if _is_retryable_aoai_error(exc) and attempt < self._max_attempts:
                    jitter = max(0.0, min(float(self._jitter_fn()), 1.0))
                    delay = float(2**attempt) + jitter
                    logger.warning(
                        "Transient Azure OpenAI error; backing off before retry",
                        extra={
                            "route": routing.route.value,
                            "attempt": attempt,
                            "backoff_seconds": round(delay, 3),
                            "error_type": type(exc).__name__,
                        },
                    )
                    await self._sleep_fn(delay)
                    continue
                break

        logger.error(
            "Model Gateway invocation failed",
            extra={
                "route": routing.route.value,
                "deployment": routing.deployment_name,
                "error_type": type(last_exc).__name__ if last_exc else "UnknownError",
            },
        )
        if isinstance(last_exc, RateLimitError) or (
            isinstance(last_exc, APIStatusError) and getattr(last_exc, "status_code", None) == 429
        ):
            raise ModelRateLimitError(
                "Azure OpenAI rate limit exceeded after maximum retry attempts"
            ) from None
        raise ModelGatewayError("Azure OpenAI extraction request failed") from None

    def _parse_completion(
        self,
        raw_response: Any,
        *,
        routing: RoutingDecision,
        latency_ms: int,
        attempts: int,
    ) -> ModelGatewayResponse:
        choices = getattr(raw_response, "choices", None)
        if not choices or not isinstance(choices, list):
            raise ModelResponseParseError("Azure OpenAI returned no completion choices")

        msg = getattr(choices[0], "message", None)
        raw_content = getattr(msg, "content", None)
        if not isinstance(raw_content, str) or not raw_content.strip():
            raise ModelResponseParseError("Azure OpenAI returned empty completion content")
        if len(raw_content) > MAX_RESPONSE_CHARS:
            raise ModelResponseParseError(
                f"Azure OpenAI completion exceeds maximum size of {MAX_RESPONSE_CHARS} characters"
            )

        try:
            parsed = json.loads(raw_content)
        except (json.JSONDecodeError, RecursionError):
            raise ModelResponseParseError("Azure OpenAI returned malformed JSON output") from None

        if not isinstance(parsed, dict):
            raise ModelResponseParseError("Azure OpenAI JSON output must be a JSON object")
        _enforce_max_json_depth(parsed)

        usage = _extract_usage_metrics(raw_response, latency_ms=latency_ms)
        model_version = str(getattr(raw_response, "model", routing.deployment_name))

        logger.info(
            "Model Gateway invocation completed",
            extra={
                "route": routing.route.value,
                "deployment": routing.deployment_name,
                "model_version": model_version,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "cached_prompt_tokens": usage.cached_prompt_tokens,
                "latency_ms": usage.latency_ms,
                "attempts": attempts,
            },
        )
        return ModelGatewayResponse(
            routing=routing,
            parsed_json=parsed,
            raw_content=raw_content,
            model_version=model_version,
            usage=usage,
            attempts=attempts,
        )


_GATEWAY_LOCK = threading.Lock()
_CACHED_GATEWAY: ModelGateway | None = None
_CACHED_GATEWAY_KEY: tuple[str, bool, bool, str, str, str, str, str] | None = None


def reset_model_gateway_cache() -> None:
    """Clear cached ModelGateway singleton (for isolated unit testing)."""
    global _CACHED_GATEWAY, _CACHED_GATEWAY_KEY
    with _GATEWAY_LOCK:
        _CACHED_GATEWAY = None
        _CACHED_GATEWAY_KEY = None


def get_model_gateway(
    settings: Settings | None = None,
    *,
    chat_client: AOAIChatClientProtocol | None = None,
) -> ModelGateway:
    """
    Return the configured ``ModelGateway`` singleton.

    Enforces:
    - ``USE_MOCK_AOAI=True`` is strictly blocked outside ``dev``/``local``/``test``
      or whenever ``USE_LOCAL_SQLITE=False`` (CWE-489).
    - Production uses keyless ``KeylessAzureOpenAIClient`` pinned to ``*.openai.azure.com/`` (ADR-007).
    """
    global _CACHED_GATEWAY, _CACHED_GATEWAY_KEY
    cfg = settings or get_settings()
    env_name = cfg.APP_ENV.strip().lower()

    if chat_client is not None:
        return ModelGateway(settings=cfg, chat_client=chat_client)

    if cfg.USE_MOCK_AOAI:
        if env_name not in MOCK_AOAI_ALLOWED_ENVS:
            raise ModelGatewayConfigurationError(
                f"USE_MOCK_AOAI=true is strictly prohibited in environment '{env_name}'"
            )
        if not cfg.USE_LOCAL_SQLITE:
            raise ModelGatewayConfigurationError(
                "USE_MOCK_AOAI=true requires USE_LOCAL_SQLITE=true (cannot pair mock AI with Azure SQL)"
            )

    cache_key = (
        env_name,
        cfg.USE_MOCK_AOAI,
        cfg.USE_LOCAL_SQLITE,
        cfg.SAMPLE_DATA_DIR,
        cfg.AZURE_OPENAI_ENDPOINT,
        cfg.AZURE_OPENAI_API_VERSION,
        cfg.AZURE_OPENAI_MINI_DEPLOYMENT,
        cfg.AZURE_OPENAI_GPT4O_DEPLOYMENT,
    )
    with _GATEWAY_LOCK:
        if _CACHED_GATEWAY is not None and _CACHED_GATEWAY_KEY == cache_key:
            return _CACHED_GATEWAY

        if cfg.USE_MOCK_AOAI:
            from src.extraction.mock_aoai_client import MockAOAIClient

            client: AOAIChatClientProtocol = MockAOAIClient(settings=cfg)
        else:
            client = KeylessAzureOpenAIClient(
                endpoint=cfg.AZURE_OPENAI_ENDPOINT,
                api_version=cfg.AZURE_OPENAI_API_VERSION,
            )

        gateway = ModelGateway(settings=cfg, chat_client=client)
        _CACHED_GATEWAY = gateway
        _CACHED_GATEWAY_KEY = cache_key
        return gateway


__all__ = [
    "AOAIChatClientProtocol",
    "AZURE_COGNITIVE_SERVICES_SCOPE",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "DocumentClassificationResult",
    "DocumentType",
    "KeylessAzureOpenAIClient",
    "MAX_OUTPUT_TOKENS",
    "MAX_PROMPT_CHARS",
    "MAX_RESPONSE_CHARS",
    "MAX_RETRY_ATTEMPTS",
    "MAX_TOTAL_VISION_DATA_URL_CHARS",
    "MAX_VISION_IMAGES",
    "ModelGateway",
    "ModelGatewayConfigurationError",
    "ModelGatewayError",
    "ModelGatewayResponse",
    "ModelRateLimitError",
    "ModelResponseParseError",
    "ModelRoute",
    "ModelUsageMetrics",
    "RoutingDecision",
    "classify_document",
    "get_model_gateway",
    "reset_model_gateway_cache",
    "validate_api_version",
    "validate_azure_openai_endpoint",
    "validate_deployment_name",
]
