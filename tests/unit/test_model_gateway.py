"""
Unit and Security Tests for Model Gateway (P6-2).

Tests: ADR-001, ADR-004, ADR-007, HLD §7.1, LLD §6.2, CLAUDE.md §4.2, §7.3, CWE-20, CWE-209, CWE-400, CWE-489, CWE-522, CWE-532, CWE-918
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from openai import APIStatusError, APITimeoutError, BadRequestError, RateLimitError

from src.core.config import Settings
from src.extraction.document_classifier import DocumentClassificationResult, DocumentType
from src.extraction.model_gateway import (
    MAX_OUTPUT_TOKENS,
    MAX_PROMPT_CHARS,
    MAX_RESPONSE_CHARS,
    MAX_TOTAL_VISION_DATA_URL_CHARS,
    MAX_VISION_IMAGES,
    KeylessAzureOpenAIClient,
    ModelGateway,
    ModelGatewayConfigurationError,
    ModelGatewayError,
    ModelRateLimitError,
    ModelResponseParseError,
    ModelRoute,
    get_model_gateway,
    reset_model_gateway_cache,
    validate_api_version,
    validate_azure_openai_endpoint,
)


def _make_fake_aoai_response(
    payload: dict[str, Any] | str,
    *,
    model: str = "gpt-4o-mini-2024-07-18",
    prompt_tokens: int = 1200,
    completion_tokens: int = 450,
    cached_tokens: int = 600,
) -> MagicMock:
    """Create a realistic OpenAI ChatCompletion-shaped mock response object."""
    resp = MagicMock()
    resp.model = model
    choice = MagicMock()
    choice.message.content = payload if isinstance(payload, str) else json.dumps(payload)
    resp.choices = [choice]
    resp.usage.prompt_tokens = prompt_tokens
    resp.usage.completion_tokens = completion_tokens
    resp.usage.total_tokens = prompt_tokens + completion_tokens
    resp.usage.prompt_tokens_details.cached_tokens = cached_tokens
    return resp


class _RecordingChatClient:
    """In-memory async AOAI client stub recording calls and replaying scripted responses/errors."""

    def __init__(self, script: list[Any]) -> None:
        self._script = list(script)
        self.calls: list[dict[str, Any]] = []

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
        self.calls.append(
            {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "response_format": response_format,
                "timeout": timeout,
            }
        )
        nxt = self._script.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt


def _make_rate_limit_error() -> RateLimitError:
    req = httpx.Request("POST", "https://aoai-ap-eastus2.openai.azure.com/openai/deployments/x")
    resp = httpx.Response(429, request=req)
    return RateLimitError("Rate limit exceeded", response=resp, body=None)


def _make_bad_request_error() -> BadRequestError:
    req = httpx.Request("POST", "https://aoai-ap-eastus2.openai.azure.com/openai/deployments/x")
    resp = httpx.Response(400, request=req)
    return BadRequestError("Bad request", response=resp, body=None)


def test_select_route_maps_searchable_pdf_xlsx_to_mini_and_scanned_image_to_vision() -> None:
    """Verify ADR-004 hybrid routing: searchable_pdf/xlsx -> gpt-4o-mini, scanned_image -> gpt-4o-vision."""
    settings = Settings(
        AZURE_OPENAI_MINI_DEPLOYMENT="gpt-4o-mini-prod",
        AZURE_OPENAI_GPT4O_DEPLOYMENT="gpt-4o-vision-prod",
    )
    gateway = ModelGateway(settings=settings, chat_client=_RecordingChatClient([]))

    pdf_route = gateway.select_route(DocumentType.SEARCHABLE_PDF)
    assert pdf_route.route == ModelRoute.GPT4O_MINI
    assert pdf_route.deployment_name == "gpt-4o-mini-prod"
    assert pdf_route.requires_vision is False

    xlsx_route = gateway.select_route(DocumentType.XLSX)
    assert xlsx_route.route == ModelRoute.GPT4O_MINI
    assert xlsx_route.deployment_name == "gpt-4o-mini-prod"
    assert xlsx_route.requires_vision is False

    scan_route = gateway.select_route(DocumentType.SCANNED_IMAGE)
    assert scan_route.route == ModelRoute.GPT4O_VISION
    assert scan_route.deployment_name == "gpt-4o-vision-prod"
    assert scan_route.requires_vision is True

    # Classification result object + explicit Vision escalation override
    cls_res = DocumentClassificationResult(
        document_type=DocumentType.SEARCHABLE_PDF,
        detected_mime="application/pdf",
        page_count=1,
        total_text_chars=300,
        mean_chars_per_page=300.0,
        text_density_ratio=1.0,
        reason="pdf_dense_text_layer",
    )
    escalated = gateway.select_route(cls_res, force_vision=True)
    assert escalated.route == ModelRoute.GPT4O_VISION
    assert escalated.requires_vision is True
    assert "escalated" in escalated.reason


def test_invoke_enforces_prompt_caching_order_json_mode_and_2000_token_budget() -> None:
    """Verify static system prompt precedes user prompt, JSON mode & temperature=0.0, and <=2000 token cap."""
    stub = _RecordingChatClient([_make_fake_aoai_response({"invoice_number": "INV-2026-1001"})])
    gateway = ModelGateway(settings=Settings(), chat_client=stub)

    async def _run() -> None:
        res = await gateway.invoke(
            classification=DocumentType.SEARCHABLE_PDF,
            system_prompt="Extract invoice JSON strictly per schema.",
            user_content="<invoice_text>INVOICE #INV-2026-1001 Total 1350.00</invoice_text>",
            max_output_tokens=1500,
        )
        assert res.routing.route == ModelRoute.GPT4O_MINI
        assert res.parsed_json == {"invoice_number": "INV-2026-1001"}
        assert res.usage.prompt_tokens == 1200
        assert res.usage.completion_tokens == 450
        assert res.usage.cached_prompt_tokens == 600
        assert res.usage.total_tokens == 1650
        assert res.attempts == 1

        call = stub.calls[0]
        assert call["messages"][0]["role"] == "system"
        assert call["messages"][1]["role"] == "user"
        assert call["response_format"] == {"type": "json_object"}
        assert call["temperature"] == 0.0
        assert call["max_tokens"] == 1500

        # Output token ceiling >2000 or <=0 MUST fail closed (HLD §243)
        for bad_tokens in (0, -10, MAX_OUTPUT_TOKENS + 1):
            with pytest.raises(ValueError, match="max_output_tokens"):
                await gateway.invoke(
                    classification=DocumentType.SEARCHABLE_PDF,
                    system_prompt="System",
                    user_content="User",
                    max_output_tokens=bad_tokens,
                )

    asyncio.run(_run())


def test_invoke_retries_http_429_with_lld_exponential_backoff_and_fails_fast_on_400() -> None:
    """Verify LLD §6.2 backoff (2^attempt + Uniform(0,1), max 4 attempts) and zero retries on 400."""

    async def _run() -> None:
        sleeps: list[float] = []

        async def _fake_sleep(sec: float) -> None:
            sleeps.append(sec)

        # 1. Succeeds on attempt 3 after two 429s -> sleeps [2^1+0.25=2.25, 2^2+0.25=4.25]
        stub_ok = _RecordingChatClient(
            [
                _make_rate_limit_error(),
                _make_rate_limit_error(),
                _make_fake_aoai_response({"ok": True}),
            ]
        )
        gw_ok = ModelGateway(
            settings=Settings(),
            chat_client=stub_ok,
            sleep_fn=_fake_sleep,
            jitter_fn=lambda: 0.25,
        )
        res = await gw_ok.invoke(
            classification=DocumentType.SEARCHABLE_PDF,
            system_prompt="System",
            user_content="User",
        )
        assert res.attempts == 3
        assert sleeps == [2.25, 4.25]

        # 2. Exhausting all 4 attempts raises ModelRateLimitError with sleeps [2.5, 4.5, 8.5]
        sleeps.clear()
        stub_exhaust = _RecordingChatClient([_make_rate_limit_error() for _ in range(4)])
        gw_exhaust = ModelGateway(
            settings=Settings(),
            chat_client=stub_exhaust,
            sleep_fn=_fake_sleep,
            jitter_fn=lambda: 0.5,
        )
        with pytest.raises(ModelRateLimitError):
            await gw_exhaust.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="System",
                user_content="User",
            )
        assert len(stub_exhaust.calls) == 4
        assert sleeps == [2.5, 4.5, 8.5]

        # 3. Non-retryable 400 fails immediately on attempt 1 (zero sleeps)
        sleeps.clear()
        stub_400 = _RecordingChatClient([_make_bad_request_error()])
        gw_400 = ModelGateway(settings=Settings(), chat_client=stub_400, sleep_fn=_fake_sleep)
        with pytest.raises(ModelGatewayError):
            await gw_400.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="System",
                user_content="User",
            )
        assert len(stub_400.calls) == 1
        assert sleeps == []

    asyncio.run(_run())


def test_endpoint_validation_blocks_ssrf_and_factory_blocks_mock_aoai_in_production() -> None:
    """Verify AOAI endpoint pins strictly to HTTPS *.openai.azure.com/ and USE_MOCK_AOAI blocks prod (CWE-918/489)."""
    assert (
        validate_azure_openai_endpoint("https://aoai-ap-eastus2.openai.azure.com")
        == "https://aoai-ap-eastus2.openai.azure.com/"
    )

    for bad_ep in (
        "",
        "http://aoai-ap-eastus2.openai.azure.com/",
        "https://evil.attacker.example/",
        "https://aoai.openai.azure.com.evil.example/",
        "https://user:pass@aoai-ap-eastus2.openai.azure.com/",
        "https://aoai-ap-eastus2.openai.azure.com/?api-key=leaked",
        "https://aoai-ap-eastus2.openai.azure.com/\r\nX-Evil: 1",
    ):
        with pytest.raises(ModelGatewayConfigurationError):
            validate_azure_openai_endpoint(bad_ep)

    reset_model_gateway_cache()
    for blocked_env in ("staging", "production", "prod", "uat"):
        with pytest.raises(ModelGatewayConfigurationError):
            get_model_gateway(Settings(APP_ENV=blocked_env, USE_MOCK_AOAI=True))

    # Even in dev, USE_MOCK_AOAI=True cannot pair with real Azure SQL (USE_LOCAL_SQLITE=False)
    with pytest.raises(ModelGatewayConfigurationError):
        get_model_gateway(Settings(APP_ENV="dev", USE_MOCK_AOAI=True, USE_LOCAL_SQLITE=False))
    reset_model_gateway_cache()


def test_vision_input_blocks_external_ssrf_urls_excessive_images_and_oversized_prompts() -> None:
    """Verify Vision payloads allow only base64 data URIs (blocking SSRF), <=10 images, and bounded prompt size."""
    stub = _RecordingChatClient([_make_fake_aoai_response({"ok": True})])
    gateway = ModelGateway(settings=Settings(), chat_client=stub)

    async def _run() -> None:
        # Valid base64 PNG data URI passes
        valid_vision = [
            {"type": "text", "text": "Extract invoice fields from scan."},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
        ]
        res = await gateway.invoke(
            classification=DocumentType.SCANNED_IMAGE,
            system_prompt="System prompt",
            user_content=valid_vision,
        )
        assert res.routing.route == ModelRoute.GPT4O_VISION

        # External HTTP/HTTPS image URLs blocked (prevents AOAI SSRF / data exfiltration: CWE-918)
        for bad_url in (
            "https://evil.attacker.example/pixel.png",
            "http://169.254.169.254/latest/meta-data/",
            "data:image/svg+xml;base64,PHN2Zz4=",
        ):
            with pytest.raises(ValueError, match="image_url"):
                await gateway.invoke(
                    classification=DocumentType.SCANNED_IMAGE,
                    system_prompt="System",
                    user_content=[{"type": "image_url", "image_url": {"url": bad_url}}],
                )

        # Excessive Vision image count (> MAX_VISION_IMAGES) rejected (CWE-400)
        too_many_imgs = [
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
            for _ in range(MAX_VISION_IMAGES + 1)
        ]
        with pytest.raises(ValueError, match="images"):
            await gateway.invoke(
                classification=DocumentType.SCANNED_IMAGE,
                system_prompt="System",
                user_content=too_many_imgs,
            )

        # Oversized text prompt rejected (CWE-400)
        with pytest.raises(ValueError, match="length"):
            await gateway.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="System",
                user_content="A" * (MAX_PROMPT_CHARS + 1),
            )

    asyncio.run(_run())


def test_rejects_malformed_or_non_object_json_responses_and_sanitizes_errors() -> None:
    """Verify non-JSON / non-dict model outputs raise ModelResponseParseError and errors never leak secrets."""

    async def _run() -> None:
        # Malformed JSON
        gw_bad_json = ModelGateway(
            settings=Settings(),
            chat_client=_RecordingChatClient([_make_fake_aoai_response("{not-json")]),
        )
        with pytest.raises(ModelResponseParseError):
            await gw_bad_json.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content="Usr",
            )

        # Valid JSON array instead of JSON object
        gw_arr = ModelGateway(
            settings=Settings(),
            chat_client=_RecordingChatClient([_make_fake_aoai_response("[1, 2, 3]")]),
        )
        with pytest.raises(ModelResponseParseError):
            await gw_arr.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content="Usr",
            )

        # Timeout error containing sensitive text is sanitized (CWE-209)
        req = httpx.Request("POST", "https://aoai.openai.azure.com/")
        timeout_err = APITimeoutError(request=req)
        gw_timeout = ModelGateway(
            settings=Settings(),
            chat_client=_RecordingChatClient([timeout_err for _ in range(4)]),
            sleep_fn=lambda _s: asyncio.sleep(0),
        )
        with pytest.raises(ModelGatewayError) as exc_info:
            await gw_timeout.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content="Usr",
            )
        assert "openai.azure.com" not in str(exc_info.value)

    asyncio.run(_run())


def test_keyless_hygiene_zero_pii_logs_and_layering_compliance(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify zero static API keys, zero DB/validation imports, and zero prompt PII in logs (ADR-007/CWE-532)."""
    src_code = Path("src/extraction/model_gateway.py").read_text(encoding="utf-8")
    for forbidden in ("api_key=", "sk-", "src.database", "src.validation", "sqlalchemy"):
        assert forbidden not in src_code

    stub = _RecordingChatClient([_make_fake_aoai_response({"total": "100.00"})])
    gateway = ModelGateway(settings=Settings(), chat_client=stub)

    async def _run() -> None:
        with caplog.at_level(logging.DEBUG, logger="ap.extraction.model_gateway"):
            await gateway.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Extract JSON.",
                user_content="<invoice_text>Tax ID US-12-3456789 IBAN DE89370400440532013000</invoice_text>",
            )

    asyncio.run(_run())
    combined = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined
    assert "DE89370400440532013000" not in combined


def test_rejects_oversized_or_deeply_nested_json_response_and_cumulative_vision_bomb() -> None:
    """Verify CWE-400/674/20 guards: response size cap, JSON recursion bomb, cumulative Vision cap, and strict part keys."""

    async def _run() -> None:
        # 1. Oversized model completion (> MAX_RESPONSE_CHARS) fails closed before json.loads
        oversized_json = '{"pad":"' + ("x" * MAX_RESPONSE_CHARS) + '"}'
        gw_big = ModelGateway(
            settings=Settings(),
            chat_client=_RecordingChatClient([_make_fake_aoai_response(oversized_json)]),
        )
        with pytest.raises(ModelResponseParseError, match="maximum size"):
            await gw_big.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content="Usr",
            )

        # 2. Deeply nested JSON bomb triggers RecursionError -> ModelResponseParseError
        nested_bomb = '{"a":' * 2000 + "1" + "}" * 2000
        gw_nest = ModelGateway(
            settings=Settings(),
            chat_client=_RecordingChatClient([_make_fake_aoai_response(nested_bomb)]),
        )
        with pytest.raises(ModelResponseParseError):
            await gw_nest.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content="Usr",
            )

        # 3. Cumulative Vision payload (> MAX_TOTAL_VISION_DATA_URL_CHARS) rejected even if each image <= 10 MB
        gw_vis = ModelGateway(settings=Settings(), chat_client=_RecordingChatClient([]))
        big_img = "data:image/png;base64," + ("A" * (9 * 1024 * 1024))
        assert len(big_img) * 3 > MAX_TOTAL_VISION_DATA_URL_CHARS
        with pytest.raises(ValueError, match="Cumulative Vision image payload"):
            await gw_vis.invoke(
                classification=DocumentType.SCANNED_IMAGE,
                system_prompt="Sys",
                user_content=[
                    {"type": "image_url", "image_url": {"url": big_img}} for _ in range(3)
                ],
            )

        # 4. Injected extra keys or invalid detail in multimodal part rejected (CWE-20)
        for bad_part in (
            {"type": "text", "text": "ok", "role": "system"},
            {
                "type": "image_url",
                "image_url": {"url": "data:image/png;base64,AAAA", "detail": "ultra"},
            },
            {
                "type": "image_url",
                "image_url": {"url": "data:image/png;base64,AAAA", "headers": {"X": "1"}},
            },
        ):
            with pytest.raises(ValueError):
                await gw_vis.invoke(
                    classification=DocumentType.SCANNED_IMAGE,
                    system_prompt="Sys",
                    user_content=[bad_part],
                )

        # 5. Image part sent to non-Vision route (SEARCHABLE_PDF without force_vision) rejected
        with pytest.raises(ValueError, match="Vision-capable route"):
            await gw_vis.invoke(
                classification=DocumentType.SEARCHABLE_PDF,
                system_prompt="Sys",
                user_content=[
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
                ],
            )

    asyncio.run(_run())


def test_api_version_injection_and_production_keyless_client_factory_wiring() -> None:
    """Verify API version allowlist blocks query injection and production factory uses KeylessAzureOpenAIClient."""
    assert validate_api_version("2024-10-21") == "2024-10-21"
    assert validate_api_version("2025-01-01-preview") == "2025-01-01-preview"

    for bad_ver in (
        "",
        "2024-10-21&api-key=evil",
        "../v2?foo=bar",
        "2024-10-21\r\nX-Evil: 1",
        "latest",
    ):
        with pytest.raises(ModelGatewayConfigurationError):
            validate_api_version(bad_ver)

    reset_model_gateway_cache()
    prod_settings = Settings(
        APP_ENV="production",
        USE_MOCK_AOAI=False,
        USE_LOCAL_SQLITE=False,
        AZURE_OPENAI_ENDPOINT="https://aoai-ap-eastus2.openai.azure.com/",
        AZURE_OPENAI_API_VERSION="2024-10-21",
    )
    gw_prod = get_model_gateway(prod_settings)
    assert isinstance(gw_prod._chat_client, KeylessAzureOpenAIClient)

    # Changing API version refreshes singleton instead of returning stale instance
    prod_settings_v2 = Settings(
        APP_ENV="production",
        USE_MOCK_AOAI=False,
        USE_LOCAL_SQLITE=False,
        AZURE_OPENAI_ENDPOINT="https://aoai-ap-eastus2.openai.azure.com/",
        AZURE_OPENAI_API_VERSION="2025-01-01-preview",
    )
    gw_prod_v2 = get_model_gateway(prod_settings_v2)
    assert gw_prod_v2 is not gw_prod
    reset_model_gateway_cache()


def test_retry_policy_handles_5xx_retries_and_fails_fast_on_403_and_classifies_429_status_error() -> (
    None
):
    """Verify HTTP 500 retries, HTTP 403 fails fast without secret leakage, and 429 APIStatusError raises ModelRateLimitError."""

    def _status_err(code: int, message: str) -> APIStatusError:
        req = httpx.Request("POST", "https://aoai-ap-eastus2.openai.azure.com/openai/deployments/x")
        resp = httpx.Response(code, request=req)
        return APIStatusError(message, response=resp, body=None)

    async def _run() -> None:
        sleeps: list[float] = []

        async def _fake_sleep(sec: float) -> None:
            sleeps.append(sec)

        # 1. Transient HTTP 503 retries and succeeds on attempt 2
        stub_503 = _RecordingChatClient(
            [_status_err(503, "Service Unavailable"), _make_fake_aoai_response({"ok": True})]
        )
        gw_503 = ModelGateway(
            settings=Settings(),
            chat_client=stub_503,
            sleep_fn=_fake_sleep,
            jitter_fn=lambda: 0.1,
        )
        res = await gw_503.invoke(
            classification=DocumentType.XLSX,
            system_prompt="Sys",
            user_content="Usr",
        )
        assert res.attempts == 2
        assert sleeps == [2.1]

        # 2. HTTP 403 fails fast on attempt 1 without leaking upstream error details
        sleeps.clear()
        stub_403 = _RecordingChatClient([_status_err(403, "Bearer secret-token-denied")])
        gw_403 = ModelGateway(settings=Settings(), chat_client=stub_403, sleep_fn=_fake_sleep)
        with pytest.raises(ModelGatewayError) as exc_403:
            await gw_403.invoke(
                classification=DocumentType.XLSX,
                system_prompt="Sys",
                user_content="Usr",
            )
        assert len(stub_403.calls) == 1
        assert sleeps == []
        assert "secret-token-denied" not in str(exc_403.value)

        # 3. Exhausted raw APIStatusError(429) raises ModelRateLimitError
        sleeps.clear()
        stub_429 = _RecordingChatClient([_status_err(429, "Too Many Requests") for _ in range(4)])
        gw_429 = ModelGateway(
            settings=Settings(),
            chat_client=stub_429,
            sleep_fn=_fake_sleep,
            jitter_fn=lambda: 0.0,
        )
        with pytest.raises(ModelRateLimitError):
            await gw_429.invoke(
                classification=DocumentType.XLSX,
                system_prompt="Sys",
                user_content="Usr",
            )
        assert len(stub_429.calls) == 4
        assert sleeps == [2.0, 4.0, 8.0]

    asyncio.run(_run())
