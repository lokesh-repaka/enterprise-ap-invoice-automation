"""
Unit and Security Hygiene Tests for Azure Key Vault Stub (P3-5).

Tests: N1, N8, BR-030, ADR-007, CWE-22, CWE-200, CWE-489, CWE-522, CWE-532, CWE-798, CWE-918
"""

import logging
import pickle
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.core.config import Settings
from src.core.secrets import (
    AzureKeyVaultClient,
    LocalKeyVaultStub,
    SecretNotFoundError,
    SecretProviderConfigurationError,
    SecretValue,
    get_secret_provider,
    reset_secret_provider_cache,
    validate_key_vault_url,
    validate_secret_name,
)


def test_secret_value_redacts_repr_str_and_uses_safe_equality() -> None:
    """Verify SecretValue redacts str/repr to prevent log/traceback leakage (CWE-532)."""
    secret = SecretValue("ephemeral-test-token-987654")

    assert str(secret) == "***REDACTED***"
    assert repr(secret) == "SecretValue('***REDACTED***')"
    assert "ephemeral-test-token-987654" not in f"{secret}"
    assert "ephemeral-test-token-987654" not in f"{secret!r}"
    assert secret.get_secret_value() == "ephemeral-test-token-987654"

    # Constant-time equality only between SecretValue instances (not raw strings)
    assert secret == SecretValue("ephemeral-test-token-987654")
    assert secret != SecretValue("different-value")
    assert (secret == "ephemeral-test-token-987654") is False

    # Reject empty, whitespace-only, or oversized (>25 KB) secret values, and block pickling (CWE-312/400)
    with pytest.raises(ValueError, match="non-empty"):
        SecretValue("")
    with pytest.raises(ValueError, match="non-empty"):
        SecretValue("   ")
    with pytest.raises(ValueError, match="maximum permitted size"):
        SecretValue("A" * 30_000)
    with pytest.raises(TypeError, match="pickled"):
        pickle.dumps(secret)


def test_local_keyvault_stub_in_memory_and_scoped_env_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify LocalKeyVaultStub starts empty (zero hardcoded secrets) and scopes env fallback."""
    stub = LocalKeyVaultStub(allow_env_fallback=True)

    # Starts completely empty; missing secrets fail closed
    with pytest.raises(SecretNotFoundError):
        stub.get_secret("missing-secret")

    # Arbitrary unscoped env vars (e.g. PATH, HOME) must NEVER be exposed (CWE-200)
    monkeypatch.setenv("UNSCOPED_SENSITIVE_VAR", "do-not-expose")
    with pytest.raises(SecretNotFoundError):
        stub.get_secret("UNSCOPED-SENSITIVE-VAR")

    # Explicitly prefixed KV_STUB_<UPPER_SNAKE> env var works when allow_env_fallback=True
    monkeypatch.setenv("KV_STUB_AOAI_PROXY_TOKEN", "local-dev-proxy-val")
    env_secret = stub.get_secret("aoai-proxy-token")
    assert isinstance(env_secret, SecretValue)
    assert env_secret.get_secret_value() == "local-dev-proxy-val"

    # When allow_env_fallback=False, even prefixed env var is ignored
    strict_stub = LocalKeyVaultStub(allow_env_fallback=False)
    with pytest.raises(SecretNotFoundError):
        strict_stub.get_secret("aoai-proxy-token")

    # In-memory set/get/has/clear lifecycle
    strict_stub.set_secret("vendor-hmac-salt", "ephemeral-in-memory-salt")
    assert strict_stub.has_secret("vendor-hmac-salt") is True
    assert (
        strict_stub.get_secret("vendor-hmac-salt").get_secret_value() == "ephemeral-in-memory-salt"
    )
    strict_stub.clear()
    assert strict_stub.has_secret("vendor-hmac-salt") is False


def test_secret_name_validation_blocks_traversal_and_injection() -> None:
    """Verify Azure Key Vault secret name allowlist rejects traversal, query, and CRLF (CWE-22/74)."""
    assert validate_secret_name("valid-secret-01") == "valid-secret-01"
    assert validate_secret_name("A1-b2-C3") == "A1-b2-C3"

    for invalid_name in (
        "",
        "   ",
        "../other-secret",
        "secret/version",
        "secret?api-version=7.4",
        "secret with spaces",
        "secret_with_underscore",
        "secret\r\nX-Injected: 1",
        "a" * 128,
    ):
        with pytest.raises(ValueError, match="Invalid Key Vault secret name"):
            validate_secret_name(invalid_name)


def test_key_vault_url_validation_blocks_ssrf_and_non_https() -> None:
    """Verify Key Vault URL pins strictly to https://<vault>.vault.azure.net/ (CWE-918/522)."""
    assert (
        validate_key_vault_url("https://kv-ap-eastus2.vault.azure.net")
        == "https://kv-ap-eastus2.vault.azure.net/"
    )
    assert (
        validate_key_vault_url("https://kv-ap-eastus2.vault.azure.net/")
        == "https://kv-ap-eastus2.vault.azure.net/"
    )

    for bad_url in (
        "",
        "http://kv-ap-eastus2.vault.azure.net/",
        "https://evil.attacker.example/",
        "https://kv-ap-eastus2.vault.azure.net.evil.example/",
        "https://kv-ap-eastus2.vault.azure.net/secrets/stolen",
        "https://kv-ap-eastus2.vault.azure.net:8443/",
        "https://ab.vault.azure.net/",  # Too short (<3 chars)
        "https://" + "a" * 25 + ".vault.azure.net/",  # Too long (>24 chars)
        "https://kv--double.vault.azure.net/",  # Consecutive hyphens prohibited by Azure
        "https://1kv-numeric.vault.azure.net/",  # Must begin with a letter
    ):
        with pytest.raises(ValueError, match="Invalid Azure Key Vault URL"):
            validate_key_vault_url(bad_url)


def test_azure_keyvault_client_ttl_caching_and_rotation_invalidation() -> None:
    """Verify AzureKeyVaultClient caches secrets within TTL and reloads on expiry or invalidation."""
    current_time = {"now": 1000.0}
    vault_values = {"erp-hmac-salt": "v1-ephemeral-salt"}
    mock_sdk_client = MagicMock()

    def _fake_get_secret(name: str):
        if name not in vault_values:
            raise KeyError(name)
        obj = MagicMock()
        obj.value = vault_values[name]
        return obj

    mock_sdk_client.get_secret.side_effect = _fake_get_secret

    kv_client = AzureKeyVaultClient(
        vault_url="https://kv-ap-eastus2.vault.azure.net/",
        cache_ttl_seconds=300,
        secret_client=mock_sdk_client,
        clock_fn=lambda: current_time["now"],
    )

    # First read fetches from SDK and caches
    s1 = kv_client.get_secret("erp-hmac-salt")
    assert s1.get_secret_value() == "v1-ephemeral-salt"
    assert mock_sdk_client.get_secret.call_count == 1

    # Second read within TTL served from cache
    current_time["now"] = 1100.0
    s2 = kv_client.get_secret("erp-hmac-salt")
    assert s2.get_secret_value() == "v1-ephemeral-salt"
    assert mock_sdk_client.get_secret.call_count == 1

    # Explicit invalidation forces fresh fetch of rotated secret
    vault_values["erp-hmac-salt"] = "v2-rotated-salt"
    kv_client.invalidate_cache("erp-hmac-salt")
    s3 = kv_client.get_secret("erp-hmac-salt")
    assert s3.get_secret_value() == "v2-rotated-salt"
    assert mock_sdk_client.get_secret.call_count == 2

    # TTL expiration also triggers automatic refresh
    vault_values["erp-hmac-salt"] = "v3-post-ttl-salt"
    current_time["now"] = 1500.0
    s4 = kv_client.get_secret("erp-hmac-salt")
    assert s4.get_secret_value() == "v3-post-ttl-salt"
    assert mock_sdk_client.get_secret.call_count == 3


def test_get_secret_provider_blocks_mock_stub_in_production_and_staging() -> None:
    """Verify USE_MOCK_KEY_VAULT=True is hard-blocked outside dev/local/test (CWE-489/1188)."""
    reset_secret_provider_cache()

    # Local dev with USE_MOCK_KEY_VAULT=True returns LocalKeyVaultStub
    dev_provider = get_secret_provider(Settings(APP_ENV="dev", USE_MOCK_KEY_VAULT=True))
    assert isinstance(dev_provider, LocalKeyVaultStub)

    # Staging/production MUST reject USE_MOCK_KEY_VAULT=True
    for blocked_env in ("staging", "prod", "production", "uat"):
        with pytest.raises(SecretProviderConfigurationError):
            get_secret_provider(Settings(APP_ENV=blocked_env, USE_MOCK_KEY_VAULT=True))

    # Real Azure SQL (USE_LOCAL_SQLITE=False) MUST also block USE_MOCK_KEY_VAULT=True even in dev (CWE-489)
    with pytest.raises(SecretProviderConfigurationError):
        get_secret_provider(
            Settings(APP_ENV="dev", USE_MOCK_KEY_VAULT=True, USE_LOCAL_SQLITE=False)
        )

    # Production with USE_MOCK_KEY_VAULT=False and missing/invalid URL fails closed
    with pytest.raises(SecretProviderConfigurationError):
        get_secret_provider(
            Settings(APP_ENV="production", USE_MOCK_KEY_VAULT=False, AZURE_KEY_VAULT_URL="")
        )

    # Production with valid Key Vault URL constructs AzureKeyVaultClient (lazy SDK, zero network)
    prod_provider = get_secret_provider(
        Settings(
            APP_ENV="production",
            USE_MOCK_KEY_VAULT=False,
            AZURE_KEY_VAULT_URL="https://kv-ap-eastus2.vault.azure.net/",
        )
    )
    assert isinstance(prod_provider, AzureKeyVaultClient)
    reset_secret_provider_cache()


def test_secrets_logs_and_errors_never_leak_secret_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify logs and error messages never expose raw secret values (CWE-532/209)."""
    raw_secret = "ultra-sensitive-kv-value-771199"
    stub = LocalKeyVaultStub(allow_env_fallback=False)
    stub.set_secret("audit-signing-key", raw_secret)

    mock_sdk = MagicMock()
    mock_resp = MagicMock()
    mock_resp.value = raw_secret
    mock_sdk.get_secret.return_value = mock_resp
    kv = AzureKeyVaultClient(
        vault_url="https://kv-ap-eastus2.vault.azure.net/",
        secret_client=mock_sdk,
    )

    with caplog.at_level(logging.DEBUG, logger="ap.core.secrets"):
        _ = stub.get_secret("audit-signing-key")
        _ = kv.get_secret("audit-signing-key")

    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert raw_secret not in combined_logs


def test_codebase_hygiene_zero_static_secrets_in_src_and_env_example() -> None:
    """Verify zero static credentials, API keys, or private keys exist in src/ or .env.example (N1/N8/ADR-007)."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    files_to_scan = list((repo_root / "src").rglob("*.py")) + [repo_root / ".env.example"]

    forbidden_patterns: list[tuple[str, re.Pattern[str]]] = [
        ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("Azure Storage AccountKey", re.compile(r"AccountKey\s*=\s*[A-Za-z0-9+/=]{16,}")),
        ("OpenAI static API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
        ("Hardcoded SQL Password", re.compile(r"(?i)Password\s*=\s*[^;\s<]{6,}")),
        ("Hardcoded client_secret", re.compile(r'(?i)client_secret\s*=\s*["\'][^"\']{6,}["\']')),
        ("Hardcoded static API key", re.compile(r'(?i)api_key\s*=\s*["\'][^"\']{12,}["\']')),
    ]

    violations: list[str] = []
    for file_path in files_to_scan:
        content = file_path.read_text(encoding="utf-8")
        for label, pattern in forbidden_patterns:
            if pattern.search(content):
                violations.append(f"{file_path.relative_to(repo_root)}: matched {label}")

    assert violations == [], f"Static secret violations detected: {violations}"
