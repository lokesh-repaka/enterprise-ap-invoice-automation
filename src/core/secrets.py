"""
Azure Key Vault Secret Provider & Offline Local Stub (P3-5).

Enforces the 100% Keyless Architecture mandated by ADR-007, BR-030, N1, and N8:
- Zero static credentials, API keys, passwords, or private keys in source code or config.
- Production retrieves residual configuration values via Azure Key Vault using
  Microsoft Entra ID Managed Identity (``DefaultAzureCredential``).
- Local development and offline test suites use ``LocalKeyVaultStub`` (empty by default),
  strictly hard-blocked outside ``APP_ENV in {"dev", "local", "test"}`` (CWE-489).
- All secrets are wrapped in ``SecretValue`` with redacted ``__str__``/``__repr__``
  and constant-time equality (CWE-532, CWE-208).
"""

import hmac
import os
import re
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from src.core.config import Settings, get_settings
from src.core.logging import get_logger

logger = get_logger("ap.core.secrets")

# Allowed non-production environments for LocalKeyVaultStub (CWE-489)
MOCK_KV_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

# Azure Key Vault secret name specification: 1-127 alphanumeric characters and hyphens only (CWE-22/74)
SECRET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,127}$")

# Strict Azure Key Vault HTTPS origin pin (3-24 char vault name starting with letter) — CWE-918/522
KEY_VAULT_URL_PATTERN = re.compile(
    r"^https://([a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9])\.vault\.azure\.net/?$"
)

# Azure Key Vault 25 KB secret size limit and bounded in-memory cache capacity (CWE-400)
MAX_SECRET_VALUE_BYTES: int = 25_600
MAX_CACHED_SECRETS: int = 256

# Explicit environment variable prefix for local dev stub fallback (never exposes arbitrary env vars)
KV_STUB_ENV_PREFIX: str = "KV_STUB_"

_PROVIDER_LOCK = threading.Lock()
_CACHED_PROVIDER: tuple[tuple[Any, ...], "SecretProvider"] | None = None


class SecretProviderError(RuntimeError):
    """Base error for Key Vault secret resolution failures."""


class SecretNotFoundError(SecretProviderError):
    """Raised when a requested secret does not exist in the active provider."""


class SecretProviderConfigurationError(SecretProviderError):
    """Raised when Key Vault configuration violates security invariants (fail-closed)."""


class SecretValue:
    """
    Immutable secret wrapper preventing accidental leakage into logs, f-strings, or tracebacks.

    ``str(secret)`` and ``repr(secret)`` always return redacted placeholders (CWE-532).
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Secret value must be a non-empty string")
        if len(value.encode("utf-8")) > MAX_SECRET_VALUE_BYTES:
            raise ValueError(
                f"Secret value exceeds maximum permitted size ({MAX_SECRET_VALUE_BYTES} bytes)"
            )
        object.__setattr__(self, "_value", value)

    def get_secret_value(self) -> str:
        """Explicitly unwrap the underlying secret value."""
        return self._value

    def __str__(self) -> str:
        return "***REDACTED***"

    def __repr__(self) -> str:
        return "SecretValue('***REDACTED***')"

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SecretValue is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SecretValue is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return False
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    def __hash__(self) -> int:
        raise TypeError("SecretValue is unhashable to prevent accidental dict-key leakage")

    def __reduce__(self) -> Any:
        raise TypeError("SecretValue cannot be pickled or serialized (CWE-312)")


def validate_secret_name(name: str) -> str:
    """Validate an Azure Key Vault secret name against strict alphanumeric/hyphen allowlist."""
    if not isinstance(name, str) or not SECRET_NAME_PATTERN.match(name):
        raise ValueError(
            "Invalid Key Vault secret name; expected 1-127 ASCII letters, digits, or hyphens"
        )
    return name


def validate_key_vault_url(url: str) -> str:
    """Validate and normalize an Azure Key Vault HTTPS URL (prevents SSRF & token exfiltration)."""
    if not isinstance(url, str):
        raise ValueError("Invalid Azure Key Vault URL; expected https://<vault>.vault.azure.net/")
    stripped = url.strip()
    match = KEY_VAULT_URL_PATTERN.match(stripped)
    if not match or "--" in match.group(1):
        raise ValueError("Invalid Azure Key Vault URL; expected https://<vault>.vault.azure.net/")
    vault_name = match.group(1).lower()
    return f"https://{vault_name}.vault.azure.net/"


@runtime_checkable
class SecretProvider(Protocol):
    """Protocol implemented by both LocalKeyVaultStub and AzureKeyVaultClient."""

    def get_secret(self, name: str) -> SecretValue:
        """Retrieve a secret by canonical Key Vault name."""
        ...


class LocalKeyVaultStub:
    """
    Offline in-memory Azure Key Vault stub for local dev and zero-network unit testing.

    Contains ZERO hardcoded default secrets. Optionally resolves explicitly prefixed
    ``KV_STUB_<UPPER_SNAKE_NAME>`` environment variables when ``allow_env_fallback=True``.
    """

    def __init__(self, *, allow_env_fallback: bool = True) -> None:
        self._store: dict[str, SecretValue] = {}
        self._allow_env_fallback = allow_env_fallback
        self._lock = threading.Lock()

    def set_secret(self, name: str, value: str) -> None:
        """Store an ephemeral secret value in memory for local dev or unit testing."""
        valid_name = validate_secret_name(name)
        wrapped = SecretValue(value)
        with self._lock:
            if valid_name not in self._store and len(self._store) >= MAX_CACHED_SECRETS:
                raise SecretProviderError("Local Key Vault stub secret capacity exceeded")
            self._store[valid_name] = wrapped

    def has_secret(self, name: str) -> bool:
        """Return True if the secret is available in memory or scoped KV_STUB_ env."""
        valid_name = validate_secret_name(name)
        with self._lock:
            if valid_name in self._store:
                return True
        if self._allow_env_fallback:
            env_key = f"{KV_STUB_ENV_PREFIX}{valid_name.upper().replace('-', '_')}"
            env_val = os.environ.get(env_key, "")
            return bool(env_val.strip())
        return False

    def clear(self) -> None:
        """Remove all in-memory secrets from the stub."""
        with self._lock:
            self._store.clear()

    def get_secret(self, name: str) -> SecretValue:
        """Fetch secret from memory or strictly scoped ``KV_STUB_`` environment fallback."""
        valid_name = validate_secret_name(name)

        with self._lock:
            cached = self._store.get(valid_name)
        if cached is not None:
            logger.debug(
                "Resolved secret from local Key Vault stub", extra={"secret_name": valid_name}
            )
            return cached

        if self._allow_env_fallback:
            env_key = f"{KV_STUB_ENV_PREFIX}{valid_name.upper().replace('-', '_')}"
            env_val = os.environ.get(env_key)
            if env_val and env_val.strip():
                logger.debug(
                    "Resolved secret from scoped KV_STUB_ environment fallback",
                    extra={"secret_name": valid_name},
                )
                return SecretValue(env_val)

        raise SecretNotFoundError(f"Secret '{valid_name}' not found in local Key Vault stub")


class AzureKeyVaultClient:
    """
    Keyless Azure Key Vault client backed by Microsoft Entra ID Managed Identity (ADR-007).

    Enforces strict HTTPS ``*.vault.azure.net`` host pinning, thread-safe bounded TTL caching,
    explicit rotation invalidation, and lazy SDK initialization so offline tests never trigger
    network calls or require ``azure-keyvault-secrets`` to be installed.
    """

    def __init__(
        self,
        vault_url: str,
        *,
        cache_ttl_seconds: int = 300,
        secret_client: Any | None = None,
        credential: Any | None = None,
        clock_fn: Callable[[], float] | None = None,
    ) -> None:
        self._vault_url = validate_key_vault_url(vault_url)
        self._cache_ttl_seconds = max(30, min(cache_ttl_seconds, 3600))
        self._secret_client = secret_client
        self._credential = credential
        self._clock_fn = clock_fn or time.monotonic
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[SecretValue, float]] = {}

    @property
    def vault_url(self) -> str:
        """Return the validated canonical Azure Key Vault HTTPS URL."""
        return self._vault_url

    def _get_or_create_sdk_client(self) -> Any:
        """Lazily construct Azure Key Vault SecretClient using DefaultAzureCredential (thread-safe)."""
        with self._lock:
            if self._secret_client is not None:
                return self._secret_client

            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient
            except ImportError as exc:
                raise SecretProviderConfigurationError(
                    "azure-keyvault-secrets and azure-identity are required for live Azure Key Vault access"
                ) from exc

            cred = self._credential or DefaultAzureCredential()
            self._secret_client = SecretClient(vault_url=self._vault_url, credential=cred)
            return self._secret_client

    def invalidate_cache(self, name: str | None = None) -> None:
        """Evict one secret or the entire secret cache to force immediate rotation pickup."""
        with self._lock:
            if name is None:
                self._cache.clear()
            else:
                valid_name = validate_secret_name(name)
                self._cache.pop(valid_name, None)

    def get_secret(self, name: str) -> SecretValue:
        """Fetch a secret by canonical Key Vault name using Managed Identity and TTL cache."""
        valid_name = validate_secret_name(name)
        now = self._clock_fn()

        with self._lock:
            cached_entry = self._cache.get(valid_name)
            if cached_entry is not None and now < cached_entry[1]:
                logger.debug(
                    "Resolved secret from Key Vault cache",
                    extra={"secret_name": valid_name, "cache_hit": True},
                )
                return cached_entry[0]

        client = self._get_or_create_sdk_client()
        try:
            sdk_secret = client.get_secret(valid_name)
        except Exception as exc:
            logger.error(
                "Azure Key Vault secret retrieval failed",
                extra={"secret_name": valid_name, "error_type": type(exc).__name__},
            )
            raise SecretNotFoundError(
                f"Unable to retrieve secret '{valid_name}' from Azure Key Vault"
            ) from None

        raw_val = getattr(sdk_secret, "value", None)
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise SecretNotFoundError(f"Secret '{valid_name}' returned an empty value")

        wrapped = SecretValue(raw_val)
        now_store = self._clock_fn()
        with self._lock:
            # Evict expired entries and bound cache capacity to prevent memory exhaustion (CWE-400)
            if len(self._cache) >= MAX_CACHED_SECRETS and valid_name not in self._cache:
                expired = [k for k, (_, exp) in self._cache.items() if now_store >= exp]
                for k in expired:
                    self._cache.pop(k, None)
                if len(self._cache) >= MAX_CACHED_SECRETS:
                    oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                    self._cache.pop(oldest_key, None)
            self._cache[valid_name] = (wrapped, now_store + self._cache_ttl_seconds)

        logger.info(
            "Retrieved secret from Azure Key Vault",
            extra={"secret_name": valid_name, "cache_hit": False},
        )
        return wrapped


def get_secret_provider(settings: Settings | None = None) -> SecretProvider:
    """
    Return the active ``SecretProvider`` singleton based on application settings.

    Fail-closed production guards:
    - ``USE_MOCK_KEY_VAULT=True`` is strictly rejected outside ``APP_ENV in {"dev", "local", "test"}``.
    - ``USE_MOCK_KEY_VAULT=False`` requires a valid ``https://<vault>.vault.azure.net/`` URL.
    """
    global _CACHED_PROVIDER
    cfg = settings or get_settings()
    env_name = cfg.APP_ENV.strip().lower()
    cache_key = (
        env_name,
        cfg.USE_MOCK_KEY_VAULT,
        cfg.USE_LOCAL_SQLITE,
        cfg.AZURE_KEY_VAULT_URL.strip(),
        cfg.KEY_VAULT_CACHE_TTL_SECONDS,
    )

    with _PROVIDER_LOCK:
        if _CACHED_PROVIDER is not None and _CACHED_PROVIDER[0] == cache_key:
            return _CACHED_PROVIDER[1]

        if cfg.USE_MOCK_KEY_VAULT:
            if env_name not in MOCK_KV_ALLOWED_ENVS or not cfg.USE_LOCAL_SQLITE:
                raise SecretProviderConfigurationError(
                    "USE_MOCK_KEY_VAULT is prohibited outside local dev/test environments"
                )
            provider: SecretProvider = LocalKeyVaultStub(allow_env_fallback=True)
        else:
            try:
                validated_url = validate_key_vault_url(cfg.AZURE_KEY_VAULT_URL)
            except ValueError as exc:
                raise SecretProviderConfigurationError(str(exc)) from None
            provider = AzureKeyVaultClient(
                vault_url=validated_url,
                cache_ttl_seconds=cfg.KEY_VAULT_CACHE_TTL_SECONDS,
            )

        _CACHED_PROVIDER = (cache_key, provider)
        return provider


def reset_secret_provider_cache() -> None:
    """Clear the cached SecretProvider singleton (used for clean test isolation)."""
    global _CACHED_PROVIDER
    with _PROVIDER_LOCK:
        _CACHED_PROVIDER = None
