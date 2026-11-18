"""
Azurite Local Blob Storage Emulator Setup & Bootstrap Helpers (P4-2).

Enables local development and integration smoke testing against the official
Microsoft Azurite Blob emulator (``127.0.0.1:10000``) while strictly preserving:
- Zero static credentials in source code or ``.env.example`` (ADR-007, N8).
- Triple fail-closed production gate (``USE_AZURITE_EMULATOR=true`` AND
  ``APP_ENV in {"dev", "local", "test"}`` AND ``USE_LOCAL_SQLITE=true`` — CWE-489).
- Strict loopback/compose host pinning on port 10000 (blocks SSRF/IMDS — CWE-918).
"""

import os
import re
import socket
from typing import Any
from urllib.parse import urlparse

from azure.core.exceptions import AzureError, ResourceExistsError
from azure.storage.blob import BlobServiceClient

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.core.secrets import LocalKeyVaultStub, SecretNotFoundError, SecretValue
from src.storage.blob_client import (
    BLOB_EXISTS_TIMEOUT_SECONDS,
    BLOB_OPERATION_TIMEOUT_SECONDS,
    AzureBlobWORMClient,
    BlobStorageConfigurationError,
    BlobStorageError,
    validate_container_name,
)

logger = get_logger("ap.storage.azurite")

DEFAULT_AZURITE_BLOB_URL: str = "http://127.0.0.1:10000/devstoreaccount1/"
AZURITE_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

# Strict Azurite loopback / local Docker Compose origin pin (prevents SSRF / IMDS — CWE-918)
AZURITE_URL_PATTERN = re.compile(
    r"^http://(127\.0\.0\.1|localhost|azurite):10000/([a-z0-9]{3,24})/?$"
)


def is_azurite_enabled(settings: Settings | None = None) -> bool:
    """
    Return True ONLY when all three local-emulator safety gates hold:
      1. ``USE_AZURITE_EMULATOR`` is True,
      2. ``APP_ENV`` is in ``{"dev", "local", "test"}``, AND
      3. ``USE_LOCAL_SQLITE`` is True (blocks emulator whenever Azure SQL is active).
    """
    cfg = settings or get_settings()
    if not cfg.USE_AZURITE_EMULATOR or not cfg.USE_LOCAL_SQLITE:
        return False
    return cfg.APP_ENV.strip().lower() in AZURITE_ALLOWED_ENVS


def validate_azurite_url(url: str) -> str:
    """Validate and normalize a local Azurite Blob endpoint URL (loopback/compose port 10000 only)."""
    if not isinstance(url, str):
        raise ValueError("Invalid Azurite URL; expected http://127.0.0.1:10000/<account>/")
    stripped = url.strip()
    match = AZURITE_URL_PATTERN.match(stripped)
    if not match:
        raise ValueError("Invalid Azurite URL; expected http://127.0.0.1:10000/<account>/")
    host, account = match.group(1), match.group(2)
    return f"http://{host}:10000/{account}/"


def check_azurite_reachable(url: str = DEFAULT_AZURITE_BLOB_URL, *, timeout: float = 1.0) -> bool:
    """
    Perform a bounded TCP reachability check against a validated Azurite loopback endpoint.

    Validates ``url`` first so arbitrary hosts/ports cannot be probed (CWE-918).
    """
    validated = validate_azurite_url(url)
    parsed = urlparse(validated)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 10000
    bounded_timeout = max(0.1, min(timeout, 5.0))
    try:
        with socket.create_connection((host, port), timeout=bounded_timeout):
            return True
    except OSError:
        return False


def ensure_worm_container(service_client: Any, container_name: str) -> bool:
    """
    Idempotently create the WORM Blob container in Azurite if it does not yet exist.

    Returns:
        True if newly created, False if it already existed.
    """
    valid_name = validate_container_name(container_name)
    container_client = service_client.get_container_client(valid_name)
    try:
        container_client.create_container()
        logger.info("Created local Azurite WORM container", extra={"container": valid_name})
        return True
    except ResourceExistsError:
        logger.debug("Local Azurite WORM container already exists", extra={"container": valid_name})
        return False
    except AzureError as exc:
        logger.error(
            "Failed to bootstrap local Azurite container",
            extra={"container": valid_name, "error_type": type(exc).__name__},
        )
        raise BlobStorageError("Failed to ensure Azurite container") from None


def _resolve_azurite_credential(
    validated_account_name: str,
    explicit_credential: Any | None = None,
) -> Any:
    """
    Resolve runtime credentials for local Azurite without embedding any static key in source.

    Accepts either an explicit credential (e.g. OAuth TokenCredential or key dict) or a local
    runtime key supplied via ``KV_STUB_AZURITE_ACCOUNT_KEY`` or ``AZURITE_ACCOUNT_KEY``.
    """
    if explicit_credential is not None:
        return explicit_credential

    stub = LocalKeyVaultStub(allow_env_fallback=True)
    key_secret: SecretValue | None = None
    try:
        key_secret = stub.get_secret("azurite-account-key")
    except SecretNotFoundError:
        raw_env = os.environ.get("AZURITE_ACCOUNT_KEY", "").strip()
        if raw_env:
            key_secret = SecretValue(raw_env)

    if key_secret is None:
        raise BlobStorageConfigurationError(
            "Azurite credential not configured; pass credential or set KV_STUB_AZURITE_ACCOUNT_KEY"
        )

    return {
        "account_name": validated_account_name,
        "account_key": key_secret.get_secret_value(),
    }


def create_azurite_worm_client(
    settings: Settings | None = None,
    *,
    credential: Any | None = None,
    blob_service_client: Any | None = None,
    ensure_container: bool = True,
) -> AzureBlobWORMClient:
    """
    Construct an ``AzureBlobWORMClient`` wired to the local Azurite Blob emulator.

    Enforces triple non-production gate (CWE-489) and strict loopback URL validation (CWE-918).
    """
    cfg = settings or get_settings()
    if not is_azurite_enabled(cfg):
        raise BlobStorageConfigurationError(
            "Azurite local emulator is disabled or prohibited outside local dev/test environments"
        )

    try:
        validated_url = validate_azurite_url(cfg.AZURITE_BLOB_URL)
        valid_container = validate_container_name(cfg.AZURE_BLOB_WORM_CONTAINER)
    except ValueError as exc:
        raise BlobStorageConfigurationError(str(exc)) from None

    if blob_service_client is not None:
        service_client = blob_service_client
    else:
        url_account_name = urlparse(validated_url).path.strip("/")
        resolved_cred = _resolve_azurite_credential(
            url_account_name, explicit_credential=credential
        )
        service_client = BlobServiceClient(
            account_url=validated_url,
            credential=resolved_cred,
            connection_timeout=BLOB_EXISTS_TIMEOUT_SECONDS,
            read_timeout=BLOB_OPERATION_TIMEOUT_SECONDS,
        )

    if ensure_container:
        ensure_worm_container(service_client, valid_container)

    return AzureBlobWORMClient(
        account_url=validated_url,
        container_name=valid_container,
        blob_service_client=service_client,
        allow_local_emulator=True,
    )
