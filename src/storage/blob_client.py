"""
Azure Blob Storage WORM (Write-Once, Read-Many) Client with Managed Identity Auth (P4-1).

Enforces:
- 100% Keyless Managed Identity authentication via ``DefaultAzureCredential`` (ADR-007, N1, N8).
  Never accepts static connection strings, AccountKeys, or SAS query tokens.
- Strict WORM immutability semantics (ADR-005, N6, BR-026):
  ``overwrite=False`` on every upload; zero delete or overwrite APIs exposed.
- Strict Azure HTTPS host pinning (``https://<account>.blob.core.windows.net/``) to prevent
  Managed Identity Bearer token exfiltration / SSRF (CWE-918, CWE-522).
- Strict path-traversal validation, 25 MB size cap (FR-01), and HTTP-header-safe metadata
  validation (CWE-22, CWE-113, CWE-400).
- Zero business logic in ``src/storage/`` per CLAUDE.md §4.2.
"""

import json
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from azure.core.exceptions import AzureError, ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient, ContentSettings, ImmutabilityPolicy
from pydantic import BaseModel, ConfigDict, Field

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.storage.metadata import parse_invoice_blob_metadata, prepare_upload_metadata

logger = get_logger("ap.storage.blob_client")

# Allowed non-production environments for InMemoryWORMBlobClient (CWE-489)
MOCK_BLOB_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

# Maximum file size per FR-01 and CLAUDE.md §7.1 (25 MB)
MAX_BLOB_SIZE_BYTES: int = 25 * 1024 * 1024

# Statutory 7-year WORM retention window (ADR-005, BR-026, N6)
DEFAULT_WORM_RETENTION_DAYS: int = 2555

# Strict Azure Storage Account HTTPS URL pin (3-24 lowercase alphanumeric account name)
BLOB_ACCOUNT_URL_PATTERN = re.compile(r"^https://([a-z0-9]{3,24})\.blob\.core\.windows\.net/?$")

# Optional local Azurite loopback origin pattern (only when allow_local_emulator=True in dev/test)
LOCAL_EMULATOR_URL_PATTERN = re.compile(
    r"^http://(?:127\.0\.0\.1|localhost|azurite):10000/[a-z0-9]{3,24}/?$"
)

# Azure Blob container naming rules: 3-63 lowercase alnum/hyphens, start/end alnum, no '--'
CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$")

# Strict identifier & filename patterns preventing path traversal / injection (CWE-22)
INVOICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SAFE_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_BLOB_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Strict Content-Type syntax & active web-script MIME denylist (CWE-113 / CWE-434)
CONTENT_TYPE_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9.+-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9.+-]{0,63}$"
)
FORBIDDEN_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/javascript",
        "application/javascript",
        "image/svg+xml",
    }
)

# Bounded Azure SDK operation timeouts & local mock store cap (CWE-400)
BLOB_OPERATION_TIMEOUT_SECONDS: int = 30
BLOB_EXISTS_TIMEOUT_SECONDS: int = 10
MAX_IN_MEMORY_BLOBS: int = 1000

_CLIENT_LOCK = threading.Lock()
_CACHED_CLIENT: tuple[tuple[Any, ...], "BlobWORMClientProtocol"] | None = None


class BlobStorageError(RuntimeError):
    """Base error for Azure Blob WORM storage failures."""


class BlobAlreadyExistsError(BlobStorageError):
    """Raised when attempting to write to an existing WORM blob path (immutability violation)."""


class BlobNotFoundError(BlobStorageError):
    """Raised when a requested blob does not exist in the WORM container."""


class BlobStorageConfigurationError(BlobStorageError):
    """Raised when storage configuration violates keyless or production safety invariants."""


class BlobUploadResult(BaseModel):
    """Immutable metadata receipt returned after a verified WORM blob upload."""

    model_config = ConfigDict(frozen=True)

    blob_name: str
    blob_url: str
    container_name: str
    content_type: str
    size_bytes: int
    sha256_hash: str
    etag: str
    uploaded_at: datetime
    metadata: dict[str, str] = Field(default_factory=dict)


def validate_blob_account_url(url: str, *, allow_local_emulator: bool = False) -> str:
    """
    Validate and normalize an Azure Blob Storage HTTPS account URL.

    Rejects plaintext HTTP, embedded SAS query strings, userinfo credentials, and
    foreign hosts to prevent Managed Identity Bearer token exfiltration (CWE-918/522).
    """
    if not isinstance(url, str):
        raise ValueError(
            "Invalid Azure Blob account URL; expected https://<account>.blob.core.windows.net/"
        )
    stripped = url.strip()
    match = BLOB_ACCOUNT_URL_PATTERN.match(stripped)
    if match:
        return f"https://{match.group(1)}.blob.core.windows.net/"

    if allow_local_emulator and LOCAL_EMULATOR_URL_PATTERN.match(stripped):
        return stripped if stripped.endswith("/") else f"{stripped}/"

    raise ValueError(
        "Invalid Azure Blob account URL; expected https://<account>.blob.core.windows.net/"
    )


def validate_container_name(container_name: str) -> str:
    """Validate an Azure Blob container name against Azure naming rules."""
    if (
        not isinstance(container_name, str)
        or not CONTAINER_NAME_PATTERN.match(container_name)
        or "--" in container_name
    ):
        raise ValueError("Invalid Azure Blob container name")
    return container_name


def validate_blob_name(blob_name: str) -> str:
    """Validate a relative blob path, blocking traversal (..), backslashes, and control chars."""
    if not isinstance(blob_name, str) or not blob_name or blob_name.startswith("/"):
        raise ValueError("Invalid blob name")
    if "\\" in blob_name or ".." in blob_name:
        raise ValueError("Invalid blob name: path traversal prohibited")

    segments = blob_name.split("/")
    if not (1 <= len(segments) <= 6):
        raise ValueError("Invalid blob name segment depth")
    for seg in segments:
        if not SAFE_BLOB_SEGMENT_PATTERN.match(seg) or seg in (".", ".."):
            raise ValueError("Invalid blob name segment")
    return blob_name


def build_raw_invoice_blob_name(invoice_id: str, filename: str) -> str:
    """Construct canonical WORM path ``raw-invoices/{invoice_id}/{filename}`` (HLD §4)."""
    if not isinstance(invoice_id, str) or not INVOICE_ID_PATTERN.match(invoice_id):
        raise ValueError("Invalid invoice_id for blob path")
    if (
        not isinstance(filename, str)
        or "/" in filename
        or "\\" in filename
        or ".." in filename
        or not SAFE_FILENAME_PATTERN.match(filename)
    ):
        raise ValueError("Invalid filename for blob path")
    return f"raw-invoices/{invoice_id}/{filename}"


def build_extraction_json_blob_name(invoice_id: str) -> str:
    """Construct canonical WORM path ``json-extractions/{invoice_id}/extraction.json`` (HLD §4)."""
    if not isinstance(invoice_id, str) or not INVOICE_ID_PATTERN.match(invoice_id):
        raise ValueError("Invalid invoice_id for extraction JSON blob path")
    return f"json-extractions/{invoice_id}/extraction.json"


def _validate_blob_bytes(data: bytes) -> None:
    """Enforce non-empty and <= 25 MB payload bounds (FR-01, CWE-400)."""
    if not isinstance(data, bytes) or len(data) == 0:
        raise ValueError("Blob payload must be non-empty bytes")
    if len(data) > MAX_BLOB_SIZE_BYTES:
        raise ValueError(
            f"Blob payload exceeds maximum permitted size ({MAX_BLOB_SIZE_BYTES} bytes)"
        )


def _validate_content_type(content_type: str) -> str:
    """Validate MIME Content-Type syntax and reject active browser script types (CWE-113/434)."""
    if not isinstance(content_type, str) or not CONTENT_TYPE_PATTERN.match(content_type):
        raise ValueError("Invalid content_type header value")
    normalized = content_type.lower()
    if normalized in FORBIDDEN_CONTENT_TYPES:
        raise ValueError(f"Disallowed active content_type: {normalized}")
    return normalized


@runtime_checkable
class BlobWORMClientProtocol(Protocol):
    """Strict Write-Once, Read-Many storage protocol (zero delete/overwrite operations)."""

    @property
    def account_url(self) -> str: ...

    @property
    def container_name(self) -> str: ...

    def upload_raw_invoice(
        self,
        invoice_id: str,
        filename: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult: ...

    def upload_extraction_json(
        self,
        invoice_id: str,
        payload: dict[str, Any],
        *,
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult: ...

    def download_blob(self, blob_name: str) -> bytes: ...

    def get_blob_metadata(self, blob_name: str) -> dict[str, str]: ...

    def blob_exists(self, blob_name: str) -> bool: ...


class AzureBlobWORMClient:
    """
    Keyless Azure Blob Storage WORM client using Microsoft Entra ID Managed Identity.

    Enforces ``overwrite=False`` on every write and omits all delete/overwrite methods
    to maintain defense-in-depth WORM compliance alongside Azure's 7-year retention lock.
    """

    def __init__(
        self,
        account_url: str,
        container_name: str,
        *,
        credential: Any | None = None,
        blob_service_client: Any | None = None,
        allow_local_emulator: bool = False,
        enable_blob_immutability_policy: bool = False,
        retention_days: int = DEFAULT_WORM_RETENTION_DAYS,
    ) -> None:
        self._account_url = validate_blob_account_url(
            account_url, allow_local_emulator=allow_local_emulator
        )
        self._container_name = validate_container_name(container_name)
        self._credential = credential
        self._service_client = blob_service_client
        self._enable_blob_immutability_policy = enable_blob_immutability_policy
        self._retention_days = max(1, retention_days)
        self._lock = threading.Lock()

    @property
    def account_url(self) -> str:
        """Return the validated canonical Azure Blob Storage account URL."""
        return self._account_url

    @property
    def container_name(self) -> str:
        """Return the validated WORM container name."""
        return self._container_name

    def _get_service_client(self) -> Any:
        """Lazily initialize keyless BlobServiceClient backed by DefaultAzureCredential."""
        with self._lock:
            if self._service_client is not None:
                return self._service_client

            from azure.identity import DefaultAzureCredential

            cred = self._credential or DefaultAzureCredential()
            self._service_client = BlobServiceClient(
                account_url=self._account_url,
                credential=cred,
                connection_timeout=BLOB_EXISTS_TIMEOUT_SECONDS,
                read_timeout=BLOB_OPERATION_TIMEOUT_SECONDS,
            )
            return self._service_client

    def _upload_worm_bytes(
        self,
        blob_name: str,
        data: bytes,
        *,
        content_type: str,
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        valid_blob = validate_blob_name(blob_name)
        _validate_blob_bytes(data)
        valid_content_type = _validate_content_type(content_type)
        clean_metadata = prepare_upload_metadata(
            data,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
            extra_metadata=metadata,
        )
        sha256_hex = clean_metadata["FileHash"]

        container_client = self._get_service_client().get_container_client(self._container_name)
        blob_client = container_client.get_blob_client(valid_blob)

        upload_kwargs: dict[str, Any] = {
            "overwrite": False,  # Non-negotiable WORM write-once guard (ADR-005)
            "content_settings": ContentSettings(content_type=valid_content_type),
            "metadata": clean_metadata,
            "timeout": BLOB_OPERATION_TIMEOUT_SECONDS,
        }
        if self._enable_blob_immutability_policy:
            expiry = datetime.now(UTC) + timedelta(days=self._retention_days)
            upload_kwargs["immutability_policy"] = ImmutabilityPolicy(
                expiry_time=expiry,
                policy_mode="Unlocked",
            )

        try:
            response = blob_client.upload_blob(data, **upload_kwargs)
        except ResourceExistsError:
            logger.warning(
                "Blocked WORM overwrite attempt on existing blob",
                extra={"blob_name": valid_blob, "container": self._container_name},
            )
            raise BlobAlreadyExistsError(
                f"WORM blob already exists and cannot be overwritten: {valid_blob}"
            ) from None
        except AzureError as exc:
            logger.error(
                "Azure Blob WORM upload failed",
                extra={"blob_name": valid_blob, "error_type": type(exc).__name__},
            )
            raise BlobStorageError("Failed to upload immutable blob") from None

        etag = str(response.get("etag", "")) if isinstance(response, dict) else ""
        uploaded_at = parse_invoice_blob_metadata(clean_metadata).upload_timestamp
        logger.info(
            "Uploaded immutable WORM blob",
            extra={
                "blob_name": valid_blob,
                "size_bytes": len(data),
                "sha256_prefix": sha256_hex[:12],
                "vendor_id": clean_metadata["VendorID"],
            },
        )
        return BlobUploadResult(
            blob_name=valid_blob,
            blob_url=str(blob_client.url),
            container_name=self._container_name,
            content_type=valid_content_type,
            size_bytes=len(data),
            sha256_hash=sha256_hex,
            etag=etag,
            uploaded_at=uploaded_at,
            metadata=dict(clean_metadata),
        )

    def upload_raw_invoice(
        self,
        invoice_id: str,
        filename: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        """Upload raw invoice bytes once under ``raw-invoices/{invoice_id}/{filename}``."""
        blob_name = build_raw_invoice_blob_name(invoice_id, filename)
        return self._upload_worm_bytes(
            blob_name,
            data,
            content_type=content_type,
            metadata=metadata,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
        )

    def upload_extraction_json(
        self,
        invoice_id: str,
        payload: dict[str, Any],
        *,
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        """Upload structured extraction JSON once under ``json-extractions/{invoice_id}/extraction.json``."""
        blob_name = build_extraction_json_blob_name(invoice_id)
        serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return self._upload_worm_bytes(
            blob_name,
            serialized,
            content_type="application/json",
            metadata=metadata,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
        )

    def download_blob(self, blob_name: str) -> bytes:
        """Download immutable blob bytes with bounded stream read (prevents OOM: CWE-400)."""
        valid_blob = validate_blob_name(blob_name)
        container_client = self._get_service_client().get_container_client(self._container_name)
        blob_client = container_client.get_blob_client(valid_blob)

        try:
            downloader = blob_client.download_blob(
                offset=0,
                length=MAX_BLOB_SIZE_BYTES + 1,
                max_concurrency=1,
                timeout=BLOB_OPERATION_TIMEOUT_SECONDS,
            )
            props = getattr(downloader, "properties", None)
            reported_size = getattr(props, "size", None)
            if isinstance(reported_size, int) and reported_size > MAX_BLOB_SIZE_BYTES:
                raise ValueError(
                    f"Remote blob exceeds maximum permitted size ({MAX_BLOB_SIZE_BYTES} bytes)"
                )
            raw_bytes: bytes = downloader.readall()
        except ResourceNotFoundError:
            raise BlobNotFoundError(f"Blob not found: {valid_blob}") from None
        except AzureError as exc:
            logger.error(
                "Azure Blob download failed",
                extra={"blob_name": valid_blob, "error_type": type(exc).__name__},
            )
            raise BlobStorageError("Failed to download blob") from None

        if len(raw_bytes) > MAX_BLOB_SIZE_BYTES:
            raise ValueError(
                f"Downloaded blob exceeds maximum permitted size ({MAX_BLOB_SIZE_BYTES} bytes)"
            )

        logger.debug(
            "Downloaded immutable WORM blob",
            extra={"blob_name": valid_blob, "size_bytes": len(raw_bytes)},
        )
        return raw_bytes

    def get_blob_metadata(self, blob_name: str) -> dict[str, str]:
        """Read immutable blob metadata dictionary via ``get_blob_properties`` (zero mutation)."""
        valid_blob = validate_blob_name(blob_name)
        container_client = self._get_service_client().get_container_client(self._container_name)
        blob_client = container_client.get_blob_client(valid_blob)
        try:
            props = blob_client.get_blob_properties(timeout=BLOB_EXISTS_TIMEOUT_SECONDS)
        except ResourceNotFoundError:
            raise BlobNotFoundError(f"Blob not found: {valid_blob}") from None
        except AzureError as exc:
            logger.error(
                "Azure Blob metadata read failed",
                extra={"blob_name": valid_blob, "error_type": type(exc).__name__},
            )
            raise BlobStorageError("Failed to read blob metadata") from None

        raw_meta = getattr(props, "metadata", None)
        return dict(raw_meta) if isinstance(raw_meta, dict) else {}

    def blob_exists(self, blob_name: str) -> bool:
        """Return True if a blob exists at ``blob_name`` inside the WORM container."""
        valid_blob = validate_blob_name(blob_name)
        container_client = self._get_service_client().get_container_client(self._container_name)
        blob_client = container_client.get_blob_client(valid_blob)
        try:
            return bool(blob_client.exists(timeout=BLOB_EXISTS_TIMEOUT_SECONDS))
        except AzureError as exc:
            logger.error(
                "Azure Blob existence check failed",
                extra={"blob_name": valid_blob, "error_type": type(exc).__name__},
            )
            raise BlobStorageError("Failed to check blob existence") from None


class InMemoryWORMBlobClient:
    """
    Offline in-memory WORM Blob client for local dev and zero-network unit testing.

    Mirrors ``AzureBlobWORMClient`` validation, write-once immutability, SHA-256 hashing,
    and zero-delete API surface.
    """

    def __init__(self, account_url: str, container_name: str) -> None:
        self._account_url = validate_blob_account_url(account_url)
        self._container_name = validate_container_name(container_name)
        self._blobs: dict[str, tuple[bytes, dict[str, str] | None]] = {}
        self._lock = threading.Lock()

    @property
    def account_url(self) -> str:
        return self._account_url

    @property
    def container_name(self) -> str:
        return self._container_name

    def _store_once(
        self,
        blob_name: str,
        data: bytes,
        *,
        content_type: str,
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        valid_blob = validate_blob_name(blob_name)
        _validate_blob_bytes(data)
        valid_content_type = _validate_content_type(content_type)
        clean_metadata = prepare_upload_metadata(
            data,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
            extra_metadata=metadata,
        )
        sha256_hex = clean_metadata["FileHash"]

        with self._lock:
            if valid_blob in self._blobs:
                raise BlobAlreadyExistsError(
                    f"WORM blob already exists and cannot be overwritten: {valid_blob}"
                )
            if len(self._blobs) >= MAX_IN_MEMORY_BLOBS:
                raise BlobStorageError("In-memory mock WORM store capacity exceeded")
            self._blobs[valid_blob] = (bytes(data), dict(clean_metadata))

        logger.info(
            "Uploaded immutable WORM blob (in-memory mock)",
            extra={
                "blob_name": valid_blob,
                "size_bytes": len(data),
                "sha256_prefix": sha256_hex[:12],
                "vendor_id": clean_metadata["VendorID"],
            },
        )
        return BlobUploadResult(
            blob_name=valid_blob,
            blob_url=f"{self._account_url}{self._container_name}/{valid_blob}",
            container_name=self._container_name,
            content_type=valid_content_type,
            size_bytes=len(data),
            sha256_hash=sha256_hex,
            etag=f'"mem-{sha256_hex[:16]}"',
            uploaded_at=parse_invoice_blob_metadata(clean_metadata).upload_timestamp,
            metadata=dict(clean_metadata),
        )

    def upload_raw_invoice(
        self,
        invoice_id: str,
        filename: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        blob_name = build_raw_invoice_blob_name(invoice_id, filename)
        return self._store_once(
            blob_name,
            data,
            content_type=content_type,
            metadata=metadata,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
        )

    def upload_extraction_json(
        self,
        invoice_id: str,
        payload: dict[str, Any],
        *,
        metadata: dict[str, str] | None = None,
        vendor_id: str | None = None,
        upload_timestamp: datetime | None = None,
    ) -> BlobUploadResult:
        blob_name = build_extraction_json_blob_name(invoice_id)
        serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return self._store_once(
            blob_name,
            serialized,
            content_type="application/json",
            metadata=metadata,
            vendor_id=vendor_id,
            upload_timestamp=upload_timestamp,
        )

    def download_blob(self, blob_name: str) -> bytes:
        valid_blob = validate_blob_name(blob_name)
        with self._lock:
            entry = self._blobs.get(valid_blob)
        if entry is None:
            raise BlobNotFoundError(f"Blob not found: {valid_blob}")
        logger.debug(
            "Downloaded immutable WORM blob (in-memory mock)",
            extra={"blob_name": valid_blob, "size_bytes": len(entry[0])},
        )
        return entry[0]

    def get_blob_metadata(self, blob_name: str) -> dict[str, str]:
        valid_blob = validate_blob_name(blob_name)
        with self._lock:
            entry = self._blobs.get(valid_blob)
        if entry is None:
            raise BlobNotFoundError(f"Blob not found: {valid_blob}")
        return dict(entry[1]) if entry[1] else {}

    def blob_exists(self, blob_name: str) -> bool:
        valid_blob = validate_blob_name(blob_name)
        with self._lock:
            return valid_blob in self._blobs


def get_blob_worm_client(settings: Settings | None = None) -> BlobWORMClientProtocol:
    """
    Return the active WORM Blob client singleton based on application settings.

    Fail-closed guards:
    - ``USE_MOCK_BLOB_STORAGE=True`` is prohibited outside ``APP_ENV in {"dev", "local", "test"}``
      or whenever ``USE_LOCAL_SQLITE=False`` (CWE-489).
    """
    global _CACHED_CLIENT
    cfg = settings or get_settings()
    env_name = cfg.APP_ENV.strip().lower()
    cache_key = (
        env_name,
        cfg.USE_MOCK_BLOB_STORAGE,
        cfg.USE_AZURITE_EMULATOR,
        cfg.USE_LOCAL_SQLITE,
        cfg.AZURE_BLOB_ACCOUNT_URL.strip(),
        cfg.AZURITE_BLOB_URL.strip(),
        cfg.AZURE_BLOB_WORM_CONTAINER.strip(),
    )

    with _CLIENT_LOCK:
        if _CACHED_CLIENT is not None and _CACHED_CLIENT[0] == cache_key:
            return _CACHED_CLIENT[1]

        if cfg.USE_MOCK_BLOB_STORAGE:
            if env_name not in MOCK_BLOB_ALLOWED_ENVS or not cfg.USE_LOCAL_SQLITE:
                raise BlobStorageConfigurationError(
                    "USE_MOCK_BLOB_STORAGE is prohibited outside local dev/test environments"
                )
            try:
                client: BlobWORMClientProtocol = InMemoryWORMBlobClient(
                    account_url=cfg.AZURE_BLOB_ACCOUNT_URL,
                    container_name=cfg.AZURE_BLOB_WORM_CONTAINER,
                )
            except ValueError as exc:
                raise BlobStorageConfigurationError(str(exc)) from None
        elif cfg.USE_AZURITE_EMULATOR:
            from src.storage.azurite import create_azurite_worm_client

            client = create_azurite_worm_client(settings=cfg)
        else:
            try:
                client = AzureBlobWORMClient(
                    account_url=cfg.AZURE_BLOB_ACCOUNT_URL,
                    container_name=cfg.AZURE_BLOB_WORM_CONTAINER,
                )
            except ValueError as exc:
                raise BlobStorageConfigurationError(str(exc)) from None

        _CACHED_CLIENT = (cache_key, client)
        return client


def reset_blob_client_cache() -> None:
    """Clear cached WORM Blob client singleton (used for clean test isolation)."""
    global _CACHED_CLIENT
    with _CLIENT_LOCK:
        _CACHED_CLIENT = None
