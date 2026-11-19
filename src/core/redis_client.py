"""
Async Redis Job Queue & Idempotency Client (P5-2).

Provides FIFO invoice job enqueue/dequeue, Dead-Letter Queue (DLQ) poison-pill
quarantine, and atomic ``SET NX EX`` idempotency key management per LLD §6.1,
CLAUDE.md §4.1, and §16 rule 6.

Security controls:
- Strict ``USE_FAKE_REDIS=true`` environment gate (dev/local/test only — CWE-489).
- Mandatory TLS (``rediss://``) in staging and production (CWE-319).
- SHA-256 actor-scoped idempotency keys preventing Redis key injection & cross-clerk
  collision (CWE-74 / CWE-639).
- Atomic ``SET NX EX`` claims eliminating TOCTOU duplicate-upload races (CWE-362).
- Bounded 64 KB job payloads & strict identifier/path validation (CWE-22 / CWE-400).
- Sanitized error wrapping preventing Redis URL/credential leaks (CWE-209 / CWE-532).
"""

import hashlib
import json
import re
import threading
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

try:
    import fakeredis.aioredis
except ImportError:  # pragma: no cover
    fakeredis = None  # type: ignore[assignment]
import redis.asyncio as aioredis
from pydantic import BaseModel, ConfigDict, ValidationError
from redis.exceptions import RedisError, WatchError

from src.core.config import Settings, get_settings
from src.core.logging import get_logger

logger = get_logger("ap.core.redis_client")

# Canonical Redis namespaces
DEFAULT_INVOICE_QUEUE_KEY: str = "ap:queue:invoices"
DEFAULT_DEAD_LETTER_QUEUE_KEY: str = "ap:queue:invoices:dlq"
IDEMPOTENCY_KEY_PREFIX: str = "ap:idempotency:"

# Bounded operational limits (CWE-400 / CWE-770)
DEFAULT_IDEMPOTENCY_TTL_SECONDS: int = 86_400
MIN_IDEMPOTENCY_TTL_SECONDS: int = 60
MAX_IDEMPOTENCY_TTL_SECONDS: int = 7 * 86_400
MAX_JOB_PAYLOAD_BYTES: int = 64 * 1024
MAX_QUEUE_DEPTH: int = 100_000
MAX_DLQ_LENGTH: int = 10_000
MAX_DLQ_RAW_PREVIEW_CHARS: int = 2048
MAX_DEQUEUE_TIMEOUT_SECONDS: int = 30
REDIS_SOCKET_TIMEOUT_SECONDS: float = 2.0

FAKE_REDIS_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

# Strict validation patterns
_REDIS_KEY_PATTERN = re.compile(r"^[A-Za-z0-9:_-]{1,128}$")
_INVOICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CLIENT_IDEM_KEY_PATTERN = re.compile(r"^[\x21-\x7e]{1,128}$")
_STATUS_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,49}$")
_ALLOWED_BLOB_URL_PREFIXES: tuple[str, ...] = (
    "https://",
    "http://127.0.0.1:",
    "http://localhost:",
    "http://azurite:",
)
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


class RedisQueueError(RuntimeError):
    """Base error raised on Redis queue transport or storage failures."""


class RedisQueueConfigurationError(RedisQueueError):
    """Raised when Redis queue configuration violates production TLS or mock-isolation rules."""


class RedisJobPayloadError(ValueError):
    """Raised when an enqueued or dequeued invoice job payload is invalid or oversized."""


class InvoiceQueueJob(BaseModel):
    """Immutable FIFO queue message for background invoice extraction workers."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    blob_name: str
    blob_url: str
    file_hash: str
    filename: str
    detected_mime: str
    vendor_id: str = "UNKNOWN"
    uploaded_by: str
    request_id: str | None = None
    enqueued_at: str
    attempt: int = 0


class IdempotencyRecord(BaseModel):
    """Immutable idempotency state stored atomically under ``ap:idempotency:<sha256>``."""

    model_config = ConfigDict(frozen=True)

    idempotency_key: str
    invoice_id: str
    status: str = "UPLOADED"
    created_at: str
    file_hash: str | None = None


def _validate_redis_key(key: str, *, label: str) -> str:
    if not isinstance(key, str) or not _REDIS_KEY_PATTERN.match(key):
        raise ValueError(f"Invalid Redis {label}: must match ^[A-Za-z0-9:_-]{{1,128}}$")
    return key


def _validate_sha256_key(idempotency_key: str) -> str:
    if not isinstance(idempotency_key, str) or not _SHA256_HEX_PATTERN.match(idempotency_key):
        raise ValueError("Invalid idempotency_key: expected 64-character lowercase SHA-256 hex")
    return idempotency_key


def _validate_ttl(ttl_seconds: int) -> int:
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not (MIN_IDEMPOTENCY_TTL_SECONDS <= ttl_seconds <= MAX_IDEMPOTENCY_TTL_SECONDS)
    ):
        raise ValueError(
            f"idempotency TTL must be between {MIN_IDEMPOTENCY_TTL_SECONDS} and {MAX_IDEMPOTENCY_TTL_SECONDS} seconds"
        )
    return ttl_seconds


def _validate_status(status: str) -> str:
    if not isinstance(status, str) or not _STATUS_PATTERN.match(status):
        raise ValueError("Invalid workflow status for idempotency record")
    return status


def _validate_job_model(job: InvoiceQueueJob) -> InvoiceQueueJob:
    """Enforce strict identifier, path-traversal, URL, and SHA-256 invariants on queue jobs."""
    if not _INVOICE_ID_PATTERN.match(job.invoice_id):
        raise RedisJobPayloadError("Invalid invoice_id in job payload")
    if (
        not job.blob_name
        or job.blob_name.startswith("/")
        or ".." in job.blob_name
        or "\\" in job.blob_name
        or _CONTROL_CHAR_RE.search(job.blob_name)
    ):
        raise RedisJobPayloadError("Unsafe blob_name in job payload")
    if (
        not isinstance(job.blob_url, str)
        or _CONTROL_CHAR_RE.search(job.blob_url)
        or not job.blob_url.startswith(_ALLOWED_BLOB_URL_PREFIXES)
    ):
        raise RedisJobPayloadError("Unsafe blob_url scheme in job payload")
    if not _SHA256_HEX_PATTERN.match(job.file_hash):
        raise RedisJobPayloadError("Invalid file_hash in job payload")
    if job.attempt < 0 or job.attempt > 20:
        raise RedisJobPayloadError("Invalid retry attempt count in job payload")
    return job


def compute_idempotency_key(file_bytes: bytes, clerk_id: str) -> str:
    """
    Compute canonical LLD §6.1 idempotency key: ``SHA256(file_bytes + clerk_id)``.

    Isolates identical file submissions across distinct clerks (CWE-639).
    """
    if not isinstance(file_bytes, bytes) or len(file_bytes) == 0:
        raise ValueError("file_bytes must be non-empty bytes")
    if not isinstance(clerk_id, str) or not clerk_id.strip() or _CONTROL_CHAR_RE.search(clerk_id):
        raise ValueError("clerk_id must be a non-empty string without control characters")
    return hashlib.sha256(file_bytes + clerk_id.strip().encode("utf-8")).hexdigest()


def hash_client_idempotency_key(raw_key: str, *, clerk_id: str) -> str:
    """
    Validate and SHA-256 hash a client-supplied ``Idempotency-Key`` header scoped by ``clerk_id``.

    Prevents Redis key injection (CWE-74) and cross-clerk cache collisions (CWE-639).
    """
    if not isinstance(raw_key, str) or not _CLIENT_IDEM_KEY_PATTERN.match(raw_key):
        raise ValueError(
            "Invalid Idempotency-Key header: expected 1-128 printable non-whitespace ASCII characters"
        )
    if not isinstance(clerk_id, str) or not clerk_id.strip() or _CONTROL_CHAR_RE.search(clerk_id):
        raise ValueError("clerk_id must be a non-empty string without control characters")
    scoped = (
        b"client-idem\x00" + clerk_id.strip().encode("utf-8") + b"\x00" + raw_key.encode("ascii")
    )
    return hashlib.sha256(scoped).hexdigest()


def validate_redis_url(url: str, *, app_env: str) -> str:
    """
    Validate Redis connection URL and enforce TLS (``rediss://``) outside local dev/test (CWE-319).
    """
    if not isinstance(url, str) or not url.strip() or _CONTROL_CHAR_RE.search(url):
        raise RedisQueueConfigurationError("Invalid REDIS_URL configuration")

    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("redis", "rediss") or not parsed.hostname:
        raise RedisQueueConfigurationError(
            "REDIS_URL must use redis:// or rediss:// with a valid host"
        )

    env_name = app_env.strip().lower()
    if env_name not in FAKE_REDIS_ALLOWED_ENVS and scheme != "rediss":
        raise RedisQueueConfigurationError(
            f"REDIS_URL must enforce TLS (rediss://) in environment '{env_name}'"
        )
    return url.strip()


class RedisJobQueueClient:
    """
    Async FIFO Redis job queue and atomic idempotency client for invoice processing.
    """

    def __init__(
        self,
        redis_client: Any,
        *,
        queue_key: str = DEFAULT_INVOICE_QUEUE_KEY,
        dlq_key: str = DEFAULT_DEAD_LETTER_QUEUE_KEY,
        idempotency_ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
    ) -> None:
        self._redis = redis_client
        self._queue_key = _validate_redis_key(queue_key, label="queue key")
        self._dlq_key = _validate_redis_key(dlq_key, label="DLQ key")
        self._idempotency_ttl_seconds = _validate_ttl(idempotency_ttl_seconds)

    @property
    def queue_key(self) -> str:
        return self._queue_key

    @property
    def dlq_key(self) -> str:
        return self._dlq_key

    async def ping(self) -> bool:
        """Return True if the backing Redis instance responds to PING."""
        try:
            return bool(await self._redis.ping())
        except (RedisError, OSError):
            return False

    async def queue_depth(self) -> int:
        """Return current number of queued invoice jobs."""
        try:
            return int(await self._redis.llen(self._queue_key))
        except (RedisError, OSError) as exc:
            logger.error(
                "Failed to query Redis queue depth", extra={"error_type": type(exc).__name__}
            )
            raise RedisQueueError("Failed to query invoice job queue depth") from None

    async def dlq_depth(self) -> int:
        """Return current number of quarantined dead-letter jobs."""
        try:
            return int(await self._redis.llen(self._dlq_key))
        except (RedisError, OSError) as exc:
            logger.error(
                "Failed to query Redis DLQ depth", extra={"error_type": type(exc).__name__}
            )
            raise RedisQueueError("Failed to query dead-letter queue depth") from None

    async def enqueue(self, job: InvoiceQueueJob | dict[str, Any]) -> int:
        """Validate, serialize, and enqueue a job onto the FIFO Redis queue via ``RPUSH``."""
        if isinstance(job, dict):
            try:
                job_model = InvoiceQueueJob(**job)
            except ValidationError:
                raise RedisJobPayloadError("Malformed invoice job payload") from None
        elif isinstance(job, InvoiceQueueJob):
            job_model = job
        else:
            raise RedisJobPayloadError("Expected InvoiceQueueJob or dict")

        _validate_job_model(job_model)
        serialized = job_model.model_dump_json()
        if len(serialized.encode("utf-8")) > MAX_JOB_PAYLOAD_BYTES:
            raise RedisJobPayloadError(
                f"Job payload size exceeds maximum limit of {MAX_JOB_PAYLOAD_BYTES} bytes"
            )

        try:
            current_depth = int(await self._redis.llen(self._queue_key))
            if current_depth >= MAX_QUEUE_DEPTH:
                raise RedisQueueError("Invoice job queue capacity exceeded")
            depth = int(await self._redis.rpush(self._queue_key, serialized))
        except RedisQueueError:
            raise
        except (RedisError, OSError) as exc:
            logger.error(
                "Redis enqueue failed",
                extra={"invoice_id": job_model.invoice_id, "error_type": type(exc).__name__},
            )
            raise RedisQueueError("Failed to enqueue invoice job") from None

        logger.info(
            "Enqueued invoice job",
            extra={"invoice_id": job_model.invoice_id, "queue_depth": depth},
        )
        return depth

    async def enqueue_dead_letter(
        self,
        raw_payload: str | InvoiceQueueJob,
        *,
        reason: str,
    ) -> int:
        """Quarantine a malformed or exhausted job into the Dead-Letter Queue."""
        preview = (
            raw_payload.model_dump_json()
            if isinstance(raw_payload, InvoiceQueueJob)
            else str(raw_payload)
        )[:MAX_DLQ_RAW_PREVIEW_CHARS]
        clean_reason = _CONTROL_CHAR_RE.sub(" ", reason).strip()[:256] or "unspecified_error"
        envelope = json.dumps(
            {
                "reason": clean_reason,
                "quarantined_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "payload_preview": preview,
            },
            sort_keys=True,
        )
        try:
            depth = int(await self._redis.rpush(self._dlq_key, envelope))
            if depth > MAX_DLQ_LENGTH:
                await self._redis.ltrim(self._dlq_key, -MAX_DLQ_LENGTH, -1)
                return MAX_DLQ_LENGTH
            return depth
        except (RedisError, OSError) as exc:
            logger.error("Redis DLQ push failed", extra={"error_type": type(exc).__name__})
            raise RedisQueueError("Failed to push message to dead-letter queue") from None

    async def dequeue(self, *, timeout_seconds: int = 0) -> InvoiceQueueJob | None:
        """
        Dequeue the next FIFO invoice job (``LPOP`` when timeout=0, ``BLPOP`` when timeout>0).

        Corrupted or schema-invalid poison-pill payloads are automatically quarantined into
        the DLQ before raising ``RedisJobPayloadError``.
        """
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 0
        ):
            raise ValueError("timeout_seconds must be a non-negative integer")
        bounded_timeout = min(timeout_seconds, MAX_DEQUEUE_TIMEOUT_SECONDS)

        try:
            if bounded_timeout == 0:
                raw_item = await self._redis.lpop(self._queue_key)
            else:
                popped = await self._redis.blpop([self._queue_key], timeout=bounded_timeout)
                raw_item = popped[1] if popped else None
        except (RedisError, OSError) as exc:
            logger.error("Redis dequeue failed", extra={"error_type": type(exc).__name__})
            raise RedisQueueError("Failed to dequeue invoice job") from None

        if raw_item is None:
            return None

        raw_str = (
            raw_item.decode("utf-8", errors="replace")
            if isinstance(raw_item, bytes)
            else str(raw_item)
        )
        if len(raw_str.encode("utf-8")) > MAX_JOB_PAYLOAD_BYTES:
            await self.enqueue_dead_letter(raw_str, reason="oversized_job_payload")
            raise RedisJobPayloadError("Dequeued job payload exceeds size limit (moved to DLQ)")

        try:
            job = InvoiceQueueJob.model_validate_json(raw_str)
            return _validate_job_model(job)
        except (ValidationError, RedisJobPayloadError, ValueError) as exc:
            await self.enqueue_dead_letter(raw_str, reason=f"invalid_payload:{type(exc).__name__}")
            raise RedisJobPayloadError("Corrupted or invalid job payload (moved to DLQ)") from None

    def _idem_redis_key(self, idempotency_key: str) -> str:
        return f"{IDEMPOTENCY_KEY_PREFIX}{_validate_sha256_key(idempotency_key)}"

    async def get_idempotency_record(self, idempotency_key: str) -> IdempotencyRecord | None:
        """Retrieve an existing idempotency record by canonical SHA-256 key, or None."""
        redis_key = self._idem_redis_key(idempotency_key)
        try:
            raw = await self._redis.get(redis_key)
        except (RedisError, OSError) as exc:
            logger.error(
                "Redis idempotency lookup failed", extra={"error_type": type(exc).__name__}
            )
            raise RedisQueueError("Failed to query idempotency record") from None

        if raw is None:
            return None
        raw_str = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        try:
            return IdempotencyRecord.model_validate_json(raw_str)
        except ValidationError:
            raise RedisJobPayloadError("Corrupted idempotency record stored in Redis") from None

    async def claim_idempotency_key(
        self,
        idempotency_key: str,
        invoice_id: str,
        *,
        status: str = "UPLOADED",
        file_hash: str | None = None,
        ttl_seconds: int | None = None,
    ) -> tuple[bool, IdempotencyRecord]:
        """
        Atomically claim an idempotency slot using ``SET key value NX EX ttl`` (CWE-362).

        Returns:
            ``(True, new_record)`` if this caller won the claim, or
            ``(False, existing_record)`` if an earlier/concurrent upload already owns the key.
        """
        clean_key = _validate_sha256_key(idempotency_key)
        if not isinstance(invoice_id, str) or not _INVOICE_ID_PATTERN.match(invoice_id):
            raise ValueError("Invalid invoice_id for idempotency claim")
        clean_status = _validate_status(status)
        clean_file_hash: str | None = None
        if file_hash is not None:
            if not isinstance(file_hash, str) or not _SHA256_HEX_PATTERN.match(file_hash):
                raise ValueError("Invalid file_hash for idempotency claim")
            clean_file_hash = file_hash
        ttl = self._idempotency_ttl_seconds if ttl_seconds is None else _validate_ttl(ttl_seconds)

        candidate = IdempotencyRecord(
            idempotency_key=clean_key,
            invoice_id=invoice_id,
            status=clean_status,
            created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            file_hash=clean_file_hash,
        )
        redis_key = f"{IDEMPOTENCY_KEY_PREFIX}{clean_key}"

        try:
            acquired = await self._redis.set(
                redis_key,
                candidate.model_dump_json(),
                nx=True,
                ex=ttl,
            )
            if acquired:
                return True, candidate

            existing = await self.get_idempotency_record(clean_key)
            if existing is not None:
                return False, existing

            # Rare edge case: winner expired between SET NX and GET — attempt one final claim
            re_acquired = await self._redis.set(
                redis_key,
                candidate.model_dump_json(),
                nx=True,
                ex=ttl,
            )
            if re_acquired:
                return True, candidate
            existing_after = await self.get_idempotency_record(clean_key)
            if existing_after is not None:
                return False, existing_after
            raise RedisQueueError("Concurrent idempotency state transition conflict")
        except (RedisError, OSError) as exc:
            logger.error("Redis idempotency claim failed", extra={"error_type": type(exc).__name__})
            raise RedisQueueError("Failed to claim idempotency key") from None

    async def update_idempotency_status(
        self,
        idempotency_key: str,
        *,
        invoice_id: str,
        status: str,
    ) -> bool:
        """
        Atomically update status on an existing idempotency key via WATCH/MULTI/EXEC,
        only if owned by ``invoice_id``, while preserving remaining TTL (CWE-362).
        """
        clean_key = _validate_sha256_key(idempotency_key)
        clean_status = _validate_status(status)
        redis_key = f"{IDEMPOTENCY_KEY_PREFIX}{clean_key}"

        try:
            async with self._redis.pipeline() as pipe:
                await pipe.watch(redis_key)
                raw = await pipe.get(redis_key)
                if raw is None:
                    await pipe.unwatch()
                    return False
                raw_str = (
                    raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                )
                existing = IdempotencyRecord.model_validate_json(raw_str)
                if existing.invoice_id != invoice_id:
                    await pipe.unwatch()
                    return False

                updated = IdempotencyRecord(
                    idempotency_key=existing.idempotency_key,
                    invoice_id=existing.invoice_id,
                    status=clean_status,
                    created_at=existing.created_at,
                    file_hash=existing.file_hash,
                )
                pipe.multi()
                pipe.set(redis_key, updated.model_dump_json(), xx=True, keepttl=True)
                exec_res = await pipe.execute()
                return bool(exec_res and exec_res[0])
        except WatchError:
            return False
        except ValidationError:
            raise RedisJobPayloadError("Corrupted idempotency record stored in Redis") from None
        except (RedisError, OSError) as exc:
            logger.error(
                "Redis idempotency status update failed", extra={"error_type": type(exc).__name__}
            )
            raise RedisQueueError("Failed to update idempotency status") from None

    async def release_idempotency_key(
        self,
        idempotency_key: str,
        *,
        expected_invoice_id: str,
    ) -> bool:
        """
        Atomically release an idempotency key on rollback via WATCH/MULTI/EXEC ONLY if
        still owned by ``expected_invoice_id`` (prevents deleting a newer lock: CWE-362).
        """
        clean_key = _validate_sha256_key(idempotency_key)
        redis_key = f"{IDEMPOTENCY_KEY_PREFIX}{clean_key}"

        try:
            async with self._redis.pipeline() as pipe:
                await pipe.watch(redis_key)
                raw = await pipe.get(redis_key)
                if raw is None:
                    await pipe.unwatch()
                    return False
                raw_str = (
                    raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                )
                existing = IdempotencyRecord.model_validate_json(raw_str)
                if existing.invoice_id != expected_invoice_id:
                    await pipe.unwatch()
                    return False

                pipe.multi()
                pipe.delete(redis_key)
                exec_res = await pipe.execute()
                return bool(exec_res and exec_res[0])
        except WatchError:
            return False
        except ValidationError:
            raise RedisJobPayloadError("Corrupted idempotency record stored in Redis") from None
        except (RedisError, OSError) as exc:
            logger.error(
                "Redis idempotency release failed", extra={"error_type": type(exc).__name__}
            )
            raise RedisQueueError("Failed to release idempotency key") from None


_CLIENT_LOCK = threading.Lock()
_CACHED_QUEUE_CLIENT: RedisJobQueueClient | None = None
_CACHED_CLIENT_KEY: tuple[str, bool, str] | None = None


def reset_redis_queue_client_cache() -> None:
    """Clear the cached RedisJobQueueClient singleton (for isolated unit testing)."""
    global _CACHED_QUEUE_CLIENT, _CACHED_CLIENT_KEY
    with _CLIENT_LOCK:
        _CACHED_QUEUE_CLIENT = None
        _CACHED_CLIENT_KEY = None


def get_redis_queue_client(settings: Settings | None = None) -> RedisJobQueueClient:
    """
    Return the configured ``RedisJobQueueClient`` singleton.

    Enforces:
    - ``USE_FAKE_REDIS=True`` is hard-blocked outside ``dev``/``local``/``test`` (CWE-489).
    - Non-TLS ``redis://`` URLs are hard-blocked in staging/production (CWE-319).
    """
    global _CACHED_QUEUE_CLIENT, _CACHED_CLIENT_KEY
    cfg = settings or get_settings()
    env_name = cfg.APP_ENV.strip().lower()
    cache_key = (env_name, cfg.USE_FAKE_REDIS, cfg.REDIS_URL)

    with _CLIENT_LOCK:
        if _CACHED_QUEUE_CLIENT is not None and _CACHED_CLIENT_KEY == cache_key:
            return _CACHED_QUEUE_CLIENT

        if cfg.USE_FAKE_REDIS:
            if env_name not in FAKE_REDIS_ALLOWED_ENVS:
                raise RedisQueueConfigurationError(
                    f"USE_FAKE_REDIS=true is strictly prohibited in environment '{env_name}'"
                )
            if not cfg.USE_LOCAL_SQLITE:
                raise RedisQueueConfigurationError(
                    "USE_FAKE_REDIS=true requires USE_LOCAL_SQLITE=true (cannot pair ephemeral RAM queue with Azure SQL)"
                )
            if fakeredis is None:
                raise RedisQueueConfigurationError(
                    "fakeredis package is required when USE_FAKE_REDIS=true. Install via: pip install fakeredis"
                )
            backend: Any = fakeredis.aioredis.FakeRedis(decode_responses=True)
        else:
            valid_url = validate_redis_url(cfg.REDIS_URL, app_env=env_name)
            backend = aioredis.from_url(
                valid_url,
                decode_responses=True,
                socket_connect_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
                socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            )

        client = RedisJobQueueClient(backend)
        _CACHED_QUEUE_CLIENT = client
        _CACHED_CLIENT_KEY = cache_key
        return client
