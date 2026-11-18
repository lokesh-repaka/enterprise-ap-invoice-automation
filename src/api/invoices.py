"""
Invoice Upload API Route (P5-1).

Implements ``POST /api/v1/invoices/upload`` per FR-01, BR-001, GAP-004, HLD §4,
LLD §2, and CLAUDE.md §4.1 & §9:
1. Enforces Entra ID / Demo RBAC (``ap_clerk`` and ``finance_manager`` only; ``system_admin`` -> 403).
2. Reads multipart upload in bounded 64 KB chunks up to 25 MB (anti-OOM CWE-400).
3. Runs deep magic-byte file validation (MIME, 25 MB cap, TIFF/GAP-004, encrypted & active-script PDF,
   pixel bombs, XLSX Zip-Slip/ZIP-bomb/XXE/macro guards).
4. Writes immutable raw document to Azure Blob WORM storage with canonical ``VendorID``,
   ``UploadTimestamp``, and ``FileHash`` tags.
5. Persists ``Invoice(status="UPLOADED")`` in SQL and records an isolated-transaction ``INGEST`` audit event.
6. Enqueues the async job payload onto Redis (``RPUSH ap:queue:invoices``) — failing closed with 503 if
   storage or Redis is unavailable — and returns **202 Accepted** with ``Location`` header.
"""

import asyncio
import threading
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any

import fakeredis.aioredis
import redis.asyncio as aioredis
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from src.api.schemas.invoices import InvoiceJobPayload, InvoiceUploadResponse
from src.core.audit import AuditActionType, AuditLogger
from src.core.config import get_settings
from src.core.logging import get_logger, request_id_ctx
from src.core.security import AuthenticatedUser, Role, require_role
from src.database.models import Invoice, Vendor
from src.database.repositories import InvoiceRepository, VendorRepository, compute_composite_hash
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import (
    BlobStorageError,
    BlobWORMClientProtocol,
    get_blob_worm_client,
)
from src.storage.file_validator import (
    MAX_UPLOAD_SIZE_BYTES,
    FileValidationError,
    validate_invoice_file,
)
from src.storage.metadata import (
    DEFAULT_UNKNOWN_VENDOR_ID,
    BlobMetadataError,
    validate_vendor_id,
)

logger = get_logger("ap.api.invoices")

router = APIRouter(prefix="/api/v1/invoices", tags=["Invoices"])

# Canonical FIFO Redis queue key for async invoice extraction jobs
INVOICE_QUEUE_KEY: str = "ap:queue:invoices"
UPLOAD_READ_CHUNK_BYTES: int = 64 * 1024
MULTIPART_OVERHEAD_BYTES: int = 1 * 1024 * 1024
REDIS_QUEUE_SOCKET_TIMEOUT_SECONDS: float = 2.0
FAKE_REDIS_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

_DEP_LOCK = threading.Lock()
_DEFAULT_ENGINE: AsyncEngine | None = None
_DEFAULT_SESSION_FACTORY: async_sessionmaker[AsyncSession] | None = None
_DEFAULT_FAKE_REDIS: fakeredis.aioredis.FakeRedis | None = None
_DEFAULT_REAL_REDIS: aioredis.Redis | None = None
_DEFAULT_REAL_REDIS_URL: str | None = None


def get_upload_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return cached async SQL session factory (overridable in tests via dependency_overrides)."""
    global _DEFAULT_ENGINE, _DEFAULT_SESSION_FACTORY
    with _DEP_LOCK:
        if _DEFAULT_SESSION_FACTORY is None:
            _DEFAULT_ENGINE = create_db_engine()
            _DEFAULT_SESSION_FACTORY = create_session_factory(_DEFAULT_ENGINE)
        return _DEFAULT_SESSION_FACTORY


def get_upload_blob_client() -> BlobWORMClientProtocol:
    """Return active WORM Blob storage client (overridable in tests via dependency_overrides)."""
    return get_blob_worm_client()


def get_upload_redis_client() -> Any:
    """Return async Redis client for job enqueueing (FakeRedis strictly gated to dev/local/test)."""
    global _DEFAULT_FAKE_REDIS, _DEFAULT_REAL_REDIS, _DEFAULT_REAL_REDIS_URL
    settings = get_settings()
    with _DEP_LOCK:
        if settings.USE_FAKE_REDIS:
            env_name = settings.APP_ENV.strip().lower()
            if env_name not in FAKE_REDIS_ALLOWED_ENVS:
                logger.error(
                    "Blocked USE_FAKE_REDIS=true outside local development environment",
                    extra={"app_env": env_name},
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Processing queue configuration is invalid for this environment",
                )
            if _DEFAULT_FAKE_REDIS is None:
                _DEFAULT_FAKE_REDIS = fakeredis.aioredis.FakeRedis(decode_responses=True)
            return _DEFAULT_FAKE_REDIS
        if _DEFAULT_REAL_REDIS is None or _DEFAULT_REAL_REDIS_URL != settings.REDIS_URL:
            _DEFAULT_REAL_REDIS = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=REDIS_QUEUE_SOCKET_TIMEOUT_SECONDS,
                socket_timeout=REDIS_QUEUE_SOCKET_TIMEOUT_SECONDS,
            )
            _DEFAULT_REAL_REDIS_URL = settings.REDIS_URL
        return _DEFAULT_REAL_REDIS


def guard_upload_content_length(request: Request) -> None:
    """Fail fast on absurd or malformed Content-Length headers before heavy processing (CWE-400)."""
    raw_len = request.headers.get("content-length")
    if raw_len is None:
        return
    try:
        declared_len = int(raw_len.strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Content-Length header",
        ) from None
    if declared_len < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Content-Length header",
        )
    if declared_len > MAX_UPLOAD_SIZE_BYTES + MULTIPART_OVERHEAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded payload exceeds maximum limit of {MAX_UPLOAD_SIZE_BYTES} bytes",
        )


def reset_upload_dependencies() -> None:
    """Reset cached upload route dependency singletons (for isolated testing)."""
    global _DEFAULT_ENGINE, _DEFAULT_SESSION_FACTORY, _DEFAULT_FAKE_REDIS
    global _DEFAULT_REAL_REDIS, _DEFAULT_REAL_REDIS_URL
    with _DEP_LOCK:
        _DEFAULT_ENGINE = None
        _DEFAULT_SESSION_FACTORY = None
        _DEFAULT_FAKE_REDIS = None
        _DEFAULT_REAL_REDIS = None
        _DEFAULT_REAL_REDIS_URL = None


async def _read_upload_bounded(
    file: UploadFile, *, max_size_bytes: int = MAX_UPLOAD_SIZE_BYTES
) -> bytes:
    """Read multipart upload in fixed 64 KB chunks, aborting immediately above max_size_bytes (CWE-400)."""
    chunks: list[bytes] = []
    total_read = 0
    try:
        while True:
            chunk = await file.read(UPLOAD_READ_CHUNK_BYTES)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_size_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded file exceeds maximum limit of {max_size_bytes} bytes",
                )
            chunks.append(chunk)
    finally:
        await file.close()
    return b"".join(chunks)


async def _ensure_unknown_sentinel_vendor(session: AsyncSession) -> Vendor:
    """Idempotently ensure the inactive 'UNKNOWN' placeholder vendor exists for pre-OCR uploads."""
    repo = VendorRepository(session)
    existing = await repo.get_by_tax_id(DEFAULT_UNKNOWN_VENDOR_ID)
    if existing is not None:
        return existing

    sentinel = Vendor(
        vendor_tax_id=DEFAULT_UNKNOWN_VENDOR_ID,
        vendor_id=DEFAULT_UNKNOWN_VENDOR_ID,
        vendor_name="Pending Extraction",
        country_code="US",
        date_format_locale="MM/DD/YYYY",
        number_format_preference="1,234.56",
        default_currency="USD",
        tax_scheme="US_SALES_TAX",
        is_active=False,
    )
    try:
        return await repo.create(sentinel)
    except IntegrityError:
        await session.rollback()
        winner = await repo.get_by_tax_id(DEFAULT_UNKNOWN_VENDOR_ID)
        if winner is not None:
            return winner
        raise


async def _resolve_vendor_for_upload(
    session: AsyncSession,
    requested_vendor_id: str | None,
) -> tuple[str, str, str | None, str]:
    """
    Resolve (vendor_id_tag, vendor_tax_id, vendor_name, currency) for a raw upload.

    If ``requested_vendor_id`` is explicitly supplied, verifies it refers to an active Vendor
    in SQL (returning HTTP 422 otherwise). If omitted, resolves the inactive UNKNOWN sentinel.
    """
    if requested_vendor_id is None:
        sentinel = await _ensure_unknown_sentinel_vendor(session)
        return (
            DEFAULT_UNKNOWN_VENDOR_ID,
            sentinel.vendor_tax_id,
            None,
            sentinel.default_currency,
        )

    try:
        clean_vendor_id = validate_vendor_id(requested_vendor_id)
    except BlobMetadataError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    repo = VendorRepository(session)
    vendor = await repo.get_by_vendor_id(clean_vendor_id)
    if vendor is None or not vendor.is_active:
        raise HTTPException(status_code=422, detail="Unknown or inactive vendor_id")
    return (
        vendor.vendor_id or clean_vendor_id,
        vendor.vendor_tax_id,
        vendor.vendor_name,
        vendor.default_currency,
    )


@router.post(
    "/upload",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvoiceUploadResponse,
    dependencies=[Depends(guard_upload_content_length)],
    summary="Upload raw invoice document and enqueue async extraction job",
)
async def upload_invoice(
    response: Response,
    file: Annotated[
        UploadFile, File(description="Invoice document (PDF, JPG, PNG, XLSX <= 25 MB)")
    ],
    current_user: Annotated[
        AuthenticatedUser,
        Depends(require_role(Role.AP_CLERK, Role.FINANCE_MANAGER)),
    ],
    session_factory: Annotated[
        async_sessionmaker[AsyncSession],
        Depends(get_upload_session_factory),
    ],
    blob_client: Annotated[
        BlobWORMClientProtocol,
        Depends(get_upload_blob_client),
    ],
    redis_client: Annotated[Any, Depends(get_upload_redis_client)],
    vendor_id: Annotated[str | None, Form(description="Optional active VendorID")] = None,
) -> InvoiceUploadResponse:
    """
    Validate, store immutably in WORM Blob Storage, persist SQL Invoice(UPLOADED),
    log an immutable INGEST audit record, and enqueue an async Redis extraction job.
    """
    raw_filename = (file.filename or "").strip()
    if not raw_filename:
        await file.close()
        raise HTTPException(
            status_code=422,
            detail="Uploaded file must include a valid filename",
        )

    # Validate optional vendor_id syntax early before reading/storing upload bytes
    if vendor_id is not None:
        try:
            validate_vendor_id(vendor_id)
        except BlobMetadataError as exc:
            await file.close()
            raise HTTPException(status_code=422, detail=str(exc)) from None

    # 1. Bounded multipart stream read (anti-OOM: CWE-400)
    raw_bytes = await _read_upload_bounded(file, max_size_bytes=MAX_UPLOAD_SIZE_BYTES)

    # 2. Deep binary magic-byte, 25 MB, TIFF/GAP-004, encrypted-PDF, pixel & XLSX validation (P4-3)
    # Offloaded via asyncio.to_thread to avoid blocking the FastAPI event loop (CWE-400)
    try:
        validated = await asyncio.to_thread(
            validate_invoice_file,
            raw_filename,
            raw_bytes,
            declared_content_type=file.content_type,
        )
    except FileValidationError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from None

    # 3. Resolve Vendor FK in SQL before writing immutable WORM blob (avoids orphan blobs on bad vendor_id)
    try:
        async with session_factory() as session:
            (
                resolved_vendor_id,
                resolved_vendor_tax_id,
                resolved_vendor_name,
                resolved_currency,
            ) = await _resolve_vendor_for_upload(session, vendor_id)
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        logger.error(
            "Database error resolving vendor during invoice upload",
            extra={"error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice database is temporarily unavailable",
        ) from None

    # 4. Mint canonical InvoiceID and write immutable WORM Blob with canonical metadata tags (P4-1 + P4-4)
    # Offloaded via asyncio.to_thread to avoid blocking the async event loop on storage network I/O
    invoice_id = str(uuid.uuid4())
    upload_ts = datetime.now(UTC)
    try:
        upload_result = await asyncio.to_thread(
            blob_client.upload_raw_invoice,
            invoice_id,
            validated.filename,
            raw_bytes,
            content_type=validated.detected_mime,
            vendor_id=resolved_vendor_id,
            upload_timestamp=upload_ts,
            metadata={"InvoiceID": invoice_id},
        )
    except (BlobStorageError, BlobMetadataError) as exc:
        logger.error(
            "WORM Blob storage upload failed during invoice intake",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Immutable document storage is temporarily unavailable",
        ) from None

    # 5. Persist Invoice(status="UPLOADED") in SQL (P2-3)
    placeholder_number = f"PENDING-{invoice_id[:12]}"
    placeholder_hash = compute_composite_hash(
        vendor_tax_id=resolved_vendor_tax_id,
        invoice_number=f"PENDING-{invoice_id}",
        total_amount=Decimal("0.00"),
    )
    invoice_record = Invoice(
        invoice_id=invoice_id,
        vendor_tax_id=resolved_vendor_tax_id,
        vendor_name=resolved_vendor_name,
        invoice_number=placeholder_number,
        total_amount=Decimal("0.00"),
        currency=resolved_currency,
        status="UPLOADED",
        composite_hash=placeholder_hash,
        blob_raw_url=upload_result.blob_url,
    )
    try:
        async with session_factory() as session:
            await InvoiceRepository(session).create(invoice_record)
    except SQLAlchemyError as exc:
        logger.error(
            "Failed to persist Invoice record after WORM blob upload",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to persist invoice metadata",
        ) from None

    # 6. Write immutable INGEST audit event in isolated transaction (P3-4)
    active_request_id = request_id_ctx.get() or None
    try:
        audit_logger = AuditLogger(session_factory)
        await audit_logger.record(
            invoice_id=invoice_id,
            user_id=current_user.user_id,
            action_type=AuditActionType.INGEST,
            field_name="blob_raw_url",
            new_value=upload_result.sha256_hash,
            comment=f"Uploaded {validated.extension} ({validated.size_bytes} bytes)",
            request_id=active_request_id,
        )
    except SQLAlchemyError as exc:
        logger.error(
            "Failed to record INGEST audit event",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit trail is temporarily unavailable",
        ) from None

    # 7. Enqueue async extraction job onto Redis FIFO queue (fail-closed -> 503 if Redis down)
    job = InvoiceJobPayload(
        invoice_id=invoice_id,
        blob_name=upload_result.blob_name,
        blob_url=upload_result.blob_url,
        file_hash=upload_result.sha256_hash,
        filename=validated.filename,
        detected_mime=validated.detected_mime,
        vendor_id=resolved_vendor_id,
        uploaded_by=current_user.user_id,
        request_id=active_request_id,
        enqueued_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    try:
        await redis_client.rpush(INVOICE_QUEUE_KEY, job.model_dump_json())
    except (RedisError, OSError) as exc:
        logger.error(
            "Failed to enqueue invoice processing job in Redis",
            extra={"invoice_id": invoice_id, "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invoice stored but processing queue is temporarily unavailable",
        ) from None

    logger.info(
        "Accepted invoice upload and enqueued async job",
        extra={
            "invoice_id": invoice_id,
            "extension": validated.extension,
            "size_bytes": validated.size_bytes,
            "sha256_prefix": upload_result.sha256_hash[:12],
            "vendor_id": resolved_vendor_id,
        },
    )

    response.headers["Location"] = f"/api/v1/invoices/{invoice_id}"
    response.headers["Cache-Control"] = "no-store"
    return InvoiceUploadResponse(
        invoice_id=invoice_id,
        status="UPLOADED",
        queued=True,
        filename=validated.filename,
        detected_mime=validated.detected_mime,
        size_bytes=validated.size_bytes,
        file_hash=upload_result.sha256_hash,
        blob_url=upload_result.blob_url,
        vendor_id=resolved_vendor_id,
        uploaded_at=upload_result.uploaded_at,
        request_id=active_request_id,
    )
