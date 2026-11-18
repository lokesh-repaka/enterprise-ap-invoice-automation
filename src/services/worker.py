"""
Background Invoice Processing Worker Skeleton (P5-3).

Consumes async FIFO jobs from Redis (``RedisJobQueueClient``), verifies WORM Blob
integrity (``FileHash`` constant-time check + invoice-scoped path pin), transitions
invoice state in SQL (``UPLOADED -> EXTRACTING -> <pipeline_outcome>``), invokes the
pluggable extraction/validation pipeline, persists immutable ``AuditLog`` entries with
propagated ``request_id``, and handles bounded retries + Dead-Letter Queue (DLQ)
escalation cleanly.

Security invariants (CLAUDE.md §4.2, §5, §8, LLD §4, §6.2):
- Zero self-approval: pipeline outcomes are strictly restricted to non-approval states;
  ``APPROVED_CLERK``, ``APPROVED_MANAGER``, and ``STAGED_FOR_EXPORT`` are hard-blocked (CWE-863).
- Cross-invoice blob-swap guard: ``job.blob_name`` MUST be rooted under
  ``raw-invoices/{job.invoice_id}/`` (CWE-639).
- End-to-end cryptographic integrity: downloaded bytes are verified against both WORM
  Blob metadata ``FileHash`` and queued ``job.file_hash`` via ``hmac.compare_digest`` (CWE-354).
- Bounded per-job execution timeout prevents hung pipelines from wedging workers (CWE-400).
- Isolated-transaction audit logging + strict ``request_id_ctx`` reset (zero cross-job leak).
"""

import asyncio
import hmac
import re
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.core.audit import AuditActionType, AuditLogger
from src.core.logging import get_logger, request_id_ctx
from src.core.redis_client import (
    InvoiceQueueJob,
    RedisJobPayloadError,
    RedisJobQueueClient,
)
from src.database.repositories import InvoiceRepository
from src.storage.blob_client import (
    BlobAlreadyExistsError,
    BlobNotFoundError,
    BlobStorageError,
    BlobWORMClientProtocol,
    build_extraction_json_blob_name,
)
from src.storage.metadata import (
    BlobMetadataError,
    verify_blob_metadata_integrity,
)

logger = get_logger("ap.services.worker")

# Legal SQL entry statuses eligible for background pipeline execution
ALLOWED_WORKER_ENTRY_STATUSES: frozenset[str] = frozenset({"UPLOADED", "EXTRACTING"})

# Explicit allowlist of non-approval statuses a pipeline may transition an invoice to (CLAUDE.md §8)
# APPROVED_CLERK, APPROVED_MANAGER, and STAGED_FOR_EXPORT are STRICTLY FORBIDDEN here.
ALLOWED_PIPELINE_TARGET_STATUSES: frozenset[str] = frozenset(
    {
        "VALIDATED",
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "REQUIRES_MANAGER_APPROVAL",
    }
)

_WORKER_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SAFE_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
DEFAULT_MAX_RETRIES: int = 3
MAX_ALLOWED_RETRIES: int = 10
DEFAULT_JOB_TIMEOUT_SECONDS: float = 60.0
MIN_JOB_TIMEOUT_SECONDS: float = 0.01
MAX_JOB_TIMEOUT_SECONDS: float = 300.0


class PipelineStatusViolationError(PermissionError):
    """Raised when a pipeline attempts to transition an invoice to a forbidden/approval status."""


class PipelineContext(BaseModel):
    """Immutable verified inputs passed to the pluggable invoice processing pipeline."""

    model_config = ConfigDict(frozen=True)

    job: InvoiceQueueJob
    raw_bytes: bytes
    verified_file_hash: str


class PipelineResult(BaseModel):
    """Immutable structured outcome returned by an invoice processing pipeline."""

    model_config = ConfigDict(frozen=True)

    target_status: str
    extraction_payload: dict[str, Any] | None = None
    confidence_macro_avg: Decimal | None = None
    summary_comment: str | None = None


class WorkerProcessOutcome(BaseModel):
    """Immutable receipt describing the result of a single worker job cycle."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str | None
    status: str
    final_invoice_status: str | None = None
    attempt: int = 0
    error_code: str | None = None


@runtime_checkable
class InvoicePipelineProtocol(Protocol):
    """Pluggable extraction + validation pipeline interface wired in Phases 6–8."""

    async def execute(self, context: PipelineContext) -> PipelineResult: ...


class DefaultSkeletonPipeline:
    """
    Conservative P5-3 skeleton pipeline prior to Phase 6/7 model & rules wiring.

    Routes processed invoices safely to ``REQUIRES_REVIEW`` (never falsely marking
    unextracted documents as ``VALIDATED`` or ``APPROVED_*``).
    """

    async def execute(self, context: PipelineContext) -> PipelineResult:
        return PipelineResult(
            target_status="REQUIRES_REVIEW",
            summary_comment="Skeleton pipeline completed; awaiting extraction engine integration",
        )


def _validate_pipeline_result(result: PipelineResult) -> PipelineResult:
    """Enforce non-approval target status allowlist and bounded confidence score (CWE-863)."""
    if not isinstance(result, PipelineResult):
        raise PipelineStatusViolationError("Pipeline must return a PipelineResult instance")
    if result.target_status not in ALLOWED_PIPELINE_TARGET_STATUSES:
        raise PipelineStatusViolationError(
            f"Forbidden pipeline target_status '{result.target_status}': "
            "pipelines may never self-approve or emit unknown states"
        )
    if result.confidence_macro_avg is not None:
        if (
            not result.confidence_macro_avg.is_finite()
            or result.confidence_macro_avg < Decimal("0.00")
            or result.confidence_macro_avg > Decimal("100.00")
        ):
            raise ValueError("confidence_macro_avg must be a finite Decimal within [0.00, 100.00]")
    return result


class InvoiceBackgroundWorker:
    """
    Stateless async background worker orchestrating Redis -> WORM Blob -> Pipeline -> SQL & Audit.
    """

    def __init__(
        self,
        *,
        queue_client: RedisJobQueueClient,
        blob_client: BlobWORMClientProtocol,
        session_factory: async_sessionmaker[AsyncSession],
        pipeline: InvoicePipelineProtocol | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        job_timeout_seconds: float = DEFAULT_JOB_TIMEOUT_SECONDS,
        worker_id: str = "system-worker",
    ) -> None:
        if not isinstance(worker_id, str) or not _WORKER_ID_PATTERN.match(worker_id):
            raise ValueError("Invalid worker_id: expected 1-64 [A-Za-z0-9._-] characters")
        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or not (0 <= max_retries <= MAX_ALLOWED_RETRIES)
        ):
            raise ValueError(f"max_retries must be an integer within [0, {MAX_ALLOWED_RETRIES}]")
        if not (MIN_JOB_TIMEOUT_SECONDS <= float(job_timeout_seconds) <= MAX_JOB_TIMEOUT_SECONDS):
            raise ValueError(
                f"job_timeout_seconds must be within [{MIN_JOB_TIMEOUT_SECONDS}, {MAX_JOB_TIMEOUT_SECONDS}]"
            )

        self._queue = queue_client
        self._blob = blob_client
        self._session_factory = session_factory
        self._pipeline: InvoicePipelineProtocol = pipeline or DefaultSkeletonPipeline()
        self._audit = AuditLogger(session_factory)
        self._max_retries = max_retries
        self._job_timeout_seconds = float(job_timeout_seconds)
        self._worker_id = worker_id

    async def _escalate_and_dead_letter(
        self,
        job: InvoiceQueueJob,
        *,
        reason: str,
        error_code: str,
        update_sql_status: bool = True,
    ) -> WorkerProcessOutcome:
        """Escalate failed/tampered invoice to REQUIRES_APPROVAL, audit, and quarantine to DLQ."""
        if update_sql_status:
            async with self._session_factory() as session:
                await InvoiceRepository(session).update_status(job.invoice_id, "REQUIRES_APPROVAL")
            await self._audit.record(
                invoice_id=job.invoice_id,
                user_id=self._worker_id,
                action_type=AuditActionType.STATUS_TRANSITION,
                field_name="status",
                previous_value="EXTRACTING",
                new_value="REQUIRES_APPROVAL",
                comment=f"Escalated to Human Exception Queue ({error_code})",
                request_id=job.request_id,
            )

        await self._queue.enqueue_dead_letter(job, reason=reason)
        logger.warning(
            "Quarantined invoice job to dead-letter queue",
            extra={
                "invoice_id": job.invoice_id,
                "attempt": job.attempt,
                "error_code": error_code,
            },
        )
        return WorkerProcessOutcome(
            invoice_id=job.invoice_id,
            status="DEAD_LETTERED",
            final_invoice_status="REQUIRES_APPROVAL" if update_sql_status else None,
            attempt=job.attempt,
            error_code=error_code,
        )

    async def process_job(self, job: InvoiceQueueJob) -> WorkerProcessOutcome:
        """Execute the full verified processing lifecycle for a single dequeued invoice job."""
        safe_req_id = (
            job.request_id.strip()
            if isinstance(job.request_id, str)
            and _SAFE_REQUEST_ID_PATTERN.match(job.request_id.strip())
            else ""
        )
        ctx_token = request_id_ctx.set(safe_req_id)
        try:
            # 1. Verify SQL Invoice exists and is in an eligible entry state (UPLOADED / EXTRACTING)
            async with self._session_factory() as session:
                inv_repo = InvoiceRepository(session)
                invoice = await inv_repo.get_by_id(job.invoice_id, include_relations=False)
                if invoice is None:
                    await self._queue.enqueue_dead_letter(job, reason="missing_invoice_record")
                    logger.warning(
                        "Skipped job for nonexistent invoice record",
                        extra={"invoice_id": job.invoice_id},
                    )
                    return WorkerProcessOutcome(
                        invoice_id=job.invoice_id,
                        status="SKIPPED_MISSING_INVOICE",
                        attempt=job.attempt,
                        error_code="MISSING_INVOICE",
                    )

                prev_status = invoice.status
                recorded_blob_raw_url = invoice.blob_raw_url
                if prev_status not in ALLOWED_WORKER_ENTRY_STATUSES:
                    logger.info(
                        "Skipped job because invoice is already past intake state",
                        extra={"invoice_id": job.invoice_id, "current_status": prev_status},
                    )
                    return WorkerProcessOutcome(
                        invoice_id=job.invoice_id,
                        status="SKIPPED_INVALID_STATE",
                        final_invoice_status=prev_status,
                        attempt=job.attempt,
                    )

                if prev_status != "EXTRACTING":
                    await inv_repo.update_status(job.invoice_id, "EXTRACTING")

            if prev_status != "EXTRACTING":
                await self._audit.record(
                    invoice_id=job.invoice_id,
                    user_id=self._worker_id,
                    action_type=AuditActionType.STATUS_TRANSITION,
                    field_name="status",
                    previous_value=prev_status,
                    new_value="EXTRACTING",
                    comment=f"Worker picked job (attempt={job.attempt})",
                    request_id=safe_req_id or None,
                )

            # 2. Cross-invoice blob-swap guard (CWE-639): blob_name MUST match job.invoice_id and SQL blob_raw_url
            expected_prefix = f"raw-invoices/{job.invoice_id}/"
            if not job.blob_name.startswith(expected_prefix) or (
                recorded_blob_raw_url is not None
                and not recorded_blob_raw_url.endswith(f"/{job.blob_name}")
            ):
                return await self._escalate_and_dead_letter(
                    job,
                    reason="cross_invoice_blob_path_mismatch",
                    error_code="BLOB_PATH_MISMATCH",
                )

            # 3. Download WORM Blob + verify SHA-256 metadata integrity & queue FileHash parity (CWE-354)
            try:
                raw_bytes = await asyncio.to_thread(self._blob.download_blob, job.blob_name)
                stored_meta = await asyncio.to_thread(self._blob.get_blob_metadata, job.blob_name)
                verified_meta = verify_blob_metadata_integrity(raw_bytes, stored_meta)
                if not hmac.compare_digest(verified_meta.file_hash, job.file_hash):
                    raise BlobMetadataError(
                        "Queue FileHash does not match stored WORM blob FileHash"
                    )
            except (BlobNotFoundError, BlobMetadataError):
                return await self._escalate_and_dead_letter(
                    job,
                    reason="blob_integrity_or_missing_file",
                    error_code="INTEGRITY_MISMATCH",
                )
            except BlobStorageError as exc:
                return await self._handle_transient_failure(
                    job, error_code="BLOB_STORAGE_ERROR", exc_type=type(exc).__name__
                )

            # 4. Execute pluggable pipeline under bounded execution timeout (CWE-400)
            context = PipelineContext(
                job=job,
                raw_bytes=raw_bytes,
                verified_file_hash=verified_meta.file_hash,
            )
            try:
                raw_result = await asyncio.wait_for(
                    self._pipeline.execute(context),
                    timeout=self._job_timeout_seconds,
                )
                result = _validate_pipeline_result(raw_result)
            except PipelineStatusViolationError:
                return await self._escalate_and_dead_letter(
                    job,
                    reason="forbidden_pipeline_target_status",
                    error_code="PIPELINE_STATUS_VIOLATION",
                )
            except TimeoutError:
                return await self._handle_transient_failure(
                    job, error_code="JOB_TIMEOUT", exc_type="TimeoutError"
                )
            except Exception as exc:
                return await self._handle_transient_failure(
                    job, error_code="PIPELINE_ERROR", exc_type=type(exc).__name__
                )

            # 5. Optionally store immutable extraction JSON in WORM Blob (idempotent on retry)
            blob_json_url: str | None = None
            if result.extraction_payload is not None:
                try:
                    json_upload = await asyncio.to_thread(
                        self._blob.upload_extraction_json,
                        job.invoice_id,
                        result.extraction_payload,
                        vendor_id=job.vendor_id,
                        metadata={"InvoiceID": job.invoice_id},
                    )
                    blob_json_url = json_upload.blob_url
                except BlobAlreadyExistsError:
                    json_blob_name = build_extraction_json_blob_name(job.invoice_id)
                    blob_json_url = (
                        f"{self._blob.account_url}{self._blob.container_name}/{json_blob_name}"
                    )
                except BlobStorageError as exc:
                    return await self._handle_transient_failure(
                        job,
                        error_code="EXTRACTION_JSON_UPLOAD_ERROR",
                        exc_type=type(exc).__name__,
                    )

            # 6. Persist final status, confidence, and blob_json_url in SQL + immutable AuditLog
            update_fields: dict[str, Any] = {"status": result.target_status}
            if result.confidence_macro_avg is not None:
                update_fields["confidence_macro_avg"] = result.confidence_macro_avg
            if blob_json_url is not None:
                update_fields["blob_json_url"] = blob_json_url

            async with self._session_factory() as session:
                await InvoiceRepository(session).update_fields(job.invoice_id, **update_fields)

            await self._audit.record(
                invoice_id=job.invoice_id,
                user_id=self._worker_id,
                action_type=AuditActionType.EXTRACTION,
                field_name="status",
                previous_value="EXTRACTING",
                new_value=result.target_status,
                comment=result.summary_comment,
                request_id=safe_req_id or None,
            )

            logger.info(
                "Completed background invoice job",
                extra={
                    "invoice_id": job.invoice_id,
                    "final_status": result.target_status,
                    "attempt": job.attempt,
                },
            )
            return WorkerProcessOutcome(
                invoice_id=job.invoice_id,
                status="COMPLETED",
                final_invoice_status=result.target_status,
                attempt=job.attempt,
            )
        finally:
            request_id_ctx.reset(ctx_token)

    async def _handle_transient_failure(
        self,
        job: InvoiceQueueJob,
        *,
        error_code: str,
        exc_type: str,
    ) -> WorkerProcessOutcome:
        """Re-enqueue job up to max_retries; escalate & dead-letter once attempts are exhausted."""
        if job.attempt < self._max_retries:
            retry_job = job.model_copy(update={"attempt": job.attempt + 1})
            await self._queue.enqueue(retry_job)
            logger.warning(
                "Re-enqueued invoice job after transient failure",
                extra={
                    "invoice_id": job.invoice_id,
                    "attempt": job.attempt,
                    "next_attempt": retry_job.attempt,
                    "error_code": error_code,
                    "error_type": exc_type,
                },
            )
            return WorkerProcessOutcome(
                invoice_id=job.invoice_id,
                status="RETRIED",
                final_invoice_status="EXTRACTING",
                attempt=job.attempt,
                error_code=error_code,
            )

        return await self._escalate_and_dead_letter(
            job,
            reason=f"retries_exhausted:{error_code}:{exc_type}",
            error_code=error_code,
        )

    async def process_next_job(self, *, dequeue_timeout_seconds: int = 0) -> WorkerProcessOutcome:
        """Pop and process a single job from Redis (non-blocking by default)."""
        try:
            job = await self._queue.dequeue(timeout_seconds=dequeue_timeout_seconds)
        except RedisJobPayloadError:
            logger.warning("Quarantined poison-pill payload from invoice queue")
            return WorkerProcessOutcome(
                invoice_id=None,
                status="POISON_PILL_DLQ",
                error_code="INVALID_JOB_PAYLOAD",
            )

        if job is None:
            return WorkerProcessOutcome(invoice_id=None, status="SKIPPED_EMPTY")

        return await self.process_job(job)

    async def run_loop(
        self,
        *,
        max_jobs: int | None = None,
        poll_timeout_seconds: int = 1,
        stop_event: asyncio.Event | None = None,
    ) -> list[WorkerProcessOutcome]:
        """
        Continuously poll Redis and process jobs until ``stop_event`` is set or ``max_jobs`` reached.
        """
        outcomes: list[WorkerProcessOutcome] = []
        processed_count = 0

        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if max_jobs is not None and processed_count >= max_jobs:
                break

            outcome = await self.process_next_job(dequeue_timeout_seconds=poll_timeout_seconds)
            if outcome.status == "SKIPPED_EMPTY":
                if max_jobs is not None:
                    break
                if poll_timeout_seconds == 0:
                    await asyncio.sleep(0.05)
                continue

            outcomes.append(outcome)
            processed_count += 1

        return outcomes
