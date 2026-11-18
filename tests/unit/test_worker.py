"""
Unit, Integration, and Security Tests for Background Worker Skeleton (P5-3).

Tests: CLAUDE.md §4.1, §4.2, §5, §8, LLD §4, §6.2, CWE-209, CWE-354, CWE-400, CWE-532, CWE-863
"""

import asyncio
import hashlib
import logging
import uuid
from decimal import Decimal
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from src.core.logging import request_id_ctx
from src.core.redis_client import (
    DEFAULT_INVOICE_QUEUE_KEY,
    InvoiceQueueJob,
    RedisJobQueueClient,
)
from src.database.models import Base, Invoice, Vendor
from src.database.repositories import (
    AuditLogRepository,
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory
from src.services.worker import (
    ALLOWED_PIPELINE_TARGET_STATUSES,
    DefaultSkeletonPipeline,
    InvoiceBackgroundWorker,
    PipelineContext,
    PipelineResult,
)
from src.storage.blob_client import InMemoryWORMBlobClient


async def _setup_worker_fixture():
    """Create isolated offline SQLite DB, WORM Blob client, and FakeRedis queue client."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    async with session_factory() as session:
        await VendorRepository(session).create(
            Vendor(
                vendor_tax_id="US-12-3456789",
                vendor_id="VEND-1001",
                vendor_name="Acme Technologies Inc.",
                country_code="US",
                date_format_locale="MM/DD/YYYY",
                default_currency="USD",
                tax_scheme="US_SALES_TAX",
                is_active=True,
            )
        )

    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    queue_client = RedisJobQueueClient(fake_redis)
    return engine, session_factory, blob_client, fake_redis, queue_client


async def _seed_uploaded_invoice(
    session_factory,
    blob_client: InMemoryWORMBlobClient,
    queue_client: RedisJobQueueClient,
    *,
    payload: bytes = b"%PDF-1.4 Synthetic Worker Invoice",
    status: str = "UPLOADED",
    request_id: str = "req-worker-001",
    enqueue: bool = True,
    override_job_hash: str | None = None,
) -> tuple[str, InvoiceQueueJob]:
    """Upload raw WORM blob, persist SQL Invoice, and optionally enqueue Redis job."""
    inv_id = str(uuid.uuid4())
    upload_res = blob_client.upload_raw_invoice(
        invoice_id=inv_id,
        filename="invoice.pdf",
        data=payload,
        content_type="application/pdf",
        vendor_id="VEND-1001",
    )
    async with session_factory() as session:
        await InvoiceRepository(session).create(
            Invoice(
                invoice_id=inv_id,
                vendor_tax_id="US-12-3456789",
                vendor_name="Acme Technologies Inc.",
                invoice_number=f"PENDING-{inv_id[:12]}",
                total_amount=Decimal("0.00"),
                currency="USD",
                status=status,
                composite_hash=compute_composite_hash(
                    "US-12-3456789", f"PENDING-{inv_id}", Decimal("0.00")
                ),
                blob_raw_url=upload_res.blob_url,
            )
        )

    job = InvoiceQueueJob(
        invoice_id=inv_id,
        blob_name=upload_res.blob_name,
        blob_url=upload_res.blob_url,
        file_hash=override_job_hash or upload_res.sha256_hash,
        filename="invoice.pdf",
        detected_mime="application/pdf",
        vendor_id="VEND-1001",
        uploaded_by="demo-oid-sarah-clerk",
        request_id=request_id,
        enqueued_at="2026-11-18T11:30:00Z",
    )
    if enqueue:
        await queue_client.enqueue(job)
    return inv_id, job


def test_worker_picks_job_from_redis_runs_skeleton_pipeline_updates_sql_and_writes_audit() -> None:
    """Verify worker dequeues job, transitions UPLOADED->EXTRACTING->REQUIRES_REVIEW, and logs request_id."""

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            inv_id, _ = await _seed_uploaded_invoice(sf, blob, queue, request_id="req-trace-999")
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=DefaultSkeletonPipeline(),
            )

            assert request_id_ctx.get() == ""
            outcome = await worker.process_next_job(dequeue_timeout_seconds=0)
            assert outcome.status == "COMPLETED"
            assert outcome.invoice_id == inv_id
            assert outcome.final_invoice_status == "REQUIRES_REVIEW"
            # Context variable MUST be cleanly reset after job completion (zero cross-job leak)
            assert request_id_ctx.get() == ""

            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "REQUIRES_REVIEW"

                logs = await AuditLogRepository(session).get_by_invoice_id(inv_id)
                assert len(logs) == 2
                assert logs[0].action_type == "STATUS_TRANSITION"
                assert logs[0].previous_value == "UPLOADED"
                assert logs[0].new_value == "EXTRACTING"
                assert "req-trace-999" in (logs[0].comment or "")

                assert logs[1].action_type == "EXTRACTION"
                assert logs[1].previous_value == "EXTRACTING"
                assert logs[1].new_value == "REQUIRES_REVIEW"
                assert "req-trace-999" in (logs[1].comment or "")
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_executes_custom_pipeline_stores_extraction_json_worm_blob_and_updates_confidence() -> (
    None
):
    """Verify worker persists extraction JSON to WORM Blob and writes confidence_macro_avg & blob_json_url."""

    class _StubValidatedPipeline:
        async def execute(self, context: PipelineContext) -> PipelineResult:
            assert context.raw_bytes.startswith(b"%PDF-1.4")
            return PipelineResult(
                target_status="VALIDATED",
                confidence_macro_avg=Decimal("96.50"),
                extraction_payload={"invoice_number": "INV-2026-1001", "total_amount": "1350.00"},
                summary_comment="All deterministic rules passed at 96.50% confidence",
            )

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            inv_id, _ = await _seed_uploaded_invoice(sf, blob, queue)
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=_StubValidatedPipeline(),
            )
            outcome = await worker.process_next_job()
            assert outcome.status == "COMPLETED"
            assert outcome.final_invoice_status == "VALIDATED"

            json_blob_name = f"json-extractions/{inv_id}/extraction.json"
            assert blob.blob_exists(json_blob_name) is True

            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "VALIDATED"
                assert inv.confidence_macro_avg == Decimal("96.50")
                assert inv.blob_json_url is not None and json_blob_name in inv.blob_json_url
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_blocks_unauthorized_self_approval_status_from_pipeline() -> None:
    """Verify worker hard-blocks APPROVED_CLERK/APPROVED_MANAGER/STAGED_FOR_EXPORT from pipeline (CLAUDE.md §8/CWE-863)."""

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            for forbidden_status in (
                "APPROVED_CLERK",
                "APPROVED_MANAGER",
                "STAGED_FOR_EXPORT",
                "HACKED",
            ):
                assert forbidden_status not in ALLOWED_PIPELINE_TARGET_STATUSES

                class _RoguePipeline:
                    def __init__(self, target: str) -> None:
                        self._target = target

                    async def execute(self, context: PipelineContext) -> PipelineResult:
                        return PipelineResult(target_status=self._target)

                inv_id, _ = await _seed_uploaded_invoice(sf, blob, queue)
                worker = InvoiceBackgroundWorker(
                    queue_client=queue,
                    blob_client=blob,
                    session_factory=sf,
                    pipeline=_RoguePipeline(forbidden_status),
                )
                outcome = await worker.process_next_job()
                assert outcome.status == "DEAD_LETTERED"
                assert outcome.error_code == "PIPELINE_STATUS_VIOLATION"

                async with sf() as session:
                    inv = await InvoiceRepository(session).get_by_id(inv_id)
                    assert inv is not None
                    assert inv.status == "REQUIRES_APPROVAL"
                    assert inv.status != forbidden_status

            assert await queue.dlq_depth() == 4
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_rejects_file_hash_mismatch_and_quarantines_tampered_job() -> None:
    """Verify worker detects WORM Blob vs queue FileHash tampering before running pipeline (CWE-354)."""

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            spoofed_hash = hashlib.sha256(b"different-tampered-bytes").hexdigest()
            inv_id, _ = await _seed_uploaded_invoice(
                sf, blob, queue, override_job_hash=spoofed_hash
            )
            mock_pipeline = AsyncMock()
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=mock_pipeline,
            )

            outcome = await worker.process_next_job()
            assert outcome.status == "DEAD_LETTERED"
            assert outcome.error_code == "INTEGRITY_MISMATCH"
            mock_pipeline.execute.assert_not_awaited()
            assert await queue.dlq_depth() == 1

            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "REQUIRES_APPROVAL"
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_retries_transient_failures_up_to_max_retries_then_dead_letters_and_escalates() -> (
    None
):
    """Verify transient errors re-enqueue with incremented attempt until max_retries, then escalate & DLQ."""

    class _AlwaysFailingPipeline:
        async def execute(self, context: PipelineContext) -> PipelineResult:
            raise RuntimeError("Transient AOAI 429 rate limit")

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            inv_id, _ = await _seed_uploaded_invoice(sf, blob, queue)
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=_AlwaysFailingPipeline(),
                max_retries=2,
            )

            # Attempt 0 -> RETRIED (attempt becomes 1)
            r0 = await worker.process_next_job()
            assert r0.status == "RETRIED" and r0.attempt == 0
            assert await queue.queue_depth() == 1

            # Attempt 1 -> RETRIED (attempt becomes 2)
            r1 = await worker.process_next_job()
            assert r1.status == "RETRIED" and r1.attempt == 1
            assert await queue.queue_depth() == 1

            # Attempt 2 -> Exhausted -> DEAD_LETTERED + REQUIRES_APPROVAL
            r2 = await worker.process_next_job()
            assert r2.status == "DEAD_LETTERED" and r2.attempt == 2
            assert await queue.queue_depth() == 0
            assert await queue.dlq_depth() == 1

            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "REQUIRES_APPROVAL"
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_enforces_per_job_timeout_and_recovers_gracefully() -> None:
    """Verify hung pipelines are aborted by job_timeout_seconds and routed to retry/DLQ (CWE-400)."""

    class _HangingPipeline:
        async def execute(self, context: PipelineContext) -> PipelineResult:
            await asyncio.sleep(5.0)
            return PipelineResult(target_status="VALIDATED")

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            inv_id, _ = await _seed_uploaded_invoice(sf, blob, queue)
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=_HangingPipeline(),
                max_retries=0,
                job_timeout_seconds=0.05,
            )
            outcome = await worker.process_next_job()
            assert outcome.status == "DEAD_LETTERED"
            assert outcome.error_code == "JOB_TIMEOUT"
            assert await queue.dlq_depth() == 1

            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "REQUIRES_APPROVAL"
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_skips_terminal_or_missing_invoices_and_survives_poison_pills() -> None:
    """Verify worker skips already-approved/validated invoices, handles missing SQL rows, and survives poison pills."""

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            mock_pipeline = AsyncMock()
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=mock_pipeline,
            )

            # 1. Empty queue -> SKIPPED_EMPTY
            empty = await worker.process_next_job()
            assert empty.status == "SKIPPED_EMPTY"

            # 2. Already APPROVED_CLERK invoice -> SKIPPED_INVALID_STATE (never re-processed!)
            approved_id, _ = await _seed_uploaded_invoice(sf, blob, queue, status="APPROVED_CLERK")
            o_approved = await worker.process_next_job()
            assert o_approved.status == "SKIPPED_INVALID_STATE"
            mock_pipeline.execute.assert_not_awaited()
            async with sf() as session:
                inv = await InvoiceRepository(session).get_by_id(approved_id)
                assert inv is not None and inv.status == "APPROVED_CLERK"

            # 3. Job referencing nonexistent SQL invoice -> SKIPPED_MISSING_INVOICE + DLQ
            orphan_job = InvoiceQueueJob(
                invoice_id="inv-does-not-exist",
                blob_name="raw-invoices/inv-does-not-exist/doc.pdf",
                blob_url="https://mockblob.blob.core.windows.net/raw-invoices-immutable/raw-invoices/inv-does-not-exist/doc.pdf",
                file_hash=hashlib.sha256(b"orphan").hexdigest(),
                filename="doc.pdf",
                detected_mime="application/pdf",
                vendor_id="UNKNOWN",
                uploaded_by="demo-oid-sarah-clerk",
                enqueued_at="2026-11-18T11:30:00Z",
            )
            await queue.enqueue(orphan_job)
            o_missing = await worker.process_next_job()
            assert o_missing.status == "SKIPPED_MISSING_INVOICE"

            # 4. Poison pill in Redis -> POISON_PILL_DLQ
            await fake_redis.rpush(DEFAULT_INVOICE_QUEUE_KEY, "{corrupt-json")
            o_poison = await worker.process_next_job()
            assert o_poison.status == "POISON_PILL_DLQ"
            assert await queue.dlq_depth() == 2
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_run_loop_drains_queue_respects_max_jobs_and_never_logs_pii(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify run_loop honors max_jobs & stop_event while keeping raw invoice PII out of logs (CWE-532)."""

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            secret_bytes = b"%PDF-1.4 IBAN DE89370400440532013000 TAX US-12-3456789"
            for _ in range(3):
                await _seed_uploaded_invoice(sf, blob, queue, payload=secret_bytes)

            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
            )

            with caplog.at_level(logging.DEBUG, logger="ap.services.worker"):
                batch = await worker.run_loop(max_jobs=2, poll_timeout_seconds=0)
            assert len(batch) == 2
            assert all(o.status == "COMPLETED" for o in batch)
            assert await queue.queue_depth() == 1

            # Stop event halts loop cleanly
            stop_event = asyncio.Event()
            stop_event.set()
            stopped = await worker.run_loop(stop_event=stop_event, poll_timeout_seconds=0)
            assert stopped == []

            combined_logs = " ".join(r.getMessage() for r in caplog.records)
            assert "DE89370400440532013000" not in combined_logs
            assert "US-12-3456789" not in combined_logs
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())


def test_worker_blocks_cross_invoice_blob_swap_invalid_confidence_and_enforces_layering() -> None:
    """Verify cross-invoice blob swapping fails closed, invalid confidence fails, and zero HTTP imports exist."""
    from pathlib import Path

    # CLAUDE.md §4.2: Services MUST NOT talk HTTP directly to external systems
    worker_src = Path("src/services/worker.py").read_text(encoding="utf-8")
    for forbidden_http in ("import httpx", "import requests", "import aiohttp", "urllib.request"):
        assert forbidden_http not in worker_src

    async def _run() -> None:
        engine, sf, blob, fake_redis, queue = await _setup_worker_fixture()
        try:
            inv_a, job_a = await _seed_uploaded_invoice(sf, blob, queue, enqueue=False)
            inv_b, job_b = await _seed_uploaded_invoice(sf, blob, queue, enqueue=False)

            # Craft tampered queue job referencing inv_a but pointing to inv_b's blob_name (CWE-639)
            swapped_job = job_a.model_copy(update={"blob_name": job_b.blob_name})
            await queue.enqueue(swapped_job)

            mock_pipeline = AsyncMock()
            worker = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=mock_pipeline,
            )
            outcome = await worker.process_next_job()
            assert outcome.status == "DEAD_LETTERED"
            assert outcome.error_code == "BLOB_PATH_MISMATCH"
            mock_pipeline.execute.assert_not_awaited()

            # Pipeline returning out-of-range confidence (150.00) must be rejected (retried/DLQ'd)
            class _BadConfidencePipeline:
                async def execute(self, context: PipelineContext) -> PipelineResult:
                    return PipelineResult(
                        target_status="VALIDATED",
                        confidence_macro_avg=Decimal("150.00"),
                    )

            await queue.enqueue(job_b)
            worker_bad_conf = InvoiceBackgroundWorker(
                queue_client=queue,
                blob_client=blob,
                session_factory=sf,
                pipeline=_BadConfidencePipeline(),
                max_retries=0,
            )
            bad_out = await worker_bad_conf.process_next_job()
            assert bad_out.status == "DEAD_LETTERED"
            assert bad_out.error_code == "PIPELINE_ERROR"
        finally:
            await fake_redis.aclose()
            await engine.dispose()

    asyncio.run(_run())
