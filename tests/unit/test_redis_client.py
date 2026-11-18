"""
Unit and Security Tests for Redis Job Queue & Idempotency Client (P5-2).

Tests: LLD §6.1, CLAUDE.md §4.1, §16.6, CWE-22, CWE-74, CWE-209, CWE-319, CWE-362, CWE-400, CWE-489, CWE-532, CWE-639
"""

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest
from redis.exceptions import RedisError

from src.core.config import Settings
from src.core.redis_client import (
    DEFAULT_DEAD_LETTER_QUEUE_KEY,
    DEFAULT_INVOICE_QUEUE_KEY,
    MAX_JOB_PAYLOAD_BYTES,
    IdempotencyRecord,
    InvoiceQueueJob,
    RedisJobPayloadError,
    RedisJobQueueClient,
    RedisQueueConfigurationError,
    RedisQueueError,
    compute_idempotency_key,
    get_redis_queue_client,
    hash_client_idempotency_key,
    reset_redis_queue_client_cache,
    validate_redis_url,
)


def _sample_job(invoice_id: str = "inv-001", **overrides) -> InvoiceQueueJob:
    """Build a valid canonical InvoiceQueueJob for offline testing."""
    data = {
        "invoice_id": invoice_id,
        "blob_name": f"raw-invoices/{invoice_id}/invoice.pdf",
        "blob_url": f"https://mockblob.blob.core.windows.net/raw-invoices-immutable/raw-invoices/{invoice_id}/invoice.pdf",
        "file_hash": hashlib.sha256(invoice_id.encode("utf-8")).hexdigest(),
        "filename": "invoice.pdf",
        "detected_mime": "application/pdf",
        "vendor_id": "VEND-1001",
        "uploaded_by": "demo-oid-sarah-clerk",
        "request_id": "req-queue-001",
        "enqueued_at": "2026-11-18T11:00:00Z",
    }
    data.update(overrides)
    return InvoiceQueueJob(**data)


def test_enqueue_and_dequeue_fifo_ordering_and_queue_depth() -> None:
    """Verify RedisJobQueueClient enforces strict FIFO ordering for both non-blocking and blocking dequeue."""

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            client = RedisJobQueueClient(fake)
            assert await client.ping() is True
            assert await client.queue_depth() == 0
            assert await client.dequeue(timeout_seconds=0) is None

            for idx in (1, 2, 3):
                depth = await client.enqueue(_sample_job(f"inv-fifo-{idx}"))
                assert depth == idx
            assert await client.queue_depth() == 3

            j1 = await client.dequeue(timeout_seconds=0)
            j2 = await client.dequeue(timeout_seconds=1)
            j3 = await client.dequeue(timeout_seconds=0)
            assert [j1.invoice_id, j2.invoice_id, j3.invoice_id] == [
                "inv-fifo-1",
                "inv-fifo-2",
                "inv-fifo-3",
            ]
            assert await client.queue_depth() == 0
            assert await client.dequeue(timeout_seconds=0) is None
        finally:
            await fake.aclose()

    asyncio.run(_run())


def test_idempotency_key_computation_follows_lld_sha256_and_actor_isolation() -> None:
    """Verify LLD §6.1 SHA256(file_bytes + clerk_id) formula and actor-scoped header hashing (CWE-74/639)."""
    raw_pdf = b"%PDF-1.4 Identical Invoice Bytes"
    clerk_a = "demo-oid-sarah-clerk"
    clerk_b = "demo-oid-michael-manager"

    key_a = compute_idempotency_key(raw_pdf, clerk_a)
    expected_a = hashlib.sha256(raw_pdf + clerk_a.encode("utf-8")).hexdigest()
    assert key_a == expected_a
    assert len(key_a) == 64

    # Different actors uploading identical bytes MUST NOT collide (CWE-639)
    key_b = compute_idempotency_key(raw_pdf, clerk_b)
    assert key_a != key_b

    # Empty bytes or blank clerk_id fail closed
    with pytest.raises(ValueError):
        compute_idempotency_key(b"", clerk_a)
    with pytest.raises(ValueError):
        compute_idempotency_key(raw_pdf, "   ")

    # Client-supplied Idempotency-Key header is actor-scoped & SHA-256 hashed (blocks Redis key injection)
    hdr_a = hash_client_idempotency_key("client-retry-key-42", clerk_id=clerk_a)
    hdr_b = hash_client_idempotency_key("client-retry-key-42", clerk_id=clerk_b)
    assert len(hdr_a) == 64
    assert hdr_a != hdr_b

    for bad_hdr in ("", "   ", "bad\r\nFLUSHALL", "x" * 129, "null\x00key"):
        with pytest.raises(ValueError):
            hash_client_idempotency_key(bad_hdr, clerk_id=clerk_a)


def test_atomic_idempotency_claim_prevents_concurrent_duplicate_processing() -> None:
    """Verify atomic SET NX EX guarantees exactly one winner under concurrent upload races (CWE-362)."""

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            client = RedisJobQueueClient(fake)
            idem_key = compute_idempotency_key(b"%PDF-1.4 race-test", "demo-oid-sarah-clerk")

            # Launch 10 concurrent claims for the exact same idempotency key
            results = await asyncio.gather(
                *[client.claim_idempotency_key(idem_key, f"inv-race-{i}") for i in range(10)]
            )

            winners = [rec for acquired, rec in results if acquired]
            losers = [rec for acquired, rec in results if not acquired]
            assert len(winners) == 1
            assert len(losers) == 9

            winning_id = winners[0].invoice_id
            assert all(rec.invoice_id == winning_id for _, rec in results)
            assert all(isinstance(rec, IdempotencyRecord) for _, rec in results)

            # Subsequent lookup returns the exact winning record
            fetched = await client.get_idempotency_record(idem_key)
            assert fetched is not None
            assert fetched.invoice_id == winning_id
            assert fetched.status == "UPLOADED"
        finally:
            await fake.aclose()

    asyncio.run(_run())


def test_idempotency_status_update_preserves_ttl_and_safe_release_checks_owner() -> None:
    """Verify status updates preserve TTL (KEEPTTL) and release_idempotency_key enforces owner match."""

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            client = RedisJobQueueClient(fake, idempotency_ttl_seconds=3600)
            idem_key = compute_idempotency_key(b"%PDF-1.4 ttl-test", "demo-oid-sarah-clerk")

            acquired, _ = await client.claim_idempotency_key(idem_key, "inv-owner-1")
            assert acquired is True

            # Wrong invoice_id cannot update or release another upload's lock
            assert (
                await client.update_idempotency_status(
                    idem_key, invoice_id="inv-wrong", status="VALIDATED"
                )
                is False
            )
            assert (
                await client.release_idempotency_key(idem_key, expected_invoice_id="inv-wrong")
                is False
            )

            # Matching owner updates status while keeping positive TTL
            assert (
                await client.update_idempotency_status(
                    idem_key, invoice_id="inv-owner-1", status="VALIDATED"
                )
                is True
            )
            updated = await client.get_idempotency_record(idem_key)
            assert updated is not None and updated.status == "VALIDATED"
            remaining_ttl = await fake.ttl(f"ap:idempotency:{idem_key}")
            assert 0 < remaining_ttl <= 3600

            # Matching owner can release lock cleanly on rollback
            assert (
                await client.release_idempotency_key(idem_key, expected_invoice_id="inv-owner-1")
                is True
            )
            assert await client.get_idempotency_record(idem_key) is None
        finally:
            await fake.aclose()

    asyncio.run(_run())


def test_poison_pill_payload_is_quarantined_to_dlq_without_crashing_worker() -> None:
    """Verify corrupted or schema-invalid queue messages are moved to DLQ and raise RedisJobPayloadError."""

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            client = RedisJobQueueClient(fake)
            # Inject poison pills + 1 valid job behind them
            await fake.rpush(DEFAULT_INVOICE_QUEUE_KEY, "{not-valid-json")
            await fake.rpush(
                DEFAULT_INVOICE_QUEUE_KEY,
                json.dumps({"invoice_id": "../traversal", "blob_name": "bad"}),
            )
            await client.enqueue(_sample_job("inv-healthy-after-poison"))

            with pytest.raises(RedisJobPayloadError):
                await client.dequeue(timeout_seconds=0)
            with pytest.raises(RedisJobPayloadError):
                await client.dequeue(timeout_seconds=0)

            assert await client.dlq_depth() == 2
            dlq_entries = await fake.lrange(DEFAULT_DEAD_LETTER_QUEUE_KEY, 0, -1)
            assert all("reason" in json.loads(item) for item in dlq_entries)

            # Next valid job still dequeues cleanly!
            healthy = await client.dequeue(timeout_seconds=0)
            assert healthy is not None
            assert healthy.invoice_id == "inv-healthy-after-poison"
        finally:
            await fake.aclose()

    asyncio.run(_run())


def test_enqueue_and_idempotency_reject_oversized_traversal_and_injection_inputs() -> None:
    """Verify oversized jobs, path-traversal blob names, and raw/injected Redis keys fail closed (CWE-22/74/400)."""

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            # Unsafe Redis queue key rejected at construction (CWE-74)
            with pytest.raises(ValueError, match="queue key"):
                RedisJobQueueClient(fake, queue_key="ap:queue\r\nFLUSHALL")

            client = RedisJobQueueClient(fake)

            # Traversal blob_name and malformed invoice_id rejected
            with pytest.raises(RedisJobPayloadError):
                await client.enqueue(_sample_job("inv-1", blob_name="../etc/passwd"))
            with pytest.raises(RedisJobPayloadError):
                await client.enqueue(_sample_job("../bad-id"))
            with pytest.raises(RedisJobPayloadError):
                await client.enqueue(_sample_job("inv-1", file_hash="not-a-sha256"))

            # Oversized payload (>64 KB) rejected before RPUSH (CWE-400)
            huge_job = _sample_job(
                "inv-huge", blob_url="https://x.test/" + "a" * MAX_JOB_PAYLOAD_BYTES
            )
            with pytest.raises(RedisJobPayloadError, match="size"):
                await client.enqueue(huge_job)

            # Unhashed / injected idempotency key rejected (must be 64-char SHA-256 hex)
            for bad_key in ("raw-key", "inv:1\r\nDEL *", "G" * 64):
                with pytest.raises(ValueError, match="idempotency_key"):
                    await client.claim_idempotency_key(bad_key, "inv-1")
        finally:
            await fake.aclose()

    asyncio.run(_run())


def test_factory_blocks_fake_redis_and_plaintext_redis_url_in_production_and_staging() -> None:
    """Verify USE_FAKE_REDIS=True and non-TLS redis:// URLs are hard-blocked outside dev/local/test (CWE-489/319)."""
    reset_redis_queue_client_cache()

    # Local dev with FakeRedis succeeds
    dev_client = get_redis_queue_client(Settings(APP_ENV="dev", USE_FAKE_REDIS=True))
    assert isinstance(dev_client, RedisJobQueueClient)

    # Staging/production MUST reject USE_FAKE_REDIS=True
    for blocked_env in ("staging", "production", "prod", "uat"):
        with pytest.raises(RedisQueueConfigurationError):
            get_redis_queue_client(Settings(APP_ENV=blocked_env, USE_FAKE_REDIS=True))

    # Staging/production MUST require TLS rediss:// (CWE-319)
    with pytest.raises(RedisQueueConfigurationError, match="TLS"):
        validate_redis_url("redis://ap-redis.redis.cache.windows.net:6379/0", app_env="production")
    with pytest.raises(RedisQueueConfigurationError, match="TLS"):
        get_redis_queue_client(
            Settings(
                APP_ENV="production",
                USE_FAKE_REDIS=False,
                REDIS_URL="redis://ap-redis.redis.cache.windows.net:6379/0",
            )
        )

    # CRLF injection in REDIS_URL rejected
    with pytest.raises(RedisQueueConfigurationError):
        validate_redis_url("rediss://host:6380/0\r\nFLUSHALL", app_env="production")

    # Production with valid TLS rediss:// constructs client lazily (zero network calls)
    prod_client = get_redis_queue_client(
        Settings(
            APP_ENV="production",
            USE_FAKE_REDIS=False,
            REDIS_URL="rediss://ap-redis.redis.cache.windows.net:6380/0",
        )
    )
    assert isinstance(prod_client, RedisJobQueueClient)
    reset_redis_queue_client_cache()


def test_redis_errors_wrap_cleanly_without_leaking_credentials_or_urls() -> None:
    """Verify Redis transport failures raise RedisQueueError with sanitized messages (CWE-209/532)."""

    async def _run() -> None:
        broken = AsyncMock()
        secret_err = RedisError("Connection refused to rediss://:super-secret-redis-pass@host:6380")
        broken.llen.return_value = 0
        broken.rpush.side_effect = secret_err
        broken.lpop.side_effect = secret_err
        broken.set.side_effect = secret_err

        client = RedisJobQueueClient(broken)
        idem_key = compute_idempotency_key(b"bytes", "clerk-1")

        with pytest.raises(RedisQueueError) as exc_enq:
            await client.enqueue(_sample_job("inv-err-1"))
        assert "super-secret-redis-pass" not in str(exc_enq.value)

        with pytest.raises(RedisQueueError) as exc_deq:
            await client.dequeue(timeout_seconds=0)
        assert "super-secret-redis-pass" not in str(exc_deq.value)

        with pytest.raises(RedisQueueError) as exc_claim:
            await client.claim_idempotency_key(idem_key, "inv-err-1")
        assert "super-secret-redis-pass" not in str(exc_claim.value)

    asyncio.run(_run())


def test_security_hardening_blocks_unsafe_blob_url_invalid_status_colon_collision_and_queue_overflow() -> (
    None
):
    """Verify URL scheme guard, status regex, null-delimited key hashing, queue capacity cap, and SQLite gate."""
    # Domain-separated client idempotency key prevents tuple boundary collisions (CWE-327)
    k1 = hash_client_idempotency_key("c", clerk_id="a:b")
    k2 = hash_client_idempotency_key("b:c", clerk_id="a")
    assert k1 != k2

    # USE_FAKE_REDIS=True paired with real Azure SQL (USE_LOCAL_SQLITE=False) must fail closed (CWE-489)
    reset_redis_queue_client_cache()
    with pytest.raises(RedisQueueConfigurationError):
        get_redis_queue_client(Settings(APP_ENV="dev", USE_FAKE_REDIS=True, USE_LOCAL_SQLITE=False))
    reset_redis_queue_client_cache()

    async def _run() -> None:
        fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            client = RedisJobQueueClient(fake)
            idem_key = compute_idempotency_key(b"status-test", "clerk-1")

            # Unsafe blob_url schemes blocked (CWE-20)
            for bad_url in ("file:///etc/passwd", "javascript:alert(1)", "http://evil.test/x"):
                with pytest.raises(RedisJobPayloadError, match="blob_url"):
                    await client.enqueue(_sample_job("inv-url", blob_url=bad_url))

            # Invalid workflow status strings blocked
            for bad_status in ("", "lowercase", "UPLOADED\r\nEVIL", "A" * 60):
                with pytest.raises(ValueError, match="status"):
                    await client.claim_idempotency_key(idem_key, "inv-st", status=bad_status)
        finally:
            await fake.aclose()

        # Queue depth capacity cap blocks unbounded memory flood (CWE-400)
        full_redis = AsyncMock()
        full_redis.llen.return_value = 100_000
        full_client = RedisJobQueueClient(full_redis)
        with pytest.raises(RedisQueueError, match="capacity"):
            await full_client.enqueue(_sample_job("inv-full"))

    asyncio.run(_run())
