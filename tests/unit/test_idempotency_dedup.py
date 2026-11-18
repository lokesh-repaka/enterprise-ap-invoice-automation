"""
Unit, Integration, and Security Tests for Upload Idempotency Key Deduplication (P5-5).

Tests: LLD §6.1, CLAUDE.md §16.6, CWE-74, CWE-113, CWE-209, CWE-345, CWE-362, CWE-525, CWE-636, CWE-639
"""

import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import fitz
import pytest
from fastapi.testclient import TestClient
from redis.exceptions import RedisError

from src.api.invoices import (
    INVOICE_QUEUE_KEY,
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
)
from src.api.main import app
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.core.redis_client import compute_idempotency_key
from src.database.models import Base
from src.database.repositories import InvoiceRepository
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import BlobStorageError, InMemoryWORMBlobClient


def _make_pdf(text: str = "Idempotent Invoice #1001") -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    try:
        return doc.tobytes()
    finally:
        doc.close()


def _auth_headers(username: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    settings = Settings(APP_ENV="test", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
    token = issue_demo_token(username, settings=settings)
    headers = {"Authorization": f"Bearer {token}"}
    if extra:
        headers.update(extra)
    return headers


@pytest.fixture
def dedup_env(monkeypatch: pytest.MonkeyPatch):
    """Provide isolated offline SQLite, WORM Blob, FakeRedis, and demo auth for dedup testing."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    session_factory = create_session_factory(engine)

    async def _init() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init())

    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis

    try:
        yield {
            "client": TestClient(app),
            "session_factory": session_factory,
            "blob_client": blob_client,
            "redis": fake_redis,
        }
    finally:
        app.dependency_overrides.clear()
        reset_demo_keypair_cache()
        get_settings.cache_clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())


def test_resubmitting_identical_file_returns_200_with_existing_invoice_id_and_zero_duplicate_writes(
    dedup_env: dict,
) -> None:
    """Verify LLD §6.1: re-submitting identical bytes returns HTTP 200 with existing InvoiceID & zero dupes."""
    client: TestClient = dedup_env["client"]
    fake_redis = dedup_env["redis"]
    session_factory = dedup_env["session_factory"]
    headers = _auth_headers("sarah.clerk")
    pdf_bytes = _make_pdf("Duplicate Submission Invoice #500")
    expected_idem = compute_idempotency_key(pdf_bytes, "demo-oid-sarah-clerk")

    # 1. First upload -> 202 Accepted
    first = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("INV-500.pdf", pdf_bytes, "application/pdf")},
    )
    assert first.status_code == 202, first.text
    first_body = first.json()
    assert first_body["deduplicated"] is False
    assert first_body["queued"] is True
    assert first_body["idempotency_key"] == expected_idem
    assert first.headers.get("X-Idempotency-Replayed") is None

    # 2. Re-submit exact same bytes (even with a different filename) -> 200 OK, same InvoiceID!
    second = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("INV-500-retry.pdf", pdf_bytes, "application/pdf")},
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["invoice_id"] == first_body["invoice_id"]
    assert second_body["blob_url"] == first_body["blob_url"]
    assert second_body["file_hash"] == hashlib.sha256(pdf_bytes).hexdigest()
    assert second_body["deduplicated"] is True
    assert second_body["queued"] is False
    assert second_body["idempotency_key"] == expected_idem
    assert second.headers["Location"] == f"/api/v1/invoices/{first_body['invoice_id']}"
    assert second.headers["Cache-Control"] == "no-store"
    assert second.headers["X-Idempotency-Replayed"] == "true"

    # Zero duplicate Redis queue jobs and zero duplicate SQL rows
    assert asyncio.run(fake_redis.llen(INVOICE_QUEUE_KEY)) == 1

    async def _count_invoices() -> int:
        async with session_factory() as session:
            return len(await InvoiceRepository(session).list_by_status())

    assert asyncio.run(_count_invoices()) == 1


def test_deduplicated_upload_reflects_live_sql_status_after_worker_progression(
    dedup_env: dict,
) -> None:
    """Verify duplicate upload returns live SQL status (e.g. VALIDATED) once worker updates invoice."""
    client: TestClient = dedup_env["client"]
    session_factory = dedup_env["session_factory"]
    headers = _auth_headers("sarah.clerk")
    pdf_bytes = _make_pdf("Worker Progressed Invoice #501")

    first = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("INV-501.pdf", pdf_bytes, "application/pdf")},
    )
    assert first.status_code == 202
    inv_id = first.json()["invoice_id"]

    async def _advance_status() -> None:
        async with session_factory() as session:
            await InvoiceRepository(session).update_status(inv_id, "VALIDATED")

    asyncio.run(_advance_status())

    replay = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("INV-501.pdf", pdf_bytes, "application/pdf")},
    )
    assert replay.status_code == 200
    assert replay.json()["invoice_id"] == inv_id
    assert replay.json()["status"] == "VALIDATED"
    assert replay.json()["deduplicated"] is True


def test_explicit_idempotency_key_header_deduplicates_matching_file_and_returns_409_on_payload_mismatch(
    dedup_env: dict,
) -> None:
    """Verify explicit Idempotency-Key replays matching payload (200) and rejects different bytes (409: CWE-345)."""
    client: TestClient = dedup_env["client"]
    fake_redis = dedup_env["redis"]
    headers = _auth_headers("sarah.clerk", {"Idempotency-Key": "client-retry-batch-42"})
    pdf_a = _make_pdf("Invoice Payload Alpha")
    pdf_b = _make_pdf("Invoice Payload Beta (Different)")

    r1 = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
    )
    assert r1.status_code == 202

    # Same header + same bytes -> 200 OK replay
    r2 = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
    )
    assert r2.status_code == 200
    assert r2.json()["invoice_id"] == r1.json()["invoice_id"]
    assert r2.json()["deduplicated"] is True

    # Same header + DIFFERENT bytes -> 409 Conflict (blocks silent wrong-invoice return!)
    r3 = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("beta.pdf", pdf_b, "application/pdf")},
    )
    assert r3.status_code == 409
    assert "Idempotency-Key" in r3.json()["detail"]
    assert asyncio.run(fake_redis.llen(INVOICE_QUEUE_KEY)) == 1


def test_idempotency_is_isolated_across_different_clerks(dedup_env: dict) -> None:
    """Verify identical files or identical Idempotency-Key headers across distinct actors never collide (CWE-639)."""
    client: TestClient = dedup_env["client"]
    pdf_bytes = _make_pdf("Shared Vendor Invoice #700")

    r_sarah = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("sarah.clerk", {"Idempotency-Key": "shared-client-key"}),
        files={"file": ("inv700.pdf", pdf_bytes, "application/pdf")},
    )
    r_michael = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("michael.manager", {"Idempotency-Key": "shared-client-key"}),
        files={"file": ("inv700.pdf", pdf_bytes, "application/pdf")},
    )
    assert r_sarah.status_code == 202
    assert r_michael.status_code == 202
    assert r_sarah.json()["invoice_id"] != r_michael.json()["invoice_id"]

    # Content-derived (no header) isolation across clerks as well
    pdf_bytes_2 = _make_pdf("Shared Vendor Invoice #701")
    c_sarah = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("sarah.clerk"),
        files={"file": ("inv701.pdf", pdf_bytes_2, "application/pdf")},
    )
    c_michael = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("michael.manager"),
        files={"file": ("inv701.pdf", pdf_bytes_2, "application/pdf")},
    )
    assert c_sarah.status_code == 202
    assert c_michael.status_code == 202
    assert c_sarah.json()["invoice_id"] != c_michael.json()["invoice_id"]


def test_failed_storage_write_releases_idempotency_lock_allowing_clean_retry(
    dedup_env: dict,
) -> None:
    """Verify transient Blob failure rolls back the claimed idempotency lock so immediate retries succeed."""
    client: TestClient = dedup_env["client"]
    headers = _auth_headers("sarah.clerk")
    pdf_bytes = _make_pdf("Transient Failure Retry Invoice #800")

    broken_blob = MagicMock()
    broken_blob.upload_raw_invoice.side_effect = BlobStorageError("temporary outage")
    app.dependency_overrides[get_upload_blob_client] = lambda: broken_blob

    fail_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("inv800.pdf", pdf_bytes, "application/pdf")},
    )
    assert fail_resp.status_code == 503

    # Storage recovers -> immediate retry MUST succeed with 202 Accepted (not ghost-deduped!)
    app.dependency_overrides[get_upload_blob_client] = lambda: dedup_env["blob_client"]
    retry_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("inv800.pdf", pdf_bytes, "application/pdf")},
    )
    assert retry_resp.status_code == 202
    assert retry_resp.json()["deduplicated"] is False


def test_malformed_idempotency_key_header_fails_422_and_redis_claim_failure_fails_503(
    dedup_env: dict,
) -> None:
    """Verify invalid Idempotency-Key headers fail with 422 (CWE-74/113) and Redis outage fails closed 503."""
    client: TestClient = dedup_env["client"]
    blob_client: InMemoryWORMBlobClient = dedup_env["blob_client"]
    pdf_bytes = _make_pdf("Header Guard Invoice #900")

    for bad_key in ("   ", "has space", "x" * 129):
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=_auth_headers("sarah.clerk", {"Idempotency-Key": bad_key}),
            files={"file": ("inv900.pdf", pdf_bytes, "application/pdf")},
        )
        assert resp.status_code == 422

    # Redis outage during claim_idempotency_key -> 503 fail-closed BEFORE any WORM Blob write
    broken_redis = AsyncMock()
    broken_redis.set.side_effect = RedisError("rediss://:secret-pw@host:6380")
    app.dependency_overrides[get_upload_redis_client] = lambda: broken_redis

    outage_resp = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("sarah.clerk"),
        files={"file": ("inv900.pdf", pdf_bytes, "application/pdf")},
    )
    assert outage_resp.status_code == 503
    assert "secret-pw" not in outage_resp.json()["detail"]
    assert len(blob_client._blobs) == 0


def test_explicit_idempotency_key_conflict_on_vendor_mismatch_and_in_flight_replay(
    dedup_env: dict,
) -> None:
    """Verify conflicting vendor_id on explicit Idempotency-Key returns 409 and in-flight race returns 200."""
    from src.core.redis_client import RedisJobQueueClient
    from src.database.models import Vendor
    from src.database.repositories import VendorRepository

    client: TestClient = dedup_env["client"]
    session_factory = dedup_env["session_factory"]
    fake_redis = dedup_env["redis"]

    async def _seed_two_vendors() -> None:
        async with session_factory() as session:
            repo = VendorRepository(session)
            for tax_id, vid, name in (
                ("US-11-1111111", "VEND-A", "Vendor Alpha LLC"),
                ("US-22-2222222", "VEND-B", "Vendor Beta LLC"),
            ):
                await repo.create(
                    Vendor(
                        vendor_tax_id=tax_id,
                        vendor_id=vid,
                        vendor_name=name,
                        country_code="US",
                        date_format_locale="MM/DD/YYYY",
                        default_currency="USD",
                        tax_scheme="US_SALES_TAX",
                        is_active=True,
                    )
                )

    asyncio.run(_seed_two_vendors())

    pdf_bytes = _make_pdf("Vendor Conflict Invoice #950")
    headers = _auth_headers("sarah.clerk", {"Idempotency-Key": "vendor-bound-key"})

    first = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        data={"vendor_id": "VEND-A"},
        files={"file": ("v_a.pdf", pdf_bytes, "application/pdf")},
    )
    assert first.status_code == 202

    # Same Idempotency-Key + same bytes + DIFFERENT vendor_id -> 409 Conflict (CWE-345)
    conflict = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        data={"vendor_id": "VEND-B"},
        files={"file": ("v_b.pdf", pdf_bytes, "application/pdf")},
    )
    assert conflict.status_code == 409
    assert "vendor_id" in conflict.json()["detail"]

    # In-flight concurrent race: Redis claim already exists before SQL row commits -> clean 200 OK
    pdf_inflight = _make_pdf("In-Flight Race Invoice #951")
    inflight_key = compute_idempotency_key(pdf_inflight, "demo-oid-sarah-clerk")
    q_client = RedisJobQueueClient(fake_redis, queue_key=INVOICE_QUEUE_KEY)
    asyncio.run(
        q_client.claim_idempotency_key(
            inflight_key,
            "inv-inflight-winner",
            status="UPLOADED",
            file_hash=hashlib.sha256(pdf_inflight).hexdigest(),
        )
    )
    race_resp = client.post(
        "/api/v1/invoices/upload",
        headers=_auth_headers("sarah.clerk"),
        files={"file": ("inflight.pdf", pdf_inflight, "application/pdf")},
    )
    assert race_resp.status_code == 200
    assert race_resp.json()["invoice_id"] == "inv-inflight-winner"
    assert race_resp.json()["deduplicated"] is True
    assert race_resp.json()["queued"] is False
