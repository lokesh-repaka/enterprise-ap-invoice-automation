"""
End-to-End Offline Integration Test for Ingestion Dashboard UI -> FastAPI Backend (P11-2).

Tests: FR-01, BR-001, GAP-004, P11-2, CLAUDE.md §4.1, §12, §16.6
"""

import asyncio
import sqlite3
from decimal import Decimal
from pathlib import Path

import fakeredis.aioredis
import fitz
import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.invoices import (
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
)
from src.api.main import app
from src.core.config import get_settings
from src.core.demo_auth import reset_demo_keypair_cache
from src.database.models import Base, Vendor
from src.database.repositories import VendorRepository
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import InMemoryWORMBlobClient
from src.ui.api_client import APInvoiceAPIClient
from src.ui.ingestion_dashboard import (
    IngestionDashboardController,
    PendingUploadFile,
    summarize_batch,
)


class _TestClientBridgeTransport(httpx.BaseTransport):
    """Bridge synchronous httpx calls directly to FastAPI TestClient offline."""

    def __init__(self, test_client: TestClient) -> None:
        self._tc = test_client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path_with_query = str(request.url.raw_path.decode("ascii"))
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")
        }
        resp = self._tc.request(
            method=request.method,
            url=path_with_query,
            headers=headers,
            content=request.read(),
            follow_redirects=False,
        )
        return httpx.Response(
            status_code=resp.status_code,
            headers=resp.headers,
            content=resp.content,
            request=request,
        )


def _make_pdf(text: str) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    out = doc.tobytes()
    doc.close()
    return out


def test_ingestion_dashboard_live_fastapi_upload_idempotency_and_polling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise full upload -> idempotent replay -> live SQL status polling against real FastAPI."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_2_integration.db"
    engine = create_db_engine(f"sqlite+aiosqlite:///{db_path}")
    session_factory = create_session_factory(engine)
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )

    async def _seed() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with session_factory() as session:
            await VendorRepository(session).create(
                Vendor(
                    vendor_tax_id="US-12-3456789",
                    vendor_id="V-001",
                    vendor_name="Acme Technologies Inc.",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    standard_tax_rate=Decimal("0.0950"),
                    is_active=True,
                )
            )
            await session.commit()

    asyncio.run(_seed())
    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis

    try:
        tc = TestClient(app)
        with APInvoiceAPIClient(
            base_url="http://127.0.0.1:8000", transport=_TestClientBridgeTransport(tc)
        ) as client:
            tok = client.issue_demo_token("sarah.clerk")
            assert tok.role == "ap_clerk"

            controller = IngestionDashboardController(client)
            pdf_bytes = _make_pdf("INVOICE #INV-INT-2026-01 Total 1200.00 USD")

            # 1. Real multipart upload via FastAPI + WORM Blob + SQL + Redis
            items = controller.submit_batch(
                [
                    PendingUploadFile(
                        filename="integration_inv.pdf",
                        content=pdf_bytes,
                        content_type="application/pdf",
                    )
                ],
                vendor_id="V-001",
                user_roles=["ap_clerk"],
            )
            assert len(items) == 1
            inv_id = items[0].invoice_id
            assert inv_id is not None
            assert items[0].status == "UPLOADED"
            assert items[0].deduplicated is False

            # 2. Idempotent re-submission hits FastAPI 200 OK replay without creating duplicate row
            replayed = controller.submit_batch(
                [
                    PendingUploadFile(
                        filename="integration_inv.pdf",
                        content=pdf_bytes,
                        content_type="application/pdf",
                    )
                ],
                vendor_id="V-001",
                existing_items=items,
                user_roles=["ap_clerk"],
            )
            assert len(replayed) == 1
            assert replayed[0].invoice_id == inv_id
            assert replayed[0].deduplicated is True

            # 3. Simulate worker moving invoice UPLOADED -> VALIDATED in SQL, then poll via FastAPI
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "UPDATE invoices SET status = ?, confidence_macro_avg = ? WHERE invoice_id = ?",
                    ("VALIDATED", 97.50, inv_id),
                )
                conn.commit()
            finally:
                conn.close()

            polled_items, poll_res = controller.poll_batch_once(replayed, poll_cycle_count=0)
            assert poll_res.polled_count == 1
            assert poll_res.updated_count == 1
            assert poll_res.remaining_in_progress == 0
            assert poll_res.should_continue_polling is False
            assert polled_items[0].status == "VALIDATED"
            assert polled_items[0].confidence_macro_avg == Decimal("97.50")

            summary = summarize_batch(polled_items)
            assert summary.total_uploaded == 1
            assert summary.passed == 1
            assert summary.processing == 0
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
