"""
End-to-End Offline Integration Test for Human Exception Queue UI -> FastAPI Backend (P11-4).

Tests: PRD Screen 3, FR-13, P11-4, CLAUDE.md §4.2, §9, §12
"""

import asyncio
from datetime import date
from decimal import Decimal
from pathlib import Path

import fakeredis.aioredis
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
from src.database.models import Base, Invoice, Vendor
from src.database.repositories import InvoiceRepository, VendorRepository, compute_composite_hash
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import InMemoryWORMBlobClient
from src.ui.api_client import APInvoiceAPIClient
from src.ui.exception_queue import (
    ExceptionQueueController,
    resolve_exception_preset,
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


def test_exception_queue_live_fastapi_filtering_and_bulk_manager_approve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Query real FastAPI /exceptions with presets and execute bulk manager approval end-to-end."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_4_exceptions.db"
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
            repo = InvoiceRepository(session)
            seeded = [
                (
                    "inv-q-tax",
                    "INV-Q-001",
                    Decimal("1200.00"),
                    Decimal("91.00"),
                    "REJECTED_TAX_MISMATCH",
                ),
                (
                    "inv-q-dup",
                    "INV-Q-002",
                    Decimal("800.00"),
                    Decimal("96.00"),
                    "DUPLICATE_INVOICE",
                ),
                ("inv-q-rev", "INV-Q-003", Decimal("450.00"), Decimal("84.00"), "REQUIRES_REVIEW"),
                (
                    "inv-q-mgr",
                    "INV-Q-004",
                    Decimal("15000.00"),
                    Decimal("95.00"),
                    "REQUIRES_MANAGER_APPROVAL",
                ),
            ]
            for inv_id, inv_num, total, conf, st in seeded:
                await repo.create(
                    Invoice(
                        invoice_id=inv_id,
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Acme Technologies Inc.",
                        invoice_number=inv_num,
                        invoice_date=date(2026, 2, 10),
                        due_date=date(2026, 3, 10),
                        subtotal=total,
                        total_tax_amount=Decimal("0.00"),
                        total_amount=total,
                        currency="USD",
                        total_amount_usd=total,
                        confidence_macro_avg=conf,
                        status=st,
                        composite_hash=compute_composite_hash("US-12-3456789", inv_num, total),
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
            tok = client.issue_demo_token("michael.manager")
            assert tok.role == "finance_manager"

            controller = ExceptionQueueController(client)

            # 1. All Exceptions -> 4 seeded items
            all_q = controller.fetch_queue(resolve_exception_preset("All Exceptions"))
            assert all_q.total == 4

            # 2. Tax Mismatch preset -> 1 item
            tax_q = controller.fetch_queue(resolve_exception_preset("Tax Mismatch"))
            assert tax_q.total == 1
            assert tax_q.items[0].invoice_id == "inv-q-tax"

            # 3. Duplicate / Revision preset -> 1 item
            dup_q = controller.fetch_queue(resolve_exception_preset("Duplicate / Revision"))
            assert dup_q.total == 1
            assert dup_q.items[0].invoice_id == "inv-q-dup"

            # 4. Bulk manager approve: approves inv-q-mgr ($15k), safely skips inv-q-dup
            bulk_res = controller.bulk_manager_approve(
                ["inv-q-mgr", "inv-q-dup"],
                queue_items=all_q.items,
                comment="Batch approved by Finance Manager",
                user_roles=["finance_manager"],
            )
            assert bulk_res.succeeded_ids == ["inv-q-mgr"]
            assert bulk_res.skipped_ids == ["inv-q-dup"]

            # 5. Queue now has 3 remaining exceptions (inv-q-mgr moved to APPROVED_MANAGER)
            post_q = controller.fetch_queue(resolve_exception_preset("All Exceptions"))
            assert post_q.total == 3
            assert all(item.invoice_id != "inv-q-mgr" for item in post_q.items)
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
