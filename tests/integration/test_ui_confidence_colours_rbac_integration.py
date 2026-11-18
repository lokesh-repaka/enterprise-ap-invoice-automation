"""
End-to-End Offline Integration Test for Role-Aware UI & Backend RBAC Parity (P11-7).

Tests: FR-04, FR-13, CLAUDE.md §2, §12, §16.1, P11-7
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
from src.database.models import Base, Invoice, InvoiceLine, Vendor
from src.database.repositories import (
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import InMemoryWORMBlobClient
from src.ui.api_client import APIAuthorizationError, APInvoiceAPIClient
from src.ui.theme_rbac import evaluate_invoice_ui_capabilities


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


def test_ui_role_aware_approve_parity_with_live_fastapi_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify UI hides Approve for ap_clerk >$10k AND FastAPI returns 403 if invoked directly."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_7_rbac.db"
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
                    standard_tax_rate=Decimal("0.0800"),
                    is_active=True,
                )
            )
            inv_repo = InvoiceRepository(session)
            line_repo = InvoiceLineRepository(session)
            for inv_id, inv_num, total in (
                ("inv-low-2500", "INV-LOW-2500", Decimal("2500.00")),
                ("inv-high-15000", "INV-HIGH-15000", Decimal("15000.00")),
            ):
                await inv_repo.create(
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
                        confidence_macro_avg=Decimal("96.00"),
                        status="VALIDATED",
                        composite_hash=compute_composite_hash("US-12-3456789", inv_num, total),
                    )
                )
                await line_repo.create(
                    InvoiceLine(
                        invoice_id=inv_id,
                        line_number=1,
                        description="Enterprise License",
                        quantity=Decimal("1.0000"),
                        unit_price=total,
                        line_total=total,
                        line_tax_rate=Decimal("0.0000"),
                        confidence_score=Decimal("96.00"),
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
            # 1. AP Clerk: $2,500 shown & approved; $15,000 hidden in UI AND 403 on backend
            client.issue_demo_token("sarah.clerk")
            inv_low = client.get_invoice("inv-low-2500")
            inv_high = client.get_invoice("inv-high-15000")

            assert (
                evaluate_invoice_ui_capabilities(inv_low, ["ap_clerk"]).show_approve_button is True
            )
            assert (
                evaluate_invoice_ui_capabilities(inv_high, ["ap_clerk"]).show_approve_button
                is False
            )

            low_resp = client.approve_invoice("inv-low-2500")
            assert low_resp.status == "APPROVED_CLERK"

            with pytest.raises(APIAuthorizationError):
                client.approve_invoice("inv-high-15000")

            # 2. Finance Manager: $15,000 shown in UI AND approved via FastAPI
            client.issue_demo_token("michael.manager")
            assert (
                evaluate_invoice_ui_capabilities(inv_high, ["finance_manager"]).show_approve_button
                is True
            )
            high_resp = client.approve_invoice("inv-high-15000")
            assert high_resp.status == "APPROVED_MANAGER"
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
