"""
End-to-End Offline Integration Test for Review Workbench UI -> FastAPI Backend (P11-3).

Tests: FR-12, BR-016, BR-017, PRD Screen 2, PRD Journey 5 (EU Reverse Charge), P11-3
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
from src.api.schemas.invoices import ReasonCode
from src.core.config import get_settings
from src.core.demo_auth import reset_demo_keypair_cache
from src.database.models import Base, ExchangeRate, Invoice, InvoiceLine, Vendor
from src.database.repositories import (
    ExchangeRateRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import InMemoryWORMBlobClient
from src.ui.api_client import APInvoiceAPIClient
from src.ui.review_workbench import (
    HeaderFormDraft,
    LineFormDraft,
    ReviewWorkbenchController,
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


def test_review_workbench_live_fastapi_revalidate_and_approve_journey(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PRD Journey 5: Load REJECTED_TAX_MISMATCH DE invoice -> reverse-charge Re-Validate -> Clerk Approve."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_3_workbench.db"
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
                    vendor_tax_id="DE-123456789",
                    vendor_id="V-006",
                    vendor_name="Münster Analytics GmbH",
                    country_code="DE",
                    date_format_locale="DD/MM/YYYY",
                    default_currency="EUR",
                    tax_scheme="DE_MWST",
                    standard_tax_rate=Decimal("0.1900"),
                    is_active=True,
                )
            )
            await ExchangeRateRepository(session).create(
                ExchangeRate(
                    rate_date=date(2026, 2, 10),
                    from_currency="EUR",
                    to_currency="USD",
                    exchange_rate=Decimal("1.090000"),
                )
            )
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-wb-de-001",
                    vendor_tax_id="DE-123456789",
                    vendor_name="Münster Analytics GmbH",
                    invoice_number="DE-2026-0042",
                    invoice_date=date(2026, 2, 10),
                    due_date=date(2026, 3, 12),
                    po_number="PO-DE-42",
                    subtotal=Decimal("2000.00"),
                    total_tax_amount=Decimal("0.00"),
                    total_amount=Decimal("2000.00"),
                    currency="EUR",
                    total_amount_usd=Decimal("2180.00"),
                    confidence_macro_avg=Decimal("94.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "DE-123456789", "DE-2026-0042", Decimal("2000.00")
                    ),
                )
            )
            await InvoiceLineRepository(session).create(
                InvoiceLine(
                    invoice_id="inv-wb-de-001",
                    line_number=1,
                    description="EU Analytics Advisory",
                    quantity=Decimal("20.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("2000.00"),
                    line_tax_rate=Decimal("0.0000"),
                    confidence_score=Decimal("94.00"),
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
            client.issue_demo_token("sarah.clerk")
            controller = ReviewWorkbenchController(client)

            # 1. Load flagged EU invoice via GET /api/v1/invoices/{id}
            invoice = controller.load_invoice("inv-wb-de-001")
            assert invoice.status == "REJECTED_TAX_MISMATCH"
            assert len(invoice.lines) == 1

            # 2. Apply EU Reverse Charge tax override via Re-Validate button
            header_draft = HeaderFormDraft.from_invoice(invoice)
            line_drafts = [LineFormDraft.from_line(line) for line in invoice.lines]
            reval_resp, refreshed = controller.submit_revalidation(
                invoice,
                header_draft=header_draft,
                line_drafts=line_drafts,
                reason_code=ReasonCode.TAX_CODE_OVERRIDE,
                comment="EU B2B Reverse Charge confirmed per PDF footer",
                is_reverse_charge=True,
                user_roles=["ap_clerk"],
            )
            assert reval_resp.status == "VALIDATED"
            assert reval_resp.validation_summary.all_passed is True
            assert reval_resp.eligible_for_clerk_approval is True
            assert refreshed.status == "VALIDATED"

            # 3. One-click clerk approval (<= $10,000 USD)
            approve_resp, final_inv = controller.submit_approval(
                refreshed,
                user_roles=["ap_clerk"],
                high_value_threshold_usd=Decimal("10000.00"),
            )
            assert approve_resp.status == "APPROVED_CLERK"
            assert final_inv.status == "APPROVED_CLERK"
            assert final_inv.audit_event_count >= 2
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
