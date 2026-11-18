"""
End-to-End Offline Integration Test for Audit Trail Viewer UI -> FastAPI Backend (P11-6).

Tests: PRD Screen 5, N3, N6, BR-031, P11-6, CLAUDE.md §4.2, §9, §12
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
from src.api.schemas.invoices import (
    InvoiceHeaderEdits,
    InvoiceRevalidateRequest,
    ReasonCode,
)
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
from src.ui.api_client import APInvoiceAPIClient
from src.ui.audit_viewer import (
    AuditTrailFilter,
    AuditTrailViewerController,
    build_chronological_timeline_rows,
    summarize_audit_trail,
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


def test_audit_trail_viewer_live_fastapi_revalidate_approve_timeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Execute real Re-Validate -> Approve -> Audit Trail Viewer chronological inspection."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_6_audit.db"
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
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-aud-live",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-AUD-LIVE-01",
                    invoice_date=date(2026, 2, 10),
                    due_date=date(2026, 3, 10),
                    po_number="PO-AUD-01",
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("50.00"),
                    total_amount=Decimal("1050.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1050.00"),
                    confidence_macro_avg=Decimal("94.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-AUD-LIVE-01", Decimal("1050.00")
                    ),
                )
            )
            await InvoiceLineRepository(session).create(
                InvoiceLine(
                    invoice_id="inv-aud-live",
                    line_number=1,
                    description="Enterprise Cloud Plan",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1000.00"),
                    line_tax_rate=Decimal("0.0800"),
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
            # 1. AP Clerk re-validates and approves
            client.issue_demo_token("sarah.clerk")
            client.revalidate_invoice(
                "inv-aud-live",
                InvoiceRevalidateRequest(
                    reason_code=ReasonCode.OCR_MISREAD,
                    comment="Fixed US 8% sales tax",
                    header_edits=InvoiceHeaderEdits(
                        total_tax_amount=Decimal("80.00"),
                        total_amount=Decimal("1080.00"),
                    ),
                ),
            )
            client.approve_invoice("inv-aud-live")

            # 2. System Admin inspects immutable chronological audit trail via AuditTrailViewerController
            client.issue_demo_token("dave.admin")
            controller = AuditTrailViewerController(client)
            trail = controller.load_audit_trail(
                AuditTrailFilter(invoice_id="inv-aud-live"),
                user_roles=["system_admin"],
            )
            assert trail.immutable is True
            assert trail.current_status == "APPROVED_CLERK"
            assert trail.total_events >= 3

            rows = build_chronological_timeline_rows(trail.events)
            actions = [r["Action"] for r in rows]
            assert "EDIT" in actions
            assert "REVALIDATE" in actions
            assert "APPROVE" in actions
            assert actions.index("EDIT") < actions.index("APPROVE")

            summary = summarize_audit_trail(trail)
            assert summary.manual_edits >= 2  # total_tax_amount + total_amount
            assert summary.revalidations == 1
            assert summary.approvals == 1
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
