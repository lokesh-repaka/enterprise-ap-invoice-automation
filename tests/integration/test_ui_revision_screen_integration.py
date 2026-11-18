"""
End-to-End Offline Integration Test for Revision Comparison Screen UI -> FastAPI Backend (P11-5).

Tests: FR-10, PRD Screen 4, P11-5, CLAUDE.md §4.2, §9, §12
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
from src.core.audit import AuditActionType, AuditLogger
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
from src.ui.revision_screen import RevisionComparisonController, RevisionDecision


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


def test_revision_comparison_live_fastapi_side_by_side_pair_and_audit_lookup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Load real original APPROVED_CLERK + FLAGGED_POTENTIAL_REVISION pair & approval audit from FastAPI."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / "p11_5_revision.db"
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
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-orig-live",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-2026-8800",
                    invoice_date=date(2026, 2, 1),
                    due_date=date(2026, 3, 1),
                    po_number="PO-8800",
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("80.00"),
                    total_amount=Decimal("1080.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1080.00"),
                    confidence_macro_avg=Decimal("96.00"),
                    status="APPROVED_CLERK",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-2026-8800", Decimal("1080.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-orig-live",
                    line_number=1,
                    description="Core Licenses",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1000.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("96.00"),
                )
            )
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-rev-live",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-2026-8800-REV",
                    invoice_date=date(2026, 2, 5),
                    due_date=date(2026, 3, 5),
                    po_number="PO-8800",
                    subtotal=Decimal("1200.00"),
                    total_tax_amount=Decimal("96.00"),
                    total_amount=Decimal("1296.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1296.00"),
                    confidence_macro_avg=Decimal("93.50"),
                    status="FLAGGED_POTENTIAL_REVISION",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-2026-8800-REV", Decimal("1296.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-rev-live",
                    line_number=1,
                    description="Core Licenses",
                    quantity=Decimal("12.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1200.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("93.50"),
                )
            )
            await session.commit()

        # Record real immutable APPROVE audit entry on the original invoice
        await AuditLogger(session_factory).record(
            invoice_id="inv-orig-live",
            user_id="sarah.clerk@company.com",
            action_type=AuditActionType.APPROVE,
            field_name="status",
            previous_value="VALIDATED",
            new_value="APPROVED_CLERK",
            comment="One-click clerk approval",
        )

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
            controller = RevisionComparisonController(client)

            pair = controller.load_comparison_pair("inv-orig-live", "inv-rev-live")
            assert pair.original.status == "APPROVED_CLERK"
            assert pair.revision.status == "FLAGGED_POTENTIAL_REVISION"
            assert pair.original_approved_by == "sarah.clerk@company.com"
            assert pair.original_approved_at is not None
            assert pair.diff.markers.has_revision_marker is True
            assert pair.diff.markers.same_base_invoice_number is True
            assert pair.diff.total_amount_delta == Decimal("216.00")
            assert pair.diff.modified_line_count == 1

            _, decision_rec = controller.record_decision(
                pair.original,
                pair.revision,
                decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
                comment="Confirmed vendor-issued -REV quantity increase",
                user_roles=["ap_clerk"],
            )
            assert decision_rec.handoff_route == "/workbench/inv-rev-live"
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()
