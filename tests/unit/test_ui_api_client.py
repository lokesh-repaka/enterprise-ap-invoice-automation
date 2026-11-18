"""
Unit, Integration, and Security Tests for Typed UI HTTP API Client (P11-1).

Tests: P11-1, CLAUDE.md §4.2, §9, §12, LLD §2,
       SEC-187 (CWE-918/601), SEC-188 (CWE-22/113), SEC-189 (CWE-400/532)
"""

import ast
import asyncio
import json
import logging
from datetime import date
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
from src.api.schemas.invoices import (
    InvoiceApprovalRequest,
    InvoiceHeaderEdits,
    InvoiceRevalidateRequest,
)
from src.core.audit import ReasonCode
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
from src.ui.api_client import (
    APIAuthenticationError,
    APIAuthorizationError,
    APIClientError,
    APIConflictError,
    APINotFoundError,
    APInvoiceAPIClient,
    APIRateLimitError,
    APIServiceUnavailableError,
    APIValidationError,
)


class _TestClientBridgeTransport(httpx.BaseTransport):
    """Bridge synchronous httpx calls directly to FastAPI TestClient offline (zero sockets)."""

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


@pytest.fixture
def live_api_client_env(monkeypatch: pytest.MonkeyPatch):
    """Wire APInvoiceAPIClient directly to real FastAPI app backed by in-memory SQLite + FakeRedis + WORM mock."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
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
                    vendor_id="VEND-1001",
                    vendor_name="Acme Technologies Inc.",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    standard_tax_rate=Decimal("0.0800"),
                    is_active=True,
                )
            )
            await ExchangeRateRepository(session).create(
                ExchangeRate(
                    rate_date=date(2026, 2, 1),
                    from_currency="EUR",
                    to_currency="USD",
                    exchange_rate=Decimal("1.090000"),
                )
            )
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-ui-001",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-UI-2026-001",
                    invoice_date=date(2026, 2, 10),
                    due_date=date(2026, 3, 10),
                    po_number="PO-UI-100",
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("50.00"),
                    total_amount=Decimal("1050.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1050.00"),
                    confidence_macro_avg=Decimal("88.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-UI-2026-001", Decimal("1050.00")
                    ),
                )
            )
            await InvoiceLineRepository(session).create(
                InvoiceLine(
                    invoice_id="inv-ui-001",
                    line_number=1,
                    description="Enterprise Cloud Plan",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1000.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("88.00"),
                )
            )

    asyncio.run(_seed())
    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client

    tc = TestClient(app)
    transport = _TestClientBridgeTransport(tc)
    client = APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport)

    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()
        reset_demo_keypair_cache()
        get_settings.cache_clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())


def test_api_client_covers_all_backend_routes_end_to_end(
    live_api_client_env: APInvoiceAPIClient,
) -> None:
    """Verify APInvoiceAPIClient exercises every single FastAPI route end-to-end with typed Pydantic outputs."""
    api = live_api_client_env

    # 1. Public health + demo personas
    h = api.health()
    assert h["status"] == "healthy"
    personas = api.list_demo_personas()
    assert {p.username for p in personas.personas} == {
        "sarah.clerk",
        "michael.manager",
        "dave.admin",
    }

    # 2. Mint demo token as sarah.clerk and verify /auth/me
    tok = api.issue_demo_token("sarah.clerk")
    assert tok.role == "ap_clerk"
    me = api.get_me()
    assert me.user_id == "demo-oid-sarah-clerk"
    assert "ap_clerk" in me.roles

    # 3. Upload valid PDF via multipart
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Synthetic Invoice INV-UI-UPLOAD")
    pdf_bytes = doc.tobytes()
    doc.close()
    uploaded = api.upload_invoice(
        "test-invoice.pdf",
        pdf_bytes,
        content_type="application/pdf",
        vendor_id="VEND-1001",
    )
    assert uploaded.status == "UPLOADED"
    assert uploaded.queued is True

    # 4. Query exception queue + invoice detail
    exc_queue = api.list_exceptions(statuses=["REJECTED_TAX_MISMATCH"], currency="USD")
    assert exc_queue.total == 1
    assert exc_queue.items[0].invoice_id == "inv-ui-001"

    detail = api.get_invoice("inv-ui-001")
    assert detail.invoice_number == "INV-UI-2026-001"
    assert len(detail.lines) == 1

    # 5. Re-validate -> Approve -> Audit trail
    reval = api.revalidate_invoice(
        "inv-ui-001",
        InvoiceRevalidateRequest(
            reason_code=ReasonCode.OCR_MISREAD,
            comment="Corrected US 8% sales tax",
            header_edits=InvoiceHeaderEdits(
                total_tax_amount=Decimal("80.00"),
                total_amount=Decimal("1080.00"),
            ),
        ),
    )
    assert reval.status == "VALIDATED"
    assert reval.eligible_for_clerk_approval is True

    approved = api.approve_invoice(
        "inv-ui-001",
        InvoiceApprovalRequest(comment="One-click clerk sign-off"),
    )
    assert approved.status == "APPROVED_CLERK"

    # 6. Switch to dave.admin -> verify /health/ready and /audit
    api.issue_demo_token("dave.admin")
    ready = api.health_ready()
    assert ready["status"] == "ready"

    audit = api.get_invoice_audit("inv-ui-001")
    assert audit.total_events == 4
    assert [e.action_type for e in audit.events] == ["EDIT", "EDIT", "REVALIDATE", "APPROVE"]


def test_api_client_maps_http_and_transport_errors_to_typed_exceptions() -> None:
    """Verify HTTP 401/403/404/409/422/429/503 and transport failures map cleanly to typed exceptions."""
    cases = [
        (401, APIAuthenticationError),
        (403, APIAuthorizationError),
        (404, APINotFoundError),
        (409, APIConflictError),
        (422, APIValidationError),
        (429, APIRateLimitError),
        (503, APIServiceUnavailableError),
    ]
    for code, exc_cls in cases:
        transport = httpx.MockTransport(
            lambda req, c=code: httpx.Response(
                c,
                json={"detail": f"Error {c}"},
                headers={"X-Request-ID": "req-err-1"},
            )
        )
        with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as api:
            with pytest.raises(exc_cls) as exc_info:
                api.get_invoice("inv-123")
            assert exc_info.value.status_code == code
            assert exc_info.value.request_id == "req-err-1"

    def _boom(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with APInvoiceAPIClient(
        base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(_boom)
    ) as api:
        with pytest.raises(APIServiceUnavailableError):
            api.health()


def test_api_client_sec187_blocks_ssrf_base_urls_and_disables_redirect_token_forwarding() -> None:
    """Verify SEC-187: blocks non-http(s), embedded creds, remote plain HTTP, and 302 redirect forwarding."""
    for bad_url in (
        "file:///etc/passwd",
        "ftp://127.0.0.1:8000",
        "http://user:pass@127.0.0.1:8000",
        "http://169.254.169.254/latest/meta-data",
        "http://evil.example.com",
        "https://api.example.com?foo=bar",
        "http://127.0.0.1:8000\r\nX-Inject: 1",
    ):
        with pytest.raises(ValueError):
            APInvoiceAPIClient(base_url=bad_url)

    # Valid remote HTTPS and internal Docker service HTTP accepted
    for ok_url in ("https://ap-api.eastus2.azurecontainerapps.io", "http://api:8000"):
        c = APInvoiceAPIClient(base_url=ok_url)
        c.close()

    # 302 redirect must NOT be followed (prevents leaking Bearer token to attacker host)
    redirect_transport = httpx.MockTransport(
        lambda req: httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
    )
    with APInvoiceAPIClient(
        base_url="http://127.0.0.1:8000",
        access_token="secret-jwt-token",
        transport=redirect_transport,
    ) as api:
        with pytest.raises(APIClientError) as exc_info:
            api.get_me()
        assert exc_info.value.status_code == 302


def test_api_client_sec188_blocks_path_traversal_and_header_crlf_injection() -> None:
    """Verify SEC-188: path traversal in invoice_id and CRLF in headers fail client-side before sending."""
    called = False

    def _should_not_run(_req: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    with APInvoiceAPIClient(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(_should_not_run),
    ) as api:
        for bad_id in ("../auth/me", "inv/../../admin", "inv?x=1", "a" * 80, "inv 1"):
            with pytest.raises(ValueError, match="invoice_id"):
                api.get_invoice(bad_id)
            with pytest.raises(ValueError, match="invoice_id"):
                api.approve_invoice(bad_id)
            with pytest.raises(ValueError, match="invoice_id"):
                api.get_invoice_audit(bad_id)

        with pytest.raises(ValueError, match="access_token"):
            api.set_access_token("valid\r\nX-Evil: 1")

        with pytest.raises(ValueError, match="idempotency_key"):
            api.upload_invoice("a.pdf", b"%PDF-1.4", idempotency_key="bad\r\nkey")

    assert called is False


def test_api_client_sec189_redacts_bearer_token_and_caps_oversized_responses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify SEC-189: Bearer token never appears in repr/logs and >10 MB responses fail closed."""
    secret = "eyJhbGciOiJSUzI1NiJ9.SUPER_SECRET_DEMO_PAYLOAD.SIGNATURE"
    ok_transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"status": "healthy"}))
    with caplog.at_level(logging.DEBUG, logger="ap.ui"):
        with APInvoiceAPIClient(
            base_url="http://127.0.0.1:8000",
            access_token=secret,
            transport=ok_transport,
        ) as api:
            assert secret not in repr(api)
            assert api.health()["status"] == "healthy"
    assert secret not in " ".join(r.getMessage() for r in caplog.records)

    # Oversized JSON response (> 10 MB) rejected fail-closed (CWE-400)
    big_payload = json.dumps({"status": "x" * (10 * 1024 * 1024 + 64)}).encode("utf-8")
    big_transport = httpx.MockTransport(lambda req: httpx.Response(200, content=big_payload))
    with APInvoiceAPIClient(
        base_url="http://127.0.0.1:8000",
        transport=big_transport,
    ) as api:
        with pytest.raises(APIClientError, match="maximum permitted size"):
            api.health()


def test_ui_api_client_obeys_layering_rules() -> None:
    """Verify CLAUDE.md §4.2 & §12: src/ui/api_client.py never imports DB, storage, validation, or Azure SDKs."""
    tree = ast.parse(Path("src/ui/api_client.py").read_text(encoding="utf-8"))
    forbidden = (
        "src.database",
        "src.storage",
        "src.extraction",
        "src.validation",
        "src.services",
        "sqlalchemy",
        "redis",
        "openai",
        "azure",
    )
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for imp in mods:
            assert not imp.startswith(forbidden), (
                f"Layering violation in src/ui/api_client.py: forbidden import '{imp}'"
            )


def test_api_client_sec190_blocks_upload_filename_traversal_oversized_upload_and_bad_timeout() -> (
    None
):
    """Verify SEC-190: client-side filename traversal, empty/oversized uploads, and invalid timeouts fail closed."""
    for bad_timeout in (0, -5.0, 999.0, True):
        with pytest.raises(ValueError, match="timeout_seconds"):
            APInvoiceAPIClient(base_url="http://127.0.0.1:8000", timeout_seconds=bad_timeout)  # type: ignore[arg-type]

    transport = httpx.MockTransport(lambda req: httpx.Response(202, json={}))
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as api:
        for bad_name in ("../evil.pdf", "dir/inv.pdf", "dir\\inv.pdf"):
            with pytest.raises(ValueError, match="filename"):
                api.upload_invoice(bad_name, b"%PDF-1.4")

        with pytest.raises(ValueError, match="non-empty"):
            api.upload_invoice("empty.pdf", b"")

        with pytest.raises(ValueError, match="maximum client limit"):
            api.upload_invoice("huge.pdf", b"x" * (25 * 1024 * 1024 + 1))
