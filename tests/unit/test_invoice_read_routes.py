"""
Unit, Integration, and Security Tests for Invoice Read & Exception Queue Routes (P5-4).

Tests: CLAUDE.md §9, PRD Screen 2 & Screen 3, LLD §2.1, CWE-20, CWE-89, CWE-200, CWE-209, CWE-400, CWE-525, CWE-532, CWE-863
"""

import asyncio
import logging
from datetime import date
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from src.api.invoices import get_upload_session_factory
from src.api.main import app
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.database.models import AuditLog, Base, Invoice, InvoiceLine, Vendor
from src.database.repositories import (
    AuditLogRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory


def _auth_headers(username: str) -> dict[str, str]:
    settings = Settings(APP_ENV="test", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
    token = issue_demo_token(username, settings=settings)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def seeded_read_env(monkeypatch: pytest.MonkeyPatch):
    """Create isolated SQLite DB seeded with 2 vendors, 9 mixed-status invoices, lines, and audit logs."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    session_factory = create_session_factory(engine)

    async def _seed() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with session_factory() as session:
            v_repo = VendorRepository(session)
            await v_repo.create(
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
            await v_repo.create(
                Vendor(
                    vendor_tax_id="DE999888777",
                    vendor_id="VEND-1002",
                    vendor_name="Berlin Systems GmbH",
                    country_code="DE",
                    date_format_locale="DD/MM/YYYY",
                    default_currency="EUR",
                    tax_scheme="DE_MWST",
                    is_active=True,
                )
            )

            inv_repo = InvoiceRepository(session)
            fixtures = [
                # Non-exception invoices (MUST NOT appear in /exceptions)
                (
                    "inv-ok-1",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-001",
                    date(2026, 1, 10),
                    Decimal("1200.00"),
                    "USD",
                    Decimal("98.50"),
                    "UPLOADED",
                ),
                (
                    "inv-ok-2",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-002",
                    date(2026, 1, 12),
                    Decimal("2400.00"),
                    "USD",
                    Decimal("96.00"),
                    "VALIDATED",
                ),
                (
                    "inv-ok-3",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-003",
                    date(2026, 1, 15),
                    Decimal("3100.00"),
                    "USD",
                    Decimal("95.00"),
                    "APPROVED_CLERK",
                ),
                (
                    "inv-ok-4",
                    "DE999888777",
                    "Berlin Systems GmbH",
                    "INV-DE-001",
                    date(2026, 1, 20),
                    Decimal("15000.00"),
                    "EUR",
                    Decimal("97.00"),
                    "APPROVED_MANAGER",
                ),
                # Exception queue invoices (5 total)
                (
                    "inv-exc-1",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-101",
                    date(2026, 2, 5),
                    Decimal("1350.00"),
                    "USD",
                    Decimal("84.50"),
                    "REQUIRES_REVIEW",
                ),
                (
                    "inv-exc-2",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-102",
                    date(2026, 2, 10),
                    Decimal("4500.00"),
                    "USD",
                    Decimal("71.00"),
                    "REQUIRES_APPROVAL",
                ),
                (
                    "inv-exc-3",
                    "DE999888777",
                    "Berlin Systems GmbH",
                    "INV-DE-201",
                    date(2026, 2, 14),
                    Decimal("6200.00"),
                    "EUR",
                    Decimal("88.00"),
                    "REJECTED_TAX_MISMATCH",
                ),
                (
                    "inv-exc-4",
                    "DE999888777",
                    "Berlin Systems GmbH",
                    "INV-DE-202",
                    date(2026, 2, 18),
                    Decimal("8900.00"),
                    "EUR",
                    Decimal("92.00"),
                    "DUPLICATE_INVOICE",
                ),
                (
                    "inv-exc-5",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-US-105",
                    date(2026, 3, 2),
                    Decimal("14500.00"),
                    "USD",
                    Decimal("94.00"),
                    "REQUIRES_MANAGER_APPROVAL",
                ),
            ]
            for inv_id, tax_id, vname, num, inv_dt, total, curr, conf, st in fixtures:
                await inv_repo.create(
                    Invoice(
                        invoice_id=inv_id,
                        vendor_tax_id=tax_id,
                        vendor_name=vname,
                        invoice_number=num,
                        invoice_date=inv_dt,
                        subtotal=total,
                        total_tax_amount=Decimal("0.00"),
                        total_amount=total,
                        currency=curr,
                        total_amount_usd=total,
                        confidence_macro_avg=conf,
                        status=st,
                        composite_hash=compute_composite_hash(tax_id, num, total),
                        blob_raw_url=f"https://mockblob.blob.core.windows.net/raw-invoices-immutable/raw-invoices/{inv_id}/{num}.pdf",
                    )
                )

            line_repo = InvoiceLineRepository(session)
            await line_repo.create_many(
                [
                    InvoiceLine(
                        invoice_id="inv-exc-1",
                        line_number=1,
                        description="Cloud Compute Reserved Instances",
                        quantity=Decimal("10.0000"),
                        unit_price=Decimal("100.0000"),
                        line_total=Decimal("1000.00"),
                        line_tax_rate=Decimal("0.0000"),
                        confidence_score=Decimal("85.00"),
                    ),
                    InvoiceLine(
                        invoice_id="inv-exc-1",
                        line_number=2,
                        description="Enterprise Support Retainer",
                        quantity=Decimal("1.0000"),
                        unit_price=Decimal("350.0000"),
                        line_total=Decimal("350.00"),
                        line_tax_rate=Decimal("0.0000"),
                        confidence_score=Decimal("84.00"),
                    ),
                ]
            )
            await AuditLogRepository(session).create(
                AuditLog(
                    invoice_id="inv-exc-1",
                    user_id="demo-oid-sarah-clerk",
                    action_type="INGEST",
                    field_name="blob_raw_url",
                    new_value="sha256-test",
                )
            )

    asyncio.run(_seed())
    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory

    try:
        yield {"client": TestClient(app), "session_factory": session_factory}
    finally:
        app.dependency_overrides.clear()
        reset_demo_keypair_cache()
        get_settings.cache_clear()
        asyncio.run(engine.dispose())


def test_get_invoice_by_id_returns_full_header_lines_and_audit_count(seeded_read_env: dict) -> None:
    """Verify GET /api/v1/invoices/{id} returns full header, ordered line items, audit count, and 404 on missing."""
    client: TestClient = seeded_read_env["client"]
    headers = _auth_headers("sarah.clerk")

    resp = client.get("/api/v1/invoices/inv-exc-1", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("Cache-Control") == "no-store"

    body = resp.json()
    assert body["invoice_id"] == "inv-exc-1"
    assert body["vendor_id"] == "VEND-1001"
    assert body["vendor_tax_id"] == "US-12-3456789"
    assert body["invoice_number"] == "INV-US-101"
    assert body["status"] == "REQUIRES_REVIEW"
    assert Decimal(body["total_amount"]) == Decimal("1350.00")
    assert Decimal(body["confidence_macro_avg"]) == Decimal("84.50")
    assert body["audit_event_count"] == 1
    assert len(body["lines"]) == 2
    assert [ln["line_number"] for ln in body["lines"]] == [1, 2]
    assert body["lines"][0]["description"] == "Cloud Compute Reserved Instances"

    # Nonexistent valid invoice ID -> 404 with generic message
    missing = client.get("/api/v1/invoices/inv-does-not-exist", headers=headers)
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Invoice not found"}


def test_get_exceptions_returns_only_exception_statuses_and_omits_sensitive_tax_id(
    seeded_read_env: dict,
) -> None:
    """Verify GET /api/v1/invoices/exceptions returns only exception states and minimizes PII (CWE-200)."""
    client: TestClient = seeded_read_env["client"]
    resp = client.get("/api/v1/invoices/exceptions", headers=_auth_headers("sarah.clerk"))
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("Cache-Control") == "no-store"

    body = resp.json()
    assert body["total"] == 5
    returned_ids = {item["invoice_id"] for item in body["items"]}
    assert returned_ids == {"inv-exc-1", "inv-exc-2", "inv-exc-3", "inv-exc-4", "inv-exc-5"}

    # Data minimization: bulk exception list MUST NOT expose raw vendor_tax_id or composite_hash
    for item in body["items"]:
        assert "vendor_tax_id" not in item
        assert "composite_hash" not in item


def test_get_exceptions_supports_status_vendor_currency_amount_date_confidence_and_pagination_filters(
    seeded_read_env: dict,
) -> None:
    """Verify all PRD Screen 3 exception queue query filters, sorting, and pagination."""
    client: TestClient = seeded_read_env["client"]
    headers = _auth_headers("michael.manager")

    # 1. Multi-status filter
    r_status = client.get(
        "/api/v1/invoices/exceptions?status=REJECTED_TAX_MISMATCH&status=DUPLICATE_INVOICE",
        headers=headers,
    )
    assert r_status.status_code == 200
    assert {i["invoice_id"] for i in r_status.json()["items"]} == {"inv-exc-3", "inv-exc-4"}

    # 2. Vendor ID + currency (case-insensitive)
    r_vendor = client.get(
        "/api/v1/invoices/exceptions?vendor_id=VEND-1002&currency=eur",
        headers=headers,
    )
    assert r_vendor.status_code == 200
    assert r_vendor.json()["total"] == 2

    # 3. Vendor name substring + invoice number substring
    r_search = client.get(
        "/api/v1/invoices/exceptions?vendor_name=Berlin&invoice_number=INV-DE-201",
        headers=headers,
    )
    assert r_search.status_code == 200
    assert [i["invoice_id"] for i in r_search.json()["items"]] == ["inv-exc-3"]

    # 4. Amount range + date range
    r_range = client.get(
        "/api/v1/invoices/exceptions?min_amount=4000&max_amount=9000&date_from=2026-02-01&date_to=2026-02-28",
        headers=headers,
    )
    assert r_range.status_code == 200
    assert {i["invoice_id"] for i in r_range.json()["items"]} == {
        "inv-exc-2",
        "inv-exc-3",
        "inv-exc-4",
    }

    # 5. Confidence upper bound
    r_conf = client.get("/api/v1/invoices/exceptions?max_confidence=85.00", headers=headers)
    assert r_conf.status_code == 200
    assert {i["invoice_id"] for i in r_conf.json()["items"]} == {"inv-exc-1", "inv-exc-2"}

    # 6. Sorting + pagination (total reflects full matching set = 5, page returns 2)
    r_page = client.get(
        "/api/v1/invoices/exceptions?sort_by=total_amount&sort_order=asc&limit=2&offset=1",
        headers=headers,
    )
    assert r_page.status_code == 200
    page_body = r_page.json()
    assert page_body["total"] == 5
    assert page_body["limit"] == 2
    assert page_body["offset"] == 1
    assert [i["invoice_id"] for i in page_body["items"]] == ["inv-exc-2", "inv-exc-3"]


def test_read_routes_enforce_rbac_for_clerk_manager_unauth_and_system_admin(
    seeded_read_env: dict,
) -> None:
    """Verify CLAUDE.md §9 RBAC on both read routes: unauth=401, system_admin=403, clerk/manager=200."""
    client: TestClient = seeded_read_env["client"]

    for path in ("/api/v1/invoices/exceptions", "/api/v1/invoices/inv-exc-1"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth_headers("dave.admin")).status_code == 403
        assert client.get(path, headers=_auth_headers("sarah.clerk")).status_code == 200
        assert client.get(path, headers=_auth_headers("michael.manager")).status_code == 200


def test_read_routes_block_sql_injection_like_wildcards_invalid_ids_and_bad_filters(
    seeded_read_env: dict,
) -> None:
    """Verify SQL injection, LIKE wildcard abuse, invalid IDs, and bad filter combinations fail safely (CWE-89/20)."""
    client: TestClient = seeded_read_env["client"]
    headers = _auth_headers("sarah.clerk")

    # Malformed / SQLi invoice_id -> 422 before hitting SQL
    for bad_id in ("inv-1' OR '1'='1", "inv;DROP TABLE invoices", "a" * 80):
        assert client.get(f"/api/v1/invoices/{bad_id}", headers=headers).status_code == 422

    # LIKE wildcard & SQLi strings in search parameters MUST be escaped (return 0 matches, not all 5!)
    for tricky_search in ("%", "_", "%' OR 1=1 --"):
        resp = client.get(
            "/api/v1/invoices/exceptions",
            params={"vendor_name": tricky_search},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    # Non-exception status, invalid sort column, inverted ranges, unbounded limit -> 422
    for bad_query in (
        "status=APPROVED_CLERK",
        "status=UNKNOWN_STATUS",
        "sort_by=vendor_tax_id",
        "currency=US",
        "min_amount=5000&max_amount=1000",
        "date_from=2026-03-01&date_to=2026-02-01",
        "limit=500",
        "offset=-1",
        "vendor_id=../evil",
    ):
        assert (
            client.get(f"/api/v1/invoices/exceptions?{bad_query}", headers=headers).status_code
            == 422
        )


def test_read_routes_fail_closed_with_503_on_database_error_and_never_log_tax_ids(
    seeded_read_env: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify DB errors return sanitized 503 (CWE-209) and read logs never echo raw Tax IDs (CWE-532)."""
    client: TestClient = seeded_read_env["client"]
    headers = _auth_headers("sarah.clerk")

    with caplog.at_level(logging.DEBUG, logger="ap.api.invoices"):
        assert client.get("/api/v1/invoices/inv-exc-1", headers=headers).status_code == 200
        assert client.get("/api/v1/invoices/exceptions", headers=headers).status_code == 200

    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined_logs
    assert "DE999888777" not in combined_logs

    # Simulate database failure -> 503 with zero SQL/credential detail leakage
    class _BrokenSessionCtx:
        async def __aenter__(self):
            raise OperationalError("SELECT * FROM invoices", {}, Exception("sql-password-leak"))

        async def __aexit__(self, *args):
            return False

    app.dependency_overrides[get_upload_session_factory] = lambda: lambda: _BrokenSessionCtx()

    for path in ("/api/v1/invoices/inv-exc-1", "/api/v1/invoices/exceptions"):
        err_resp = client.get(path, headers=headers)
        assert err_resp.status_code == 503
        assert "sql-password-leak" not in err_resp.json()["detail"]


def test_exceptions_blocks_excessive_status_params_extreme_amounts_and_error_reflection(
    seeded_read_env: dict,
) -> None:
    """Verify repeated status flood, extreme numeric bounds, and XSS error reflection fail safely (CWE-116/400)."""
    client: TestClient = seeded_read_env["client"]
    headers = _auth_headers("sarah.clerk")

    # Reflected XSS payload in status filter MUST NOT be echoed in 422 error detail (CWE-116)
    xss_resp = client.get(
        "/api/v1/invoices/exceptions",
        params={"status": "<script>alert(1)</script>"},
        headers=headers,
    )
    assert xss_resp.status_code == 422
    assert "<script>" not in xss_resp.json()["detail"]

    # Excessive repeated status parameters (> 7) rejected (CWE-400)
    many_statuses = [("status", "REQUIRES_REVIEW")] * 10
    flood_resp = client.get("/api/v1/invoices/exceptions", params=many_statuses, headers=headers)
    assert flood_resp.status_code == 422

    # Extreme decimal overflow rejected
    overflow_resp = client.get(
        "/api/v1/invoices/exceptions",
        params={"max_amount": "999999999999999999999999999"},
        headers=headers,
    )
    assert overflow_resp.status_code == 422
