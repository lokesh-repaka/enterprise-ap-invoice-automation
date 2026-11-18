"""
Unit, Integration, and Security Tests for GET /api/v1/invoices/{id}/audit (P9-3).

Tests: BR-031, N3, N6, N8, PRD Screen 5, LLD §2.1, §3.1,
       CLAUDE.md §4.2, §4.3, §6, §8, §9, §12,
       CWE-20, CWE-89, CWE-116, CWE-117, CWE-200, CWE-209, CWE-400, CWE-451, CWE-525, CWE-532, CWE-863
"""

import ast
import asyncio
import logging
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from src.api.invoices import get_upload_session_factory
from src.api.main import app
from src.core.audit import AuditActionType
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.core.security import AuthenticatedUser, get_current_user
from src.database.models import AuditLog, Base, Invoice, InvoiceLine, Vendor
from src.database.repositories import (
    AuditLogRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory


def _auth_headers(username: str, *, request_id: str | None = None) -> dict[str, str]:
    settings = Settings(APP_ENV="test", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
    token = issue_demo_token(username, settings=settings)
    headers = {"Authorization": f"Bearer {token}"}
    if request_id is not None:
        headers["X-Request-ID"] = request_id
    return headers


@pytest.fixture
def audit_env(monkeypatch: pytest.MonkeyPatch):
    """Isolated async SQLite DB seeded with vendors, invoices, and multi-event audit history."""
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

            inv_repo = InvoiceRepository(session)
            line_repo = InvoiceLineRepository(session)
            audit_repo = AuditLogRepository(session)

            # 1. Invoice with 5 lifecycle audit events inserted out of timestamp order
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-aud-full",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-AUD-2026-001",
                    invoice_date=date(2026, 2, 10),
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("80.00"),
                    total_amount=Decimal("1080.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1080.00"),
                    confidence_macro_avg=Decimal("94.00"),
                    status="APPROVED_CLERK",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-AUD-2026-001", Decimal("1080.00")
                    ),
                )
            )
            t0 = datetime(2026, 2, 10, 12, 0, 0, tzinfo=UTC)
            out_of_order_logs = [
                AuditLog(
                    audit_id="aud-5",
                    invoice_id="inv-aud-full",
                    user_id="demo-oid-sarah-clerk",
                    action_type="APPROVE",
                    field_name="status",
                    previous_value="VALIDATED",
                    new_value="APPROVED_CLERK",
                    comment="[request_id=req-5] Approved by ap_clerk",
                    timestamp=t0 + timedelta(minutes=4),
                ),
                AuditLog(
                    audit_id="aud-1",
                    invoice_id="inv-aud-full",
                    user_id="demo-oid-sarah-clerk",
                    action_type="INGEST",
                    field_name="blob_raw_url",
                    new_value="sha256-raw-hash",
                    comment="[request_id=req-1] Uploaded .pdf",
                    timestamp=t0,
                ),
                AuditLog(
                    audit_id="aud-3",
                    invoice_id="inv-aud-full",
                    user_id="demo-oid-sarah-clerk",
                    action_type="EDIT",
                    field_name="total_tax_amount",
                    previous_value="50.00",
                    new_value="80.00",
                    reason_code="OCR_MISREAD",
                    comment="[request_id=req-3] Corrected OCR tax digit",
                    timestamp=t0 + timedelta(minutes=2),
                ),
                AuditLog(
                    audit_id="aud-2",
                    invoice_id="inv-aud-full",
                    user_id="worker-1",
                    action_type="EXTRACTION",
                    field_name="status",
                    previous_value="EXTRACTING",
                    new_value="REJECTED_TAX_MISMATCH",
                    comment="Model gpt-4o-mini extracted header & lines",
                    timestamp=t0 + timedelta(minutes=1),
                ),
                AuditLog(
                    audit_id="aud-4",
                    invoice_id="inv-aud-full",
                    user_id="demo-oid-sarah-clerk",
                    action_type="REVALIDATE",
                    field_name="status",
                    previous_value="REJECTED_TAX_MISMATCH",
                    new_value="VALIDATED",
                    reason_code="OCR_MISREAD",
                    comment="[request_id=req-3] Re-validation passed",
                    timestamp=t0 + timedelta(minutes=3),
                ),
            ]
            for entry in out_of_order_logs:
                await audit_repo.create(entry)

            # 2. Invoice with zero audit logs
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-aud-empty",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-AUD-2026-002",
                    invoice_date=date(2026, 2, 11),
                    subtotal=Decimal("200.00"),
                    total_tax_amount=Decimal("16.00"),
                    total_amount=Decimal("216.00"),
                    currency="USD",
                    total_amount_usd=Decimal("216.00"),
                    confidence_macro_avg=Decimal("96.00"),
                    status="VALIDATED",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-AUD-2026-002", Decimal("216.00")
                    ),
                )
            )

            # 3. Invoice with sensitive PII audit fields (Tax ID & IBAN masking test)
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-aud-pii",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-AUD-2026-003",
                    invoice_date=date(2026, 2, 12),
                    subtotal=Decimal("500.00"),
                    total_tax_amount=Decimal("40.00"),
                    total_amount=Decimal("540.00"),
                    currency="USD",
                    total_amount_usd=Decimal("540.00"),
                    confidence_macro_avg=Decimal("95.00"),
                    status="VALIDATED",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-AUD-2026-003", Decimal("540.00")
                    ),
                )
            )
            await audit_repo.create(
                AuditLog(
                    audit_id="aud-pii-1",
                    invoice_id="inv-aud-pii",
                    user_id="demo-oid-sarah-clerk",
                    action_type="EDIT",
                    field_name="vendor_tax_id",
                    previous_value="US-12-3456789",
                    new_value="US-98-7654321",
                    reason_code="OCR_MISREAD",
                    timestamp=t0,
                )
            )
            await audit_repo.create(
                AuditLog(
                    audit_id="aud-pii-2",
                    invoice_id="inv-aud-pii",
                    user_id="demo-oid-sarah-clerk",
                    action_type="EDIT",
                    field_name="iban",
                    previous_value="DE89370400440532013000",
                    new_value="DE11370400440532019999",
                    reason_code="OCR_MISREAD",
                    timestamp=t0 + timedelta(seconds=10),
                )
            )
            await audit_repo.create(
                AuditLog(
                    audit_id="aud-pii-3",
                    invoice_id="inv-aud-pii",
                    user_id="demo-oid-sarah-clerk",
                    action_type="EDIT",
                    field_name="total_amount",
                    previous_value="500.00",
                    new_value="540.00",
                    reason_code="OCR_MISREAD",
                    timestamp=t0 + timedelta(seconds=20),
                )
            )

            # 4. Invoice ready for end-to-end revalidate -> approve -> audit chain test
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-aud-e2e",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-AUD-E2E-004",
                    invoice_date=date(2026, 2, 14),
                    due_date=date(2026, 3, 14),
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("50.00"),
                    total_amount=Decimal("1050.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1050.00"),
                    confidence_macro_avg=Decimal("88.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-AUD-E2E-004", Decimal("1050.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-aud-e2e",
                    line_number=1,
                    description="Cloud Support",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1000.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("88.00"),
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


# Tests: BR-031, N3, PRD Screen 5, CLAUDE.md §9
def test_get_audit_trail_returns_chronological_immutable_events_with_all_fields(
    audit_env: dict,
) -> None:
    """Verify GET /api/v1/invoices/{id}/audit returns chronological timeline with full audit metadata."""
    client: TestClient = audit_env["client"]
    resp = client.get("/api/v1/invoices/inv-aud-full/audit", headers=_auth_headers("sarah.clerk"))
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("Cache-Control") == "no-store"

    body = resp.json()
    assert body["invoice_id"] == "inv-aud-full"
    assert body["invoice_number"] == "INV-AUD-2026-001"
    assert body["current_status"] == "APPROVED_CLERK"
    assert body["immutable"] is True
    assert body["total_events"] == 5
    assert [e["audit_id"] for e in body["events"]] == ["aud-1", "aud-2", "aud-3", "aud-4", "aud-5"]
    assert [e["action_type"] for e in body["events"]] == [
        "INGEST",
        "EXTRACTION",
        "EDIT",
        "REVALIDATE",
        "APPROVE",
    ]

    edit_ev = body["events"][2]
    assert edit_ev["field_name"] == "total_tax_amount"
    assert edit_ev["previous_value"] == "50.00"
    assert edit_ev["new_value"] == "80.00"
    assert edit_ev["reason_code"] == "OCR_MISREAD"
    assert "[request_id=req-3]" in edit_ev["comment"]

    # Existing invoice with zero audit rows -> 200 OK with empty list
    empty_resp = client.get(
        "/api/v1/invoices/inv-aud-empty/audit", headers=_auth_headers("sarah.clerk")
    )
    assert empty_resp.status_code == 200
    assert empty_resp.json()["total_events"] == 0
    assert empty_resp.json()["events"] == []


# Tests: CLAUDE.md §9, LLD §2.1, CWE-863
def test_get_audit_trail_enforces_rbac_for_clerk_manager_admin_unauth_and_no_role(
    audit_env: dict,
) -> None:
    """Verify unauth=401, all 3 authorized roles (ap_clerk, finance_manager, system_admin)=200, empty roles=403."""
    client: TestClient = audit_env["client"]
    path = "/api/v1/invoices/inv-aud-full/audit"

    assert client.get(path).status_code == 401
    assert client.get(path, headers=_auth_headers("sarah.clerk")).status_code == 200
    assert client.get(path, headers=_auth_headers("michael.manager")).status_code == 200
    assert client.get(path, headers=_auth_headers("dave.admin")).status_code == 200

    # Authenticated principal with no roles -> 403 Forbidden
    app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
        user_id="user-no-role",
        subject="user-no-role",
        tenant_id="00000000-0000-4000-8000-000000000001",
        roles=frozenset(),
    )
    try:
        assert client.get(path).status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)


# Tests: PRD Screen 5, CWE-400, CWE-770
def test_get_audit_trail_supports_action_type_user_id_and_pagination_filters(
    audit_env: dict,
) -> None:
    """Verify action_type multi-filter, user_id filter, and bounded pagination with exact total_events."""
    client: TestClient = audit_env["client"]
    headers = _auth_headers("michael.manager")

    # 1. Multi action_type filter (case-insensitive)
    r_act = client.get(
        "/api/v1/invoices/inv-aud-full/audit?action_type=edit&action_type=APPROVE",
        headers=headers,
    )
    assert r_act.status_code == 200, r_act.text
    act_body = r_act.json()
    assert act_body["total_events"] == 2
    assert [e["action_type"] for e in act_body["events"]] == ["EDIT", "APPROVE"]

    # 2. user_id filter
    r_usr = client.get(
        "/api/v1/invoices/inv-aud-full/audit?user_id=worker-1",
        headers=headers,
    )
    assert r_usr.status_code == 200
    assert r_usr.json()["total_events"] == 1
    assert r_usr.json()["events"][0]["action_type"] == "EXTRACTION"

    # 3. Pagination (total_events=5 across full set, page returns 2 items at offset 1)
    r_page = client.get(
        "/api/v1/invoices/inv-aud-full/audit?limit=2&offset=1",
        headers=headers,
    )
    assert r_page.status_code == 200
    page_body = r_page.json()
    assert page_body["total_events"] == 5
    assert page_body["limit"] == 2
    assert page_body["offset"] == 1
    assert [e["audit_id"] for e in page_body["events"]] == ["aud-2", "aud-3"]


# Tests: End-to-End Phase 9 chain (P9-1 Revalidate -> P9-2 Approve -> P9-3 Audit Trail)
def test_get_audit_trail_end_to_end_after_revalidate_and_approve(
    audit_env: dict,
) -> None:
    """Verify full Phase 9 flow produces complete chronological EDIT -> REVALIDATE -> APPROVE audit trail."""
    client: TestClient = audit_env["client"]
    clerk_headers = _auth_headers("sarah.clerk", request_id="req-e2e-p9")
    admin_headers = _auth_headers("dave.admin")

    # 1. Re-validate tax fix
    r_reval = client.post(
        "/api/v1/invoices/inv-aud-e2e/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "comment": "Fixed 8% sales tax to $80.00",
            "header_edits": {"total_tax_amount": "80.00", "total_amount": "1080.00"},
        },
        headers=clerk_headers,
    )
    assert r_reval.status_code == 200, r_reval.text
    reval_audit_id = r_reval.json()["audit_event_id"]

    # 2. Approve invoice
    r_app = client.post(
        "/api/v1/invoices/inv-aud-e2e/approve",
        json={"comment": "Confirmed totals post-revalidation"},
        headers=clerk_headers,
    )
    assert r_app.status_code == 200, r_app.text
    app_audit_id = r_app.json()["audit_event_id"]

    # 3. Query full audit trail as system_admin (Auditor persona)
    r_aud = client.get("/api/v1/invoices/inv-aud-e2e/audit", headers=admin_headers)
    assert r_aud.status_code == 200, r_aud.text
    body = r_aud.json()
    assert body["current_status"] == "APPROVED_CLERK"
    assert body["total_events"] == 4
    actions = [e["action_type"] for e in body["events"]]
    assert actions == ["EDIT", "EDIT", "REVALIDATE", "APPROVE"]
    assert body["events"][2]["audit_id"] == reval_audit_id
    assert body["events"][3]["audit_id"] == app_audit_id
    for ev in body["events"][:2]:
        assert ev["previous_value"] != ev["new_value"]


# Tests: CLAUDE.md §6, N3, N6 (Strictly read-only / immutable surface)
def test_audit_endpoint_blocks_all_mutating_http_methods_405(
    audit_env: dict,
) -> None:
    """Verify audit trail endpoint exposes zero POST/PUT/PATCH/DELETE methods (immutable append-only)."""
    client: TestClient = audit_env["client"]
    headers = _auth_headers("dave.admin")
    path = "/api/v1/invoices/inv-aud-full/audit"

    assert client.post(path, json={}, headers=headers).status_code == 405
    assert client.put(path, json={}, headers=headers).status_code == 405
    assert client.patch(path, json={}, headers=headers).status_code == 405
    assert client.delete(path, headers=headers).status_code == 405


# Tests: CLAUDE.md §8, N3, N8, CWE-200, CWE-532
def test_get_audit_trail_masks_sensitive_pii_fields_and_never_logs_raw_secrets(
    audit_env: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify SENSITIVE_AUDIT_FIELDS (vendor_tax_id, iban) are masked as ***-**-XXXX and never logged raw."""
    client: TestClient = audit_env["client"]

    with caplog.at_level(logging.DEBUG, logger="ap"):
        resp = client.get("/api/v1/invoices/inv-aud-pii/audit", headers=_auth_headers("dave.admin"))
    assert resp.status_code == 200, resp.text
    events = resp.json()["events"]

    # vendor_tax_id masked
    assert events[0]["field_name"] == "vendor_tax_id"
    assert events[0]["previous_value"] == "***-**-6789"
    assert events[0]["new_value"] == "***-**-4321"
    assert "US-12-3456789" not in resp.text
    assert "US-98-7654321" not in resp.text

    # iban masked
    assert events[1]["field_name"] == "iban"
    assert events[1]["previous_value"] == "***-**-3000"
    assert events[1]["new_value"] == "***-**-9999"
    assert "DE89370400440532013000" not in resp.text

    # Non-sensitive financial total remains visible for audit reconciliation
    assert events[2]["field_name"] == "total_amount"
    assert events[2]["previous_value"] == "500.00"
    assert events[2]["new_value"] == "540.00"

    # Zero raw Tax ID or IBAN in application logs (CWE-532)
    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined_logs
    assert "DE89370400440532013000" not in combined_logs


# Tests: CWE-20, CWE-89, CWE-116, CWE-209, CWE-400
def test_get_audit_trail_blocks_sqli_xss_reflection_excessive_params_and_handles_404_503(
    audit_env: dict,
) -> None:
    """Verify malformed IDs, XSS action_type reflection, param floods, 404, and sanitized 503."""
    client: TestClient = audit_env["client"]
    headers = _auth_headers("sarah.clerk")

    # SQLi / malformed invoice_id -> 422
    for bad_id in ("inv-1' OR '1'='1", "inv;DROP TABLE audit_logs", "a" * 80):
        assert client.get(f"/api/v1/invoices/{bad_id}/audit", headers=headers).status_code == 422

    # Nonexistent invoice_id -> 404
    r_404 = client.get("/api/v1/invoices/inv-does-not-exist/audit", headers=headers)
    assert r_404.status_code == 404
    assert r_404.json() == {"detail": "Invoice not found"}

    # Reflected XSS in action_type -> 422 without echoing script payload (CWE-116)
    r_xss = client.get(
        "/api/v1/invoices/inv-aud-full/audit",
        params={"action_type": "<script>alert(1)</script>"},
        headers=headers,
    )
    assert r_xss.status_code == 422
    assert "<script>" not in r_xss.json()["detail"]

    # Excessive repeated action_type params (> len(AuditActionType)) -> 422 (CWE-400)
    many_actions = [("action_type", "EDIT")] * (len(AuditActionType) + 3)
    assert (
        client.get(
            "/api/v1/invoices/inv-aud-full/audit", params=many_actions, headers=headers
        ).status_code
        == 422
    )

    # Control / bidi chars in user_id and out-of-bounds pagination -> 422
    for bad_params in (
        {"user_id": "bad\r\nuser"},
        {"user_id": "spoof\u202euser"},
        {"limit": 501},
        {"limit": 0},
        {"offset": -1},
    ):
        assert (
            client.get(
                "/api/v1/invoices/inv-aud-full/audit", params=bad_params, headers=headers
            ).status_code
            == 422
        )

    # Database outage -> sanitized 503 (CWE-209)
    class _BrokenSessionCtx:
        async def __aenter__(self):
            raise OperationalError("SELECT * FROM audit_logs", {}, Exception("audit-db-secret"))

        async def __aexit__(self, *args):
            return False

    app.dependency_overrides[get_upload_session_factory] = lambda: lambda: _BrokenSessionCtx()
    r_503 = client.get("/api/v1/invoices/inv-aud-full/audit", headers=headers)
    assert r_503.status_code == 503
    assert "audit-db-secret" not in r_503.json()["detail"]


# Tests: CLAUDE.md §4.2 & §4.3 Layering Rules
def test_audit_route_layering_rules_enforced() -> None:
    """Verify src/api/audit.py exists and obeys strict CLAUDE.md §4.2 layering boundaries."""
    api_path = Path("src/api/audit.py")
    assert api_path.is_file(), "src/api/audit.py must exist per CLAUDE.md §4.3"

    tree = ast.parse(api_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for imp in mods:
            assert not imp.startswith(("src.validation", "src.extraction", "src.storage")), (
                f"Layering violation in src/api/audit.py: forbidden import '{imp}'"
            )


# Tests: SEC-181 (CWE-200 / CWE-359 dotted sensitive field names + embedded comment PII redaction)
def test_audit_sec181_masks_prefixed_sensitive_fields_and_embedded_pii_in_comments(
    audit_env: dict,
) -> None:
    """Verify dotted field names (header.vendor_tax_id) and embedded VAT/IBAN/EIN in comments are masked without corrupting status words."""
    client: TestClient = audit_env["client"]
    session_factory = audit_env["session_factory"]

    async def _seed_prefixed() -> None:
        async with session_factory() as session:
            await AuditLogRepository(session).create(
                AuditLog(
                    audit_id="aud-sec181",
                    invoice_id="inv-aud-empty",
                    user_id="demo-oid-sarah-clerk",
                    action_type="EDIT",
                    field_name="header.vendor_tax_id",
                    previous_value="DE111222333",
                    new_value="DE999888777",
                    reason_code="OCR_MISREAD",
                    comment=(
                        "[request_id=req-99] Verified VAT DE999888777 and IBAN "
                        "DE89370400440532013000 for VALIDATED invoice"
                    ),
                )
            )

    asyncio.run(_seed_prefixed())

    resp = client.get("/api/v1/invoices/inv-aud-empty/audit", headers=_auth_headers("dave.admin"))
    assert resp.status_code == 200, resp.text
    ev = resp.json()["events"][0]
    assert ev["previous_value"] == "***-**-2333"
    assert ev["new_value"] == "***-**-8777"
    assert "DE999888777" not in resp.text
    assert "DE111222333" not in resp.text
    assert "DE89370400440532013000" not in resp.text
    # Ensure request_id and status words are NOT corrupted by masking
    assert "[request_id=req-99]" in ev["comment"]
    assert "VALIDATED" in ev["comment"]


# Tests: SEC-182 (CWE-20 / CWE-400 repository allowlist + param length cap)
def test_audit_sec182_repo_enforces_action_type_allowlist_and_api_caps_param_length(
    audit_env: dict,
) -> None:
    """Verify AuditLogRepository.list_for_invoice rejects unknown action types and API rejects oversized action_type params."""
    client: TestClient = audit_env["client"]
    session_factory = audit_env["session_factory"]

    async def _check_repo() -> None:
        async with session_factory() as session:
            repo = AuditLogRepository(session)
            with pytest.raises(ValueError, match="Unsupported audit action_type"):
                await repo.list_for_invoice("inv-aud-full", action_types=["DROP_TABLE"])

    asyncio.run(_check_repo())

    resp = client.get(
        "/api/v1/invoices/inv-aud-full/audit",
        params={"action_type": "E" * 200},
        headers=_auth_headers("sarah.clerk"),
    )
    assert resp.status_code == 422


# Tests: SEC-183 (CWE-20 / CWE-525 blank user_id rejection + nosniff security header)
def test_audit_sec183_rejects_blank_user_id_and_emits_nosniff_header(
    audit_env: dict,
) -> None:
    """Verify whitespace-only user_id returns 422 instead of dropping filter and response sets X-Content-Type-Options: nosniff."""
    client: TestClient = audit_env["client"]
    headers = _auth_headers("sarah.clerk")

    r_blank = client.get(
        "/api/v1/invoices/inv-aud-full/audit",
        params={"user_id": "   "},
        headers=headers,
    )
    assert r_blank.status_code == 422

    r_ok = client.get("/api/v1/invoices/inv-aud-full/audit", headers=headers)
    assert r_ok.status_code == 200
    assert r_ok.headers.get("Cache-Control") == "no-store"
    assert r_ok.headers.get("X-Content-Type-Options") == "nosniff"
