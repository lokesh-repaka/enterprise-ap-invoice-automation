"""
Unit, Integration, and Security Tests for POST /api/v1/invoices/{id}/approve (P9-2).

Tests: FR-13, BR-012a, BR-014, BR-015, PRD Journey 7, LLD §2.1, §4,
       CLAUDE.md §2, §3, §4.2, §8, §9, §16 Rule 8, §16.1,
       CWE-20, CWE-117, CWE-209, CWE-290, CWE-362, CWE-400, CWE-451, CWE-532, CWE-840, CWE-863, CWE-915
"""

import ast
import asyncio
import logging
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from src.api.approvals import _resolve_effective_approver_role
from src.api.invoices import get_upload_session_factory
from src.api.main import app
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.core.security import AuthenticatedUser, Role
from src.database.models import AuditLog, Base, ExchangeRate, Invoice, InvoiceLine, Vendor
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
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
def approve_env(monkeypatch: pytest.MonkeyPatch):
    """Isolated async SQLite DB seeded with vendors, ECB FX rates, and approval test invoices."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "10000.00")
    monkeypatch.setenv("PO_VARIANCE_TOLERANCE_PERCENT", "5.0")
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
                    standard_tax_rate=Decimal("0.0800"),
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
                    standard_tax_rate=Decimal("0.1900"),
                    is_active=True,
                )
            )
            await v_repo.create(
                Vendor(
                    vendor_tax_id="GB555444333",
                    vendor_id="VEND-1003",
                    vendor_name="Meridian Software Ltd.",
                    country_code="GB",
                    date_format_locale="DD/MM/YYYY",
                    default_currency="GBP",
                    tax_scheme="UK_VAT",
                    standard_tax_rate=Decimal("0.2000"),
                    is_active=True,
                )
            )
            await v_repo.create(
                Vendor(
                    vendor_tax_id="US-99-INACTIVE",
                    vendor_id="VEND-INACTIVE",
                    vendor_name="Deactivated Corp",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    is_active=False,
                )
            )

            # Seed EUR->USD ECB rate (deliberately omit GBP to test fail-closed FX guard)
            fx_repo = ExchangeRateRepository(session)
            await fx_repo.create(
                ExchangeRate(
                    rate_date=date(2026, 2, 1),
                    from_currency="EUR",
                    to_currency="USD",
                    exchange_rate=Decimal("1.090000"),
                )
            )

            inv_repo = InvoiceRepository(session)
            line_repo = InvoiceLineRepository(session)

            core_fixtures = [
                # 1. Clean VALIDATED USD invoice <= $10,000 (clerk eligible)
                (
                    "inv-val-low",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-001",
                    date(2026, 2, 10),
                    Decimal("2500.00"),
                    "USD",
                    Decimal("2500.00"),
                    Decimal("96.50"),
                    "VALIDATED",
                ),
                # 2. Exact $10,000.00 boundary VALIDATED USD invoice (clerk eligible: strict > $10k)
                (
                    "inv-val-exact10k",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-002",
                    date(2026, 2, 10),
                    Decimal("10000.00"),
                    "USD",
                    Decimal("10000.00"),
                    Decimal("95.00"),
                    "VALIDATED",
                ),
                # 3. $10,000.01 VALIDATED USD invoice (1 cent over threshold -> manager required!)
                (
                    "inv-val-over10k",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-003",
                    date(2026, 2, 11),
                    Decimal("10000.01"),
                    "USD",
                    Decimal("10000.01"),
                    Decimal("97.00"),
                    "VALIDATED",
                ),
                # 4. Mid-range $6,000.00 VALIDATED invoice (tests dynamic settings threshold)
                (
                    "inv-val-6k",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-004",
                    date(2026, 2, 11),
                    Decimal("6000.00"),
                    "USD",
                    Decimal("6000.00"),
                    Decimal("94.00"),
                    "VALIDATED",
                ),
                # 5. High-value REQUIRES_MANAGER_APPROVAL ($14,500.00 — PRD Journey 7)
                (
                    "inv-mgr-14500",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-005",
                    date(2026, 2, 12),
                    Decimal("14500.00"),
                    "USD",
                    Decimal("14500.00"),
                    Decimal("95.50"),
                    "REQUIRES_MANAGER_APPROVAL",
                ),
                # 6. EUR invoice (€9,500 -> $10,355 USD at 1.09) with stale/understated SQL total_amount_usd!
                (
                    "inv-eur-stale-fx",
                    "DE999888777",
                    "Berlin Systems GmbH",
                    "INV-APP-006",
                    date(2026, 2, 14),
                    Decimal("9500.00"),
                    "EUR",
                    Decimal("9000.00"),  # Deliberately stale/understated to prove live ECB FX check
                    Decimal("95.00"),
                    "VALIDATED",
                ),
                # 7. GBP VALIDATED invoice with NO ECB FX rate seeded (fail-closed 422)
                (
                    "inv-gbp-nofx",
                    "GB555444333",
                    "Meridian Software Ltd.",
                    "INV-APP-007",
                    date(2026, 2, 15),
                    Decimal("5000.00"),
                    "GBP",
                    None,
                    Decimal("94.00"),
                    "VALIDATED",
                ),
                # 8. Negative-balance credit note mistakenly sitting in VALIDATED (CLAUDE.md §16.1)
                (
                    "inv-val-neg",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-008",
                    date(2026, 2, 15),
                    Decimal("-500.00"),
                    "USD",
                    Decimal("-500.00"),
                    Decimal("95.00"),
                    "VALIDATED",
                ),
                # 9. Positive header total with negative line item (credit note check)
                (
                    "inv-val-neg-line",
                    "US-12-3456789",
                    "Acme Technologies Inc.",
                    "INV-APP-009",
                    date(2026, 2, 15),
                    Decimal("500.00"),
                    "USD",
                    Decimal("500.00"),
                    Decimal("95.00"),
                    "VALIDATED",
                ),
                # 10. Inactive vendor invoice in VALIDATED
                (
                    "inv-inactive",
                    "US-99-INACTIVE",
                    "Deactivated Corp",
                    "INV-APP-010",
                    date(2026, 2, 15),
                    Decimal("500.00"),
                    "USD",
                    Decimal("500.00"),
                    Decimal("95.00"),
                    "VALIDATED",
                ),
            ]
            for inv_id, tax_id, vname, num, dt, tot, curr, usd, conf, st in core_fixtures:
                await inv_repo.create(
                    Invoice(
                        invoice_id=inv_id,
                        vendor_tax_id=tax_id,
                        vendor_name=vname,
                        invoice_number=num,
                        invoice_date=dt,
                        subtotal=tot,
                        total_tax_amount=Decimal("0.00"),
                        total_amount=tot,
                        currency=curr,
                        total_amount_usd=usd,
                        confidence_macro_avg=conf,
                        status=st,
                        composite_hash=compute_composite_hash(tax_id, num, tot),
                    )
                )

            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-val-neg-line",
                    line_number=1,
                    description="Credit Memo Rebate Line",
                    quantity=Decimal("1.0000"),
                    unit_price=Decimal("-100.0000"),
                    line_total=Decimal("-100.00"),
                    line_tax_rate=Decimal("0.0000"),
                    confidence_score=Decimal("95.00"),
                )
            )

            # Non-approvable FSM statuses (15 statuses -> all must return 409)
            non_approvable = [
                "UPLOADED",
                "EXTRACTING",
                "REQUIRES_REVIEW",
                "REQUIRES_APPROVAL",
                "REJECTED_TAX_MISMATCH",
                "REVALIDATING",
                "DUPLICATE_INVOICE",
                "FLAGGED_POTENTIAL_REVISION",
                "CREDIT_NOTE",
                "APPROVED_CLERK",
                "APPROVED_MANAGER",
                "STAGED_FOR_EXPORT",
                "REJECTED",
                "REJECTED_DUPLICATE",
                "VOID",
            ]
            for idx, st in enumerate(non_approvable, start=1):
                inv_id = f"inv-nonapp-{idx}"
                inv_num = f"INV-NA-{idx:03d}"
                await inv_repo.create(
                    Invoice(
                        invoice_id=inv_id,
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Acme Technologies Inc.",
                        invoice_number=inv_num,
                        invoice_date=date(2026, 2, 1),
                        subtotal=Decimal("400.00"),
                        total_tax_amount=Decimal("0.00"),
                        total_amount=Decimal("400.00"),
                        currency="USD",
                        total_amount_usd=Decimal("400.00"),
                        confidence_macro_avg=Decimal("95.00"),
                        status=st,
                        composite_hash=compute_composite_hash(
                            "US-12-3456789", inv_num, Decimal("400.00")
                        ),
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


# Tests: FR-13, BR-015, CLAUDE.md §2, §9, LLD §4
def test_clerk_one_click_approval_under_and_at_10k_transitions_to_approved_clerk_and_audits(
    approve_env: dict,
) -> None:
    """Verify AP Clerk approves VALIDATED invoices <= $10,000 (including exact $10,000.00) with audit log."""
    client: TestClient = approve_env["client"]
    session_factory = approve_env["session_factory"]

    # 1. One-click approval with empty body (< $10,000)
    resp_low = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        headers=_auth_headers("sarah.clerk", request_id="req-app-001"),
    )
    assert resp_low.status_code == 200, resp_low.text
    assert resp_low.headers.get("Cache-Control") == "no-store"

    body = resp_low.json()
    assert body["invoice_id"] == "inv-val-low"
    assert body["previous_status"] == "VALIDATED"
    assert body["status"] == "APPROVED_CLERK"
    assert body["approved_by"] == "demo-oid-sarah-clerk"
    assert body["approver_role"] == "ap_clerk"
    assert Decimal(body["total_amount"]) == Decimal("2500.00")
    assert Decimal(body["total_amount_usd"]) == Decimal("2500.00")
    assert Decimal(body["high_value_threshold_usd"]) == Decimal("10000.00")
    assert body["requires_manager_approval"] is False
    assert body["audit_event_id"]

    # 2. Exact $10,000.00 boundary -> still eligible for clerk approval (strict > $10k rule)
    resp_exact = client.post(
        "/api/v1/invoices/inv-val-exact10k/approve",
        json={"comment": "Exact 10k boundary approved by clerk"},
        headers=_auth_headers("sarah.clerk", request_id="req-app-002"),
    )
    assert resp_exact.status_code == 200, resp_exact.text
    assert resp_exact.json()["status"] == "APPROVED_CLERK"

    # Verify SQL persistence & immutable APPROVE audit logs
    async def _verify_db() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-val-low", include_relations=False)
            assert inv is not None
            assert inv.status == "APPROVED_CLERK"

            logs = await AuditLogRepository(session).get_by_invoice_id("inv-val-low")
            assert len(logs) == 1
            assert logs[0].audit_id == body["audit_event_id"]
            assert logs[0].action_type == "APPROVE"
            assert logs[0].user_id == "demo-oid-sarah-clerk"
            assert logs[0].field_name == "status"
            assert logs[0].previous_value == "VALIDATED"
            assert logs[0].new_value == "APPROVED_CLERK"
            assert "[request_id=req-app-001]" in (logs[0].comment or "")

    asyncio.run(_verify_db())


# Tests: FR-13, BR-014, PRD Journey 7, LLD §4
def test_manager_approves_requires_manager_approval_high_value_invoice(
    approve_env: dict,
) -> None:
    """Verify PRD Journey 7: Finance Manager approves >$10,000 invoice -> APPROVED_MANAGER + audit log."""
    client: TestClient = approve_env["client"]
    session_factory = approve_env["session_factory"]

    resp = client.post(
        "/api/v1/invoices/inv-mgr-14500/approve",
        json={"comment": "Reviewed against Master Services Agreement and approved."},
        headers=_auth_headers("michael.manager", request_id="req-mgr-001"),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("Cache-Control") == "no-store"

    body = resp.json()
    assert body["invoice_id"] == "inv-mgr-14500"
    assert body["previous_status"] == "REQUIRES_MANAGER_APPROVAL"
    assert body["status"] == "APPROVED_MANAGER"
    assert body["approved_by"] == "demo-oid-michael-manager"
    assert body["approver_role"] == "finance_manager"
    assert body["requires_manager_approval"] is True
    assert Decimal(body["total_amount_usd"]) == Decimal("14500.00")

    async def _verify_db() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id(
                "inv-mgr-14500", include_relations=False
            )
            assert inv is not None
            assert inv.status == "APPROVED_MANAGER"

            logs = await AuditLogRepository(session).get_by_invoice_id("inv-mgr-14500")
            assert len(logs) == 1
            assert logs[0].action_type == "APPROVE"
            assert logs[0].user_id == "demo-oid-michael-manager"
            assert logs[0].previous_value == "REQUIRES_MANAGER_APPROVAL"
            assert logs[0].new_value == "APPROVED_MANAGER"
            assert "[request_id=req-mgr-001]" in (logs[0].comment or "")
            assert "Master Services Agreement" in (logs[0].comment or "")

    asyncio.run(_verify_db())


# Tests: FR-13, BR-014, CLAUDE.md §8, §16.1, CWE-863
def test_clerk_blocked_with_403_on_manager_queue_high_value_stale_fx_and_po_variance(
    approve_env: dict,
) -> None:
    """Verify AP Clerk receives 403 on REQUIRES_MANAGER_APPROVAL, >$10k USD, EUR>$10k stale FX, and >5% PO variance."""
    client: TestClient = approve_env["client"]
    session_factory = approve_env["session_factory"]
    clerk_headers = _auth_headers("sarah.clerk")

    # 1. Invoice in REQUIRES_MANAGER_APPROVAL -> 403
    r_mgr_q = client.post("/api/v1/invoices/inv-mgr-14500/approve", headers=clerk_headers)
    assert r_mgr_q.status_code == 403

    # 2. VALIDATED invoice at $10,000.01 (1 cent over threshold) -> 403
    r_over = client.post("/api/v1/invoices/inv-val-over10k/approve", headers=clerk_headers)
    assert r_over.status_code == 403

    # 3. VALIDATED EUR invoice (€9,500 * 1.09 = $10,355 USD > $10k) despite stale $9,000 SQL column -> 403
    r_eur = client.post("/api/v1/invoices/inv-eur-stale-fx/approve", headers=clerk_headers)
    assert r_eur.status_code == 403

    # 4. VALIDATED $2,500 invoice with PO $2,300 (8.70% > 5% variance) -> 403
    r_po = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        json={"po_amount": "2300.00"},
        headers=clerk_headers,
    )
    assert r_po.status_code == 403

    # Verify zero status mutations and zero APPROVE audit logs across all 4 blocked attempts
    async def _verify_untouched() -> None:
        async with session_factory() as session:
            inv_repo = InvoiceRepository(session)
            audit_repo = AuditLogRepository(session)
            for inv_id, expected in (
                ("inv-mgr-14500", "REQUIRES_MANAGER_APPROVAL"),
                ("inv-val-over10k", "VALIDATED"),
                ("inv-eur-stale-fx", "VALIDATED"),
                ("inv-val-low", "VALIDATED"),
            ):
                inv = await inv_repo.get_by_id(inv_id, include_relations=False)
                assert inv is not None and inv.status == expected
                assert await audit_repo.count_by_invoice_id(inv_id) == 0

    asyncio.run(_verify_untouched())


# Tests: CLAUDE.md §2, FR-13
def test_manager_can_approve_validated_low_value_and_validated_high_value_invoices(
    approve_env: dict,
) -> None:
    """Verify finance_manager can approve <=$10k VALIDATED (-> APPROVED_CLERK) and >$10k VALIDATED (-> APPROVED_MANAGER)."""
    client: TestClient = approve_env["client"]
    mgr_headers = _auth_headers("michael.manager")

    # 1. Manager approving <=$10k VALIDATED -> APPROVED_CLERK
    r_low = client.post("/api/v1/invoices/inv-val-low/approve", headers=mgr_headers)
    assert r_low.status_code == 200, r_low.text
    assert r_low.json()["status"] == "APPROVED_CLERK"
    assert r_low.json()["approver_role"] == "finance_manager"

    # 2. Manager approving >$10k VALIDATED -> escalates & approves to APPROVED_MANAGER
    r_high = client.post("/api/v1/invoices/inv-val-over10k/approve", headers=mgr_headers)
    assert r_high.status_code == 200, r_high.text
    assert r_high.json()["status"] == "APPROVED_MANAGER"
    assert r_high.json()["requires_manager_approval"] is True

    # 3. Manager approving EUR invoice (€9,500 * 1.09 = $10,355 USD) -> updates total_amount_usd & APPROVED_MANAGER
    r_eur = client.post("/api/v1/invoices/inv-eur-stale-fx/approve", headers=mgr_headers)
    assert r_eur.status_code == 200, r_eur.text
    assert r_eur.json()["status"] == "APPROVED_MANAGER"
    assert Decimal(r_eur.json()["total_amount_usd"]) == Decimal("10355.00")


# Tests: CLAUDE.md §16 Rule 8 (Thresholds from get_settings(), not hardcoded)
def test_approve_uses_high_value_threshold_dynamically_from_settings(
    approve_env: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify HIGH_VALUE_THRESHOLD_USD is read from get_settings() rather than hardcoded $10,000."""
    client: TestClient = approve_env["client"]
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "5000.00")
    get_settings.cache_clear()

    # $6,000 exceeds custom $5,000 threshold -> clerk blocked (403), manager succeeds (APPROVED_MANAGER)
    r_clerk = client.post(
        "/api/v1/invoices/inv-val-6k/approve",
        headers=_auth_headers("sarah.clerk"),
    )
    assert r_clerk.status_code == 403

    r_mgr = client.post(
        "/api/v1/invoices/inv-val-6k/approve",
        headers=_auth_headers("michael.manager"),
    )
    assert r_mgr.status_code == 200, r_mgr.text
    body = r_mgr.json()
    assert body["status"] == "APPROVED_MANAGER"
    assert Decimal(body["high_value_threshold_usd"]) == Decimal("5000.00")


# Tests: CLAUDE.md §9, CWE-290, CWE-863
def test_approve_enforces_rbac_and_blocks_approver_id_spoofing(
    approve_env: dict,
) -> None:
    """Verify unauth=401, system_admin=403, mismatched approver_id=403, and JWT identity used for audit."""
    client: TestClient = approve_env["client"]

    assert client.post("/api/v1/invoices/inv-val-low/approve").status_code == 401
    assert (
        client.post(
            "/api/v1/invoices/inv-val-low/approve",
            headers=_auth_headers("dave.admin"),
        ).status_code
        == 403
    )

    # Actor spoofing: sarah.clerk submitting michael.manager's approver_id -> 403
    r_spoof = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        json={"approver_id": "michael.manager@company.com"},
        headers=_auth_headers("sarah.clerk"),
    )
    assert r_spoof.status_code == 403

    # Matching JWT email succeeds and records JWT user_id
    r_ok = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        json={"approver_id": "sarah.clerk@company.com"},
        headers=_auth_headers("sarah.clerk"),
    )
    assert r_ok.status_code == 200, r_ok.text
    assert r_ok.json()["approved_by"] == "demo-oid-sarah-clerk"


# Tests: LLD §4, P8-2 FSM integration, CWE-840
def test_approve_blocks_all_non_approvable_states_and_double_approval_with_409(
    approve_env: dict,
) -> None:
    """Verify non-approvable/terminal/already-approved states return 409 Conflict for both roles."""
    client: TestClient = approve_env["client"]
    clerk_headers = _auth_headers("sarah.clerk")
    mgr_headers = _auth_headers("michael.manager")

    for idx in range(1, 16):
        inv_id = f"inv-nonapp-{idx}"
        assert (
            client.post(f"/api/v1/invoices/{inv_id}/approve", headers=clerk_headers).status_code
            == 409
        )
        assert (
            client.post(f"/api/v1/invoices/{inv_id}/approve", headers=mgr_headers).status_code
            == 409
        )

    # Double-approval replay guard: first call succeeds (200), second call conflicts (409)
    first = client.post("/api/v1/invoices/inv-val-low/approve", headers=clerk_headers)
    assert first.status_code == 200
    second = client.post("/api/v1/invoices/inv-val-low/approve", headers=clerk_headers)
    assert second.status_code == 409


# Tests: CLAUDE.md §16.1, BR-012a, CWE-840
def test_approve_blocks_credit_notes_missing_fx_and_inactive_vendors(
    approve_env: dict,
) -> None:
    """Verify negative-balance credit notes return 409 and missing FX / inactive vendor return 422."""
    client: TestClient = approve_env["client"]
    mgr_headers = _auth_headers("michael.manager")

    # Negative header total and negative line item must NEVER be approved (CLAUDE.md §16.1)
    assert (
        client.post("/api/v1/invoices/inv-val-neg/approve", headers=mgr_headers).status_code == 409
    )
    assert (
        client.post("/api/v1/invoices/inv-val-neg-line/approve", headers=mgr_headers).status_code
        == 409
    )

    # Missing ECB FX rate for GBP -> fail closed (422)
    r_fx = client.post("/api/v1/invoices/inv-gbp-nofx/approve", headers=mgr_headers)
    assert r_fx.status_code == 422

    # Inactive vendor -> fail closed (422)
    r_inactive = client.post("/api/v1/invoices/inv-inactive/approve", headers=mgr_headers)
    assert r_inactive.status_code == 422
    assert "inactive" in r_inactive.json()["detail"].lower()


# Tests: CWE-20, CWE-117, CWE-209, CWE-400, CWE-451, CWE-532, CWE-915
def test_approve_blocks_mass_assignment_malformed_inputs_oversized_body_and_db_outage(
    approve_env: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify extra='forbid', control/bidi rejection, 64KB cap, 404, sanitized 503, and zero PII in logs."""
    client: TestClient = approve_env["client"]
    headers = _auth_headers("sarah.clerk")

    # Mass assignment & malformed payloads -> 422
    for bad in (
        {"status": "APPROVED_MANAGER"},
        {"total_amount_usd": "1.00"},
        {"approver_role": "finance_manager"},
        {"approver_id": "   "},
        {"comment": "evil\r\nnewline"},
        {"comment": "spoof\u202ebidi"},
        {"po_amount": "-10.00"},
        {"po_amount": True},
    ):
        r = client.post("/api/v1/invoices/inv-val-low/approve", json=bad, headers=headers)
        assert r.status_code == 422, f"Expected 422 for {bad}, got {r.status_code}: {r.text}"

    # Oversized Content-Length (> 64 KB) -> 413; malformed Content-Length -> 400
    r_big = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        content=b"{}",
        headers={**headers, "Content-Type": "application/json", "Content-Length": "100000"},
    )
    assert r_big.status_code == 413

    # SQLi invoice_id -> 422; nonexistent invoice_id -> 404
    assert (
        client.post("/api/v1/invoices/inv-1' OR '1'='1/approve", headers=headers).status_code == 422
    )
    r_404 = client.post("/api/v1/invoices/inv-does-not-exist/approve", headers=headers)
    assert r_404.status_code == 404
    assert r_404.json() == {"detail": "Invoice not found"}

    # Zero raw Tax ID leakage in logs during approval (CWE-532)
    with caplog.at_level(logging.DEBUG, logger="ap"):
        assert (
            client.post("/api/v1/invoices/inv-val-low/approve", headers=headers).status_code == 200
        )
    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined_logs

    # Simulated DB outage -> sanitized 503 (CWE-209)
    class _BrokenSessionCtx:
        async def __aenter__(self):
            raise OperationalError("SELECT * FROM invoices", {}, Exception("sql-secret-token"))

        async def __aexit__(self, *args):
            return False

    app.dependency_overrides[get_upload_session_factory] = lambda: lambda: _BrokenSessionCtx()
    r_503 = client.post("/api/v1/invoices/inv-val-6k/approve", headers=headers)
    assert r_503.status_code == 503
    assert "sql-secret-token" not in r_503.json()["detail"]


# Tests: CLAUDE.md §3 FR-13 & §4.2 Layering Rules
def test_approve_layering_rules_enforced() -> None:
    """Verify src/api/approvals.py delegates to src/services/approval.py with zero cross-layer imports."""
    api_path = Path("src/api/approvals.py")
    svc_path = Path("src/services/approval.py")
    assert api_path.is_file(), "src/api/approvals.py must exist per CLAUDE.md §3 FR-13"
    assert svc_path.is_file(), "src/services/approval.py must exist per CLAUDE.md §4.2"

    svc_tree = ast.parse(svc_path.read_text(encoding="utf-8"))
    for node in ast.walk(svc_tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for imp in mods:
            assert not imp.startswith(("fastapi", "starlette", "httpx", "openai", "src.api")), (
                f"Layering violation in src/services/approval.py: forbidden import '{imp}'"
            )

    api_tree = ast.parse(api_path.read_text(encoding="utf-8"))
    for node in ast.walk(api_tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for imp in mods:
            assert not imp.startswith("src.validation"), (
                f"Layering violation in src/api/approvals.py: forbidden import '{imp}'"
            )


# Tests: SEC-177 (BR-015 sub-90% un-revalidated guard + 2-step manager escalation audit trail)
def test_approve_sec177_blocks_unrevalidated_sub90_confidence_and_audits_two_step_escalation(
    approve_env: dict,
) -> None:
    """Verify sub-90% VALIDATED invoice requires prior REVALIDATE for clerk approval, and 2-step manager approval logs both edges."""
    client: TestClient = approve_env["client"]
    session_factory = approve_env["session_factory"]

    async def _seed_low_conf() -> None:
        async with session_factory() as session:
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-val-sub90",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-SUB90-01",
                    invoice_date=date(2026, 2, 10),
                    subtotal=Decimal("500.00"),
                    total_tax_amount=Decimal("0.00"),
                    total_amount=Decimal("500.00"),
                    currency="USD",
                    total_amount_usd=Decimal("500.00"),
                    confidence_macro_avg=Decimal("84.00"),
                    status="VALIDATED",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-SUB90-01", Decimal("500.00")
                    ),
                )
            )

    asyncio.run(_seed_low_conf())

    # 1. Never re-validated + 84% confidence -> clerk blocked (409 Conflict: BR-015)
    r_blocked = client.post(
        "/api/v1/invoices/inv-val-sub90/approve",
        headers=_auth_headers("sarah.clerk"),
    )
    assert r_blocked.status_code == 409
    assert "re-validation" in r_blocked.json()["detail"].lower()

    # 2. Record prior REVALIDATE audit event -> clerk approval now succeeds (PRD Journey 5)
    async def _add_revalidate_audit() -> None:
        async with session_factory() as session:
            await AuditLogRepository(session).create(
                AuditLog(
                    invoice_id="inv-val-sub90",
                    user_id="demo-oid-sarah-clerk",
                    action_type="REVALIDATE",
                    field_name="status",
                    previous_value="REQUIRES_REVIEW",
                    new_value="VALIDATED",
                    reason_code="OCR_MISREAD",
                )
            )

    asyncio.run(_add_revalidate_audit())
    r_ok = client.post(
        "/api/v1/invoices/inv-val-sub90/approve",
        headers=_auth_headers("sarah.clerk"),
    )
    assert r_ok.status_code == 200, r_ok.text
    assert r_ok.json()["status"] == "APPROVED_CLERK"

    # 3. Manager approving high-value VALIDATED logs BOTH STATUS_TRANSITION and APPROVE edges
    r_mgr = client.post(
        "/api/v1/invoices/inv-val-over10k/approve",
        headers=_auth_headers("michael.manager"),
    )
    assert r_mgr.status_code == 200, r_mgr.text

    async def _verify_two_step_audit() -> None:
        async with session_factory() as session:
            logs = await AuditLogRepository(session).get_by_invoice_id("inv-val-over10k")
            assert len(logs) == 2
            assert logs[0].action_type == "STATUS_TRANSITION"
            assert logs[0].previous_value == "VALIDATED"
            assert logs[0].new_value == "REQUIRES_MANAGER_APPROVAL"
            assert logs[1].action_type == "APPROVE"
            assert logs[1].previous_value == "REQUIRES_MANAGER_APPROVAL"
            assert logs[1].new_value == "APPROVED_MANAGER"

    asyncio.run(_verify_two_step_audit())


# Tests: SEC-178 (CWE-284 / CWE-345)
def test_approve_sec178_blocks_unextracted_pending_placeholder_invoice(
    approve_env: dict,
) -> None:
    """Verify unextracted PENDING- placeholder invoice cannot be approved (422)."""
    client: TestClient = approve_env["client"]
    session_factory = approve_env["session_factory"]

    async def _seed_pending() -> None:
        async with session_factory() as session:
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-pending-placeholder",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="PENDING-abcdef123456",
                    invoice_date=date(2026, 2, 10),
                    subtotal=Decimal("100.00"),
                    total_tax_amount=Decimal("0.00"),
                    total_amount=Decimal("100.00"),
                    currency="USD",
                    total_amount_usd=Decimal("100.00"),
                    confidence_macro_avg=Decimal("95.00"),
                    status="VALIDATED",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "PENDING-abcdef123456", Decimal("100.00")
                    ),
                )
            )

    asyncio.run(_seed_pending())
    resp = client.post(
        "/api/v1/invoices/inv-pending-placeholder/approve",
        headers=_auth_headers("michael.manager"),
    )
    assert resp.status_code == 422
    assert "placeholder" in resp.json()["detail"].lower()


# Tests: SEC-179 (CWE-636 fail-closed role resolution)
def test_approve_sec179_resolve_effective_role_fails_closed_for_unauthorized_roles() -> None:
    """Verify _resolve_effective_approver_role raises 403 rather than defaulting to ap_clerk."""
    from fastapi import HTTPException

    for bad_roles in (frozenset(), frozenset({Role.SYSTEM_ADMIN})):
        user = AuthenticatedUser(
            user_id="user-unauthorized",
            subject="user-unauthorized",
            tenant_id="00000000-0000-4000-8000-000000000001",
            roles=bad_roles,
        )
        with pytest.raises(HTTPException) as exc_info:
            _resolve_effective_approver_role(user)
        assert exc_info.value.status_code == 403


# Tests: SEC-180 (CWE-400 chunked & malformed Content-Length protection)
def test_approve_sec180_blocks_malformed_content_length_and_oversized_body(
    approve_env: dict,
) -> None:
    """Verify malformed Content-Length returns 400 and >64 KB body returns 413."""
    client: TestClient = approve_env["client"]
    headers = _auth_headers("sarah.clerk")

    r_bad_len = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        content=b"{}",
        headers={**headers, "Content-Type": "application/json", "Content-Length": "not-an-int"},
    )
    assert r_bad_len.status_code == 400

    oversized_body = b'{"comment": "' + (b"a" * 70_000) + b'"}'
    r_oversized = client.post(
        "/api/v1/invoices/inv-val-low/approve",
        content=oversized_body,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert r_oversized.status_code == 413
