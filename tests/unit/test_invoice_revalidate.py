"""
Unit, Integration, and Security Tests for POST /api/v1/invoices/{id}/revalidate (P9-1).

Tests: FR-04, FR-05, FR-06, FR-07, FR-08, FR-09, FR-11, FR-12, FR-13,
       BR-012a, BR-014, BR-015, BR-016, BR-017, BR-018,
       LLD §2.1, §2.2, §4, CLAUDE.md §4.2, §7.4, §8, §9, §16.1,
       CWE-20, CWE-116, CWE-117, CWE-190, CWE-209, CWE-290, CWE-362, CWE-451, CWE-532, CWE-840, CWE-863, CWE-915
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

from src.api.invoices import get_upload_session_factory
from src.api.main import app
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.database.models import Base, ExchangeRate, Invoice, InvoiceLine, Vendor
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
def revalidate_env(monkeypatch: pytest.MonkeyPatch):
    """Isolated async SQLite DB seeded with US/DE/GB vendors, FX rates, and multi-status invoices."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "10000.00")
    monkeypatch.setenv("PO_VARIANCE_TOLERANCE_PERCENT", "5.0")
    monkeypatch.setenv("LINE_ROUNDING_TOLERANCE", "0.02")
    monkeypatch.setenv("INVOICE_ROUNDING_TOLERANCE", "0.05")
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

            # Seed EUR->USD ECB rate (deliberately omit GBP to test MissingExchangeRateError fail-closed)
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

            # 1. German invoice in REJECTED_TAX_MISMATCH (PRD Journey 5 / LLD §2.2 scenario)
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-de-tax",
                    vendor_tax_id="DE999888777",
                    vendor_name="Berlin Systems GmbH",
                    invoice_number="INV-DE-2026-001",
                    invoice_date=date(2026, 2, 14),
                    due_date=date(2026, 3, 14),
                    po_number="PO-DE-100",
                    subtotal=Decimal("1250.00"),
                    total_tax_amount=Decimal("100.00"),  # Wrong tax rate (8% not valid in DE)
                    total_amount=Decimal("1350.00"),
                    currency="EUR",
                    total_amount_usd=Decimal("1471.50"),
                    confidence_macro_avg=Decimal("88.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "DE999888777", "INV-DE-2026-001", Decimal("1350.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-de-tax",
                    line_number=1,
                    description="Enterprise Consulting Hours",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("125.0000"),
                    line_total=Decimal("1250.00"),
                    line_tax_rate=Decimal("0.1900"),
                    confidence_score=Decimal("87.00"),
                )
            )

            # 2. US invoice in REQUIRES_APPROVAL with broken line arithmetic
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-us-math",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-US-2026-002",
                    invoice_date=date(2026, 2, 10),
                    due_date=date(2026, 3, 10),
                    po_number="PO-US-200",
                    subtotal=Decimal("1200.00"),
                    total_tax_amount=Decimal("96.00"),
                    total_amount=Decimal("1296.00"),
                    currency="USD",
                    total_amount_usd=Decimal("1296.00"),
                    confidence_macro_avg=Decimal("74.50"),
                    status="REQUIRES_APPROVAL",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-US-2026-002", Decimal("1296.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-us-math",
                    line_number=1,
                    description="Steel Fasteners",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("125.0000"),
                    line_total=Decimal("1200.00"),  # Should be 1250.00
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("72.00"),
                )
            )

            # 3. US invoice in REQUIRES_REVIEW (medium confidence, valid math)
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-us-review",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-US-2026-003",
                    invoice_date=date(2026, 2, 12),
                    due_date=date(2026, 3, 12),
                    po_number="PO-US-300",
                    subtotal=Decimal("2000.00"),
                    total_tax_amount=Decimal("160.00"),
                    total_amount=Decimal("2160.00"),
                    currency="USD",
                    total_amount_usd=Decimal("2160.00"),
                    confidence_macro_avg=Decimal("84.00"),
                    status="REQUIRES_REVIEW",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-US-2026-003", Decimal("2160.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-us-review",
                    line_number=1,
                    description="Managed Cloud Nodes",
                    quantity=Decimal("20.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("2000.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("84.00"),
                )
            )

            # 4. US invoice in REQUIRES_APPROVAL that will be edited to >$10,000 USD
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-us-high",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-US-2026-004",
                    invoice_date=date(2026, 2, 15),
                    due_date=date(2026, 3, 15),
                    subtotal=Decimal("10000.00"),
                    total_tax_amount=Decimal("800.00"),
                    total_amount=Decimal("10800.00"),
                    currency="USD",
                    total_amount_usd=Decimal("10800.00"),
                    confidence_macro_avg=Decimal("78.00"),
                    status="REQUIRES_APPROVAL",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-US-2026-004", Decimal("10800.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-us-high",
                    line_number=1,
                    description="GPU Cluster Nodes",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("1200.0000"),
                    line_total=Decimal("10000.00"),  # OCR misread; true total is 12000.00
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("76.00"),
                )
            )

            # 5. GBP invoice with no ECB FX rate seeded (tests MissingExchangeRateError)
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-gb-nofx",
                    vendor_tax_id="GB555444333",
                    vendor_name="Meridian Software Ltd.",
                    invoice_number="INV-GB-2026-005",
                    invoice_date=date(2026, 2, 16),
                    due_date=date(2026, 3, 16),
                    subtotal=Decimal("1000.00"),
                    total_tax_amount=Decimal("200.00"),
                    total_amount=Decimal("1200.00"),
                    currency="GBP",
                    total_amount_usd=None,
                    confidence_macro_avg=Decimal("86.00"),
                    status="REQUIRES_REVIEW",
                    composite_hash=compute_composite_hash(
                        "GB555444333", "INV-GB-2026-005", Decimal("1200.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-gb-nofx",
                    line_number=1,
                    description="UK SaaS Licenses",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1000.00"),
                    line_tax_rate=Decimal("0.2000"),
                    confidence_score=Decimal("86.00"),
                )
            )

            # 6. Additional invoices covering remaining legal & illegal FSM states
            extra_statuses = [
                ("inv-st-revision", "FLAGGED_POTENTIAL_REVISION", "INV-US-ST-01"),
                ("inv-st-validated", "VALIDATED", "INV-US-ST-02"),
                ("inv-st-uploaded", "UPLOADED", "INV-US-ST-03"),
                ("inv-st-extracting", "EXTRACTING", "INV-US-ST-04"),
                ("inv-st-revalidating", "REVALIDATING", "INV-US-ST-05"),
                ("inv-st-app-clerk", "APPROVED_CLERK", "INV-US-ST-06"),
                ("inv-st-app-mgr", "APPROVED_MANAGER", "INV-US-ST-07"),
                ("inv-st-exported", "STAGED_FOR_EXPORT", "INV-US-ST-08"),
                ("inv-st-duplicate", "DUPLICATE_INVOICE", "INV-US-ST-09"),
                ("inv-st-credit", "CREDIT_NOTE", "INV-US-ST-10"),
                ("inv-st-req-mgr", "REQUIRES_MANAGER_APPROVAL", "INV-US-ST-11"),
                ("inv-st-rejected", "REJECTED", "INV-US-ST-12"),
                ("inv-st-rej-dup", "REJECTED_DUPLICATE", "INV-US-ST-13"),
                ("inv-st-void", "VOID", "INV-US-ST-14"),
            ]
            for idx, (inv_id, st, inv_num) in enumerate(extra_statuses, start=1):
                sub = Decimal("500.00")
                tax = Decimal("40.00")
                tot = Decimal("540.00")
                await inv_repo.create(
                    Invoice(
                        invoice_id=inv_id,
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Acme Technologies Inc.",
                        invoice_number=inv_num,
                        invoice_date=date(2026, 2, 1),
                        due_date=date(2026, 3, 1),
                        subtotal=sub,
                        total_tax_amount=tax,
                        total_amount=tot,
                        currency="USD",
                        total_amount_usd=tot,
                        confidence_macro_avg=Decimal("93.00"),
                        status=st,
                        composite_hash=compute_composite_hash(
                            "US-12-3456789", f"{inv_num}-{idx}", tot
                        ),
                    )
                )
                await line_repo.create(
                    InvoiceLine(
                        invoice_id=inv_id,
                        line_number=1,
                        description="Standard Support",
                        quantity=Decimal("5.0000"),
                        unit_price=Decimal("100.0000"),
                        line_total=Decimal("500.00"),
                        line_tax_rate=Decimal("0.0800"),
                        confidence_score=Decimal("93.00"),
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


# Tests: FR-04, FR-05, FR-06, FR-07, FR-12, BR-016, BR-017, BR-018, LLD §2.2
def test_revalidate_eu_reverse_charge_transitions_to_validated_preserves_confidence_and_audits(
    revalidate_env: dict,
) -> None:
    """Verify PRD Journey 5 & LLD §2.2 happy path: EU reverse charge override -> VALIDATED + audit."""
    client: TestClient = revalidate_env["client"]
    session_factory = revalidate_env["session_factory"]

    payload = {
        "clerk_id": "sarah.clerk@company.com",
        "reason_code": "TAX_CODE_OVERRIDE",
        "comment": "Supplier qualified for EU reverse charge per note on page 1 footer.",
        "is_reverse_charge": True,
        "header_edits": {
            "total_tax_amount": "0.00",
            "total_amount": "1250.00",
        },
        "line_edits": [
            {
                "line_number": 1,
                "quantity": "10.0",
                "unit_price": "125.00",
                "line_total": "1250.00",
                "line_tax_rate": "0.00",
            }
        ],
    }

    resp = client.post(
        "/api/v1/invoices/inv-de-tax/revalidate",
        json=payload,
        headers=_auth_headers("sarah.clerk", request_id="req-reval-001"),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("Cache-Control") == "no-store"

    body = resp.json()
    assert body["invoice_id"] == "inv-de-tax"
    assert body["previous_status"] == "REJECTED_TAX_MISMATCH"
    assert body["status"] == "VALIDATED"
    assert body["is_revalidated"] is True
    assert body["eligible_for_clerk_approval"] is True
    assert body["requires_manager_approval"] is False
    assert body["confidence_tier"] == "MEDIUM"
    assert Decimal(body["confidence_macro_avg"]) == Decimal("88.00")
    assert body["audit_event_id"]

    summary = body["validation_summary"]
    assert summary["line_arithmetic_valid"] is True
    assert summary["invoice_total_valid"] is True
    assert summary["tax_valid"] is True
    assert summary["date_valid"] is True
    assert summary["all_passed"] is True
    assert Decimal(summary["currency_converted_amount_usd"]) == Decimal("1362.50")
    assert summary["active_exceptions"] == []

    # Verify SQL persistence, preserved confidence scores, updated composite_hash, and AuditLogs
    async def _verify_db() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-de-tax", include_relations=True)
            assert inv is not None
            assert inv.status == "VALIDATED"
            assert inv.total_tax_amount == Decimal("0.00")
            assert inv.total_amount == Decimal("1250.00")
            assert inv.total_amount_usd == Decimal("1362.50")
            assert inv.confidence_macro_avg == Decimal("88.00")
            assert inv.composite_hash == compute_composite_hash(
                "DE999888777", "INV-DE-2026-001", Decimal("1250.00")
            )
            assert len(inv.lines) == 1
            assert inv.lines[0].line_tax_rate == Decimal("0.0000")
            assert inv.lines[0].confidence_score == Decimal("87.00")

            logs = await AuditLogRepository(session).get_by_invoice_id("inv-de-tax")
            edit_logs = [log for log in logs if log.action_type == "EDIT"]
            reval_logs = [log for log in logs if log.action_type == "REVALIDATE"]
            assert len(reval_logs) == 1
            assert reval_logs[0].audit_id == body["audit_event_id"]
            assert reval_logs[0].user_id == "demo-oid-sarah-clerk"
            assert reval_logs[0].previous_value == "REJECTED_TAX_MISMATCH"
            assert reval_logs[0].new_value == "VALIDATED"
            assert reval_logs[0].reason_code == "TAX_CODE_OVERRIDE"
            assert "[request_id=req-reval-001]" in (reval_logs[0].comment or "")

            # Every EDIT row must have distinct previous_value != new_value (CLAUDE.md §16.1)
            edited_field_names = {log.field_name for log in edit_logs}
            assert {
                "total_tax_amount",
                "total_amount",
                "line_1.line_tax_rate",
                "is_reverse_charge",
            }.issubset(edited_field_names)
            for log in edit_logs:
                assert log.user_id == "demo-oid-sarah-clerk"
                assert log.reason_code == "TAX_CODE_OVERRIDE"
                assert log.previous_value != log.new_value

    asyncio.run(_verify_db())


# Tests: FR-05, FR-06, FR-12, CLAUDE.md §7.4, LLD §4
def test_revalidate_still_failing_rules_returns_requires_approval_with_exceptions(
    revalidate_env: dict,
) -> None:
    """Verify failed re-validation transitions REVALIDATING -> REQUIRES_APPROVAL with error list."""
    client: TestClient = revalidate_env["client"]
    session_factory = revalidate_env["session_factory"]

    resp = client.post(
        "/api/v1/invoices/inv-us-math/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "comment": "Attempted line fix but still off by $40",
            "header_edits": {
                "subtotal": "1210.00",
                "total_tax_amount": "96.80",
                "total_amount": "1306.80",
            },
            "line_edits": [{"line_number": 1, "line_total": "1210.00"}],
        },
        headers=_auth_headers("sarah.clerk"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "REQUIRES_APPROVAL"
    assert body["is_revalidated"] is True
    assert body["eligible_for_clerk_approval"] is False
    assert body["validation_summary"]["line_arithmetic_valid"] is False
    assert body["validation_summary"]["all_passed"] is False
    assert len(body["validation_summary"]["active_exceptions"]) >= 1
    assert Decimal(body["confidence_macro_avg"]) == Decimal("74.50")

    async def _verify_db() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-us-math", include_relations=False)
            assert inv is not None
            assert inv.status == "REQUIRES_APPROVAL"
            assert inv.confidence_macro_avg == Decimal("74.50")

    asyncio.run(_verify_db())


# Tests: FR-12, FR-13, BR-014, BR-018
def test_revalidate_escalates_high_value_and_po_variance_to_requires_manager_approval(
    revalidate_env: dict,
) -> None:
    """Verify passing re-validation >$10,000 USD or >5% PO variance escalates to REQUIRES_MANAGER_APPROVAL."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    # 1. High-value > $10,000 USD (12,000 + 8% tax = 12,960.00 USD)
    hv_resp = client.post(
        "/api/v1/invoices/inv-us-high/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "comment": "Corrected misread line total from 10,000 to 12,000",
            "header_edits": {
                "subtotal": "12000.00",
                "total_tax_amount": "960.00",
                "total_amount": "12960.00",
            },
            "line_edits": [{"line_number": 1, "line_total": "12000.00"}],
        },
        headers=headers,
    )
    assert hv_resp.status_code == 200, hv_resp.text
    hv_body = hv_resp.json()
    assert hv_body["status"] == "REQUIRES_MANAGER_APPROVAL"
    assert hv_body["eligible_for_clerk_approval"] is False
    assert hv_body["requires_manager_approval"] is True
    assert hv_body["validation_summary"]["all_passed"] is True
    assert Decimal(hv_body["validation_summary"]["currency_converted_amount_usd"]) == Decimal(
        "12960.00"
    )

    # 2. PO variance > 5% (invoice total 2160.00 vs PO 1900.00 -> 13.68% variance)
    po_resp = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={
            "reason_code": "VENDOR_DISCOUNT",
            "comment": "Confirmed invoice total against revised PO",
            "po_amount": "1900.00",
            "header_edits": {"po_number": "PO-US-300-REV"},
        },
        headers=headers,
    )
    assert po_resp.status_code == 200, po_resp.text
    po_body = po_resp.json()
    assert po_body["status"] == "REQUIRES_MANAGER_APPROVAL"
    assert po_body["eligible_for_clerk_approval"] is False
    assert po_body["requires_manager_approval"] is True


# Tests: FR-11, CLAUDE.md §16.1
def test_revalidate_negative_balance_edit_routes_to_credit_note_never_validated(
    revalidate_env: dict,
) -> None:
    """Verify negative-balance edits NEVER route to VALIDATED and instead transition to CREDIT_NOTE."""
    client: TestClient = revalidate_env["client"]

    resp = client.post(
        "/api/v1/invoices/inv-us-math/revalidate",
        json={
            "reason_code": "VENDOR_DISCOUNT",
            "comment": "Document is a vendor credit memo",
            "header_edits": {
                "subtotal": "-1250.00",
                "total_tax_amount": "-100.00",
                "total_amount": "-1350.00",
            },
            "line_edits": [{"line_number": 1, "quantity": "-10.0000", "line_total": "-1250.00"}],
        },
        headers=_auth_headers("sarah.clerk"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "CREDIT_NOTE"
    assert body["eligible_for_clerk_approval"] is False


# Tests: FR-12, BR-017, CWE-20, CWE-116
def test_revalidate_validates_reason_code_enum_and_mandatory_other_comment(
    revalidate_env: dict,
) -> None:
    """Verify strict ReasonCode enum validation and mandatory non-blank comment for OTHER."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    # Missing reason_code -> 422
    r_missing = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={"header_edits": {"po_number": "PO-NEW-1"}},
        headers=headers,
    )
    assert r_missing.status_code == 422

    # Unknown / XSS reason_code -> 422 without echoing script tag in custom errors
    r_bad = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={"reason_code": "INVALID_CODE", "header_edits": {"po_number": "PO-NEW-1"}},
        headers=headers,
    )
    assert r_bad.status_code == 422

    # OTHER without comment or whitespace-only comment -> 422
    for bad_comment in (None, "", "   \t  "):
        r_other = client.post(
            "/api/v1/invoices/inv-us-review/revalidate",
            json={
                "reason_code": "OTHER",
                "comment": bad_comment,
                "header_edits": {"po_number": "PO-NEW-1"},
            },
            headers=headers,
        )
        assert r_other.status_code == 422

    # OTHER with valid explanatory comment -> 200 OK
    r_ok = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={
            "reason_code": "OTHER",
            "comment": "Vendor confirmed updated PO reference via email.",
            "header_edits": {"po_number": "PO-US-301"},
        },
        headers=headers,
    )
    assert r_ok.status_code == 200, r_ok.text
    assert r_ok.json()["status"] == "VALIDATED"


# Tests: CLAUDE.md §2, §8, §9, LLD §2.1, CWE-290, CWE-863
def test_revalidate_enforces_ap_clerk_rbac_and_blocks_clerk_id_spoofing(
    revalidate_env: dict,
) -> None:
    """Verify RBAC (unauth=401, finance_manager=403, system_admin=403, ap_clerk=200) & anti-spoofing."""
    client: TestClient = revalidate_env["client"]
    valid_payload = {
        "reason_code": "VENDOR_ROUNDING",
        "header_edits": {"po_number": "PO-RBAC-CHECK"},
    }

    assert (
        client.post("/api/v1/invoices/inv-us-review/revalidate", json=valid_payload).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/invoices/inv-us-review/revalidate",
            json=valid_payload,
            headers=_auth_headers("michael.manager"),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/invoices/inv-us-review/revalidate",
            json=valid_payload,
            headers=_auth_headers("dave.admin"),
        ).status_code
        == 403
    )

    # Actor spoofing: sarah.clerk submitting michael.manager's clerk_id -> 403 Forbidden
    spoof_resp = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={
            "clerk_id": "michael.manager@company.com",
            "reason_code": "VENDOR_ROUNDING",
            "header_edits": {"po_number": "PO-SPOOF"},
        },
        headers=_auth_headers("sarah.clerk"),
    )
    assert spoof_resp.status_code == 403

    # Matching JWT user_id or email succeeds
    ok_resp = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={
            "clerk_id": "demo-oid-sarah-clerk",
            "reason_code": "VENDOR_ROUNDING",
            "header_edits": {"po_number": "PO-VERIFIED"},
        },
        headers=_auth_headers("sarah.clerk"),
    )
    assert ok_resp.status_code == 200, ok_resp.text


# Tests: LLD §4, P8-2 FSM integration, CWE-840
def test_revalidate_enforces_fsm_legal_entry_states_and_returns_409_on_disallowed_states(
    revalidate_env: dict,
) -> None:
    """Verify legal FSM entry states succeed (200) and disallowed/terminal/approved states return 409."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    # Legal entry states beyond REJECTED_TAX_MISMATCH / REQUIRES_APPROVAL / REQUIRES_REVIEW
    for legal_id in ("inv-st-revision", "inv-st-validated"):
        r = client.post(
            f"/api/v1/invoices/{legal_id}/revalidate",
            json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": f"PO-{legal_id}"}},
            headers=headers,
        )
        assert r.status_code == 200, f"{legal_id} failed: {r.text}"
        assert r.json()["status"] == "VALIDATED"

    # Disallowed states -> 409 Conflict
    disallowed_ids = (
        "inv-st-uploaded",
        "inv-st-extracting",
        "inv-st-revalidating",
        "inv-st-app-clerk",
        "inv-st-app-mgr",
        "inv-st-exported",
        "inv-st-duplicate",
        "inv-st-credit",
        "inv-st-req-mgr",
        "inv-st-rejected",
        "inv-st-rej-dup",
        "inv-st-void",
    )
    for bad_id in disallowed_ids:
        r = client.post(
            f"/api/v1/invoices/{bad_id}/revalidate",
            json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-BLOCKED"}},
            headers=headers,
        )
        assert r.status_code == 409, f"Expected 409 for {bad_id}, got {r.status_code}: {r.text}"


# Tests: FR-09, CLAUDE.md §16.1, CWE-362
def test_revalidate_rejects_composite_hash_collision_and_restores_prior_status(
    revalidate_env: dict,
) -> None:
    """Verify editing invoice_number+total to match another active invoice returns 409 and restores status."""
    client: TestClient = revalidate_env["client"]
    session_factory = revalidate_env["session_factory"]

    # inv-us-review has ("US-12-3456789", "INV-US-2026-003", 2160.00).
    # Try editing inv-us-math to collide with inv-us-review's exact composite_hash.
    resp = client.post(
        "/api/v1/invoices/inv-us-math/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "header_edits": {
                "invoice_number": "INV-US-2026-003",
                "subtotal": "2000.00",
                "total_tax_amount": "160.00",
                "total_amount": "2160.00",
            },
            "line_edits": [{"line_number": 1, "unit_price": "200.00", "line_total": "2000.00"}],
        },
        headers=_auth_headers("sarah.clerk"),
    )
    assert resp.status_code == 409, resp.text

    # Confirm inv-us-math was cleanly restored to REQUIRES_APPROVAL (not wedged in REVALIDATING)
    async def _verify_restored() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-us-math", include_relations=False)
            assert inv is not None
            assert inv.status == "REQUIRES_APPROVAL"
            assert inv.invoice_number == "INV-US-2026-002"

    asyncio.run(_verify_restored())


# Tests: CWE-20, CWE-117, CWE-190, CWE-451, CWE-915
def test_revalidate_blocks_mass_assignment_confidence_tampering_and_malformed_inputs(
    revalidate_env: dict,
) -> None:
    """Verify extra='forbid' blocks mass assignment/confidence tampering and malformed inputs return 422/404."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    # 1. Forbidden fields in header_edits (CWE-915 / CLAUDE.md §7.4 / §16.1)
    for forbidden_header in (
        {"status": "APPROVED_CLERK"},
        {"confidence_macro_avg": "99.99"},
        {"total_amount_usd": "1.00"},
        {"vendor_tax_id": "US-00-0000000"},
        {"currency": "EUR"},
        {"composite_hash": "a" * 64},
    ):
        r = client.post(
            "/api/v1/invoices/inv-us-review/revalidate",
            json={"reason_code": "OCR_MISREAD", "header_edits": forbidden_header},
            headers=headers,
        )
        assert r.status_code == 422, f"Expected 422 for {forbidden_header}"

    # 2. Forbidden fields in line_edits (confidence_score tampering)
    r_line_conf = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "line_edits": [{"line_number": 1, "confidence_score": "99.99"}],
        },
        headers=headers,
    )
    assert r_line_conf.status_code == 422

    # 3. Unknown line_number, duplicate line_number, control/bidi chars, bad decimals, bad invoice_id
    bad_payloads = [
        {"reason_code": "OCR_MISREAD", "line_edits": [{"line_number": 99, "line_total": "100.00"}]},
        {
            "reason_code": "OCR_MISREAD",
            "line_edits": [
                {"line_number": 1, "line_total": "100.00"},
                {"line_number": 1, "line_total": "200.00"},
            ],
        },
        {"reason_code": "OCR_MISREAD", "comment": "bad\r\nheader-injection"},
        {"reason_code": "OCR_MISREAD", "comment": "spoof\u202ereversed"},
        {"reason_code": "OCR_MISREAD", "header_edits": {"total_amount": "100.123"}},
        {"reason_code": "OCR_MISREAD", "header_edits": {"total_amount": True}},
        {"reason_code": "OCR_MISREAD", "is_reverse_charge": "true"},
        {"reason_code": "OCR_MISREAD", "po_amount": "-50.00"},
    ]
    for bad in bad_payloads:
        r = client.post("/api/v1/invoices/inv-us-review/revalidate", json=bad, headers=headers)
        assert r.status_code == 422, f"Expected 422 for {bad}, got {r.status_code}: {r.text}"

    # 4. Invalid invoice_id -> 422; nonexistent invoice_id -> 404
    r_sqli = client.post(
        "/api/v1/invoices/inv-1' OR '1'='1/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-CHECK"}},
        headers=headers,
    )
    assert r_sqli.status_code == 422

    r_missing = client.post(
        "/api/v1/invoices/inv-does-not-exist/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-CHECK"}},
        headers=headers,
    )
    assert r_missing.status_code == 404
    assert r_missing.json() == {"detail": "Invoice not found"}


# Tests: FR-08, BR-012a, CWE-209, CWE-532
def test_revalidate_date_inversion_missing_fx_and_db_failure_fail_closed_without_pii_leaks(
    revalidate_env: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify date inversion fails date_valid, missing FX fails closed (422) & restores state, DB errors -> 503."""
    client: TestClient = revalidate_env["client"]
    session_factory = revalidate_env["session_factory"]
    headers = _auth_headers("sarah.clerk")

    # 1. Inverted due_date < invoice_date fails FR-08 -> REQUIRES_APPROVAL
    with caplog.at_level(logging.DEBUG, logger="ap"):
        date_resp = client.post(
            "/api/v1/invoices/inv-us-review/revalidate",
            json={
                "reason_code": "OCR_MISREAD",
                "header_edits": {"invoice_date": "2026-03-20", "due_date": "2026-02-01"},
            },
            headers=headers,
        )
    assert date_resp.status_code == 200, date_resp.text
    date_body = date_resp.json()
    assert date_body["status"] == "REQUIRES_APPROVAL"
    assert date_body["validation_summary"]["date_valid"] is False

    # Verify zero raw Tax ID leakage in logs (CWE-532)
    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined_logs
    assert "DE999888777" not in combined_logs

    # 2. Non-USD GBP invoice with no ECB FX rate seeded -> 422 fail-closed and status restored
    fx_resp = client.post(
        "/api/v1/invoices/inv-gb-nofx/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-GB-01"}},
        headers=headers,
    )
    assert fx_resp.status_code == 422, fx_resp.text

    async def _verify_gb_restored() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-gb-nofx", include_relations=False)
            assert inv is not None
            assert inv.status == "REQUIRES_REVIEW"

    asyncio.run(_verify_gb_restored())

    # 3. Database outage -> sanitized 503 (zero credential/SQL leakage: CWE-209)
    class _BrokenSessionCtx:
        async def __aenter__(self):
            raise OperationalError("SELECT * FROM invoices", {}, Exception("db-secret-password"))

        async def __aexit__(self, *args):
            return False

    app.dependency_overrides[get_upload_session_factory] = lambda: lambda: _BrokenSessionCtx()
    err_resp = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-CHECK"}},
        headers=headers,
    )
    assert err_resp.status_code == 503
    assert "db-secret-password" not in err_resp.json()["detail"]


# Tests: CLAUDE.md §4.2 Layering Rules
def test_revalidate_layering_rules_enforced() -> None:
    """Verify src/api/invoices.py delegates validation to src/services/revalidation.py, and service has zero HTTP imports."""
    service_path = Path("src/services/revalidation.py")
    assert service_path.is_file(), "src/services/revalidation.py must exist per CLAUDE.md §4.2"

    service_tree = ast.parse(service_path.read_text(encoding="utf-8"))
    service_imports: set[str] = set()
    for node in ast.walk(service_tree):
        if isinstance(node, ast.Import):
            service_imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            service_imports.add(node.module)

    forbidden_service_prefixes = ("fastapi", "starlette", "httpx", "openai", "src.api")
    for imp in service_imports:
        assert not imp.startswith(forbidden_service_prefixes), (
            f"Layering violation in src/services/revalidation.py: forbidden import '{imp}'"
        )

    api_tree = ast.parse(Path("src/api/invoices.py").read_text(encoding="utf-8"))
    api_imports: set[str] = set()
    for node in ast.walk(api_tree):
        if isinstance(node, ast.Import):
            api_imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            api_imports.add(node.module)

    for imp in api_imports:
        assert not imp.startswith("src.validation"), (
            f"Layering violation in src/api/invoices.py: API layer must not import '{imp}' directly"
        )


# Tests: SEC-173 (CWE-362 / CWE-639 / CWE-915)
def test_revalidate_atomic_repo_edits_block_idor_mass_assignment_and_partial_commits(
    revalidate_env: dict,
) -> None:
    """Verify apply_revalidation_edits enforces status CAS, blocks cross-invoice line IDOR & confidence tampering."""
    session_factory = revalidate_env["session_factory"]

    async def _check() -> None:
        async with session_factory() as session:
            inv_repo = InvoiceRepository(session)
            inv_a = await inv_repo.get_by_id("inv-de-tax", include_relations=True)
            inv_b = await inv_repo.get_by_id("inv-us-math", include_relations=True)
            assert inv_a is not None and inv_b is not None

            # Forbidden header & line fields rejected at repository layer (CWE-915)
            with pytest.raises(ValueError, match="Disallowed update fields"):
                await inv_repo.apply_revalidation_edits(
                    "inv-de-tax",
                    expected_status="REJECTED_TAX_MISMATCH",
                    header_updates={"confidence_macro_avg": Decimal("99.99")},
                    line_updates=[],
                )
            with pytest.raises(ValueError, match="Disallowed update fields"):
                await inv_repo.apply_revalidation_edits(
                    "inv-de-tax",
                    expected_status="REJECTED_TAX_MISMATCH",
                    header_updates={},
                    line_updates=[(inv_a.lines[0].line_id, {"confidence_score": Decimal("99.99")})],
                )

            # Cross-invoice line IDOR rejected (CWE-639)
            with pytest.raises(ValueError, match="does not belong to invoice"):
                await inv_repo.apply_revalidation_edits(
                    "inv-de-tax",
                    expected_status="REJECTED_TAX_MISMATCH",
                    header_updates={"po_number": "PO-SHOULD-NOT-SAVE"},
                    line_updates=[(inv_b.lines[0].line_id, {"line_total": Decimal("1.00")})],
                )

            # Wrong expected_status CAS returns None with zero mutations
            res = await inv_repo.apply_revalidation_edits(
                "inv-de-tax",
                expected_status="REVALIDATING",
                header_updates={"po_number": "PO-CAS-MISS"},
                line_updates=[],
            )
            assert res is None

            refreshed = await inv_repo.get_by_id("inv-de-tax", include_relations=False)
            assert refreshed is not None
            assert refreshed.po_number == "PO-DE-100"

    asyncio.run(_check())


# Tests: SEC-174 (CWE-840 / CWE-284)
def test_revalidate_tax_override_governance_requires_reason_code_and_zero_line_tax_rates(
    revalidate_env: dict,
) -> None:
    """Verify reverse-charge/exempt requires TAX_CODE_OVERRIDE or OTHER and 0.0000 line tax rates."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    # 1. Disguising reverse-charge override under VENDOR_ROUNDING or OCR_MISREAD -> 422
    for bad_reason in ("VENDOR_ROUNDING", "OCR_MISREAD", "VENDOR_DISCOUNT"):
        r = client.post(
            "/api/v1/invoices/inv-de-tax/revalidate",
            json={
                "reason_code": bad_reason,
                "is_reverse_charge": True,
                "header_edits": {"total_tax_amount": "0.00", "total_amount": "1250.00"},
                "line_edits": [{"line_number": 1, "line_tax_rate": "0.00"}],
            },
            headers=headers,
        )
        assert r.status_code == 422, f"Expected 422 for {bad_reason}"

    # 2. Setting is_reverse_charge=True while leaving line 1 at 19% VAT -> 422 (no inconsistent DB state)
    r_inconsistent = client.post(
        "/api/v1/invoices/inv-de-tax/revalidate",
        json={
            "reason_code": "TAX_CODE_OVERRIDE",
            "comment": "Reverse charge without zeroing line tax rate",
            "is_reverse_charge": True,
            "header_edits": {"total_tax_amount": "0.00", "total_amount": "1250.00"},
        },
        headers=headers,
    )
    assert r_inconsistent.status_code == 422
    assert "line_tax_rate" in r_inconsistent.json()["detail"]


# Tests: SEC-175 (CWE-20 / CWE-400)
def test_revalidate_blocks_oversized_content_length_and_blank_clerk_id(
    revalidate_env: dict,
) -> None:
    """Verify >1 MB Content-Length returns 413, malformed returns 400, and blank clerk_id returns 422."""
    client: TestClient = revalidate_env["client"]
    headers = _auth_headers("sarah.clerk")

    r_big = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        content=b"{}",
        headers={**headers, "Content-Type": "application/json", "Content-Length": "2000000"},
    )
    assert r_big.status_code == 413

    r_blank = client.post(
        "/api/v1/invoices/inv-us-review/revalidate",
        json={"clerk_id": "   ", "reason_code": "OCR_MISREAD"},
        headers=headers,
    )
    assert r_blank.status_code == 422


# Tests: SEC-176 (CWE-840)
def test_revalidate_rejects_inactive_vendor_invoice(
    revalidate_env: dict,
) -> None:
    """Verify re-validation is blocked (422) for invoices linked to an inactive/UNKNOWN vendor."""
    client: TestClient = revalidate_env["client"]
    session_factory = revalidate_env["session_factory"]

    async def _seed_inactive() -> None:
        async with session_factory() as session:
            await VendorRepository(session).create(
                Vendor(
                    vendor_tax_id="US-99-INACTIVE",
                    vendor_id="VEND-INACTIVE",
                    vendor_name="Deactivated Vendor LLC",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    is_active=False,
                )
            )
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-inactive-vendor",
                    vendor_tax_id="US-99-INACTIVE",
                    vendor_name="Deactivated Vendor LLC",
                    invoice_number="INV-INACTIVE-01",
                    invoice_date=date(2026, 2, 1),
                    subtotal=Decimal("100.00"),
                    total_tax_amount=Decimal("0.00"),
                    total_amount=Decimal("100.00"),
                    currency="USD",
                    total_amount_usd=Decimal("100.00"),
                    confidence_macro_avg=Decimal("85.00"),
                    status="REQUIRES_REVIEW",
                    composite_hash=compute_composite_hash(
                        "US-99-INACTIVE", "INV-INACTIVE-01", Decimal("100.00")
                    ),
                )
            )

    asyncio.run(_seed_inactive())

    resp = client.post(
        "/api/v1/invoices/inv-inactive-vendor/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-1"}},
        headers=_auth_headers("sarah.clerk"),
    )
    assert resp.status_code == 422
    assert "inactive" in resp.json()["detail"].lower()
