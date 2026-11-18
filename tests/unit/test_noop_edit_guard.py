"""
Unit, Integration, and Security Tests for the P9-4 No-Op Edit Guard.

Tests: P9-4, FR-12, CLAUDE.md §16.1 ("An audit log row with previous_value = new_value
       (no-op edits must be rejected at the API layer)"), LLD §2.2,
       CWE-20, CWE-116, CWE-176, CWE-532, CWE-778, CWE-840
"""

import asyncio
from datetime import date
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from src.api.invoices import get_upload_session_factory
from src.api.main import app
from src.core.audit import ReasonCode
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
from src.services.revalidation import (
    HeaderEditsInput,
    RevalidationInput,
    RevalidationNoOpError,
    RevalidationService,
)


def _auth_headers(username: str = "sarah.clerk") -> dict[str, str]:
    settings = Settings(APP_ENV="test", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
    token = issue_demo_token(username, settings=settings)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def noop_env(monkeypatch: pytest.MonkeyPatch):
    """Isolated async SQLite DB seeded with DE & US invoices for P9-4 no-op guard testing."""
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

            inv_repo = InvoiceRepository(session)
            line_repo = InvoiceLineRepository(session)

            # 1. DE invoice in REJECTED_TAX_MISMATCH with 2 lines (including NFC Unicode text)
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-noop-de",
                    vendor_tax_id="DE999888777",
                    vendor_name="Berlin Systems GmbH",
                    invoice_number="INV-NOOP-001",
                    invoice_date=date(2026, 2, 14),
                    due_date=date(2026, 3, 14),
                    po_number="PO-DE-100",
                    subtotal=Decimal("1250.00"),
                    total_tax_amount=Decimal("100.00"),
                    total_amount=Decimal("1350.00"),
                    currency="EUR",
                    total_amount_usd=Decimal("1471.50"),
                    confidence_macro_avg=Decimal("88.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "DE999888777", "INV-NOOP-001", Decimal("1350.00")
                    ),
                )
            )
            await line_repo.create_many(
                [
                    InvoiceLine(
                        invoice_id="inv-noop-de",
                        line_number=1,
                        description="M\u00fcnchen Services",  # NFC composed 'ü'
                        quantity=Decimal("10.0000"),
                        unit_price=Decimal("100.0000"),
                        line_total=Decimal("1000.00"),
                        line_tax_rate=Decimal("0.1900"),
                        confidence_score=Decimal("88.00"),
                    ),
                    InvoiceLine(
                        invoice_id="inv-noop-de",
                        line_number=2,
                        description="Berlin Support",
                        quantity=Decimal("2.0000"),
                        unit_price=Decimal("125.0000"),
                        line_total=Decimal("250.00"),
                        line_tax_rate=Decimal("0.1900"),
                        confidence_score=Decimal("88.00"),
                    ),
                ]
            )

            # 2. Zero-tax DE invoice awaiting reverse-charge flag only
            await inv_repo.create(
                Invoice(
                    invoice_id="inv-noop-zero",
                    vendor_tax_id="DE999888777",
                    vendor_name="Berlin Systems GmbH",
                    invoice_number="INV-NOOP-002",
                    invoice_date=date(2026, 2, 14),
                    due_date=date(2026, 3, 14),
                    po_number="PO-DE-200",
                    subtotal=Decimal("1250.00"),
                    total_tax_amount=Decimal("0.00"),
                    total_amount=Decimal("1250.00"),
                    currency="EUR",
                    total_amount_usd=Decimal("1362.50"),
                    confidence_macro_avg=Decimal("89.00"),
                    status="REJECTED_TAX_MISMATCH",
                    composite_hash=compute_composite_hash(
                        "DE999888777", "INV-NOOP-002", Decimal("1250.00")
                    ),
                )
            )
            await line_repo.create(
                InvoiceLine(
                    invoice_id="inv-noop-zero",
                    line_number=1,
                    description="Zero-Rate Consulting",
                    quantity=Decimal("10.0000"),
                    unit_price=Decimal("125.0000"),
                    line_total=Decimal("1250.00"),
                    line_tax_rate=Decimal("0.0000"),
                    confidence_score=Decimal("89.00"),
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


# Tests: P9-4, CLAUDE.md §16.1 (Empty / zero-edit API schema guard)
def test_noop_guard_rejects_empty_revalidate_payload_and_empty_edit_containers_at_schema_layer(
    noop_env: dict,
) -> None:
    """Verify empty revalidate payload, empty header_edits={}, and fieldless line_edits fail with 422."""
    client: TestClient = noop_env["client"]
    session_factory = noop_env["session_factory"]
    headers = _auth_headers()

    for empty_payload in (
        {"reason_code": "OCR_MISREAD"},
        {"reason_code": "OCR_MISREAD", "header_edits": {}},
        {"reason_code": "OCR_MISREAD", "line_edits": []},
        {"reason_code": "OCR_MISREAD", "line_edits": [{"line_number": 1}]},
        {"reason_code": "OCR_MISREAD", "header_edits": {}, "line_edits": []},
    ):
        resp = client.post(
            "/api/v1/invoices/inv-noop-de/revalidate",
            json=empty_payload,
            headers=headers,
        )
        assert resp.status_code == 422, f"Expected 422 for {empty_payload}, got {resp.status_code}"

    async def _verify_zero_side_effects() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-noop-de", include_relations=False)
            assert inv is not None and inv.status == "REJECTED_TAX_MISMATCH"
            assert await AuditLogRepository(session).count_by_invoice_id("inv-noop-de") == 0

    asyncio.run(_verify_zero_side_effects())


# Tests: P9-4, CLAUDE.md §16.1 (Persisted header field no-ops across text, date, and numeric formats)
def test_noop_guard_rejects_unchanged_header_fields_across_text_date_and_numeric_equivalents(
    noop_env: dict,
) -> None:
    """Verify header_edits matching existing persisted values (including decimal/whitespace equivalents) return 422."""
    client: TestClient = noop_env["client"]
    session_factory = noop_env["session_factory"]
    headers = _auth_headers()

    noop_header_cases = [
        {"po_number": "PO-DE-100"},
        {"po_number": "  PO-DE-100  "},
        {"invoice_number": "INV-NOOP-001"},
        {"invoice_date": "2026-02-14"},
        {"due_date": "2026-03-14"},
        {"subtotal": "1250"},
        {"subtotal": "1250.0"},
        {"subtotal": "1250.00"},
        {"subtotal": "+1250.00"},
        {"total_tax_amount": 100.0},
        {"total_amount": "1350.00"},
    ]
    for header_edits in noop_header_cases:
        resp = client.post(
            "/api/v1/invoices/inv-noop-de/revalidate",
            json={"reason_code": "OCR_MISREAD", "header_edits": header_edits},
            headers=headers,
        )
        assert resp.status_code == 422, (
            f"Expected 422 no-op rejection for {header_edits}, got {resp.status_code}: {resp.text}"
        )
        assert "no-op" in resp.json()["detail"].lower()

    async def _verify_untouched() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-noop-de", include_relations=False)
            assert inv is not None and inv.status == "REJECTED_TAX_MISMATCH"
            assert await AuditLogRepository(session).count_by_invoice_id("inv-noop-de") == 0

    asyncio.run(_verify_untouched())


# Tests: P9-4, CLAUDE.md §16.1 (Partial header no-op rejected)
def test_noop_guard_rejects_mixed_header_edits_containing_unchanged_field(
    noop_env: dict,
) -> None:
    """Verify header_edits with one real edit and one unchanged field is rejected (422) naming the unchanged field."""
    client: TestClient = noop_env["client"]
    session_factory = noop_env["session_factory"]

    resp = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "header_edits": {
                "po_number": "PO-DE-999",  # changed
                "total_tax_amount": "100.00",  # unchanged (previous_value == new_value)
            },
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 422, resp.text
    assert "total_tax_amount" in resp.json()["detail"]

    async def _verify_no_partial_commit() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id("inv-noop-de", include_relations=False)
            assert inv is not None
            assert inv.po_number == "PO-DE-100"
            assert inv.status == "REJECTED_TAX_MISMATCH"
            assert await AuditLogRepository(session).count_by_invoice_id("inv-noop-de") == 0

    asyncio.run(_verify_no_partial_commit())


# Tests: P9-4, CLAUDE.md §16.1 (Line-item no-op rejection)
def test_noop_guard_rejects_unchanged_line_edits_and_mixed_multiline_noop(
    noop_env: dict,
) -> None:
    """Verify unchanged line_edits (single-field, full-row, or second untouched line) fail with 422."""
    client: TestClient = noop_env["client"]
    headers = _auth_headers()

    line_noop_payloads = [
        # Full row with identical values (differing scale notation)
        [
            {
                "line_number": 1,
                "description": "M\u00fcnchen Services",
                "quantity": "10",
                "unit_price": "100.0",
                "line_total": "1000.00",
                "line_tax_rate": "0.19",
            }
        ],
        # Single unchanged field
        [{"line_number": 2, "line_total": "250.00"}],
        # Line 1 changed, Line 2 completely unchanged -> reject no-op Line 2 entry
        [
            {"line_number": 1, "description": "Updated Consulting"},
            {"line_number": 2, "quantity": "2.0", "line_total": "250.00"},
        ],
    ]
    for line_edits in line_noop_payloads:
        resp = client.post(
            "/api/v1/invoices/inv-noop-de/revalidate",
            json={"reason_code": "OCR_MISREAD", "line_edits": line_edits},
            headers=headers,
        )
        assert resp.status_code == 422, f"Expected 422 for {line_edits}, got {resp.status_code}"
        assert "no-op" in resp.json()["detail"].lower()


# Tests: LLD §2.2 & PRD Journey 5 compatibility
def test_noop_guard_allows_lld_full_row_line_edit_when_line_field_changes_and_logs_only_diffs(
    noop_env: dict,
) -> None:
    """Verify LLD §2.2 full-row line edit succeeds when >=1 field on each submitted line actually changes."""
    client: TestClient = noop_env["client"]
    session_factory = noop_env["session_factory"]

    resp = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "TAX_CODE_OVERRIDE",
            "comment": "EU reverse charge verified",
            "is_reverse_charge": True,
            "header_edits": {"total_tax_amount": "0.00", "total_amount": "1250.00"},
            "line_edits": [
                {
                    "line_number": 1,
                    "quantity": "10.0",
                    "unit_price": "100.00",
                    "line_total": "1000.00",
                    "line_tax_rate": "0.00",
                },
                {
                    "line_number": 2,
                    "quantity": "2.0",
                    "unit_price": "125.00",
                    "line_total": "250.00",
                    "line_tax_rate": "0.00",
                },
            ],
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "VALIDATED"

    async def _verify_audit_diffs() -> None:
        async with session_factory() as session:
            logs = await AuditLogRepository(session).get_by_invoice_id("inv-noop-de")
            edit_logs = [entry for entry in logs if entry.action_type == "EDIT"]
            assert len(edit_logs) == 5
            for entry in edit_logs:
                assert entry.previous_value != entry.new_value

    asyncio.run(_verify_audit_diffs())


# Tests: Security (CWE-176 Unicode NFC/NFD normalization & negative zero -0.00 evasion)
def test_noop_guard_blocks_negative_zero_and_unicode_nfd_evasion(
    noop_env: dict,
) -> None:
    """Verify -0.00 vs 0.00 and Unicode NFD vs NFC canonically equivalent strings are rejected as no-ops (422)."""
    client: TestClient = noop_env["client"]
    headers = _auth_headers()

    # 1. Negative zero '-0.00' against persisted '0.00'
    r_neg_zero = client.post(
        "/api/v1/invoices/inv-noop-zero/revalidate",
        json={"reason_code": "VENDOR_ROUNDING", "header_edits": {"total_tax_amount": "-0.00"}},
        headers=headers,
    )
    assert r_neg_zero.status_code == 422, r_neg_zero.text

    # 2. Decomposed NFD 'Mu\u0308nchen Services' against persisted NFC 'M\u00fcnchen Services'
    r_nfd = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "line_edits": [{"line_number": 1, "description": "Mu\u0308nchen Services"}],
        },
        headers=headers,
    )
    assert r_nfd.status_code == 422, r_nfd.text


# Tests: PRD Journey 5 first-time flag override vs replayed flag no-op
def test_noop_guard_allows_first_tax_override_flag_only_but_rejects_replayed_flag_noop(
    noop_env: dict,
) -> None:
    """Verify flag-only is_reverse_charge=True succeeds once on 0-tax invoice, then rejects identical replay (422)."""
    client: TestClient = noop_env["client"]
    headers = _auth_headers()

    # First call: transitions REJECTED_TAX_MISMATCH -> VALIDATED via reverse-charge flag
    first = client.post(
        "/api/v1/invoices/inv-noop-zero/revalidate",
        json={
            "reason_code": "TAX_CODE_OVERRIDE",
            "comment": "Supplier reverse-charge note confirmed",
            "is_reverse_charge": True,
        },
        headers=headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "VALIDATED"

    # Second call: replaying exact same flag with zero edits -> 422 no-op!
    replay = client.post(
        "/api/v1/invoices/inv-noop-zero/revalidate",
        json={
            "reason_code": "TAX_CODE_OVERRIDE",
            "comment": "Replaying identical reverse-charge flag",
            "is_reverse_charge": True,
        },
        headers=headers,
    )
    assert replay.status_code == 422, replay.text
    assert "no-op" in replay.json()["detail"].lower()


# Tests: CWE-116 / CWE-532 (No raw value reflection in 422 no-op error messages)
def test_noop_guard_never_reflects_raw_values_in_422_error_detail(
    noop_env: dict,
) -> None:
    """Verify no-op 422 responses report allowlisted field names only without echoing raw field values."""
    client: TestClient = noop_env["client"]

    resp = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-DE-100"}},
        headers=_auth_headers(),
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "po_number" in detail
    assert "PO-DE-100" not in detail


# Tests: SEC-184 (CWE-451 / CWE-840 non-breaking space homoglyph & explicit null rejection)
def test_noop_sec184_blocks_nbsp_homoglyph_evasion_and_explicit_null_fields(
    noop_env: dict,
) -> None:
    """Verify non-ASCII whitespace homoglyphs (\\u00a0) and explicit JSON null fields return 422."""
    client: TestClient = noop_env["client"]
    headers = _auth_headers()

    # 1. Replacing ASCII space with U+00A0 NBSP to bypass no-op guard -> 422
    r_nbsp = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "line_edits": [{"line_number": 2, "description": "Berlin\u00a0Support"}],
        },
        headers=headers,
    )
    assert r_nbsp.status_code == 422

    # 2. Explicit JSON null in header_edits or line_edits -> 422
    r_null_hdr = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "header_edits": {"po_number": "PO-NEW", "due_date": None},
        },
        headers=headers,
    )
    assert r_null_hdr.status_code == 422

    r_null_line = client.post(
        "/api/v1/invoices/inv-noop-de/revalidate",
        json={
            "reason_code": "OCR_MISREAD",
            "line_edits": [{"line_number": 1, "description": "Updated", "line_total": None}],
        },
        headers=headers,
    )
    assert r_null_line.status_code == 422


# Tests: SEC-185 (Direct service-layer empty command fast-fail without DB I/O)
def test_noop_sec185_service_rejects_empty_command_before_touching_db() -> None:
    """Verify RevalidationService fast-fails an empty RevalidationInput with RevalidationNoOpError before opening DB."""

    def _never_open_db():
        raise AssertionError("DB session should never be opened for an empty no-op command")

    service = RevalidationService(_never_open_db)  # type: ignore[arg-type]

    async def _run() -> None:
        with pytest.raises(RevalidationNoOpError):
            await service.revalidate(
                RevalidationInput(
                    invoice_id="inv-any",
                    actor_id="demo-oid-sarah-clerk",
                    reason_code=ReasonCode.OCR_MISREAD,
                    header_edits=HeaderEditsInput(),
                )
            )

    asyncio.run(_run())


# Tests: SEC-186 (CWE-200 Oracle defense: approved invoice returns 409, never 422 no-op)
def test_noop_sec186_approved_invoice_returns_409_not_422_preventing_value_oracle(
    noop_env: dict,
) -> None:
    """Verify probing an APPROVED_CLERK invoice with its exact persisted total returns 409 (FSM first), not 422."""
    client: TestClient = noop_env["client"]
    session_factory = noop_env["session_factory"]

    async def _seed_approved() -> None:
        async with session_factory() as session:
            await InvoiceRepository(session).create(
                Invoice(
                    invoice_id="inv-noop-approved",
                    vendor_tax_id="US-12-3456789",
                    vendor_name="Acme Technologies Inc.",
                    invoice_number="INV-APPROVED-001",
                    invoice_date=date(2026, 2, 10),
                    subtotal=Decimal("500.00"),
                    total_tax_amount=Decimal("40.00"),
                    total_amount=Decimal("540.00"),
                    currency="USD",
                    total_amount_usd=Decimal("540.00"),
                    confidence_macro_avg=Decimal("97.00"),
                    status="APPROVED_CLERK",
                    composite_hash=compute_composite_hash(
                        "US-12-3456789", "INV-APPROVED-001", Decimal("540.00")
                    ),
                )
            )

    asyncio.run(_seed_approved())

    # Both matching and non-matching guesses MUST return 409 Conflict identically (zero value oracle!)
    r_match = client.post(
        "/api/v1/invoices/inv-noop-approved/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"total_amount": "540.00"}},
        headers=_auth_headers(),
    )
    r_miss = client.post(
        "/api/v1/invoices/inv-noop-approved/revalidate",
        json={"reason_code": "OCR_MISREAD", "header_edits": {"total_amount": "999.00"}},
        headers=_auth_headers(),
    )
    assert r_match.status_code == 409
    assert r_miss.status_code == 409
