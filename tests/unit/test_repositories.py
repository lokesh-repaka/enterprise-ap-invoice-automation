"""
Unit tests for Async Repository Layer — CRUD for all 5 tables.

Tests: P2-3 · VendorRepository, InvoiceRepository, InvoiceLineRepository,
              AuditLogRepository (append-only), ExchangeRateRepository.
Requirements: CLAUDE.md §4.2, §6, FR-08, N3, N8.
"""

import asyncio
from datetime import date
from decimal import Decimal

import pytest

from src.database.models import (
    AuditLog,
    Base,
    ExchangeRate,
    Invoice,
    InvoiceLine,
    Vendor,
)
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    VendorRepository,
)
from src.database.session import create_db_engine, create_session_factory


async def _setup_memory_db():
    """Create an isolated in-memory async SQLite engine and session factory."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    return engine, session_factory


def test_vendor_repository_crud() -> None:
    """Verify async CRUD and soft-deactivation on VendorRepository."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                repo = VendorRepository(session)

                # Create
                vendor = Vendor(
                    vendor_tax_id="US-12-3456789",
                    vendor_id="VEND-1001",
                    vendor_name="Apex Global Logistics Inc",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="Sales Tax (CA 9.5%)",
                    standard_tax_rate=Decimal("0.0950"),
                )
                created = await repo.create(vendor)
                assert created.vendor_tax_id == "US-12-3456789"

                # Read by tax_id and vendor_id
                by_tax = await repo.get_by_tax_id("US-12-3456789")
                assert by_tax is not None
                assert by_tax.vendor_name == "Apex Global Logistics Inc"

                by_vid = await repo.get_by_vendor_id("VEND-1001")
                assert by_vid is not None
                assert by_vid.vendor_tax_id == "US-12-3456789"

                # List active
                all_active = await repo.list_all(active_only=True)
                assert len(all_active) == 1

                # Update allowed field
                updated = await repo.update(
                    "US-12-3456789",
                    vendor_name="Apex Global Logistics LLC",
                    standard_tax_rate=Decimal("0.0825"),
                )
                assert updated is not None
                assert updated.vendor_name == "Apex Global Logistics LLC"
                assert updated.standard_tax_rate == Decimal("0.0825")

                # Security: Mass assignment guard blocks disallowed field updates
                with pytest.raises(ValueError, match="Disallowed update fields"):
                    await repo.update("US-12-3456789", vendor_tax_id="HACKED-ID")

                # Deactivate (soft delete)
                deactivated = await repo.deactivate("US-12-3456789")
                assert deactivated is True
                assert len(await repo.list_all(active_only=True)) == 0
                assert len(await repo.list_all(active_only=False)) == 1
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_invoice_repository_crud() -> None:
    """Verify async CRUD, composite hash lookup, status transitions, and relation loading."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                vendor_repo = VendorRepository(session)
                inv_repo = InvoiceRepository(session)

                await vendor_repo.create(
                    Vendor(
                        vendor_tax_id="DE-198765432",
                        vendor_id="VEND-1005",
                        vendor_name="Berlin Systems GmbH",
                        country_code="DE",
                        date_format_locale="DD/MM/YYYY",
                    )
                )

                # Create invoice
                invoice = Invoice(
                    vendor_tax_id="DE-198765432",
                    vendor_name="Berlin Systems GmbH",
                    invoice_number="INV-2026-5001",
                    invoice_date=date(2026, 3, 10),
                    total_amount=Decimal("1190.00"),
                    currency="EUR",
                    confidence_macro_avg=Decimal("93.50"),
                    status="UPLOADED",
                    composite_hash="f" * 64,
                )
                created = await inv_repo.create(invoice)
                assert created.invoice_id is not None

                # Read by ID with relationships
                fetched = await inv_repo.get_by_id(created.invoice_id)
                assert fetched is not None
                assert fetched.vendor.vendor_name == "Berlin Systems GmbH"
                assert fetched.lines == []

                # Read by composite hash
                by_hash = await inv_repo.get_by_composite_hash("f" * 64)
                assert by_hash is not None
                assert by_hash.invoice_id == created.invoice_id

                # Read by vendor and invoice number
                by_vendor_num = await inv_repo.get_by_vendor_and_number(
                    "DE-198765432", "INV-2026-5001"
                )
                assert len(by_vendor_num) == 1

                # Update status
                updated = await inv_repo.update_status(created.invoice_id, "VALIDATED")
                assert updated is not None
                assert updated.status == "VALIDATED"

                # List by status
                validated = await inv_repo.list_by_status(status="VALIDATED")
                assert len(validated) == 1
                assert len(await inv_repo.list_by_status(status="UPLOADED")) == 0

                # Update fields with mass assignment guard
                updated_fields = await inv_repo.update_fields(
                    created.invoice_id,
                    total_amount_usd=Decimal("1291.15"),
                    po_number="PO-9000-101",
                )
                assert updated_fields is not None
                assert updated_fields.total_amount_usd == Decimal("1291.15")

                with pytest.raises(ValueError, match="Disallowed update fields"):
                    await inv_repo.update_fields(created.invoice_id, invoice_id="spoofed-id")

                # Delete
                deleted = await inv_repo.delete(created.invoice_id)
                assert deleted is True
                assert await inv_repo.get_by_id(created.invoice_id) is None
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_invoice_line_repository_crud_and_replace() -> None:
    """Verify async CRUD, bulk creation, ordering, and atomic replacement of invoice lines."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                vendor_repo = VendorRepository(session)
                inv_repo = InvoiceRepository(session)
                line_repo = InvoiceLineRepository(session)

                await vendor_repo.create(
                    Vendor(
                        vendor_tax_id="GB-987654321",
                        vendor_name="Meridian Software Ltd",
                        country_code="UK",
                        date_format_locale="DD/MM/YYYY",
                    )
                )
                inv = await inv_repo.create(
                    Invoice(
                        vendor_tax_id="GB-987654321",
                        invoice_number="INV-UK-100",
                        total_amount=Decimal("600.00"),
                        currency="GBP",
                        composite_hash="d" * 64,
                    )
                )

                # Bulk create lines (inserted out of order to verify ordering)
                lines = [
                    InvoiceLine(
                        invoice_id=inv.invoice_id,
                        line_number=2,
                        description="Cloud Support Package",
                        quantity=Decimal("1.0000"),
                        unit_price=Decimal("200.0000"),
                        line_total=Decimal("200.00"),
                        line_tax_rate=Decimal("0.2000"),
                    ),
                    InvoiceLine(
                        invoice_id=inv.invoice_id,
                        line_number=1,
                        description="Enterprise License",
                        quantity=Decimal("2.0000"),
                        unit_price=Decimal("150.0000"),
                        line_total=Decimal("300.00"),
                        line_tax_rate=Decimal("0.2000"),
                    ),
                ]
                created_lines = await line_repo.create_many(lines)
                assert len(created_lines) == 2

                # Read ordered by line_number
                ordered = await line_repo.get_by_invoice_id(inv.invoice_id)
                assert [ln.line_number for ln in ordered] == [1, 2]
                assert ordered[0].description == "Enterprise License"

                # Update single line
                updated = await line_repo.update(
                    ordered[0].line_id, quantity=Decimal("3.0000"), line_total=Decimal("450.00")
                )
                assert updated is not None
                assert updated.line_total == Decimal("450.00")

                # Mass assignment guard
                with pytest.raises(ValueError, match="Disallowed update fields"):
                    await line_repo.update(ordered[0].line_id, invoice_id="other-invoice")

                # Replace all lines for re-validation
                replacement = [
                    InvoiceLine(
                        invoice_id=inv.invoice_id,
                        line_number=1,
                        description="Consolidated Annual License",
                        quantity=Decimal("1.0000"),
                        unit_price=Decimal("500.0000"),
                        line_total=Decimal("500.00"),
                        line_tax_rate=Decimal("0.2000"),
                    )
                ]
                replaced = await line_repo.replace_for_invoice(inv.invoice_id, replacement)
                assert len(replaced) == 1
                assert replaced[0].description == "Consolidated Annual License"

                # Delete line
                deleted = await line_repo.delete(replaced[0].line_id)
                assert deleted is True
                assert len(await line_repo.get_by_invoice_id(inv.invoice_id)) == 0
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_log_repository_strictly_append_only() -> None:
    """Verify AuditLogRepository is append-only (no update/delete) and blocks no-op edits."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                vendor_repo = VendorRepository(session)
                inv_repo = InvoiceRepository(session)
                audit_repo = AuditLogRepository(session)

                # Security Contract (CLAUDE.md §6): NO update or delete methods permitted
                assert not hasattr(audit_repo, "update")
                assert not hasattr(audit_repo, "delete")

                await vendor_repo.create(
                    Vendor(
                        vendor_tax_id="ES-B12345678",
                        vendor_name="Madrid Consulting SL",
                        country_code="ES",
                        date_format_locale="DD/MM/YYYY",
                    )
                )
                inv = await inv_repo.create(
                    Invoice(
                        vendor_tax_id="ES-B12345678",
                        invoice_number="INV-ES-200",
                        total_amount=Decimal("1210.00"),
                        currency="EUR",
                        composite_hash="e" * 64,
                    )
                )

                # Append extraction event
                log1 = await audit_repo.create(
                    AuditLog(
                        invoice_id=inv.invoice_id,
                        user_id="system",
                        action_type="EXTRACTION",
                        comment="Initial GPT-4o Vision extraction complete",
                    )
                )
                assert log1.audit_id is not None

                # Append clerk edit event
                log2 = await audit_repo.create(
                    AuditLog(
                        invoice_id=inv.invoice_id,
                        user_id="sarah.clerk",
                        action_type="EDIT",
                        field_name="total_tax_amount",
                        previous_value="200.00",
                        new_value="210.00",
                        reason_code="OCR_MISREAD",
                    )
                )
                assert log2.audit_id is not None

                # Guard: Reject no-op edit log where previous_value == new_value
                with pytest.raises(ValueError, match="No-op audit log rejected"):
                    await audit_repo.create(
                        AuditLog(
                            invoice_id=inv.invoice_id,
                            user_id="sarah.clerk",
                            action_type="EDIT",
                            field_name="total_tax_amount",
                            previous_value="210.00",
                            new_value="210.00",
                            reason_code="OCR_MISREAD",
                        )
                    )

                # Query chronologically by invoice and by user
                trail = await audit_repo.get_by_invoice_id(inv.invoice_id)
                assert len(trail) == 2
                assert trail[0].action_type == "EXTRACTION"
                assert trail[1].action_type == "EDIT"

                clerk_logs = await audit_repo.list_by_user("sarah.clerk")
                assert len(clerk_logs) == 1
                assert clerk_logs[0].audit_id == log2.audit_id
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_exchange_rate_repository_crud_and_fallback() -> None:
    """Verify ExchangeRateRepository CRUD, upsert, and historical date fallback."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                repo = ExchangeRateRepository(session)

                # Direct create for GBP
                gbp_rate = await repo.create(
                    ExchangeRate(
                        rate_date=date(2026, 2, 13),
                        from_currency="GBP",
                        to_currency="USD",
                        exchange_rate=Decimal("1.272000"),
                    )
                )
                assert gbp_rate.rate_id is not None

                # Create rate for Friday Feb 13, 2026 via upsert
                friday_rate = await repo.upsert(
                    rate_date=date(2026, 2, 13),
                    from_currency="EUR",
                    exchange_rate=Decimal("1.082500"),
                )
                assert friday_rate.exchange_rate == Decimal("1.082500")

                # Upsert same date & currency updates rate cleanly without duplicate error
                updated_friday = await repo.upsert(
                    rate_date=date(2026, 2, 13),
                    from_currency="EUR",
                    exchange_rate=Decimal("1.085000"),
                )
                assert updated_friday.rate_id == friday_rate.rate_id
                assert updated_friday.exchange_rate == Decimal("1.085000")

                # Exact date lookup
                exact = await repo.get_rate(date(2026, 2, 13), "EUR")
                assert exact is not None
                assert exact.rate_to_usd == Decimal("1.085000")

                # Weekend fallback (Sunday Feb 15 -> falls back to Friday Feb 13)
                fallback = await repo.get_latest_rate_on_or_before(date(2026, 2, 15), "EUR")
                assert fallback is not None
                assert fallback.rate_date == date(2026, 2, 13)
                assert fallback.exchange_rate == Decimal("1.085000")

                # Missing rate before earliest date returns None
                missing = await repo.get_latest_rate_on_or_before(date(2026, 1, 1), "EUR")
                assert missing is None

                # List by date and delete
                rates_on_day = await repo.list_by_date(date(2026, 2, 13))
                assert len(rates_on_day) == 2

                deleted = await repo.delete(updated_friday.rate_id)
                assert deleted is True
                assert await repo.get_rate(date(2026, 2, 13), "EUR") is None
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_repository_edge_cases_and_composite_hash_exclusion() -> None:
    """Verify non-existent record handling and exclusion of REJECTED_DUPLICATE/VOID hashes."""

    async def _run():
        engine, session_factory = await _setup_memory_db()
        try:
            async with session_factory() as session:
                vendor_repo = VendorRepository(session)
                inv_repo = InvoiceRepository(session)
                line_repo = InvoiceLineRepository(session)
                rate_repo = ExchangeRateRepository(session)

                # Non-existent records return None / False cleanly
                assert await vendor_repo.get_by_tax_id("NON-EXISTENT") is None
                assert await vendor_repo.update("NON-EXISTENT", vendor_name="X") is None
                assert await vendor_repo.deactivate("NON-EXISTENT") is False
                assert await inv_repo.update_status("missing-id", "VALIDATED") is None
                assert await inv_repo.delete("missing-id") is False
                assert await line_repo.update("missing-line", description="X") is None
                assert await line_repo.delete("missing-line") is False
                assert await rate_repo.delete(999999) is False

                # Composite hash lookup MUST ignore REJECTED_DUPLICATE and VOID statuses (CLAUDE.md §6)
                await vendor_repo.create(
                    Vendor(
                        vendor_tax_id="US-99-0000001",
                        vendor_name="Void Test Vendor",
                        country_code="US",
                        date_format_locale="MM/DD/YYYY",
                    )
                )
                dup_hash = "9" * 64
                await inv_repo.create(
                    Invoice(
                        vendor_tax_id="US-99-0000001",
                        invoice_number="INV-VOID-01",
                        total_amount=Decimal("100.00"),
                        status="VOID",
                        composite_hash=dup_hash,
                    )
                )
                await inv_repo.create(
                    Invoice(
                        vendor_tax_id="US-99-0000001",
                        invoice_number="INV-DUP-01",
                        total_amount=Decimal("100.00"),
                        status="REJECTED_DUPLICATE",
                        composite_hash=dup_hash,
                    )
                )

                # Neither VOID nor REJECTED_DUPLICATE should block active duplicate detection
                assert await inv_repo.get_by_composite_hash(dup_hash) is None

                # Now insert an active invoice with that same hash -> must be found
                active_inv = await inv_repo.create(
                    Invoice(
                        vendor_tax_id="US-99-0000001",
                        invoice_number="INV-ACTIVE-01",
                        total_amount=Decimal("100.00"),
                        status="VALIDATED",
                        composite_hash=dup_hash,
                    )
                )
                found = await inv_repo.get_by_composite_hash(dup_hash)
                assert found is not None
                assert found.invoice_id == active_inv.invoice_id
        finally:
            await engine.dispose()

    asyncio.run(_run())
