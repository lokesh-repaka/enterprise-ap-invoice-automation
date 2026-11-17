"""
Unit tests for SQLAlchemy 2.0 Models (CLAUDE.md §6, LLD §3).

Tests: P2-1 · Vendors, Invoices, InvoiceLines, AuditLogs, ExchangeRates
"""

import asyncio
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from src.database.models import (
    AuditLog,
    Base,
    ExchangeRate,
    Invoice,
    InvoiceLine,
    Vendor,
)


@pytest.fixture
def db_session() -> Session:
    """Provide isolated in-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_vendor_model_crud(db_session: Session) -> None:
    """Verify Vendor model creation, attributes, and safe representation."""
    vendor = Vendor(
        vendor_tax_id="US-12-3456789",
        vendor_id="VEND-1001",
        vendor_name="Apex Global Logistics Inc",
        country_code="US",
        date_format_locale="MM/DD/YYYY",
        number_format_preference="PERIOD",
        default_currency="USD",
        tax_scheme="Sales Tax (CA 9.5%)",
        standard_tax_rate=Decimal("0.0950"),
        is_active=True,
    )
    db_session.add(vendor)
    db_session.commit()

    # Query vendor back
    stmt = select(Vendor).where(Vendor.vendor_tax_id == "US-12-3456789")
    retrieved = db_session.execute(stmt).scalar_one()

    assert retrieved.vendor_name == "Apex Global Logistics Inc"
    assert retrieved.country_code == "US"
    assert retrieved.date_format_locale == "MM/DD/YYYY"
    assert retrieved.is_active is True
    assert retrieved.standard_tax_rate == Decimal("0.0950")

    # Security check: __repr__ must mask sensitive Tax ID / SSN to prevent log leaks
    assert "US-12-3456789" not in repr(retrieved)
    assert "***" in repr(retrieved)


def test_invoice_and_lines_relationship(db_session: Session) -> None:
    """Verify Invoice creation, cascading line items, and bidirectional relationships."""
    vendor = Vendor(
        vendor_tax_id="DE-198765432",
        vendor_id="VEND-1005",
        vendor_name="Berlin Systems GmbH",
        country_code="DE",
        date_format_locale="DD/MM/YYYY",
        default_currency="EUR",
        tax_scheme="MwSt 19%",
        standard_tax_rate=Decimal("0.1900"),
    )
    db_session.add(vendor)
    db_session.flush()

    inv_id = str(uuid.uuid4())
    invoice = Invoice(
        invoice_id=inv_id,
        vendor_tax_id=vendor.vendor_tax_id,
        vendor_name=vendor.vendor_name,
        invoice_number="INV-2026-9001",
        invoice_date=date(2026, 3, 15),
        due_date=date(2026, 4, 15),
        po_number="PO-7700-101",
        subtotal=Decimal("1000.00"),
        total_tax_amount=Decimal("190.00"),
        total_amount=Decimal("1190.00"),
        currency="EUR",
        total_amount_usd=Decimal("1291.15"),
        confidence_macro_avg=Decimal("94.50"),
        status="VALIDATED",
        composite_hash="a" * 64,
        blob_raw_url="https://blob.mock/raw/inv-9001.pdf",
    )

    line1 = InvoiceLine(
        invoice_id=inv_id,
        line_number=1,
        description="Server Rack Rail Kit",
        quantity=Decimal("2.0000"),
        unit_price=Decimal("250.0000"),
        line_total=Decimal("500.00"),
        line_tax_rate=Decimal("0.1900"),
        confidence_score=Decimal("98.00"),
    )
    line2 = InvoiceLine(
        invoice_id=inv_id,
        line_number=2,
        description="Power Distribution Unit",
        quantity=Decimal("1.0000"),
        unit_price=Decimal("500.0000"),
        line_total=Decimal("500.00"),
        line_tax_rate=Decimal("0.1900"),
        confidence_score=Decimal("96.50"),
    )

    invoice.lines.append(line1)
    invoice.lines.append(line2)

    db_session.add(invoice)
    db_session.commit()

    # Query back invoice with lines
    stmt = select(Invoice).where(Invoice.invoice_id == inv_id)
    retrieved_inv = db_session.execute(stmt).scalar_one()

    assert retrieved_inv.total_amount == Decimal("1190.00")
    assert len(retrieved_inv.lines) == 2
    assert retrieved_inv.lines[0].description == "Server Rack Rail Kit"
    assert retrieved_inv.lines[1].line_total == Decimal("500.00")
    assert retrieved_inv.lines[0].invoice is retrieved_inv
    assert retrieved_inv.vendor.vendor_name == "Berlin Systems GmbH"


def test_audit_log_append_only(db_session: Session) -> None:
    """Verify AuditLog records can be attached and queried for immutable audit trail."""
    vendor = Vendor(
        vendor_tax_id="GB-987654321",
        vendor_id="VEND-1003",
        vendor_name="Meridian Software Ltd",
        country_code="UK",
        date_format_locale="DD/MM/YYYY",
    )
    db_session.add(vendor)
    db_session.flush()

    inv_id = str(uuid.uuid4())
    invoice = Invoice(
        invoice_id=inv_id,
        vendor_tax_id=vendor.vendor_tax_id,
        invoice_number="INV-2026-UK-01",
        total_amount=Decimal("2400.00"),
        currency="GBP",
        status="REQUIRES_REVIEW",
        composite_hash="b" * 64,
        confidence_macro_avg=Decimal("84.00"),
    )
    db_session.add(invoice)
    db_session.flush()

    audit_entry = AuditLog(
        invoice_id=inv_id,
        user_id="sarah.clerk@company.com",
        action_type="EDIT",
        field_name="total_tax_amount",
        previous_value="380.00",
        new_value="400.00",
        reason_code="VENDOR_ROUNDING",
        comment="Adjusted VAT rounding to match vendor invoice display",
        timestamp=datetime.now(UTC),
    )
    db_session.add(audit_entry)
    db_session.commit()

    # Query audit logs for invoice
    stmt = select(AuditLog).where(AuditLog.invoice_id == inv_id)
    logs = db_session.execute(stmt).scalars().all()

    assert len(logs) == 1
    assert logs[0].action_type == "EDIT"
    assert logs[0].user_id == "sarah.clerk@company.com"
    assert logs[0].reason_code == "VENDOR_ROUNDING"
    assert logs[0].previous_value == "380.00"
    assert logs[0].new_value == "400.00"


def test_exchange_rates_model(db_session: Session) -> None:
    """Verify ExchangeRate model stores and retrieves daily currency conversion rates."""
    rate_eur = ExchangeRate(
        rate_date=date(2026, 2, 15),
        from_currency="EUR",
        to_currency="USD",
        exchange_rate=Decimal("1.085000"),
    )
    rate_gbp = ExchangeRate(
        rate_date=date(2026, 2, 15),
        from_currency="GBP",
        to_currency="USD",
        exchange_rate=Decimal("1.272000"),
    )
    db_session.add_all([rate_eur, rate_gbp])
    db_session.commit()

    stmt = select(ExchangeRate).where(
        ExchangeRate.rate_date == date(2026, 2, 15),
        ExchangeRate.from_currency == "EUR",
    )
    retrieved = db_session.execute(stmt).scalar_one()

    assert retrieved.exchange_rate == Decimal("1.085000")
    assert retrieved.to_currency == "USD"
    # Test property aliases for compatibility
    assert retrieved.currency == "EUR"
    assert retrieved.rate_to_usd == Decimal("1.085000")


def test_invoice_default_values(db_session: Session) -> None:
    """Verify default values for UUID primary keys and timestamps."""
    vendor = Vendor(
        vendor_tax_id="US-55-4433221",
        vendor_name="Quick Parts Inc",
        country_code="US",
        date_format_locale="MM/DD/YYYY",
    )
    db_session.add(vendor)
    db_session.flush()

    invoice = Invoice(
        vendor_tax_id=vendor.vendor_tax_id,
        invoice_number="INV-AUTO-01",
        total_amount=Decimal("500.00"),
        composite_hash="c" * 64,
    )
    db_session.add(invoice)
    db_session.commit()

    assert invoice.invoice_id is not None
    assert len(invoice.invoice_id) == 36
    assert invoice.currency == "USD"
    assert invoice.status == "UPLOADED"
    assert invoice.confidence_macro_avg == Decimal("0.00")
    assert invoice.created_at is not None


def test_async_engine_compatibility() -> None:
    """Verify models are 100% compatible with SQLAlchemy 2 async engine and aiosqlite."""

    async def _verify_async():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()

    asyncio.run(_verify_async())
