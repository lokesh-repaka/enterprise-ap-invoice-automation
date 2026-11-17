"""
SQLAlchemy 2.0 Async Models for Enterprise AP Invoice Automation.

Covers CLAUDE.md §6 and LLD §3:
  - Vendors: Vendor master data across jurisdictions (US, UK, DE, ES)
  - Invoices: Core invoice headers, status FSM, confidence scores, and composite hashes
  - InvoiceLines: Extracted line-item breakdown with quantities, unit prices, and tax rates
  - AuditLogs: Immutable audit trail of extractions, edits, re-validations, and approvals
  - ExchangeRates: Daily ECB exchange rate feed for currency conversion to USD

Layer Rule (CLAUDE.md §4.2):
  - src/database/ MUST NOT call LLMs or Azure Blob storage directly.
"""

import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""

    pass


class Vendor(Base):
    """
    Vendor master entity representing an approved supplier.
    Stores tax registration, date formatting locale, default currency, and tax scheme.
    """

    __tablename__ = "vendors"

    vendor_tax_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    vendor_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    vendor_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    date_format_locale: Mapped[str] = mapped_column(
        String(20), nullable=False, default="MM/DD/YYYY"
    )
    number_format_preference: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PERIOD"
    )
    default_currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    tax_scheme: Mapped[str | None] = mapped_column(String(100), nullable=True)
    standard_tax_rate: Mapped[Decimal] = mapped_column(
        Numeric(5, 4), nullable=False, default=Decimal("0.0000")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationship to invoices issued by this vendor
    invoices: Mapped[list["Invoice"]] = relationship(
        "Invoice", back_populates="vendor", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        # Security: mask tax_id in string representations to prevent PII log leaks (N3, N8)
        masked_tax_id = (
            f"***-**-{self.vendor_tax_id[-4:]}"
            if len(self.vendor_tax_id) >= 4
            else "***"
        )
        return (
            f"<Vendor(name='{self.vendor_name}', country='{self.country_code}', "
            f"tax_id='{masked_tax_id}', active={self.is_active})>"
        )


class Invoice(Base):
    """
    Core invoice header entity capturing status, confidence, financial totals, and blob links.
    """

    __tablename__ = "invoices"

    invoice_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    vendor_tax_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("vendors.vendor_tax_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vendor_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    invoice_number: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    invoice_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    po_number: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    subtotal: Mapped[Decimal | None] = mapped_column(Numeric(18, 2), nullable=True)
    total_tax_amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 2), nullable=True)
    total_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    total_amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 2), nullable=True)
    confidence_macro_avg: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), nullable=False, default=Decimal("0.00")
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="UPLOADED", index=True
    )
    composite_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    blob_raw_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    blob_json_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    vendor: Mapped["Vendor"] = relationship("Vendor", back_populates="invoices")
    lines: Mapped[list["InvoiceLine"]] = relationship(
        "InvoiceLine",
        back_populates="invoice",
        cascade="all, delete-orphan",
        order_by="InvoiceLine.line_number",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="invoice",
        cascade="all, delete-orphan",
        order_by="AuditLog.timestamp",
    )

    __table_args__ = (
        Index("IX_invoices_status_date", "status", "invoice_date"),
        Index("IX_invoices_vendor_number", "vendor_tax_id", "invoice_number"),
    )

    def __repr__(self) -> str:
        return (
            f"<Invoice(id='{self.invoice_id}', number='{self.invoice_number}', "
            f"total={self.total_amount} {self.currency}, status='{self.status}')>"
        )


class InvoiceLine(Base):
    """
    Extracted line-item breakdown of an invoice.
    Tracks quantity, unit price, line total, and line-level tax rate and confidence.
    """

    __tablename__ = "invoice_lines"

    line_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    invoice_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("invoices.invoice_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    quantity: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False)
    line_total: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    line_tax_rate: Mapped[Decimal] = mapped_column(
        Numeric(5, 4), nullable=False, default=Decimal("0.0000")
    )
    confidence_score: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2), nullable=True, default=Decimal("100.00")
    )

    # Bidirectional relationship to parent invoice
    invoice: Mapped["Invoice"] = relationship("Invoice", back_populates="lines")

    __table_args__ = (
        Index("IX_invoice_lines_invoice_num", "invoice_id", "line_number"),
    )

    def __repr__(self) -> str:
        return (
            f"<InvoiceLine(inv_id='{self.invoice_id}', line={self.line_number}, "
            f"total={self.line_total}, desc='{self.description[:30]}...')>"
        )


class AuditLog(Base):
    """
    Immutable audit trail recording every extraction, human edit, re-validation,
    and approval state transition (CLAUDE.md §6).
    """

    __tablename__ = "audit_logs"

    audit_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    invoice_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("invoices.invoice_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    field_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    comment: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC), index=True
    )

    # Relationship to invoice
    invoice: Mapped["Invoice"] = relationship("Invoice", back_populates="audit_logs")

    __table_args__ = (
        Index("IX_audit_logs_invoice_timestamp", "invoice_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id='{self.audit_id}', inv_id='{self.invoice_id}', "
            f"user='{self.user_id}', action='{self.action_type}')>"
        )


class ExchangeRate(Base):
    """
    Daily foreign exchange rates (from European Central Bank feed).
    Converts non-USD invoices to USD for standardized threshold and manager approvals.
    """

    __tablename__ = "exchange_rates"

    rate_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rate_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    from_currency: Mapped[str] = mapped_column(String(10), nullable=False)
    to_currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    exchange_rate: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)

    __table_args__ = (
        UniqueConstraint("rate_date", "from_currency", "to_currency", name="UQ_exchange_rates"),
        Index("IX_exchange_rates_lookup", "rate_date", "from_currency"),
    )

    @property
    def currency(self) -> str:
        """Alias for from_currency for backward compatibility with LLD §3."""
        return self.from_currency

    @property
    def rate_to_usd(self) -> Decimal:
        """Alias for exchange_rate for backward compatibility with LLD §3."""
        return self.exchange_rate

    def __repr__(self) -> str:
        return (
            f"<ExchangeRate(date={self.rate_date}, "
            f"{self.from_currency}->{self.to_currency} = {self.exchange_rate})>"
        )
