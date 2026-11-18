"""
Async Repository Layer for Enterprise AP Invoice Automation.

Provides SQLAlchemy 2.0 async CRUD repositories for all five domain tables:
  - VendorRepository (vendors)
  - InvoiceRepository (invoices)
  - InvoiceLineRepository (invoice_lines)
  - AuditLogRepository (audit_logs — STRICTLY APPEND-ONLY per CLAUDE.md §6)
  - ExchangeRateRepository (exchange_rates)

Security & Layering Rules (CLAUDE.md §4.2, §6):
  - Parameterized ORM queries exclusively (zero raw SQL string interpolation).
  - Explicit field allowlists on all update methods to prevent mass assignment (CWE-915).
  - Bounded pagination limits to prevent unbounded result-set DoS (CWE-770).
  - AuditLogRepository exposes zero update or delete methods and rejects no-op edits.
"""

import hashlib
from datetime import date
from decimal import Decimal
from typing import Any

from sqlalchemy import delete, desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.database.models import (
    AuditLog,
    ExchangeRate,
    Invoice,
    InvoiceLine,
    Vendor,
)

MAX_PAGE_LIMIT = 500


def compute_composite_hash(
    vendor_tax_id: str,
    invoice_number: str,
    total_amount: Decimal | str | float,
) -> str:
    """
    Compute canonical SHA-256 composite hash for invoice duplicate detection (CLAUDE.md §6).

    Format: SHA256(f"{vendor_tax_id}_{invoice_number}_{total_amount:.2f}")
    Matches ground-truth dataset hashes in sample_data/ground_truth/.
    """
    clean_tax_id = vendor_tax_id.strip()
    clean_inv_num = invoice_number.strip()
    if not clean_tax_id:
        raise ValueError("vendor_tax_id must be non-empty to compute composite_hash")
    if not clean_inv_num:
        raise ValueError("invoice_number must be non-empty to compute composite_hash")

    normalized_total = Decimal(str(total_amount)).quantize(Decimal("0.01"))
    payload = f"{clean_tax_id}_{clean_inv_num}_{normalized_total:.2f}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_update_fields(fields: dict[str, Any], allowed: frozenset[str]) -> None:
    """Validate kwargs against an explicit allowlist to prevent mass assignment (CWE-915)."""
    disallowed = set(fields.keys()) - allowed
    if disallowed:
        raise ValueError(f"Disallowed update fields: {sorted(disallowed)}")


def _clamp_limit(limit: int) -> int:
    """Clamp pagination limit to safe bounds [1, MAX_PAGE_LIMIT] (CWE-770)."""
    return min(max(limit, 1), MAX_PAGE_LIMIT)


class VendorRepository:
    """Async repository for Vendor master records."""

    ALLOWED_UPDATE_FIELDS: frozenset[str] = frozenset(
        {
            "vendor_id",
            "vendor_name",
            "country_code",
            "date_format_locale",
            "number_format_preference",
            "default_currency",
            "tax_scheme",
            "standard_tax_rate",
            "is_active",
        }
    )

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, vendor: Vendor) -> Vendor:
        """Persist a new Vendor record."""
        self._session.add(vendor)
        await self._session.commit()
        await self._session.refresh(vendor)
        return vendor

    async def get_by_tax_id(self, vendor_tax_id: str) -> Vendor | None:
        """Fetch a Vendor by primary key (vendor_tax_id)."""
        stmt = select(Vendor).where(Vendor.vendor_tax_id == vendor_tax_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_vendor_id(self, vendor_id: str) -> Vendor | None:
        """Fetch a Vendor by internal vendor_id (e.g. VEND-1001)."""
        stmt = select(Vendor).where(Vendor.vendor_id == vendor_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_all(self, active_only: bool = True, limit: int = 100) -> list[Vendor]:
        """List vendors, optionally filtering to active vendors only."""
        stmt = select(Vendor).order_by(Vendor.vendor_name).limit(_clamp_limit(limit))
        if active_only:
            stmt = stmt.where(Vendor.is_active.is_(True))
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, vendor_tax_id: str, /, **fields: Any) -> Vendor | None:
        """Update allowed mutable fields on an existing Vendor."""
        _validate_update_fields(fields, self.ALLOWED_UPDATE_FIELDS)
        vendor = await self.get_by_tax_id(vendor_tax_id)
        if vendor is None:
            return None
        for key, value in fields.items():
            setattr(vendor, key, value)
        await self._session.commit()
        await self._session.refresh(vendor)
        return vendor

    async def deactivate(self, vendor_tax_id: str) -> bool:
        """Soft-deactivate a vendor without breaking historical invoice FKs."""
        vendor = await self.get_by_tax_id(vendor_tax_id)
        if vendor is None:
            return False
        vendor.is_active = False
        await self._session.commit()
        return True


class InvoiceRepository:
    """Async repository for core Invoice header records."""

    ALLOWED_UPDATE_FIELDS: frozenset[str] = frozenset(
        {
            "vendor_name",
            "invoice_number",
            "invoice_date",
            "due_date",
            "po_number",
            "subtotal",
            "total_tax_amount",
            "total_amount",
            "currency",
            "total_amount_usd",
            "confidence_macro_avg",
            "status",
            "composite_hash",
            "blob_raw_url",
            "blob_json_url",
        }
    )

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, invoice: Invoice) -> Invoice:
        """Persist a new Invoice record."""
        self._session.add(invoice)
        await self._session.commit()
        await self._session.refresh(invoice)
        return invoice

    async def upsert_duplicate_safe(self, invoice: Invoice) -> tuple[Invoice, bool]:
        """
        Insert an invoice safely while preventing active duplicates (FR-09, CWE-362).

        Returns:
            (stored_invoice, is_duplicate):
              - (created_invoice, False) if newly persisted.
              - (existing_invoice, True) if an active invoice with the same composite_hash
                already exists or won a concurrent insert race.
        """
        if not invoice.composite_hash:
            invoice.composite_hash = compute_composite_hash(
                vendor_tax_id=invoice.vendor_tax_id,
                invoice_number=invoice.invoice_number,
                total_amount=invoice.total_amount,
            )

        # Fast-path check for active duplicate (excludes REJECTED_DUPLICATE and VOID)
        existing = await self.get_by_composite_hash(invoice.composite_hash)
        if existing is not None:
            return existing, True

        try:
            created = await self.create(invoice)
            return created, False
        except IntegrityError:
            # Handle TOCTOU concurrent insert race condition cleanly
            await self._session.rollback()
            winner = await self.get_by_composite_hash(invoice.composite_hash)
            if winner is not None:
                return winner, True
            # IntegrityError was NOT caused by composite_hash duplication (e.g. invalid FK)
            raise

    async def get_by_id(self, invoice_id: str, include_relations: bool = True) -> Invoice | None:
        """Fetch an Invoice by invoice_id, optionally eager-loading relations."""
        stmt = select(Invoice).where(Invoice.invoice_id == invoice_id)
        if include_relations:
            stmt = stmt.options(
                selectinload(Invoice.vendor),
                selectinload(Invoice.lines),
                selectinload(Invoice.audit_logs),
            )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_composite_hash(self, composite_hash: str) -> Invoice | None:
        """Fetch an active invoice matching the given SHA-256 composite hash."""
        stmt = (
            select(Invoice)
            .where(
                Invoice.composite_hash == composite_hash,
                Invoice.status.notin_(["REJECTED_DUPLICATE", "VOID"]),
            )
            .order_by(Invoice.created_at)
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_vendor_and_number(
        self, vendor_tax_id: str, invoice_number: str
    ) -> list[Invoice]:
        """Fetch invoices matching a vendor Tax ID and invoice number (revision detection)."""
        stmt = (
            select(Invoice)
            .where(
                Invoice.vendor_tax_id == vendor_tax_id,
                Invoice.invoice_number == invoice_number,
            )
            .order_by(desc(Invoice.created_at))
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_status(
        self, status: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[Invoice]:
        """List invoices filtered optionally by workflow status."""
        stmt = (
            select(Invoice)
            .order_by(desc(Invoice.created_at))
            .offset(max(offset, 0))
            .limit(_clamp_limit(limit))
        )
        if status is not None:
            stmt = stmt.where(Invoice.status == status)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(self, invoice_id: str, new_status: str) -> Invoice | None:
        """Transition an invoice's persisted workflow status."""
        return await self.update_fields(invoice_id, status=new_status)

    async def update_fields(self, invoice_id: str, /, **fields: Any) -> Invoice | None:
        """Update allowed mutable fields on an existing Invoice."""
        _validate_update_fields(fields, self.ALLOWED_UPDATE_FIELDS)
        invoice = await self.get_by_id(invoice_id, include_relations=False)
        if invoice is None:
            return None
        for key, value in fields.items():
            setattr(invoice, key, value)
        await self._session.commit()
        await self._session.refresh(invoice)
        return invoice

    async def delete(self, invoice_id: str) -> bool:
        """Delete an invoice record by ID."""
        invoice = await self.get_by_id(invoice_id, include_relations=False)
        if invoice is None:
            return False
        await self._session.delete(invoice)
        await self._session.commit()
        return True


class InvoiceLineRepository:
    """Async repository for InvoiceLine breakdown items."""

    ALLOWED_UPDATE_FIELDS: frozenset[str] = frozenset(
        {
            "line_number",
            "description",
            "quantity",
            "unit_price",
            "line_total",
            "line_tax_rate",
            "confidence_score",
        }
    )

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, line: InvoiceLine) -> InvoiceLine:
        """Persist a single InvoiceLine."""
        self._session.add(line)
        await self._session.commit()
        await self._session.refresh(line)
        return line

    async def create_many(self, lines: list[InvoiceLine]) -> list[InvoiceLine]:
        """Bulk-persist multiple InvoiceLine records in a single transaction."""
        self._session.add_all(lines)
        await self._session.commit()
        for line in lines:
            await self._session.refresh(line)
        return lines

    async def get_by_id(self, line_id: str) -> InvoiceLine | None:
        """Fetch an InvoiceLine by primary key."""
        stmt = select(InvoiceLine).where(InvoiceLine.line_id == line_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_invoice_id(self, invoice_id: str) -> list[InvoiceLine]:
        """Fetch all lines for an invoice ordered by line_number."""
        stmt = (
            select(InvoiceLine)
            .where(InvoiceLine.invoice_id == invoice_id)
            .order_by(InvoiceLine.line_number)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, line_id: str, /, **fields: Any) -> InvoiceLine | None:
        """Update allowed fields on an InvoiceLine."""
        _validate_update_fields(fields, self.ALLOWED_UPDATE_FIELDS)
        line = await self.get_by_id(line_id)
        if line is None:
            return None
        for key, value in fields.items():
            setattr(line, key, value)
        await self._session.commit()
        await self._session.refresh(line)
        return line

    async def delete(self, line_id: str) -> bool:
        """Delete a single InvoiceLine."""
        line = await self.get_by_id(line_id)
        if line is None:
            return False
        await self._session.delete(line)
        await self._session.commit()
        return True

    async def replace_for_invoice(
        self, invoice_id: str, new_lines: list[InvoiceLine]
    ) -> list[InvoiceLine]:
        """Atomically replace all lines for an invoice during clerk re-validation."""
        await self._session.execute(delete(InvoiceLine).where(InvoiceLine.invoice_id == invoice_id))
        for line in new_lines:
            line.invoice_id = invoice_id
        self._session.add_all(new_lines)
        await self._session.commit()
        for line in new_lines:
            await self._session.refresh(line)
        return new_lines


class AuditLogRepository:
    """
    Append-only async repository for immutable AuditLog entries (CLAUDE.md §6).

    NON-NEGOTIABLE INVARIANT:
      No update() or delete() methods are permitted on AuditLogRepository.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, audit_log: AuditLog) -> AuditLog:
        """Append an immutable audit event. Rejects no-op EDIT records (old == new)."""
        if (
            audit_log.action_type.upper() == "EDIT"
            and audit_log.previous_value is not None
            and audit_log.previous_value == audit_log.new_value
        ):
            raise ValueError(
                "No-op audit log rejected: previous_value and new_value must differ on EDIT."
            )
        self._session.add(audit_log)
        await self._session.commit()
        await self._session.refresh(audit_log)
        return audit_log

    async def get_by_id(self, audit_id: str) -> AuditLog | None:
        """Fetch an AuditLog entry by primary key."""
        stmt = select(AuditLog).where(AuditLog.audit_id == audit_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_invoice_id(self, invoice_id: str) -> list[AuditLog]:
        """Return chronological immutable audit trail for an invoice."""
        stmt = (
            select(AuditLog).where(AuditLog.invoice_id == invoice_id).order_by(AuditLog.timestamp)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_by_user(self, user_id: str, limit: int = 100) -> list[AuditLog]:
        """List recent audit events performed by a specific user."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(desc(AuditLog.timestamp))
            .limit(_clamp_limit(limit))
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class ExchangeRateRepository:
    """Async repository for daily ECB ExchangeRate records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, rate: ExchangeRate) -> ExchangeRate:
        """Persist a new ExchangeRate record."""
        self._session.add(rate)
        await self._session.commit()
        await self._session.refresh(rate)
        return rate

    async def get_rate(
        self, rate_date: date, from_currency: str, to_currency: str = "USD"
    ) -> ExchangeRate | None:
        """Fetch exact exchange rate for a specific date and currency pair."""
        stmt = select(ExchangeRate).where(
            ExchangeRate.rate_date == rate_date,
            ExchangeRate.from_currency == from_currency.upper(),
            ExchangeRate.to_currency == to_currency.upper(),
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert(
        self,
        rate_date: date,
        from_currency: str,
        exchange_rate: Decimal,
        to_currency: str = "USD",
    ) -> ExchangeRate:
        """Insert or update an exchange rate for (rate_date, from_currency, to_currency)."""
        existing = await self.get_rate(rate_date, from_currency, to_currency)
        if existing is not None:
            existing.exchange_rate = exchange_rate
            await self._session.commit()
            await self._session.refresh(existing)
            return existing

        new_rate = ExchangeRate(
            rate_date=rate_date,
            from_currency=from_currency.upper(),
            to_currency=to_currency.upper(),
            exchange_rate=exchange_rate,
        )
        return await self.create(new_rate)

    async def get_latest_rate_on_or_before(
        self, target_date: date, from_currency: str, to_currency: str = "USD"
    ) -> ExchangeRate | None:
        """
        Retrieve the latest ECB rate on or before the invoice date (CLAUDE.md §6).
        Handles weekends and bank holidays gracefully.
        """
        stmt = (
            select(ExchangeRate)
            .where(
                ExchangeRate.rate_date <= target_date,
                ExchangeRate.from_currency == from_currency.upper(),
                ExchangeRate.to_currency == to_currency.upper(),
            )
            .order_by(desc(ExchangeRate.rate_date))
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_date(self, rate_date: date) -> list[ExchangeRate]:
        """List all currency exchange rates recorded for a given date."""
        stmt = (
            select(ExchangeRate)
            .where(ExchangeRate.rate_date == rate_date)
            .order_by(ExchangeRate.from_currency)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def delete(self, rate_id: int) -> bool:
        """Delete an ExchangeRate record by primary key."""
        stmt = select(ExchangeRate).where(ExchangeRate.rate_id == rate_id)
        result = await self._session.execute(stmt)
        rate = result.scalar_one_or_none()
        if rate is None:
            return False
        await self._session.delete(rate)
        await self._session.commit()
        return True
