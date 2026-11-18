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
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import asc, delete, desc, func, select, update
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
MAX_PAGE_OFFSET = 100_000

# Canonical Human Exception Queue statuses (CLAUDE.md §5, PRD Screen 3)
EXCEPTION_QUEUE_STATUSES: frozenset[str] = frozenset(
    {
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "REQUIRES_MANAGER_APPROVAL",
    }
)

# Complete canonical Invoice status allowlist (CLAUDE.md §5, LLD §3.1 & §4)
VALID_INVOICE_STATUSES: frozenset[str] = frozenset(
    {
        "UPLOADED",
        "EXTRACTING",
        "VALIDATED",
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "REVALIDATING",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "APPROVED_CLERK",
        "REQUIRES_MANAGER_APPROVAL",
        "APPROVED_MANAGER",
        "REJECTED",
        "STAGED_FOR_EXPORT",
        "REJECTED_DUPLICATE",
        "VOID",
    }
)


def _escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters (\\, %, _) to prevent wildcard abuse (CWE-89/400)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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

    async def get_by_id(
        self,
        invoice_id: str,
        include_relations: bool = True,
        *,
        include_audit_logs: bool = True,
    ) -> Invoice | None:
        """Fetch an Invoice by invoice_id, optionally eager-loading relations."""
        stmt = select(Invoice).where(Invoice.invoice_id == invoice_id)
        if include_relations:
            loaders = [
                selectinload(Invoice.vendor),
                selectinload(Invoice.lines),
            ]
            if include_audit_logs:
                loaders.append(selectinload(Invoice.audit_logs))
            stmt = stmt.options(*loaders)
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

    ALLOWED_SORT_COLUMNS: dict[str, Any] = {
        "created_at": Invoice.created_at,
        "total_amount": Invoice.total_amount,
        "confidence_macro_avg": Invoice.confidence_macro_avg,
        "invoice_date": Invoice.invoice_date,
    }

    async def list_exceptions(
        self,
        *,
        statuses: list[str] | None = None,
        vendor_id: str | None = None,
        vendor_name: str | None = None,
        invoice_number: str | None = None,
        currency: str | None = None,
        min_amount: Decimal | None = None,
        max_amount: Decimal | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
        max_confidence: Decimal | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Invoice], int]:
        """
        Query filtered Human Exception Queue invoices with exact pagination count (P5-4).

        Uses strictly parameterized SQLAlchemy expressions, escaped LIKE wildcards,
        and an explicit sort-column allowlist (CWE-89 / CWE-400).
        """
        target_statuses = (
            list(EXCEPTION_QUEUE_STATUSES)
            if not statuses
            else [s for s in statuses if s in EXCEPTION_QUEUE_STATUSES]
        )
        if not target_statuses:
            return [], 0

        if sort_by not in self.ALLOWED_SORT_COLUMNS:
            raise ValueError(f"Unsupported sort column: {sort_by!r}")
        if sort_order not in ("asc", "desc"):
            raise ValueError(f"Unsupported sort_order: {sort_order!r}")

        conditions: list[Any] = [Invoice.status.in_(target_statuses)]
        needs_vendor_join = False

        if vendor_id is not None:
            needs_vendor_join = True
            conditions.append(Vendor.vendor_id == vendor_id)
        if vendor_name is not None:
            escaped_vname = _escape_like(vendor_name)
            conditions.append(Invoice.vendor_name.ilike(f"%{escaped_vname}%", escape="\\"))
        if invoice_number is not None:
            escaped_num = _escape_like(invoice_number)
            conditions.append(Invoice.invoice_number.ilike(f"%{escaped_num}%", escape="\\"))
        if currency is not None:
            conditions.append(Invoice.currency == currency.upper())
        if min_amount is not None:
            conditions.append(Invoice.total_amount >= min_amount)
        if max_amount is not None:
            conditions.append(Invoice.total_amount <= max_amount)
        if date_from is not None:
            conditions.append(Invoice.invoice_date >= date_from)
        if date_to is not None:
            conditions.append(Invoice.invoice_date <= date_to)
        if max_confidence is not None:
            conditions.append(Invoice.confidence_macro_avg <= max_confidence)

        count_stmt = select(func.count(Invoice.invoice_id)).select_from(Invoice)
        if needs_vendor_join:
            count_stmt = count_stmt.join(Vendor, Invoice.vendor_tax_id == Vendor.vendor_tax_id)
        count_stmt = count_stmt.where(*conditions)
        total_count = int((await self._session.execute(count_stmt)).scalar_one())

        if total_count == 0:
            return [], 0

        sort_col = self.ALLOWED_SORT_COLUMNS[sort_by]
        order_expr = asc(sort_col) if sort_order == "asc" else desc(sort_col)
        clamped_offset = min(max(offset, 0), MAX_PAGE_OFFSET)
        clamped_limit = _clamp_limit(limit)

        data_stmt = select(Invoice).options(selectinload(Invoice.vendor))
        if needs_vendor_join:
            data_stmt = data_stmt.join(Vendor, Invoice.vendor_tax_id == Vendor.vendor_tax_id)
        data_stmt = (
            data_stmt.where(*conditions)
            .order_by(order_expr, Invoice.invoice_id)
            .offset(clamped_offset)
            .limit(clamped_limit)
        )
        rows = list((await self._session.execute(data_stmt)).scalars().all())
        return rows, total_count

    async def update_status(self, invoice_id: str, new_status: str) -> Invoice | None:
        """Transition an invoice's persisted workflow status."""
        return await self.update_fields(invoice_id, status=new_status)

    async def compare_and_update_status(
        self,
        invoice_id: str,
        *,
        expected_status: str,
        new_status: str,
    ) -> Invoice | None:
        """
        Atomically transition an invoice's status only if persisted status == expected_status
        (optimistic locking CAS guard against concurrent TOCTOU races: CWE-362).

        Returns the refreshed ``Invoice`` if the conditional UPDATE modified 1 row, or ``None``
        if the invoice does not exist or its current status no longer equals ``expected_status``.
        """
        if expected_status not in VALID_INVOICE_STATUSES:
            raise ValueError(f"Unknown expected_status: {expected_status!r}")
        if new_status not in VALID_INVOICE_STATUSES:
            raise ValueError(f"Unknown new_status: {new_status!r}")
        if expected_status == new_status:
            raise ValueError("compare_and_update_status forbids no-op self-transitions")

        stmt = (
            update(Invoice)
            .where(
                Invoice.invoice_id == invoice_id,
                Invoice.status == expected_status,
            )
            .values(status=new_status, updated_at=datetime.now(UTC))
        )
        result = await self._session.execute(stmt)
        if result.rowcount != 1:
            await self._session.rollback()
            return None
        await self._session.commit()
        self._session.expire_all()
        return await self.get_by_id(invoice_id, include_relations=False)

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

    async def count_by_invoice_id(self, invoice_id: str) -> int:
        """Return exact audit event count for an invoice without hydrating full ORM rows."""
        stmt = select(func.count(AuditLog.audit_id)).where(AuditLog.invoice_id == invoice_id)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

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
