"""
Unit tests for composite_hash partial unique index and duplicate-safe upsert logic.

Tests: P2-5 · UX_invoices_composite_hash, compute_composite_hash, upsert_duplicate_safe
Requirements: CLAUDE.md §6, LLD §3.1, FR-09, CWE-362, CWE-699.
"""

import asyncio
import json
import sqlite3
from decimal import Decimal
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.database.models import Base, Invoice, Vendor
from src.database.repositories import (
    InvoiceRepository,
    VendorRepository,
    compute_composite_hash,
)
from src.database.session import create_db_engine, create_session_factory


async def _setup_db_with_vendor():
    """Initialize in-memory async SQLite DB with one test vendor."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    async with session_factory() as session:
        vendor_repo = VendorRepository(session)
        await vendor_repo.create(
            Vendor(
                vendor_tax_id="ESA98765432",
                vendor_id="VEND-3002",
                vendor_name="Mediterraneo Quimica SA",
                country_code="ES",
                date_format_locale="DD/MM/YYYY",
                default_currency="EUR",
            )
        )
    return engine, session_factory


def test_compute_composite_hash_matches_ground_truth() -> None:
    """Verify compute_composite_hash produces exact parity with sample ground-truth JSON."""
    gt_path = Path("./sample_data/ground_truth/INV-2026-1001_ground_truth.json")
    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    computed = compute_composite_hash(
        vendor_tax_id=gt["header"]["vendor_tax_id"],
        invoice_number=gt["header"]["invoice_number"],
        total_amount=gt["header"]["total_amount"],
    )
    assert len(computed) == 64
    assert computed == gt["invoice_metadata"]["composite_hash"]

    # Decimal vs float vs string equivalence
    assert computed == compute_composite_hash("ESA98765432", "INV-2026-1001", Decimal("3449.71"))
    assert computed == compute_composite_hash(" ESA98765432 ", " INV-2026-1001 ", "3449.710")

    # Reject empty required fields
    with pytest.raises(ValueError, match="vendor_tax_id"):
        compute_composite_hash("", "INV-1", Decimal("10.00"))
    with pytest.raises(ValueError, match="invoice_number"):
        compute_composite_hash("US-12-3456789", "   ", Decimal("10.00"))


def test_db_unique_partial_index_blocks_duplicate_active_invoices() -> None:
    """Verify UX_invoices_composite_hash enforces duplicate rejection at DB engine level."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendor()
        try:
            dup_hash = compute_composite_hash("ESA98765432", "INV-2026-1001", Decimal("3449.71"))
            async with session_factory() as session:
                inv1 = Invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                    currency="EUR",
                    status="VALIDATED",
                    composite_hash=dup_hash,
                )
                session.add(inv1)
                await session.commit()

                inv2 = Invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-1001",
                    total_amount=Decimal("3449.71"),
                    currency="EUR",
                    status="UPLOADED",
                    composite_hash=dup_hash,
                )
                session.add(inv2)
                with pytest.raises(IntegrityError):
                    await session.commit()
                await session.rollback()
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_db_unique_partial_index_allows_resubmission_after_void_or_rejected() -> None:
    """Verify partial unique index excludes REJECTED_DUPLICATE and VOID statuses (CLAUDE.md §6)."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendor()
        try:
            dup_hash = compute_composite_hash("ESA98765432", "INV-2026-2002", Decimal("500.00"))
            async with session_factory() as session:
                session.add_all(
                    [
                        Invoice(
                            vendor_tax_id="ESA98765432",
                            invoice_number="INV-2026-2002",
                            total_amount=Decimal("500.00"),
                            status="VOID",
                            composite_hash=dup_hash,
                        ),
                        Invoice(
                            vendor_tax_id="ESA98765432",
                            invoice_number="INV-2026-2002",
                            total_amount=Decimal("500.00"),
                            status="REJECTED_DUPLICATE",
                            composite_hash=dup_hash,
                        ),
                        Invoice(
                            vendor_tax_id="ESA98765432",
                            invoice_number="INV-2026-2002",
                            total_amount=Decimal("500.00"),
                            status="UPLOADED",
                            composite_hash=dup_hash,
                        ),
                    ]
                )
                await session.commit()

                rows = (
                    (
                        await session.execute(
                            select(Invoice).where(Invoice.composite_hash == dup_hash)
                        )
                    )
                    .scalars()
                    .all()
                )
                assert len(rows) == 3
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_upsert_duplicate_safe_returns_existing_on_duplicate() -> None:
    """Verify upsert_duplicate_safe inserts once and safely flags subsequent duplicates."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendor()
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)

                # First submission (composite_hash auto-computed when omitted)
                inv1 = Invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-3003",
                    total_amount=Decimal("1250.00"),
                    currency="EUR",
                    status="UPLOADED",
                    composite_hash="",
                )
                stored1, is_dup1 = await repo.upsert_duplicate_safe(inv1)
                assert is_dup1 is False
                assert len(stored1.composite_hash) == 64

                # Second identical submission -> duplicate detected cleanly
                inv2 = Invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-2026-3003",
                    total_amount=Decimal("1250.00"),
                    currency="EUR",
                    status="UPLOADED",
                    composite_hash=stored1.composite_hash,
                )
                stored2, is_dup2 = await repo.upsert_duplicate_safe(inv2)
                assert is_dup2 is True
                assert stored2.invoice_id == stored1.invoice_id

                # Confirm only 1 row exists
                all_invs = await repo.list_by_status()
                assert len(all_invs) == 1
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_upsert_duplicate_safe_handles_concurrent_race_condition() -> None:
    """Security (CWE-362): Verify TOCTOU race condition IntegrityError resolves cleanly."""

    async def _run():
        engine, session_factory = await _setup_db_with_vendor()
        try:
            dup_hash = compute_composite_hash("ESA98765432", "INV-RACE-01", Decimal("999.99"))

            # Pre-insert winning invoice via Session A
            async with session_factory() as session_a:
                repo_a = InvoiceRepository(session_a)
                winner, is_dup = await repo_a.upsert_duplicate_safe(
                    Invoice(
                        vendor_tax_id="ESA98765432",
                        invoice_number="INV-RACE-01",
                        total_amount=Decimal("999.99"),
                        status="UPLOADED",
                        composite_hash=dup_hash,
                    )
                )
                assert is_dup is False

            # Simulate Session B losing a race: initial lookup returns None,
            # so INSERT hits UX_invoices_composite_hash IntegrityError, then recovers.
            async with session_factory() as session_b:
                repo_b = InvoiceRepository(session_b)
                real_lookup = repo_b.get_by_composite_hash
                repo_b.get_by_composite_hash = AsyncMock(side_effect=[None, winner])

                loser_candidate = Invoice(
                    vendor_tax_id="ESA98765432",
                    invoice_number="INV-RACE-01",
                    total_amount=Decimal("999.99"),
                    status="UPLOADED",
                    composite_hash=dup_hash,
                )
                resolved, is_dup_b = await repo_b.upsert_duplicate_safe(loser_candidate)
                assert is_dup_b is True
                assert resolved.invoice_id == winner.invoice_id
                assert repo_b.get_by_composite_hash.await_count == 2
                # Verify real lookup also finds winner cleanly after rollback
                assert (await real_lookup(dup_hash)).invoice_id == winner.invoice_id
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_schema_sql_and_alembic_0002_enforce_partial_unique_index(tmp_path: Path) -> None:
    """Verify both schema.sql and Alembic migration 0002 create UX_invoices_composite_hash."""
    # 1. Verify schema.sql on SQLite
    schema_sql = Path("src/database/schema.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(schema_sql)
        conn.execute(
            "INSERT INTO vendors (vendor_tax_id, vendor_name, country_code) "
            "VALUES ('V-1', 'Test Vendor', 'US');"
        )
        conn.execute(
            "INSERT INTO invoices (invoice_id, vendor_tax_id, invoice_number, total_amount, "
            "status, composite_hash) VALUES ('id-1', 'V-1', 'INV-1', 100.0, 'UPLOADED', 'h1');"
        )
        # Duplicate active invoice must raise sqlite3.IntegrityError
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO invoices (invoice_id, vendor_tax_id, invoice_number, total_amount, "
                "status, composite_hash) VALUES ('id-2', 'V-1', 'INV-1', 100.0, 'VALIDATED', 'h1');"
            )
        # VOID invoice with same hash must be allowed
        conn.execute(
            "INSERT INTO invoices (invoice_id, vendor_tax_id, invoice_number, total_amount, "
            "status, composite_hash) VALUES ('id-3', 'V-1', 'INV-1', 100.0, 'VOID', 'h1');"
        )
    finally:
        conn.close()

    # 2. Verify Alembic migration 0001 -> 0002 (head) -> 0001 -> base
    db_file = tmp_path / "alembic_composite_hash.db"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_file}")

    command.upgrade(cfg, "head")

    conn2 = sqlite3.connect(db_file)
    try:
        indexes = {
            row[0]
            for row in conn2.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='invoices';"
            ).fetchall()
        }
        assert "UX_invoices_composite_hash" in indexes
    finally:
        conn2.close()

    command.downgrade(cfg, "0001")
    command.downgrade(cfg, "base")
