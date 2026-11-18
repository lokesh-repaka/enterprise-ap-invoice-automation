"""
Unit tests for Vendor Master (15 vendors, 4 jurisdictions) and Exchange Rates seed scripts.

Tests: P2-4 · src/database/seed.py and src/database/seed.sql
Requirements: CLAUDE.md §5, §6, §14, FR-07, FR-08, N8.
"""

import asyncio
import json
import sqlite3
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from src.database.models import Base
from src.database.repositories import ExchangeRateRepository, VendorRepository
from src.database.seed import (
    _resolve_safe_json_path,
    seed_all,
    seed_exchange_rates,
    seed_vendors,
)
from src.database.session import create_db_engine, create_session_factory

SAMPLE_DATA_DIR = Path("./sample_data")


def test_seed_vendors_15_across_4_jurisdictions() -> None:
    """Verify seed_vendors populates all 15 vendors across US, DE, ES, and GB."""

    async def _run():
        engine = create_db_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(engine)
        try:
            async with session_factory() as session:
                summary = await seed_vendors(session, SAMPLE_DATA_DIR)
                assert summary["inserted"] == 15
                assert summary["total"] == 15

                repo = VendorRepository(session)
                vendors = await repo.list_all(active_only=True)
                assert len(vendors) == 15

                jurisdictions = {v.country_code for v in vendors}
                assert jurisdictions == {"US", "DE", "ES", "GB"}

                # Spot-check US and DE vendor attributes and derived tax schemes
                us_vendor = await repo.get_by_vendor_id("VEND-1001")
                assert us_vendor is not None
                assert us_vendor.date_format_locale == "MM/DD/YYYY"
                assert us_vendor.default_currency == "USD"
                assert us_vendor.tax_scheme is not None
                assert "Sales Tax" in us_vendor.tax_scheme

                de_vendor = await repo.get_by_vendor_id("VEND-2001")
                assert de_vendor is not None
                assert de_vendor.date_format_locale == "DD/MM/YYYY"
                assert de_vendor.number_format_preference == "COMMA"
                assert de_vendor.standard_tax_rate == Decimal("0.1900")
                assert de_vendor.tax_scheme is not None
                assert "MwSt" in de_vendor.tax_scheme
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_seed_vendors_is_idempotent() -> None:
    """Verify running seed_vendors repeatedly produces zero duplicates."""

    async def _run():
        engine = create_db_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(engine)
        try:
            async with session_factory() as session:
                first = await seed_vendors(session, SAMPLE_DATA_DIR)
                assert first["inserted"] == 15

                second = await seed_vendors(session, SAMPLE_DATA_DIR)
                assert second["inserted"] == 0
                assert second["total"] == 15

                repo = VendorRepository(session)
                assert len(await repo.list_all(active_only=False)) == 15
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_seed_exchange_rates_and_idempotency() -> None:
    """Verify seed_exchange_rates populates USD/EUR/GBP rates idempotently."""

    async def _run():
        engine = create_db_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(engine)
        try:
            async with session_factory() as session:
                first = await seed_exchange_rates(session, SAMPLE_DATA_DIR)
                assert first["upserted"] == 3

                second = await seed_exchange_rates(session, SAMPLE_DATA_DIR)
                assert second["upserted"] == 3

                repo = ExchangeRateRepository(session)
                eur = await repo.get_rate(date(2026, 2, 15), "EUR", "USD")
                gbp = await repo.get_rate(date(2026, 2, 15), "GBP", "USD")
                usd = await repo.get_rate(date(2026, 2, 15), "USD", "USD")

                assert eur is not None and eur.exchange_rate == Decimal("1.085000")
                assert gbp is not None and gbp.exchange_rate == Decimal("1.272000")
                assert usd is not None and usd.exchange_rate == Decimal("1.000000")
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_seed_all_end_to_end_sqlite_file(tmp_path: Path) -> None:
    """Verify seed_all initializes schema and seeds both tables into a SQLite file."""
    db_path = tmp_path / "enterprise_seed_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"

    summary = asyncio.run(seed_all(database_url=db_url, sample_data_dir=SAMPLE_DATA_DIR))
    assert summary["vendors"]["total"] == 15
    assert summary["exchange_rates"]["upserted"] == 3
    assert db_path.is_file()


def test_seed_validation_rejects_malformed_input(tmp_path: Path) -> None:
    """Security: Verify seed scripts reject invalid tax rates and non-positive FX rates."""
    bad_vendors = [
        {
            "VendorID": "VEND-BAD",
            "VendorName": "Invalid Tax Co",
            "TaxID_VAT": "US-00-0000000",
            "CountryCode": "US",
            "DateLocalePreference": "MM/DD/YYYY",
            "NumberFormatPreference": "PERIOD",
            "DefaultCurrency": "USD",
            "StandardTaxRate": 1.50,  # Illegal > 100% tax rate
        }
    ]
    bad_rates = [
        {
            "RateDate": "2026-02-15",
            "FromCurrency": "EUR",
            "ToCurrency": "USD",
            "ExchangeRate": -1.05,  # Illegal negative FX rate
        }
    ]
    (tmp_path / "vendor_master.json").write_text(json.dumps(bad_vendors), encoding="utf-8")
    (tmp_path / "exchange_rates.json").write_text(json.dumps(bad_rates), encoding="utf-8")

    async def _run():
        engine = create_db_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = create_session_factory(engine)
        try:
            async with session_factory() as session:
                with pytest.raises(ValueError, match="StandardTaxRate"):
                    await seed_vendors(session, tmp_path)

                with pytest.raises(ValueError, match="ExchangeRate"):
                    await seed_exchange_rates(session, tmp_path)
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_seed_sql_executes_idempotently_after_schema_sql() -> None:
    """Verify src/database/seed.sql executes cleanly after schema.sql and is idempotent."""
    schema_sql = Path("src/database/schema.sql").read_text(encoding="utf-8")
    seed_sql_path = Path("src/database/seed.sql")
    assert seed_sql_path.is_file(), "src/database/seed.sql must exist"
    seed_sql = seed_sql_path.read_text(encoding="utf-8")

    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(schema_sql)
        conn.executescript(seed_sql)
        # Execute second time to confirm idempotency
        conn.executescript(seed_sql)

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), COUNT(DISTINCT country_code) FROM vendors;")
        vendor_count, jurisdiction_count = cursor.fetchone()
        assert vendor_count == 15
        assert jurisdiction_count == 4

        cursor.execute("SELECT COUNT(*) FROM exchange_rates;")
        (rate_count,) = cursor.fetchone()
        assert rate_count == 3
    finally:
        conn.close()


def test_seed_blocks_path_traversal(tmp_path: Path) -> None:
    """Security (CWE-22): Verify path traversal attempts outside sample_data_dir are rejected."""
    with pytest.raises(ValueError, match="Path traversal blocked"):
        _resolve_safe_json_path(tmp_path, "../etc/passwd")
