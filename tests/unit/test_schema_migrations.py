"""
Unit tests for Database Schema DDL (schema.sql) and Alembic Migrations.

Tests: P2-2 · Database schema DDL and Alembic migration baseline
"""

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from src.database.models import Base


def test_schema_sql_exists_and_contains_core_tables() -> None:
    """Verify that src/database/schema.sql exists and defines all 5 core tables."""
    schema_path = Path("src/database/schema.sql")
    assert schema_path.is_file(), "src/database/schema.sql must exist"

    sql_content = schema_path.read_text(encoding="utf-8")
    assert len(sql_content.strip()) > 0, "schema.sql must not be empty"

    # Verify all 5 core tables are created
    lower_sql = sql_content.lower()
    tables = ["vendors", "invoices", "invoice_lines", "audit_logs", "exchange_rates"]
    for table in tables:
        assert (
            f"table {table}" in lower_sql
            or f"table dbo.{table}" in lower_sql
            or f"table if not exists {table}" in lower_sql
        ), f"schema.sql must contain CREATE TABLE for {table}"

    # Verify composite hash index
    assert "COMPOSITE_HASH" in sql_content.upper(), "schema.sql must index composite_hash"


def test_schema_sql_executes_cleanly_on_sqlite() -> None:
    """Verify schema.sql executes on SQLite and creates all expected tables and indexes."""
    schema_path = Path("src/database/schema.sql")
    sql_content = schema_path.read_text(encoding="utf-8")

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # SQLite executes script
    cursor.executescript(sql_content)
    conn.commit()

    # Query sqlite_master to verify tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0].lower() for row in cursor.fetchall()}

    expected_tables = {"vendors", "invoices", "invoice_lines", "audit_logs", "exchange_rates"}
    assert expected_tables.issubset(tables), f"Missing tables in SQLite: {expected_tables - tables}"

    # Verify table structure by inserting a test vendor
    cursor.execute(
        """
        INSERT INTO vendors (vendor_tax_id, vendor_name, country_code, date_format_locale)
        VALUES ('US-12-3456789', 'Acme Test Corp', 'US', 'MM/DD/YYYY');
        """
    )
    conn.commit()

    cursor.execute("SELECT vendor_name FROM vendors WHERE vendor_tax_id = 'US-12-3456789';")
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == "Acme Test Corp"
    conn.close()


def test_alembic_ini_exists_and_configured() -> None:
    """Verify alembic.ini exists and has valid script_location configured."""
    ini_path = Path("alembic.ini")
    assert ini_path.is_file(), "alembic.ini must exist in project root"

    config = Config(str(ini_path))
    script_loc = config.get_main_option("script_location")
    assert script_loc is not None
    assert Path(script_loc).is_dir(), f"Alembic script_location '{script_loc}' directory must exist"


def test_alembic_migrations_upgrade_and_downgrade(tmp_path: Path) -> None:
    """Verify Alembic migration baseline applies to head and rolls back to base cleanly."""
    db_file = tmp_path / "test_migration.db"
    db_url = f"sqlite:///{db_file}"

    ini_path = Path("alembic.ini")
    config = Config(str(ini_path))
    config.set_main_option("sqlalchemy.url", db_url)

    # 1. Upgrade to head
    command.upgrade(config, "head")

    # Verify tables created by migration
    engine = create_engine(db_url)
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    expected_tables = {"vendors", "invoices", "invoice_lines", "audit_logs", "exchange_rates"}
    assert expected_tables.issubset(table_names), (
        f"Alembic upgrade missing tables: {expected_tables - table_names}"
    )
    engine.dispose()

    # 2. Downgrade back to base
    command.downgrade(config, "base")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    remaining_tables = set(inspector.get_table_names()) - {"alembic_version"}
    assert len(remaining_tables) == 0, (
        f"Alembic downgrade left unexpected tables: {remaining_tables}"
    )
    engine.dispose()


def test_models_metadata_matches_tables() -> None:
    """Verify that SQLAlchemy declarative models match the expected core tables."""
    table_names = set(Base.metadata.tables.keys())
    expected_tables = {"vendors", "invoices", "invoice_lines", "audit_logs", "exchange_rates"}
    assert expected_tables.issubset(table_names), (
        f"Missing tables in Base.metadata: {expected_tables - table_names}"
    )
