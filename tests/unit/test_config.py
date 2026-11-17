"""
Unit tests for Centralised Settings (src/core/config.py).

Tests: N1, N2, N8, FR-13
"""
from src.core.config import Settings, get_settings


def test_default_settings():
    """Verify default business thresholds and offline defaults per CLAUDE.md §11.1."""
    settings = Settings()

    # Business rule thresholds
    assert settings.HIGH_VALUE_THRESHOLD_USD == 10000.00
    assert settings.PO_VARIANCE_TOLERANCE_PERCENT == 5.0
    assert settings.LINE_ROUNDING_TOLERANCE == 0.02
    assert settings.INVOICE_ROUNDING_TOLERANCE == 0.05

    # Offline test flags default to safe local testing
    assert settings.USE_LOCAL_SQLITE is True
    assert settings.USE_FAKE_REDIS is True
    assert settings.USE_MOCK_AOAI is True
    assert settings.SAMPLE_DATA_DIR == "./sample_data"


def test_settings_lru_cache():
    """Verify get_settings() returns a cached singleton instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_env_override(monkeypatch):
    """Verify environment variables properly override defaults."""
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "25000.00")
    monkeypatch.setenv("LINE_ROUNDING_TOLERANCE", "0.05")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "false")

    # Instantiate fresh Settings ignoring cache
    custom_settings = Settings()
    assert custom_settings.HIGH_VALUE_THRESHOLD_USD == 25000.00
    assert custom_settings.LINE_ROUNDING_TOLERANCE == 0.05
    assert custom_settings.USE_LOCAL_SQLITE is False


def test_database_url_property():
    """Verify database URL formats correctly for SQLite vs Azure SQL."""
    # SQLite local mode
    sqlite_settings = Settings(USE_LOCAL_SQLITE=True)
    assert "sqlite+aiosqlite:///" in sqlite_settings.database_url

    # Azure SQL mode (without static credentials, using pyodbc/azure-identity)
    azure_settings = Settings(
        USE_LOCAL_SQLITE=False,
        AZURE_SQL_SERVER="sqlsrv-ap-eastus2.database.windows.net",
        AZURE_SQL_DATABASE="sqldb-ap-staging",
    )
    assert "mssql+aioodbc://" in azure_settings.database_url
    assert "sqlsrv-ap-eastus2.database.windows.net" in azure_settings.database_url
    assert "sqldb-ap-staging" in azure_settings.database_url
