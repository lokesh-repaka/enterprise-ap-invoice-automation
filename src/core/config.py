"""
Centralised Application Configuration.

Single source of truth for platform settings, Azure East US 2 resource parameters,
business thresholds, and offline test switches (CLAUDE.md §11.1).
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform configuration settings loaded from environment variables and .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application Metadata ---
    APP_NAME: str = "Enterprise AP Invoice Automation"
    APP_ENV: str = "dev"
    LOG_LEVEL: str = "INFO"

    # --- Azure Tenant & Identity (Entra ID Managed Identity: ADR-007) ---
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = "system-assigned"
    AZURE_API_AUDIENCE: str = ""
    ENTRA_JWKS_CACHE_TTL_SECONDS: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="TTL in seconds for cached Microsoft Entra ID JWKS signing keys.",
    )
    ENTRA_JWT_CLOCK_SKEW_SECONDS: int = Field(
        default=30,
        ge=0,
        le=300,
        description="Maximum clock skew leeway in seconds for JWT exp/nbf checks.",
    )
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: ["http://localhost:8501", "http://127.0.0.1:8501"],
        description="Explicit CORS origin allowlist (never '*' with credentials: CWE-942).",
    )

    # --- Redis Rate Limiting (Phase 3 P3-3) ---
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Enable Redis-backed sliding-window HTTP rate limiting middleware.",
    )
    RATE_LIMIT_REQUESTS: int = Field(
        default=100,
        ge=1,
        le=100_000,
        description="Maximum requests permitted per client within RATE_LIMIT_WINDOW_SECONDS.",
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        ge=1,
        le=86_400,
        description="Sliding-window duration in seconds for Redis rate limiting.",
    )
    RATE_LIMIT_FAIL_OPEN: bool = Field(
        default=False,
        description="If False (default, fail-closed), returns 503 when Redis is unreachable (CWE-636).",
    )
    TRUSTED_PROXY_IPS: list[str] = Field(
        default_factory=list,
        description="Explicit trusted reverse-proxy IPs permitted to supply X-Forwarded-For (CWE-348).",
    )

    # --- Azure Services (East US 2 Confinement: ADR-001) ---
    AZURE_BLOB_ACCOUNT_URL: str = "https://mockblob.blob.core.windows.net/"
    AZURE_BLOB_WORM_CONTAINER: str = "raw-invoices-immutable"
    AZURE_SQL_SERVER: str = ""
    AZURE_SQL_DATABASE: str = "sqldb-ap-staging"
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Azure OpenAI East US 2 (Model Gateway: ADR-004) ---
    AZURE_OPENAI_ENDPOINT: str = "https://mockaoai.openai.azure.com/"
    AZURE_OPENAI_GPT4O_DEPLOYMENT: str = "gpt-4o-vision"
    AZURE_OPENAI_MINI_DEPLOYMENT: str = "gpt-4o-mini"
    AZURE_OPENAI_API_VERSION: str = "2024-05-01-preview"

    # --- Business Rule Thresholds (Configurable — Never Hardcode in Logic) ---
    HIGH_VALUE_THRESHOLD_USD: float = Field(
        default=10000.00,
        description="Invoices with total above this threshold require Finance Manager approval (FR-13).",
    )
    PO_VARIANCE_TOLERANCE_PERCENT: float = Field(
        default=5.0,
        description="PO total variance exceeding this percentage requires Finance Manager approval.",
    )
    LINE_ROUNDING_TOLERANCE: float = Field(
        default=0.02,
        description="Maximum arithmetic rounding difference allowed per line item (FR-05).",
    )
    INVOICE_ROUNDING_TOLERANCE: float = Field(
        default=0.05,
        description="Maximum arithmetic rounding difference allowed for grand total (FR-06).",
    )

    # --- Local Development / Strict Offline Testing Mode ---
    USE_LOCAL_SQLITE: bool = Field(
        default=True,
        description="If True, uses a local SQLite async database instead of Azure SQL.",
    )
    USE_FAKE_REDIS: bool = Field(
        default=True,
        description="If True, uses in-memory fake Redis instead of Azure Cache for Redis.",
    )
    USE_MOCK_AOAI: bool = Field(
        default=True,
        description="If True, mocks Azure OpenAI calls with synthetic fixture data.",
    )
    ENABLE_DEMO_AUTH: bool = Field(
        default=False,
        description=(
            "If True AND APP_ENV is in ('dev', 'local', 'test'), enables ephemeral RSA demo "
            "tokens for sarah.clerk, michael.manager, and dave.admin. Strictly ignored in staging/prod."
        ),
    )
    SAMPLE_DATA_DIR: str = "./sample_data"

    @property
    def database_url(self) -> str:
        """Construct database connection URL based on active storage mode."""
        if self.USE_LOCAL_SQLITE:
            db_path = Path("./data/enterprise.db").resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite+aiosqlite:///{db_path}"

        # Production Azure SQL: keyless Entra ID auth via ODBC
        return (
            f"mssql+aioodbc://@{self.AZURE_SQL_SERVER}/{self.AZURE_SQL_DATABASE}"
            "?driver=ODBC+Driver+18+for+SQL+Server&Authentication=ActiveDirectoryMsi"
        )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
