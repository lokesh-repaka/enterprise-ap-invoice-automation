"""
Idempotent Database Seed Scripts for Vendor Master and Exchange Rates.

Populates:
  - 15 Vendors across 4 jurisdictions (US, DE, ES, GB) from sample_data/vendor_master.json
  - Daily ECB Exchange Rates (USD, EUR, GBP) from sample_data/exchange_rates.json

Usage (CLAUDE.md §14):
  python -m src.database.seed

Layer & Security Rules:
  - Strict path containment within sample_data_dir (CWE-22 prevention).
  - Strict validation of tax rates [0, 1] and positive exchange rates (> 0) (CWE-20).
  - Zero PII logged (aggregate counts only — CWE-532).
"""

import asyncio
import json
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.core.logging import get_logger, setup_logging
from src.database.models import Base, Vendor
from src.database.repositories import ExchangeRateRepository, VendorRepository
from src.database.session import create_db_engine, create_session_factory

logger = get_logger(__name__)

_TAX_LABELS: dict[str, str] = {
    "US": "Sales Tax",
    "DE": "MwSt",
    "ES": "IVA",
    "GB": "VAT",
    "UK": "VAT",
}


def _resolve_safe_json_path(sample_data_dir: Path, filename: str) -> Path:
    """Resolve JSON seed path safely within sample_data_dir (CWE-22 guard)."""
    base = sample_data_dir.resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"Path traversal blocked for seed file: {filename}")
    if not target.is_file():
        raise FileNotFoundError(f"Seed file not found: {target}")
    return target


def derive_tax_scheme(country_code: str, standard_tax_rate: Decimal) -> str:
    """Derive a human-readable statutory tax scheme label from country and rate."""
    code = country_code.upper()
    label = _TAX_LABELS.get(code, "Tax")
    pct = (standard_tax_rate * Decimal("100")).normalize()
    if pct == 0:
        return f"{label} (0% / Exempt)"
    return f"{label} ({pct}%)"


def load_vendor_records(sample_data_dir: Path) -> list[dict[str, Any]]:
    """Load and validate vendor master JSON records."""
    path = _resolve_safe_json_path(sample_data_dir, "vendor_master.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("vendor_master.json must contain a JSON array")

    required_keys = {
        "VendorID",
        "VendorName",
        "TaxID_VAT",
        "CountryCode",
        "DateLocalePreference",
        "NumberFormatPreference",
        "DefaultCurrency",
        "StandardTaxRate",
    }
    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict) or not required_keys.issubset(item.keys()):
            raise ValueError(f"Vendor record at index {idx} missing required keys")

        tax_rate = Decimal(str(item["StandardTaxRate"]))
        if tax_rate < Decimal("0") or tax_rate > Decimal("1"):
            raise ValueError(
                f"Invalid StandardTaxRate '{tax_rate}' at index {idx}: must be in [0.0, 1.0]"
            )

        validated.append(
            {
                "vendor_tax_id": str(item["TaxID_VAT"]).strip(),
                "vendor_id": str(item["VendorID"]).strip(),
                "vendor_name": str(item["VendorName"]).strip(),
                "country_code": str(item["CountryCode"]).strip().upper(),
                "date_format_locale": str(item["DateLocalePreference"]).strip(),
                "number_format_preference": str(item["NumberFormatPreference"]).strip().upper(),
                "default_currency": str(item["DefaultCurrency"]).strip().upper(),
                "standard_tax_rate": tax_rate.quantize(Decimal("0.0001")),
                "tax_scheme": derive_tax_scheme(str(item["CountryCode"]), tax_rate),
            }
        )
    return validated


def load_exchange_rate_records(sample_data_dir: Path) -> list[dict[str, Any]]:
    """Load and validate exchange rate JSON records."""
    path = _resolve_safe_json_path(sample_data_dir, "exchange_rates.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("exchange_rates.json must contain a JSON array")

    required_keys = {"RateDate", "FromCurrency", "ToCurrency", "ExchangeRate"}
    validated: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict) or not required_keys.issubset(item.keys()):
            raise ValueError(f"Exchange rate record at index {idx} missing required keys")

        rate_val = Decimal(str(item["ExchangeRate"]))
        if rate_val <= Decimal("0"):
            raise ValueError(
                f"Invalid ExchangeRate '{rate_val}' at index {idx}: must be strictly positive"
            )

        from_ccy = str(item["FromCurrency"]).strip().upper()
        to_ccy = str(item["ToCurrency"]).strip().upper()
        if len(from_ccy) != 3 or len(to_ccy) != 3:
            raise ValueError(f"Invalid currency code at index {idx}: must be 3-letter ISO code")

        validated.append(
            {
                "rate_date": date.fromisoformat(str(item["RateDate"]).strip()),
                "from_currency": from_ccy,
                "to_currency": to_ccy,
                "exchange_rate": rate_val.quantize(Decimal("0.000001")),
            }
        )
    return validated


async def seed_vendors(session: AsyncSession, sample_data_dir: Path) -> dict[str, int]:
    """Idempotently seed Vendor Master records into the database."""
    records = load_vendor_records(sample_data_dir)
    repo = VendorRepository(session)

    inserted = 0
    updated = 0
    for rec in records:
        existing = await repo.get_by_tax_id(rec["vendor_tax_id"])
        if existing is None:
            await repo.create(Vendor(**rec))
            inserted += 1
        else:
            update_fields = {k: v for k, v in rec.items() if k != "vendor_tax_id"}
            await repo.update(rec["vendor_tax_id"], **update_fields)
            updated += 1

    return {"inserted": inserted, "updated": updated, "total": len(records)}


async def seed_exchange_rates(session: AsyncSession, sample_data_dir: Path) -> dict[str, int]:
    """Idempotently seed daily ECB ExchangeRate records into the database."""
    records = load_exchange_rate_records(sample_data_dir)
    repo = ExchangeRateRepository(session)

    upserted = 0
    for rec in records:
        await repo.upsert(
            rate_date=rec["rate_date"],
            from_currency=rec["from_currency"],
            to_currency=rec["to_currency"],
            exchange_rate=rec["exchange_rate"],
        )
        upserted += 1

    return {"upserted": upserted}


async def seed_all(
    database_url: str | None = None,
    sample_data_dir: Path | None = None,
) -> dict[str, dict[str, int]]:
    """Initialize schema tables (if missing) and seed Vendors + ExchangeRates."""
    settings = get_settings()
    data_dir = sample_data_dir or Path(settings.SAMPLE_DATA_DIR)
    engine = create_db_engine(database_url or settings.database_url)

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = create_session_factory(engine)
        async with session_factory() as session:
            vendor_summary = await seed_vendors(session, data_dir)
            rate_summary = await seed_exchange_rates(session, data_dir)

        logger.info(
            "Database seed completed: %d vendors (%d inserted, %d updated), %d exchange rates.",
            vendor_summary["total"],
            vendor_summary["inserted"],
            vendor_summary["updated"],
            rate_summary["upserted"],
        )
        return {"vendors": vendor_summary, "exchange_rates": rate_summary}
    finally:
        await engine.dispose()


def main() -> None:
    """CLI entrypoint for `python -m src.database.seed`."""
    setup_logging()
    asyncio.run(seed_all())


if __name__ == "__main__":
    main()
