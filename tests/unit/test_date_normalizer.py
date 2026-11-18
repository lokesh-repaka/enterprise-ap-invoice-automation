"""
Unit tests for P7-5 · Date Normaliser & Locale Disambiguator (src/validation/date_normalizer.py).

Tests: FR-08
Requirements: BR-012, Q-04, LLD §5.4, CLAUDE.md §4.2, §5, §7.1.
Strict offline isolation: zero external network or Azure calls.
"""

import json
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.extraction.schemas import InvoiceExtractionSchema
from src.validation.date_normalizer import (
    AmbiguousDateError,
    normalize_extraction_dates,
    normalize_invoice_date,
    normalize_invoice_dates,
    parse_invoice_date,
    resolve_date_locale,
)

GROUND_TRUTH_DIR = Path("./sample_data/ground_truth")
VENDOR_MASTER_PATH = Path("./sample_data/vendor_master.json")


# ---------------------------------------------------------------------------
# 1. FR-08: Vendor Master Locale Resolution (US: MM/DD/YYYY; EU: DD/MM/YYYY)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_locale", "expected"),
    [
        ("US", "US"),
        ("us", "US"),
        ("MM/DD/YYYY", "US"),
        ("en-US", "US"),
        ("GB", "EU"),
        ("UK", "EU"),
        ("DE", "EU"),
        ("ES", "EU"),
        ("EU", "EU"),
        ("DD/MM/YYYY", "EU"),
        ("de-DE", "EU"),
        (None, None),
        ("", None),
        ("UNKNOWN", None),
    ],
)
def test_resolve_date_locale_supports_country_codes_and_vendor_master_formats(
    raw_locale: str | None, expected: str | None
) -> None:
    """Tests: FR-08 & BR-012 — Maps country codes and Vendor Master locale strings deterministically."""
    assert resolve_date_locale(raw_locale) == expected


def test_parse_invoice_date_us_eu_separators_and_iso_8601() -> None:
    """Tests: FR-08 & LLD §5.4 — Disambiguates 05/06/2026 via US vs EU locale and handles -, ., / & ISO."""
    # Classic ambiguous 05/06/2026 resolved cleanly by Vendor Master locale
    assert parse_invoice_date("05/06/2026", "US") == date(2026, 5, 6)
    assert parse_invoice_date("05/06/2026", "MM/DD/YYYY") == date(2026, 5, 6)
    assert parse_invoice_date("05/06/2026", "GB") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "UK") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "DE") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "ES") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "EU") == date(2026, 6, 5)
    assert parse_invoice_date("05/06/2026", "DD/MM/YYYY") == date(2026, 6, 5)

    # Alternate delimiters: dot (German style 15.04.2026) and hyphen (04-15-2026)
    assert parse_invoice_date("15.04.2026", "DE") == date(2026, 4, 15)
    assert parse_invoice_date("04-15-2026", "US") == date(2026, 4, 15)

    # ISO 8601 works unambiguously for both known and unknown locales
    assert parse_invoice_date("2026-05-06", "UNKNOWN") == date(2026, 5, 6)
    assert parse_invoice_date("2026/05/06", None) == date(2026, 5, 6)
    assert parse_invoice_date("2026-05-06", "US") == date(2026, 5, 6)

    # Leap year valid vs non-leap year invalid
    assert parse_invoice_date("02/29/2024", "US") == date(2024, 2, 29)
    with pytest.raises(ValueError):
        parse_invoice_date("02/29/2026", "US")


# ---------------------------------------------------------------------------
# 2. FR-08: Ambiguous Date Flagging (Unlisted Vendor & Chronological Conflict)
# ---------------------------------------------------------------------------


def test_ambiguous_date_flagged_for_unlisted_vendor_and_parsed_candidates_exposed() -> None:
    """Tests: FR-08 & BR-012 — Unlisted vendor ambiguous 05/06/2026 flags clerk review and raises AmbiguousDateError."""
    # LLD §5.4 contract: parse_invoice_date raises AmbiguousDateError (ValueError)
    with pytest.raises(AmbiguousDateError, match="Ambiguous date format"):
        parse_invoice_date("05/06/2026", "UNKNOWN")

    # Structured normalizer flags is_ambiguous=True + provides both US and EU candidate dates
    res = normalize_invoice_date("05/06/2026", locale=None)
    assert res.is_valid is False
    assert res.is_ambiguous is True
    assert res.requires_clerk_verification is True
    assert res.parsed_date is None
    assert res.recommended_status == "REQUIRES_REVIEW"
    assert res.candidate_us_date == date(2026, 5, 6)
    assert res.candidate_eu_date == date(2026, 6, 5)

    # With known US Vendor Master locale, 05/06/2026 resolves deterministically (but marks syntactic ambiguity)
    res_us = normalize_invoice_date("05/06/2026", locale="US")
    assert res_us.is_valid is True
    assert res_us.is_ambiguous is False
    assert res_us.is_syntactically_ambiguous is True
    assert res_us.parsed_date == date(2026, 5, 6)
    assert res_us.resolved_via == "VENDOR_MASTER"
    assert res_us.recommended_status is None


def test_chronological_locale_conflict_flags_inv_2026_1005_and_passes_299_other_ground_truths() -> (
    None
):
    """Tests: FR-08 & CLAUDE.md §5 — 299/300 GT pass; INV-2026-1005 flagged ambiguous due to due_date < invoice_date."""
    vendors = {
        v["TaxID_VAT"]: v for v in json.loads(VENDOR_MASTER_PATH.read_text(encoding="utf-8"))
    }
    gt_files = sorted(GROUND_TRUTH_DIR.glob("*_ground_truth.json"))
    assert len(gt_files) == 300

    flagged: list[str] = []
    for path in gt_files:
        gt = json.loads(path.read_text(encoding="utf-8"))
        schema = InvoiceExtractionSchema.from_ground_truth_dict(gt)
        vendor = vendors[schema.header.vendor_tax_id.value]
        res = normalize_extraction_dates(
            schema,
            locale=vendor["DateLocalePreference"],
        )
        if not res.is_valid or res.is_ambiguous:
            flagged.append(schema.header.invoice_number.value)
        else:
            assert res.invoice_date is not None
            assert res.due_date is not None
            assert res.due_date >= res.invoice_date

    # Exact match: INV-2026-1005 (US vendor, invoice_date='05/06/2026', due_date='03/09/2026')
    assert flagged == ["INV-2026-1005"]

    # Direct check on INV-2026-1005 pair verifies chronological conflict details
    inv_1005 = normalize_invoice_dates("05/06/2026", "03/09/2026", locale="US")
    assert inv_1005.is_valid is False
    assert inv_1005.is_ambiguous is True
    assert inv_1005.chronological_conflict is True
    assert inv_1005.requires_clerk_verification is True
    assert inv_1005.recommended_status == "REQUIRES_REVIEW"
    assert "EU" in inv_1005.message


def test_normalize_invoice_dates_supports_missing_due_date() -> None:
    """Tests: FR-08 — Optional due_date=None succeeds when invoice_date is valid."""
    res = normalize_invoice_dates("15.04.2026", None, locale="DE")
    assert res.is_valid is True
    assert res.is_ambiguous is False
    assert res.invoice_date == date(2026, 4, 15)
    assert res.due_date is None


# ---------------------------------------------------------------------------
# 3. Security, Input Hardening & Layer Isolation (CLAUDE.md §4.2)
# ---------------------------------------------------------------------------


def test_security_invalid_locales_malformed_dates_year_bounds_and_layer_isolation() -> None:
    """Tests: FR-08 & CLAUDE.md §4.2 — Rejects bad locales, impossible years, control/bidi chars, zero LLM/SQL."""
    # Unsupported/spoofed locales fail closed
    for bad_loc in ("FR", "JP", "US\n", "DE\u00ad", "ＵＳ", "GB\u200b"):
        with pytest.raises(ValueError):
            resolve_date_locale(bad_loc)

    # Out-of-range financial years (0001, 9999) rejected fail-closed
    for bad_year in ("01/01/0001", "12/31/9999", "1899-01-01", "2200-01-01"):
        with pytest.raises(ValueError, match="year"):
            parse_invoice_date(bad_year, "US")

    # Control characters, invisible Unicode, non-ASCII digits rejected
    for bad_date in ("05/06/2026\r\n", "05/06/2026\u200b", "٠٥/٠٦/٢٠٢٦", "05/06/2026" * 10):
        with pytest.raises(ValueError):
            parse_invoice_date(bad_date, "US")

    # Mixed delimiters (e.g. "05/06-2026") rejected instead of silently coalesced
    with pytest.raises(ValueError):
        parse_invoice_date("05/06-2026", "US")

    # Layer isolation check (CLAUDE.md §4.2): zero LLM/SQLAlchemy/API/UI/storage imports
    src_code = Path("src/validation/date_normalizer.py").read_text(encoding="utf-8")
    for forbidden in (
        "import openai",
        "from openai",
        "sqlalchemy",
        "src.extraction.model_gateway",
        "src.extraction.extract_engine",
        "src.extraction.mock_aoai_client",
        "src.storage",
        "src.api",
        "src.ui",
        "api_key=",
        "sk-",
    ):
        assert forbidden not in src_code, f"Forbidden import/token '{forbidden}' found"


def test_pentest_cross_locale_inversion_and_eu_chronological_conflict() -> None:
    """Security (SEC-154 · CWE-840): Cross-locale inversions (25/06 on US, 06/25 on DE) & EU conflicts flag REQUIRES_REVIEW."""
    # US vendor receiving EU day-first date (25/06/2026) -> invalid as MM/DD/YYYY, flagged with EU hint
    us_inv = normalize_invoice_date("25/06/2026", locale="US")
    assert us_inv.is_valid is False
    assert us_inv.is_ambiguous is True
    assert us_inv.recommended_status == "REQUIRES_REVIEW"
    assert us_inv.candidate_eu_date == date(2026, 6, 25)
    with pytest.raises(AmbiguousDateError):
        parse_invoice_date("25/06/2026", "US")

    # DE vendor receiving US month-first date (06/25/2026) -> invalid as DD/MM/YYYY, flagged with US hint
    de_inv = normalize_invoice_date("06/25/2026", locale="DE")
    assert de_inv.is_valid is False
    assert de_inv.is_ambiguous is True
    assert de_inv.candidate_us_date == date(2026, 6, 25)

    # EU vendor printing US dates causing due_date < invoice_date -> chronological conflict flagged with US hint
    eu_conflict = normalize_invoice_dates("05/06/2026", "06/05/2026", locale="DE")
    assert eu_conflict.is_valid is False
    assert eu_conflict.chronological_conflict is True
    assert eu_conflict.recommended_status == "REQUIRES_REVIEW"
    assert "US" in eu_conflict.message


def test_pentest_two_digit_years_sqli_non_string_types_and_frozen_results() -> None:
    """Security (SEC-155/SEC-156 · CWE-20/89/117/863): Reject 2-digit years, SQLi/trailing payloads, non-strings, and mutation."""
    for bad in (
        "05/06/26",  # ambiguous 2-digit year
        "05/06/2026' OR '1'='1",  # SQLi attempt
        "2026-05-06T00:00:00Z",  # unexpected timestamp suffix
        "04/31/2026",  # invalid calendar date
        "",  # empty string
        "   ",  # whitespace only
    ):
        with pytest.raises(ValueError):
            parse_invoice_date(bad, "US")

    # Non-string date_str or locale fails closed
    with pytest.raises(ValueError, match="string"):
        parse_invoice_date(20260506, "US")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="string"):
        resolve_date_locale(True)  # type: ignore[arg-type]

    # Frozen results cannot be mutated into is_valid=True
    ambig = normalize_invoice_date("05/06/2026", locale=None)
    assert ambig.is_valid is False
    with pytest.raises(ValidationError):
        ambig.is_valid = True  # type: ignore[misc]

    conflict = normalize_invoice_dates("05/06/2026", "03/09/2026", locale="US")
    assert conflict.is_valid is False
    with pytest.raises(ValidationError):
        conflict.is_valid = True  # type: ignore[misc]
