"""
Deterministic Date Normaliser & Vendor Master Locale Disambiguator (P7-5, FR-08).

Covers FR-08, BR-012, Q-04, LLD §5.4, and CLAUDE.md §4.2, §5, §7.1:
- Resolves regional date formats deterministically using the Vendor Master locale:
  - **US Vendors (`US` / `MM/DD/YYYY`):** `MM/DD/YYYY` (supports `/`, `-`, `.` delimiters).
  - **EU / UK Vendors (`GB` / `UK` / `DE` / `ES` / `EU` / `DD/MM/YYYY`):** `DD/MM/YYYY`.
  - **ISO 8601 (`YYYY-MM-DD` / `YYYY/MM/DD`):** Always accepted unambiguously across all locales.
- Flags ambiguous dates from unlisted vendors (`locale=None` / `"UNKNOWN"`) for clerk
  verification (`is_ambiguous=True`, `requires_clerk_verification=True`,
  `recommended_status="REQUIRES_REVIEW"`), exposing both US and EU candidate interpretations.
- Detects chronological locale conflicts on `(invoice_date, due_date)` pairs (such as
  `INV-2026-1005` where US parsing of `05/06/2026` → `03/09/2026` yields `due_date < invoice_date`
  while EU parsing yields `2026-06-05` → `2026-09-03`), flagging them for clerk review.

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway, or
  SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Fail-closed locale allowlist with Unicode `Cc/Cf/Cs/Co/Cn`, non-ASCII whitespace, and
  `NFC == NFKC` homograph rejection (CWE-20 / CWE-172).
- Strict ASCII `[0-9]` uniform-delimiter regexes prevent mixed-delimiter (`05/06-2026`),
  non-ASCII digit (`٠٥/٠٦/٢٠٢٦`), ReDoS, and control-character log-injection attacks
  (CWE-117 / CWE-436 / CWE-1333).
- Enforces realistic financial year bounds `[1990, 2100]` to prevent out-of-range dates
  (`0001-01-01`, `9999-12-31`) from corrupting ECB FX lookups or SQL date logic (CWE-20).
- Logs aggregate normalization status only — zero PII in logs (CWE-532).
"""

import re
import unicodedata
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict

from src.core.logging import get_logger
from src.extraction.schemas import InvoiceExtractionSchema

logger = get_logger("ap.validation.date_normalizer")

MAX_DATE_STR_CHARS: int = 40
MAX_LOCALE_STR_CHARS: int = 32
MIN_VALID_YEAR: int = 1990
MAX_VALID_YEAR: int = 2100

_US_LOCALE_TOKENS: frozenset[str] = frozenset({"US", "MM/DD/YYYY", "EN-US", "EN_US"})
_EU_LOCALE_TOKENS: frozenset[str] = frozenset(
    {
        "GB",
        "UK",
        "DE",
        "ES",
        "EU",
        "DD/MM/YYYY",
        "EN-GB",
        "EN_GB",
        "DE-DE",
        "DE_DE",
        "ES-ES",
        "ES_ES",
    }
)
_UNKNOWN_LOCALE_TOKENS: frozenset[str] = frozenset({"", "UNKNOWN", "AUTO"})

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_DISALLOWED_UNICODE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

# Linear-time, strict ASCII [0-9], uniform-separator regexes (zero mixed separators or ReDoS)
_ISO_DATE_RE = re.compile(
    r"^(?P<year>[0-9]{4})(?P<sep>[-/.])(?P<month>[0-9]{1,2})(?P=sep)(?P<day>[0-9]{1,2})$"
)
_REGIONAL_DATE_RE = re.compile(
    r"^(?P<first>[0-9]{1,2})(?P<sep>[-/.])(?P<second>[0-9]{1,2})(?P=sep)(?P<year>[0-9]{4})$"
)


class AmbiguousDateError(ValueError):
    """Raised by ``parse_invoice_date()`` when a date format is ambiguous and requires clerk review."""


def _sanitize_ascii_token(raw: str, *, field_name: str, max_length: int) -> str:
    """Reject control chars, invisible Unicode categories, non-ASCII whitespace, and NFKC spoofing."""
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed control characters")
    for ch in raw:
        if unicodedata.category(ch) in _DISALLOWED_UNICODE_CATEGORIES:
            raise ValueError(f"{field_name} contains disallowed invisible Unicode characters")
        if ch.isspace() and ch != " ":
            raise ValueError(f"{field_name} contains disallowed non-ASCII whitespace")
    nfc = unicodedata.normalize("NFC", raw)
    if unicodedata.normalize("NFKC", nfc) != nfc:
        raise ValueError(f"{field_name} contains disallowed homograph characters")
    cleaned = nfc.strip()
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length} characters")
    return cleaned


def _validate_year_bounds(year: int) -> None:
    """Enforce realistic financial invoice year range [1990, 2100] (CWE-20)."""
    if year < MIN_VALID_YEAR or year > MAX_VALID_YEAR:
        raise ValueError(
            f"Invoice date year {year} is outside allowed financial bounds "
            f"[{MIN_VALID_YEAR}, {MAX_VALID_YEAR}]"
        )


def _try_build_date(year: int, month: int, day: int) -> date | None:
    """Return a validated ``datetime.date`` or ``None`` if calendar day/month is invalid."""
    try:
        return date(year, month, day)
    except ValueError:
        return None


def resolve_date_locale(locale: str | None) -> Literal["US", "EU"] | None:
    """
    Resolve a country code or Vendor Master date preference string to ``'US'``, ``'EU'``, or ``None``.

    - ``'US'``: ``MM/DD/YYYY`` (US vendors)
    - ``'EU'``: ``DD/MM/YYYY`` (UK/GB, DE, ES, EU vendors)
    - ``None``: unlisted/unknown vendor (only ISO 8601 auto-parses; regional dates flag ambiguous)

    Fails closed with ``ValueError`` on unsupported or spoofed locale values.
    """
    if locale is None:
        return None
    cleaned = _sanitize_ascii_token(locale, field_name="locale", max_length=MAX_LOCALE_STR_CHARS)
    upper = cleaned.upper()
    if upper in _UNKNOWN_LOCALE_TOKENS:
        return None
    if upper in _US_LOCALE_TOKENS:
        return "US"
    if upper in _EU_LOCALE_TOKENS:
        return "EU"
    raise ValueError(
        f"Unsupported date locale '{cleaned}': expected US/MM/DD/YYYY, "
        "GB/UK/DE/ES/EU/DD/MM/YYYY, or UNKNOWN"
    )


class DateNormalizationResult(BaseModel):
    """Immutable structured result for single-date normalization (FR-08)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_date: str
    parsed_date: date | None
    iso_date: str | None
    is_valid: bool
    is_ambiguous: bool
    is_syntactically_ambiguous: bool
    requires_clerk_verification: bool
    applied_locale: Literal["US", "EU"] | None
    resolved_via: Literal["ISO_8601", "VENDOR_MASTER", "UNRESOLVED"]
    candidate_us_date: date | None = None
    candidate_eu_date: date | None = None
    recommended_status: Literal["REQUIRES_REVIEW"] | None = None
    message: str


class InvoiceDatesValidationResult(BaseModel):
    """Immutable structured result for paired ``(invoice_date, due_date)`` normalization (FR-08)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool
    is_ambiguous: bool
    chronological_conflict: bool
    requires_clerk_verification: bool
    applied_locale: Literal["US", "EU"] | None
    invoice_date: date | None
    due_date: date | None
    invoice_date_result: DateNormalizationResult
    due_date_result: DateNormalizationResult | None = None
    recommended_status: Literal["REQUIRES_REVIEW"] | None = None
    message: str


def normalize_invoice_date(
    date_str: str,
    locale: str | None = None,
) -> DateNormalizationResult:
    """
    Parse and normalize an invoice date string using the Vendor Master locale (FR-08, BR-012).

    Raises ``ValueError`` on malformed input, unsupported locales, control/homograph characters,
    mixed delimiters, or out-of-range years. Returns ``is_ambiguous=True`` (without raising) when
    an unlisted vendor supplies a regional date requiring clerk verification.
    """
    resolved_locale = resolve_date_locale(locale)
    cleaned = _sanitize_ascii_token(date_str, field_name="date_str", max_length=MAX_DATE_STR_CHARS)
    if not cleaned:
        raise ValueError("date_str must be non-empty")

    # 1. ISO 8601 (YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD) — always unambiguous
    iso_match = _ISO_DATE_RE.match(cleaned)
    if iso_match is not None:
        year = int(iso_match.group("year"))
        month = int(iso_match.group("month"))
        day = int(iso_match.group("day"))
        _validate_year_bounds(year)
        parsed = _try_build_date(year, month, day)
        if parsed is None:
            raise ValueError(f"Invalid calendar date '{cleaned}'")
        result = DateNormalizationResult(
            raw_date=cleaned,
            parsed_date=parsed,
            iso_date=parsed.isoformat(),
            is_valid=True,
            is_ambiguous=False,
            is_syntactically_ambiguous=False,
            requires_clerk_verification=False,
            applied_locale=resolved_locale,
            resolved_via="ISO_8601",
            candidate_us_date=parsed,
            candidate_eu_date=parsed,
            recommended_status=None,
            message=f"Normalized unambiguous ISO 8601 date to {parsed.isoformat()}.",
        )
        _log_date_outcome(result)
        return result

    # 2. Regional date (MM/DD/YYYY or DD/MM/YYYY with uniform /, -, or . separator)
    reg_match = _REGIONAL_DATE_RE.match(cleaned)
    if reg_match is None:
        raise ValueError(
            f"Malformed date string '{cleaned}': expected YYYY-MM-DD, MM/DD/YYYY, or DD/MM/YYYY"
        )

    first = int(reg_match.group("first"))
    second = int(reg_match.group("second"))
    year = int(reg_match.group("year"))
    _validate_year_bounds(year)

    cand_us = _try_build_date(year, first, second)
    cand_eu = _try_build_date(year, second, first)

    if cand_us is None and cand_eu is None:
        raise ValueError(f"Invalid calendar date '{cleaned}'")

    syntactically_ambiguous = cand_us is not None and cand_eu is not None and cand_us != cand_eu

    # 2a. Known Vendor Master locale (US or EU)
    if resolved_locale == "US":
        if cand_us is not None:
            result = DateNormalizationResult(
                raw_date=cleaned,
                parsed_date=cand_us,
                iso_date=cand_us.isoformat(),
                is_valid=True,
                is_ambiguous=False,
                is_syntactically_ambiguous=syntactically_ambiguous,
                requires_clerk_verification=False,
                applied_locale="US",
                resolved_via="VENDOR_MASTER",
                candidate_us_date=cand_us,
                candidate_eu_date=cand_eu,
                recommended_status=None,
                message=f"Resolved date '{cleaned}' via US Vendor Master locale to {cand_us.isoformat()}.",
            )
            _log_date_outcome(result)
            return result

        # Not valid as MM/DD/YYYY, but valid as DD/MM/YYYY -> locale mismatch requiring clerk review
        result = DateNormalizationResult(
            raw_date=cleaned,
            parsed_date=None,
            iso_date=None,
            is_valid=False,
            is_ambiguous=True,
            is_syntactically_ambiguous=False,
            requires_clerk_verification=True,
            applied_locale="US",
            resolved_via="UNRESOLVED",
            candidate_us_date=None,
            candidate_eu_date=cand_eu,
            recommended_status="REQUIRES_REVIEW",
            message=(
                f"Date '{cleaned}' is invalid under US (MM/DD/YYYY) locale "
                f"(valid under EU DD/MM/YYYY as {cand_eu.isoformat() if cand_eu else 'N/A'}) "
                "and requires clerk verification."
            ),
        )
        _log_date_outcome(result)
        return result

    if resolved_locale == "EU":
        if cand_eu is not None:
            result = DateNormalizationResult(
                raw_date=cleaned,
                parsed_date=cand_eu,
                iso_date=cand_eu.isoformat(),
                is_valid=True,
                is_ambiguous=False,
                is_syntactically_ambiguous=syntactically_ambiguous,
                requires_clerk_verification=False,
                applied_locale="EU",
                resolved_via="VENDOR_MASTER",
                candidate_us_date=cand_us,
                candidate_eu_date=cand_eu,
                recommended_status=None,
                message=f"Resolved date '{cleaned}' via EU Vendor Master locale to {cand_eu.isoformat()}.",
            )
            _log_date_outcome(result)
            return result

        result = DateNormalizationResult(
            raw_date=cleaned,
            parsed_date=None,
            iso_date=None,
            is_valid=False,
            is_ambiguous=True,
            is_syntactically_ambiguous=False,
            requires_clerk_verification=True,
            applied_locale="EU",
            resolved_via="UNRESOLVED",
            candidate_us_date=cand_us,
            candidate_eu_date=None,
            recommended_status="REQUIRES_REVIEW",
            message=(
                f"Date '{cleaned}' is invalid under EU (DD/MM/YYYY) locale "
                f"(valid under US MM/DD/YYYY as {cand_us.isoformat() if cand_us else 'N/A'}) "
                "and requires clerk verification."
            ),
        )
        _log_date_outcome(result)
        return result

    # 2b. Unlisted / unknown vendor locale (BR-012, LLD §5.4): non-ISO requires clerk verification
    result = DateNormalizationResult(
        raw_date=cleaned,
        parsed_date=None,
        iso_date=None,
        is_valid=False,
        is_ambiguous=True,
        is_syntactically_ambiguous=syntactically_ambiguous,
        requires_clerk_verification=True,
        applied_locale=None,
        resolved_via="UNRESOLVED",
        candidate_us_date=cand_us,
        candidate_eu_date=cand_eu,
        recommended_status="REQUIRES_REVIEW",
        message=f"Ambiguous date format '{cleaned}' requires clerk verification.",
    )
    _log_date_outcome(result)
    return result


def parse_invoice_date(date_str: str, locale: str | None) -> date:
    """
    LLD §5.4 / FR-08 contract: parse an invoice date using the Vendor Master locale.

    Raises ``AmbiguousDateError`` (subclass of ``ValueError``) when the date is ambiguous
    and requires clerk verification, or ``ValueError`` on malformed/invalid dates.
    """
    res = normalize_invoice_date(date_str, locale=locale)
    if res.is_valid and res.parsed_date is not None:
        return res.parsed_date
    if res.is_ambiguous:
        raise AmbiguousDateError(res.message)
    raise ValueError(res.message)


def normalize_invoice_dates(
    invoice_date_str: str,
    due_date_str: str | None = None,
    *,
    locale: str | None = None,
) -> InvoiceDatesValidationResult:
    """
    Normalize ``(invoice_date, due_date)`` together and detect chronological locale conflicts
    (e.g. ``INV-2026-1005`` where ``due_date < invoice_date`` under US locale while valid under EU).
    """
    inv_res = normalize_invoice_date(invoice_date_str, locale=locale)
    due_res = (
        normalize_invoice_date(due_date_str, locale=locale) if due_date_str is not None else None
    )

    if not inv_res.is_valid or (due_res is not None and not due_res.is_valid):
        msgs = [r.message for r in (inv_res, due_res) if r is not None and not r.is_valid]
        is_ambig = inv_res.is_ambiguous or (due_res is not None and due_res.is_ambiguous)
        return InvoiceDatesValidationResult(
            is_valid=False,
            is_ambiguous=is_ambig,
            chronological_conflict=False,
            requires_clerk_verification=True,
            applied_locale=inv_res.applied_locale,
            invoice_date=inv_res.parsed_date,
            due_date=due_res.parsed_date if due_res is not None else None,
            invoice_date_result=inv_res,
            due_date_result=due_res,
            recommended_status="REQUIRES_REVIEW",
            message="; ".join(msgs),
        )

    parsed_inv = inv_res.parsed_date
    parsed_due = due_res.parsed_date if due_res is not None else None

    # Check chronological consistency: due_date MUST NOT precede invoice_date
    if parsed_inv is not None and parsed_due is not None and parsed_due < parsed_inv:
        assert due_res is not None
        alt_hint = ""
        if (
            inv_res.applied_locale == "US"
            and inv_res.candidate_eu_date is not None
            and due_res.candidate_eu_date is not None
            and due_res.candidate_eu_date >= inv_res.candidate_eu_date
        ):
            alt_hint = (
                f"; alternate EU (DD/MM/YYYY) interpretation yields valid range "
                f"({inv_res.candidate_eu_date.isoformat()} to {due_res.candidate_eu_date.isoformat()})"
            )
        elif (
            inv_res.applied_locale == "EU"
            and inv_res.candidate_us_date is not None
            and due_res.candidate_us_date is not None
            and due_res.candidate_us_date >= inv_res.candidate_us_date
        ):
            alt_hint = (
                f"; alternate US (MM/DD/YYYY) interpretation yields valid range "
                f"({inv_res.candidate_us_date.isoformat()} to {due_res.candidate_us_date.isoformat()})"
            )

        conflict_msg = (
            f"Ambiguous date locale conflict under {inv_res.applied_locale or 'ISO'} locale: "
            f"due_date ({parsed_due.isoformat()}) precedes invoice_date ({parsed_inv.isoformat()})"
            f"{alt_hint} — requires clerk verification."
        )
        logger.info(
            "Invoice date chronological locale conflict detected",
            extra={
                "applied_locale": inv_res.applied_locale,
                "chronological_conflict": True,
                "recommended_status": "REQUIRES_REVIEW",
            },
        )
        return InvoiceDatesValidationResult(
            is_valid=False,
            is_ambiguous=True,
            chronological_conflict=True,
            requires_clerk_verification=True,
            applied_locale=inv_res.applied_locale,
            invoice_date=parsed_inv,
            due_date=parsed_due,
            invoice_date_result=inv_res,
            due_date_result=due_res,
            recommended_status="REQUIRES_REVIEW",
            message=conflict_msg,
        )

    return InvoiceDatesValidationResult(
        is_valid=True,
        is_ambiguous=False,
        chronological_conflict=False,
        requires_clerk_verification=False,
        applied_locale=inv_res.applied_locale,
        invoice_date=parsed_inv,
        due_date=parsed_due,
        invoice_date_result=inv_res,
        due_date_result=due_res,
        recommended_status=None,
        message=(
            f"Normalized invoice_date={parsed_inv.isoformat() if parsed_inv else 'None'}"
            + (f", due_date={parsed_due.isoformat()}" if parsed_due else "")
            + "."
        ),
    )


def normalize_extraction_dates(
    extraction: InvoiceExtractionSchema,
    *,
    locale: str | None = None,
) -> InvoiceDatesValidationResult:
    """Normalize header ``invoice_date`` and optional ``due_date`` directly from P6-3 extraction."""
    return normalize_invoice_dates(
        extraction.header.invoice_date.value,
        extraction.header.due_date.value,
        locale=locale,
    )


def _log_date_outcome(result: DateNormalizationResult) -> None:
    """Emit structured PII-free date normalization telemetry."""
    logger.info(
        "Invoice date normalization evaluated",
        extra={
            "is_valid": result.is_valid,
            "is_ambiguous": result.is_ambiguous,
            "applied_locale": result.applied_locale,
            "resolved_via": result.resolved_via,
            "recommended_status": result.recommended_status,
        },
    )


__all__ = [
    "MAX_DATE_STR_CHARS",
    "MAX_LOCALE_STR_CHARS",
    "MAX_VALID_YEAR",
    "MIN_VALID_YEAR",
    "AmbiguousDateError",
    "DateNormalizationResult",
    "InvoiceDatesValidationResult",
    "normalize_extraction_dates",
    "normalize_invoice_date",
    "normalize_invoice_dates",
    "parse_invoice_date",
    "resolve_date_locale",
]
