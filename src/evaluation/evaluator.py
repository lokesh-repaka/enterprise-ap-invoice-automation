"""
Offline Automated Batch Evaluation Harness & Field-by-Field Comparator (P13-1).

Covers FR-14, CLAUDE.md §4.2, §10, §13, §14:
- Discovers and pairs pilot invoice documents in ``sample_data/invoices/`` against
  human-verified ground-truth JSON files in ``sample_data/ground_truth/``.
- Runs every invoice through the full offline Extraction + Validation + Routing pipeline
  (``ExtractionEngine`` + ``MockAOAIClient`` -> ``RulesEngine`` -> ``ConfidenceRouter`` ->
  ``EscalationEvaluator`` with ECB FX lookup) without touching production databases or
  external networks.
- Compares all 10 canonical header fields (flagging the 4 critical hard-floor fields) and
  all 5 line-item fields per line against ground-truth JSON with Decimal and whitespace
  normalization.
- Captures per-invoice outcomes, STP flags, status distributions, and crash isolation counts
  for metric reporting (P13-2), pytest CI threshold gates (P13-3), and CLI reporting (P13-4).

Security & Layering Invariants:
- MUST NOT be imported by production packages (``src/api``, ``src/services``, ``src/ui``,
  ``src/validation``, ``src/database``, ``src/extraction``, ``src/storage``: CLAUDE.md §4.2).
- Enforces strict path containment, symlink rejection (``O_NOFOLLOW``), and file/batch size
  ceilings (SEC-220, CWE-22 / CWE-59 / CWE-400).
- Zero raw Vendor Tax ID PII in logs or ``__repr__`` (SEC-221, CWE-532).
- Offline-only default execution, per-invoice exception isolation, and strict non-approval
  routing invariant (SEC-222, CWE-489 / CWE-863).
"""

import json
import os
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.extraction.extract_engine import ExtractionEngine
from src.extraction.mock_aoai_client import MockAOAIClient
from src.extraction.model_gateway import ModelGateway
from src.extraction.schemas import (
    CRITICAL_HEADER_FIELD_NAMES,
    HEADER_FIELD_NAMES,
    LINE_ITEM_FIELD_NAMES,
    InvoiceExtractionSchema,
    InvoiceLineItemExtraction,
)
from src.validation.confidence_router import ConfidenceRouter
from src.validation.duplicate_detector import compute_composite_hash
from src.validation.escalation_rules import EscalationEvaluator, MissingExchangeRateError
from src.validation.rules_engine import RulesEngine, VendorRuleContext

logger = get_logger("ap.evaluation.evaluator")

MAX_BATCH_INVOICES: int = 1_000
MAX_EVAL_INVOICE_BYTES: int = 25 * 1024 * 1024
MAX_EVAL_GROUND_TRUTH_BYTES: int = 1 * 1024 * 1024
SUPPORTED_INVOICE_EXTENSIONS: frozenset[str] = frozenset(
    {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".xlsx"}
)
_NUMERIC_HEADER_FIELDS: frozenset[str] = frozenset({"subtotal", "tax_amount", "total_amount"})
_UPPERCASE_STRING_FIELDS: frozenset[str] = frozenset(
    {"vendor_tax_id", "invoice_number", "currency"}
)
_NUMERIC_LINE_FIELDS: frozenset[str] = frozenset(
    {"quantity", "unit_price", "line_total", "tax_rate"}
)
_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.0001")
_CRITICAL_SET: frozenset[str] = frozenset(CRITICAL_HEADER_FIELD_NAMES)


class EvaluationSecurityError(PermissionError):
    """Raised when evaluation dataset discovery/loading violates path or symlink security bounds."""


class EvaluationCase(BaseModel):
    """Immutable discovered (invoice file, ground-truth JSON) evaluation pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    invoice_stem: str
    invoice_path: Path
    ground_truth_path: Path


class FieldComparisonResult(BaseModel):
    """Immutable field-by-field comparison outcome for a single header field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field_name: str
    expected_value: str | None
    predicted_value: str | None
    matched: bool
    is_critical: bool
    confidence: Decimal | None = None

    def __repr__(self) -> str:
        if self.field_name == "vendor_tax_id":
            return (
                f"FieldComparisonResult(field_name='vendor_tax_id', "
                f"matched={self.matched}, is_critical={self.is_critical})"
            )
        return (
            f"FieldComparisonResult(field_name={self.field_name!r}, "
            f"matched={self.matched}, is_critical={self.is_critical})"
        )


class LineFieldComparisonResult(BaseModel):
    """Immutable field-by-field comparison outcome for a single line-item field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    line_number: int
    field_name: str
    expected_value: str | None
    predicted_value: str | None
    matched: bool
    confidence: Decimal | None = None


class InvoiceEvaluationResult(BaseModel):
    """Immutable end-to-end evaluation result for a single pilot invoice."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    invoice_stem: str
    invoice_filename: str
    test_case_type: str = "standard"
    succeeded: bool
    error_message: str | None = None
    routed_status: str | None = None
    stp_achieved: bool = False
    rules_passed: bool = False
    header_comparisons: tuple[FieldComparisonResult, ...] = ()
    line_comparisons: tuple[LineFieldComparisonResult, ...] = ()
    expected_line_count: int = 0
    predicted_line_count: int = 0
    header_matched_count: int = 0
    header_total_count: int = 0
    line_matched_count: int = 0
    line_total_count: int = 0
    model_version: str | None = None
    latency_ms: int = 0

    def __repr__(self) -> str:
        # Omit header_comparisons values to prevent raw vendor_tax_id PII exposure (SEC-221)
        return (
            f"InvoiceEvaluationResult(invoice_stem={self.invoice_stem!r}, "
            f"succeeded={self.succeeded}, routed_status={self.routed_status!r}, "
            f"stp_achieved={self.stp_achieved}, "
            f"header={self.header_matched_count}/{self.header_total_count}, "
            f"lines={self.line_matched_count}/{self.line_total_count})"
        )


class BatchEvaluationResult(BaseModel):
    """Immutable aggregated output across an evaluated batch of invoices (FR-14)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_data_dir: str
    total_invoices: int
    completed_invoices: int
    crashed_invoices: int
    results: tuple[InvoiceEvaluationResult, ...]
    per_header_field_counts: dict[str, tuple[int, int]]
    total_line_fields_matched: int
    total_line_fields_expected: int
    stp_count: int
    status_distribution: dict[str, int]
    total_duration_ms: int


# ---------------------------------------------------------------------------
# Safe File I/O & Path Containment (SEC-220)
# ---------------------------------------------------------------------------


def _assert_safe_file(path: Path, *, root_dir: Path, max_bytes: int) -> Path:
    """Verify path is a regular, non-symlink file strictly inside root_dir within max_bytes."""
    if path.is_symlink():
        raise EvaluationSecurityError(
            f"Symlink file rejected inside evaluation dataset: {path.name}"
        )
    resolved_root = root_dir.resolve()
    resolved_target = path.resolve()
    if not resolved_target.is_relative_to(resolved_root):
        raise EvaluationSecurityError(
            f"Path traversal blocked outside evaluation root: {path.name}"
        )
    if not resolved_target.is_file():
        raise FileNotFoundError(f"Expected evaluation file does not exist: {path.name}")
    size = resolved_target.stat().st_size
    if size > max_bytes:
        raise EvaluationSecurityError(
            f"Evaluation file '{path.name}' exceeds maximum allowed size of {max_bytes} bytes"
        )
    return resolved_target


def _read_safe_bytes(path: Path, *, root_dir: Path, max_bytes: int) -> bytes:
    """Read file bytes using O_NOFOLLOW to prevent TOCTOU symlink swaps (SEC-220, CWE-59)."""
    safe_path = _assert_safe_file(path, root_dir=root_dir, max_bytes=max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(safe_path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EvaluationSecurityError(f"Non-regular file rejected: {safe_path.name}")
        if st.st_size > max_bytes:
            raise EvaluationSecurityError(
                f"Evaluation file '{safe_path.name}' exceeds maximum allowed size of {max_bytes} bytes"
            )
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > max_bytes:
        raise EvaluationSecurityError(
            f"Evaluation file '{safe_path.name}' exceeded bounded read ceiling"
        )
    return data


def discover_evaluation_cases(
    sample_data_dir: Path | str,
    *,
    limit: int | None = None,
) -> tuple[EvaluationCase, ...]:
    """
    Discover and pair invoice files in ``invoices/`` with ``ground_truth/<stem>_ground_truth.json``.

    Enforces deterministic sorted ordering, symlink rejection, containment checks, and a strict
    ``MAX_BATCH_INVOICES`` ceiling (SEC-220, CWE-22 / CWE-59 / CWE-400).
    """
    if limit is not None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not (1 <= limit <= MAX_BATCH_INVOICES)
        ):
            raise ValueError(f"limit must be an integer within [1, {MAX_BATCH_INVOICES}]")

    root = Path(sample_data_dir).resolve()
    invoices_dir = root / "invoices"
    gt_dir = root / "ground_truth"
    if not invoices_dir.is_dir() or not gt_dir.is_dir():
        raise FileNotFoundError(
            f"Evaluation dataset directories 'invoices/' and 'ground_truth/' not found under {root}"
        )

    cases: list[EvaluationCase] = []
    for inv_entry in sorted(invoices_dir.iterdir(), key=lambda p: p.name):
        if inv_entry.name.startswith("."):
            continue
        if inv_entry.is_symlink():
            raise EvaluationSecurityError(
                f"Symlink file rejected inside evaluation dataset: {inv_entry.name}"
            )
        if not inv_entry.is_file():
            continue
        if inv_entry.suffix.lower() not in SUPPORTED_INVOICE_EXTENSIONS:
            continue

        safe_inv = _assert_safe_file(inv_entry, root_dir=root, max_bytes=MAX_EVAL_INVOICE_BYTES)
        gt_candidate = gt_dir / f"{inv_entry.stem}_ground_truth.json"
        if gt_candidate.is_symlink():
            raise EvaluationSecurityError(
                f"Symlink ground-truth file rejected: {gt_candidate.name}"
            )
        safe_gt = _assert_safe_file(
            gt_candidate, root_dir=root, max_bytes=MAX_EVAL_GROUND_TRUTH_BYTES
        )

        cases.append(
            EvaluationCase(
                invoice_stem=inv_entry.stem,
                invoice_path=safe_inv,
                ground_truth_path=safe_gt,
            )
        )
        if limit is not None and len(cases) >= limit:
            break
        if len(cases) > MAX_BATCH_INVOICES:
            raise EvaluationSecurityError(
                f"Evaluation batch exceeds maximum allowed size of {MAX_BATCH_INVOICES} invoices"
            )

    return tuple(cases)


# ---------------------------------------------------------------------------
# Field-by-Field Comparison Logic (FR-14, CLAUDE.md §10)
# ---------------------------------------------------------------------------


def _normalize_numeric(raw: Any, *, quantum: Decimal) -> Decimal | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        dec = raw if isinstance(raw, Decimal) else Decimal(str(raw).strip())
    except InvalidOperation:
        return None
    if not dec.is_finite():
        return None
    q = dec.quantize(quantum, rounding=ROUND_HALF_UP)
    return Decimal("0").quantize(quantum) if q == 0 else q


def _normalize_text(raw: Any, *, uppercase: bool = False) -> str | None:
    if raw is None:
        return None
    cleaned = " ".join(str(raw).strip().split())
    if not cleaned:
        return None
    return cleaned.upper() if uppercase else cleaned.lower()


def _format_display(raw: Any, *, numeric_quantum: Decimal | None = None) -> str | None:
    if raw is None:
        return None
    if numeric_quantum is not None:
        norm = _normalize_numeric(raw, quantum=numeric_quantum)
        return str(norm) if norm is not None else str(raw)
    cleaned = " ".join(str(raw).strip().split())
    return cleaned or None


def _compare_single_field(
    field_name: str,
    expected_raw: Any,
    predicted_raw: Any,
    *,
    is_numeric: bool,
    numeric_quantum: Decimal = _MONEY_QUANTUM,
    uppercase: bool = False,
) -> tuple[bool, str | None, str | None]:
    if is_numeric:
        exp_num = _normalize_numeric(expected_raw, quantum=numeric_quantum)
        pred_num = _normalize_numeric(predicted_raw, quantum=numeric_quantum)
        matched = exp_num is not None and pred_num is not None and exp_num == pred_num
        return (
            matched,
            _format_display(expected_raw, numeric_quantum=numeric_quantum),
            _format_display(predicted_raw, numeric_quantum=numeric_quantum),
        )

    exp_txt = _normalize_text(expected_raw, uppercase=uppercase)
    pred_txt = _normalize_text(predicted_raw, uppercase=uppercase)
    matched = exp_txt == pred_txt
    return matched, _format_display(expected_raw), _format_display(predicted_raw)


def compare_header_fields(
    predicted: InvoiceExtractionSchema,
    ground_truth_header: Mapping[str, Any],
) -> tuple[FieldComparisonResult, ...]:
    """Compare all 10 canonical header fields between extraction output and ground-truth JSON."""
    results: list[FieldComparisonResult] = []
    for field_name in HEADER_FIELD_NAMES:
        ext_field = getattr(predicted.header, field_name)
        expected_raw = ground_truth_header.get(field_name)
        is_num = field_name in _NUMERIC_HEADER_FIELDS
        matched, exp_disp, pred_disp = _compare_single_field(
            field_name,
            expected_raw,
            ext_field.value,
            is_numeric=is_num,
            numeric_quantum=_MONEY_QUANTUM,
            uppercase=field_name in _UPPERCASE_STRING_FIELDS,
        )
        results.append(
            FieldComparisonResult(
                field_name=field_name,
                expected_value=exp_disp,
                predicted_value=pred_disp,
                matched=matched,
                is_critical=field_name in _CRITICAL_SET,
                confidence=ext_field.confidence,
            )
        )
    return tuple(results)


def compare_line_items(
    predicted_lines: Sequence[InvoiceLineItemExtraction],
    ground_truth_lines: Sequence[Mapping[str, Any]],
) -> tuple[LineFieldComparisonResult, ...]:
    """Compare all 5 fields per line item between extraction output and ground-truth JSON."""
    results: list[LineFieldComparisonResult] = []
    total_rows = max(len(predicted_lines), len(ground_truth_lines))

    for idx in range(total_rows):
        line_num = idx + 1
        pred_line = predicted_lines[idx] if idx < len(predicted_lines) else None
        gt_line = ground_truth_lines[idx] if idx < len(ground_truth_lines) else None

        for field_name in LINE_ITEM_FIELD_NAMES:
            is_num = field_name in _NUMERIC_LINE_FIELDS
            quantum = (
                _RATE_QUANTUM
                if field_name in ("tax_rate", "quantity", "unit_price")
                else _MONEY_QUANTUM
            )
            exp_raw = gt_line.get(field_name) if gt_line is not None else None
            pred_field = getattr(pred_line, field_name) if pred_line is not None else None
            pred_raw = pred_field.value if pred_field is not None else None
            conf = pred_field.confidence if pred_field is not None else None

            if pred_line is None or gt_line is None:
                matched = False
                exp_disp = _format_display(exp_raw, numeric_quantum=quantum if is_num else None)
                pred_disp = _format_display(pred_raw, numeric_quantum=quantum if is_num else None)
            else:
                matched, exp_disp, pred_disp = _compare_single_field(
                    field_name,
                    exp_raw,
                    pred_raw,
                    is_numeric=is_num,
                    numeric_quantum=quantum,
                )

            results.append(
                LineFieldComparisonResult(
                    line_number=line_num,
                    field_name=field_name,
                    expected_value=exp_disp,
                    predicted_value=pred_disp,
                    matched=matched,
                    confidence=conf,
                )
            )
    return tuple(results)


# ---------------------------------------------------------------------------
# In-Memory Batch Lookups for Offline Rules & FX Evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _EvalInvoiceRecord:
    invoice_id: str
    vendor_tax_id: str
    invoice_number: str
    total_amount: Decimal
    status: str
    composite_hash: str


class _InMemoryBatchInvoiceLookup:
    """In-memory ``InvoiceLookupProtocol`` tracking prior invoices processed in the same batch."""

    def __init__(self) -> None:
        self._records: list[_EvalInvoiceRecord] = []

    def add(self, record: _EvalInvoiceRecord) -> None:
        self._records.append(record)

    async def get_by_composite_hash(self, composite_hash: str) -> _EvalInvoiceRecord | None:
        for rec in self._records:
            if rec.composite_hash == composite_hash and rec.status not in (
                "REJECTED_DUPLICATE",
                "VOID",
            ):
                return rec
        return None

    async def get_by_vendor_and_number(
        self, vendor_tax_id: str, invoice_number: str
    ) -> list[_EvalInvoiceRecord]:
        tax_upper = vendor_tax_id.strip().upper()
        num_upper = invoice_number.strip().upper()
        return [
            rec
            for rec in self._records
            if rec.vendor_tax_id.strip().upper() == tax_upper
            and rec.invoice_number.strip().upper() == num_upper
        ]


@dataclass(frozen=True)
class _EvalExchangeRateRecord:
    rate_date: date
    from_currency: str
    to_currency: str
    exchange_rate: Decimal


class _InMemoryExchangeRateLookup:
    """In-memory ``ExchangeRateLookupProtocol`` seeded from ``sample_data/exchange_rates.json``."""

    def __init__(self, rates: Sequence[_EvalExchangeRateRecord]) -> None:
        self._rates = sorted(rates, key=lambda r: r.rate_date)

    async def get_latest_rate_on_or_before(
        self,
        target_date: date,
        from_currency: str,
        to_currency: str = "USD",
    ) -> _EvalExchangeRateRecord | None:
        fc = from_currency.strip().upper()
        tc = to_currency.strip().upper()
        matching = [r for r in self._rates if r.from_currency == fc and r.to_currency == tc]
        if not matching:
            return None
        on_or_before = [r for r in matching if r.rate_date <= target_date]
        if on_or_before:
            return on_or_before[-1]
        # Single-snapshot dev seed fallback (GAP-003): anchor earliest snapshot to target_date
        earliest = matching[0]
        return _EvalExchangeRateRecord(
            rate_date=target_date,
            from_currency=earliest.from_currency,
            to_currency=earliest.to_currency,
            exchange_rate=earliest.exchange_rate,
        )


def _load_vendor_contexts(root_dir: Path) -> dict[str, VendorRuleContext]:
    raw_bytes = _read_safe_bytes(
        root_dir / "vendor_master.json",
        root_dir=root_dir,
        max_bytes=MAX_EVAL_GROUND_TRUTH_BYTES,
    )
    vendors = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(vendors, list):
        raise ValueError("vendor_master.json must contain a JSON array")
    return {
        str(v["TaxID_VAT"]).strip().upper(): VendorRuleContext.from_vendor(v)
        for v in vendors
        if isinstance(v, Mapping) and "TaxID_VAT" in v
    }


def _load_exchange_rates(root_dir: Path) -> _InMemoryExchangeRateLookup:
    fx_path = root_dir / "exchange_rates.json"
    if not fx_path.exists():
        return _InMemoryExchangeRateLookup(())
    raw_bytes = _read_safe_bytes(
        fx_path,
        root_dir=root_dir,
        max_bytes=MAX_EVAL_GROUND_TRUTH_BYTES,
    )
    rows = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(rows, list):
        raise ValueError("exchange_rates.json must contain a JSON array")
    parsed: list[_EvalExchangeRateRecord] = []
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        parsed.append(
            _EvalExchangeRateRecord(
                rate_date=date.fromisoformat(str(item["RateDate"]).strip()),
                from_currency=str(item["FromCurrency"]).strip().upper(),
                to_currency=str(item["ToCurrency"]).strip().upper(),
                exchange_rate=Decimal(str(item["ExchangeRate"])),
            )
        )
    return _InMemoryExchangeRateLookup(parsed)


# ---------------------------------------------------------------------------
# Batch Evaluator Orchestrator (P13-1)
# ---------------------------------------------------------------------------


class InvoiceBatchEvaluator:
    """
    Offline batch inference & ground-truth evaluation engine (P13-1, FR-14, CLAUDE.md §10).
    """

    def __init__(
        self,
        *,
        sample_data_dir: Path | str | None = None,
        extraction_engine: ExtractionEngine | None = None,
        confidence_router: ConfidenceRouter | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._sample_data_dir = Path(
            sample_data_dir if sample_data_dir is not None else self._settings.SAMPLE_DATA_DIR
        ).resolve()

        if extraction_engine is not None:
            self._extraction_engine = extraction_engine
        else:
            # Offline-first default: wire MockAOAIClient so zero network calls occur (SEC-222)
            mock_client = MockAOAIClient(settings=self._settings)
            gateway = ModelGateway(settings=self._settings, chat_client=mock_client)
            self._extraction_engine = ExtractionEngine(gateway=gateway)

        self._confidence_router = confidence_router or ConfidenceRouter()

    async def evaluate_case(
        self,
        case: EvaluationCase,
        *,
        vendor_contexts: Mapping[str, VendorRuleContext],
        invoice_lookup: _InMemoryBatchInvoiceLookup,
        fx_lookup: _InMemoryExchangeRateLookup,
    ) -> InvoiceEvaluationResult:
        """Execute extraction -> validation -> routing -> comparison for a single invoice safely."""
        started = time.perf_counter()
        test_case_type = "standard"
        try:
            gt_bytes = _read_safe_bytes(
                case.ground_truth_path,
                root_dir=self._sample_data_dir,
                max_bytes=MAX_EVAL_GROUND_TRUTH_BYTES,
            )
            gt_payload = json.loads(gt_bytes.decode("utf-8"))
            if not isinstance(gt_payload, Mapping):
                raise ValueError("Ground-truth JSON must be an object")
            meta = gt_payload.get("invoice_metadata")
            if isinstance(meta, Mapping) and isinstance(meta.get("test_case_type"), str):
                test_case_type = meta["test_case_type"].strip() or "standard"
            gt_header = gt_payload["header"]
            gt_lines = gt_payload.get("line_items", [])
            if not isinstance(gt_header, Mapping) or not isinstance(gt_lines, list):
                raise ValueError("Ground-truth JSON missing 'header' object or 'line_items' list")

            inv_bytes = _read_safe_bytes(
                case.invoice_path,
                root_dir=self._sample_data_dir,
                max_bytes=MAX_EVAL_INVOICE_BYTES,
            )
            if case.invoice_path.suffix.lower() == ".txt":
                ext_result = await self._extraction_engine.extract_from_text(
                    inv_bytes.decode("utf-8")
                )
            else:
                ext_result = await self._extraction_engine.extract(inv_bytes)

            extraction = ext_result.extraction
            tax_id_key = extraction.header.vendor_tax_id.value.strip().upper()
            vendor_ctx = vendor_contexts.get(
                tax_id_key,
                VendorRuleContext(country_code="US", date_locale=None, standard_tax_rate=None),
            )

            rules_engine = RulesEngine(repository=invoice_lookup)
            rules_result = await rules_engine.validate_extraction(
                extraction,
                vendor_context=vendor_ctx,
                filename=case.invoice_path.name,
                current_invoice_id=f"eval-{case.invoice_stem}",
            )

            conf_result = self._confidence_router.route_extraction(
                extraction,
                rules_result=rules_result,
            )
            final_status: str = conf_result.target_status

            # High-value USD / FX escalation (FR-13)
            currency = extraction.header.currency.value.strip().upper()
            resolved_inv_date = (
                rules_result.date_result.invoice_date
                if rules_result.date_result is not None
                else None
            )
            evaluator = EscalationEvaluator(exchange_rate_repo=fx_lookup)
            if currency == "USD":
                esc_res = evaluator.evaluate(
                    total_amount=extraction.header.total_amount.value,
                    currency="USD",
                    current_status=final_status,  # type: ignore[arg-type]
                )
                final_status = esc_res.target_status
            elif resolved_inv_date is not None:
                try:
                    esc_res = await evaluator.evaluate_with_fx(
                        total_amount=extraction.header.total_amount.value,
                        currency=currency,
                        invoice_date=resolved_inv_date,
                        current_status=final_status,  # type: ignore[arg-type]
                    )
                    final_status = esc_res.target_status
                except MissingExchangeRateError:
                    if final_status == "VALIDATED":
                        final_status = "REQUIRES_REVIEW"

            # Never permit self-approval inside batch evaluation (CLAUDE.md §16.1, SEC-222)
            if final_status.startswith("APPROVED_"):
                raise ValueError(f"Disallowed approval status in evaluator: {final_status!r}")

            # Record processed invoice into in-memory batch lookup for downstream duplicate/rev checks
            inv_total = extraction.header.total_amount.value
            inv_num = extraction.header.invoice_number.value.strip()
            invoice_lookup.add(
                _EvalInvoiceRecord(
                    invoice_id=f"eval-{case.invoice_stem}",
                    vendor_tax_id=extraction.header.vendor_tax_id.value.strip(),
                    invoice_number=inv_num,
                    total_amount=inv_total,
                    status=final_status,
                    composite_hash=compute_composite_hash(
                        extraction.header.vendor_tax_id.value.strip(),
                        inv_num,
                        inv_total,
                    ),
                )
            )

            header_comps = compare_header_fields(extraction, gt_header)
            line_comps = compare_line_items(extraction.line_items, gt_lines)
            header_matched = sum(1 for c in header_comps if c.matched)
            line_matched = sum(1 for c in line_comps if c.matched)
            elapsed_ms = int((time.perf_counter() - started) * 1000)

            return InvoiceEvaluationResult(
                invoice_stem=case.invoice_stem,
                invoice_filename=case.invoice_path.name,
                test_case_type=test_case_type,
                succeeded=True,
                routed_status=final_status,
                stp_achieved=rules_result.all_passed and final_status == "VALIDATED",
                rules_passed=rules_result.all_passed,
                header_comparisons=header_comps,
                line_comparisons=line_comps,
                expected_line_count=len(gt_lines),
                predicted_line_count=len(extraction.line_items),
                header_matched_count=header_matched,
                header_total_count=len(header_comps),
                line_matched_count=line_matched,
                line_total_count=len(line_comps),
                model_version=ext_result.model_version,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            logger.warning(
                "Evaluation case failed with isolated exception",
                extra={"invoice_stem": case.invoice_stem, "error_type": type(exc).__name__},
            )
            return InvoiceEvaluationResult(
                invoice_stem=case.invoice_stem,
                invoice_filename=case.invoice_path.name,
                test_case_type=test_case_type,
                succeeded=False,
                error_message=f"{type(exc).__name__}: evaluation failed",
                latency_ms=elapsed_ms,
            )

    async def run_batch(self, *, limit: int | None = None) -> BatchEvaluationResult:
        """Run full offline batch inference and field-by-field comparison across discovered cases."""
        batch_start = time.perf_counter()
        cases = discover_evaluation_cases(self._sample_data_dir, limit=limit)
        vendor_contexts = _load_vendor_contexts(self._sample_data_dir)
        fx_lookup = _load_exchange_rates(self._sample_data_dir)
        invoice_lookup = _InMemoryBatchInvoiceLookup()

        results: list[InvoiceEvaluationResult] = []
        per_field_matched: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}
        per_field_total: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}
        status_dist: dict[str, int] = {}
        total_line_matched = 0
        total_line_expected = 0
        stp_count = 0
        completed = 0
        crashed = 0

        for case in cases:
            res = await self.evaluate_case(
                case,
                vendor_contexts=vendor_contexts,
                invoice_lookup=invoice_lookup,
                fx_lookup=fx_lookup,
            )
            results.append(res)
            if res.succeeded:
                completed += 1
                if res.stp_achieved:
                    stp_count += 1
                if res.routed_status is not None:
                    status_dist[res.routed_status] = status_dist.get(res.routed_status, 0) + 1
                for hc in res.header_comparisons:
                    per_field_total[hc.field_name] += 1
                    if hc.matched:
                        per_field_matched[hc.field_name] += 1
                total_line_matched += res.line_matched_count
                total_line_expected += res.line_total_count
            else:
                crashed += 1

        total_ms = int((time.perf_counter() - batch_start) * 1000)
        logger.info(
            "Batch evaluation completed",
            extra={
                "total_invoices": len(cases),
                "completed_invoices": completed,
                "crashed_invoices": crashed,
                "stp_count": stp_count,
                "duration_ms": total_ms,
            },
        )
        return BatchEvaluationResult(
            sample_data_dir=str(self._sample_data_dir),
            total_invoices=len(cases),
            completed_invoices=completed,
            crashed_invoices=crashed,
            results=tuple(results),
            per_header_field_counts={
                name: (per_field_matched[name], per_field_total[name])
                for name in HEADER_FIELD_NAMES
            },
            total_line_fields_matched=total_line_matched,
            total_line_fields_expected=total_line_expected,
            stp_count=stp_count,
            status_distribution=dict(sorted(status_dist.items())),
            total_duration_ms=total_ms,
        )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for ``python -m src.evaluation.evaluator --report`` (P13-4)."""
    from src.evaluation.cli import run_cli

    return run_cli(argv)


__all__ = [
    "BatchEvaluationResult",
    "EvaluationCase",
    "EvaluationSecurityError",
    "FieldComparisonResult",
    "InvoiceBatchEvaluator",
    "InvoiceEvaluationResult",
    "LineFieldComparisonResult",
    "MAX_BATCH_INVOICES",
    "MAX_EVAL_GROUND_TRUTH_BYTES",
    "MAX_EVAL_INVOICE_BYTES",
    "SUPPORTED_INVOICE_EXTENSIONS",
    "compare_header_fields",
    "compare_line_items",
    "discover_evaluation_cases",
    "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
