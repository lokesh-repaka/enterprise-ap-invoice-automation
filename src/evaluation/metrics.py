"""
Automated Evaluation Metric Reporting & Contractual Threshold Gates (P13-2).

Covers FR-14, CLAUDE.md §10, BRD AC-001/AC-002/AC-004/AC-007, PRD BR-006:
- Computes Header Macro-Average Accuracy (>=95.00%), Critical Field Hard Floor (>=92.00% each
  across vendor_tax_id, invoice_number, invoice_date, total_amount), Line-Item Accuracy
  (>=90.00%), Pilot STP Rate (>=65.00%), and Batch Stability (0 unhandled crashes, >=1 invoice).
- Computes slot-level Precision, Recall, and F1 across header fields, line-item fields, and
  overall extraction output (distinguishing FP hallucinations from FN omissions).
- Produces immutable, PII-redacted, host-path-stripped JSON and printable summary reports.

Security & Layering Invariants:
- MUST NOT be imported by production code paths (CLAUDE.md §4.2).
- Fail-closed on empty batches, crashed invoices, and non-finite/out-of-bounds thresholds
  (SEC-223, CWE-20 / CWE-682).
- Zero raw Vendor Tax ID PII, zero host filesystem paths, and ANSI/control-char sanitization
  in serialized reports and terminal summaries (SEC-224, CWE-532 / CWE-117).
- Authoritative integrity verification of BatchEvaluationResult counters against per-invoice
  results to prevent forged/inflated metrics from passing CI gates (SEC-225, CWE-345).
"""

import json
import re
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.logging import get_logger
from src.evaluation.evaluator import BatchEvaluationResult
from src.extraction.schemas import CRITICAL_HEADER_FIELD_NAMES, HEADER_FIELD_NAMES

logger = get_logger("ap.evaluation.metrics")

_PCT_QUANTUM = Decimal("0.01")
_HUNDRED = Decimal("100")
_ZERO = Decimal("0.00")
_CRITICAL_SET: frozenset[str] = frozenset(CRITICAL_HEADER_FIELD_NAMES)
_HEADER_SET: frozenset[str] = frozenset(HEADER_FIELD_NAMES)

LONG_TERM_STP_OBJECTIVE_PCT: Decimal = Decimal("70.00")

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*\x07|[@-~])")


class EvaluationIntegrityError(ValueError):
    """Raised when BatchEvaluationResult aggregate counters contradict per-invoice results."""


def _sanitize_label(raw: str, *, max_len: int = 80, default: str = "unknown") -> str:
    """Strip ANSI escape sequences and ASCII control characters for log/terminal safety (SEC-224)."""
    without_ansi = _ANSI_ESCAPE_RE.sub("", raw)
    cleaned = "".join(ch for ch in without_ansi if 32 <= ord(ch) < 127).strip()
    if not cleaned:
        return default
    return cleaned[:max_len]


def _extract_dataset_label(sample_data_dir: str) -> str:
    """Return only a sanitized basename label, never an absolute host filesystem path (SEC-224)."""
    name = Path(sample_data_dir).name
    return _sanitize_label(name, max_len=64, default="dataset")


def _pct(numerator: int | Decimal, denominator: int | Decimal) -> Decimal:
    """Compute percentage rounded HALF_UP to 2 decimal places; fail-closed to 0.00 on zero denom."""
    denom = Decimal(denominator)
    if denom <= 0:
        return _ZERO
    return ((Decimal(numerator) * _HUNDRED) / denom).quantize(_PCT_QUANTUM, rounding=ROUND_HALF_UP)


def _f1_pct(tp: int, fp: int, fn: int) -> Decimal:
    """Compute exact harmonic F1 percentage directly from TP/FP/FN counts."""
    denom = (2 * tp) + fp + fn
    if denom <= 0:
        return _ZERO
    return ((Decimal(2 * tp) * _HUNDRED) / Decimal(denom)).quantize(
        _PCT_QUANTUM, rounding=ROUND_HALF_UP
    )


class EvaluationThresholds(BaseModel):
    """Contractual pilot acceptance thresholds (CLAUDE.md §10, BRD AC-001..AC-004)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    header_macro_accuracy_pct: Decimal = Decimal("95.00")
    critical_field_floor_pct: Decimal = Decimal("92.00")
    line_item_accuracy_pct: Decimal = Decimal("90.00")
    stp_rate_pct: Decimal = Decimal("65.00")
    max_crashed_invoices: int = Field(default=0, ge=0)
    min_invoices: int = Field(default=1, ge=1)

    @field_validator(
        "header_macro_accuracy_pct",
        "critical_field_floor_pct",
        "line_item_accuracy_pct",
        "stp_rate_pct",
        mode="before",
    )
    @classmethod
    def _reject_bool_percentage(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("Threshold percentage must not be a boolean")
        return value

    @field_validator("max_crashed_invoices", "min_invoices", mode="before")
    @classmethod
    def _reject_bool_int(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("Integer threshold must not be a boolean")
        return value

    @field_validator(
        "header_macro_accuracy_pct",
        "critical_field_floor_pct",
        "line_item_accuracy_pct",
        "stp_rate_pct",
    )
    @classmethod
    def _validate_percentage(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("Threshold percentage must be a finite Decimal value")
        if value < _ZERO or value > _HUNDRED:
            raise ValueError("Threshold percentage must be within [0.00, 100.00]")
        return value.quantize(_PCT_QUANTUM, rounding=ROUND_HALF_UP)


DEFAULT_THRESHOLDS = EvaluationThresholds()


class FieldMetricSummary(BaseModel):
    """Per-header-field accuracy, precision, recall, and F1 breakdown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field_name: str
    is_critical: bool
    matched_count: int
    total_count: int
    accuracy_pct: Decimal
    precision_pct: Decimal
    recall_pct: Decimal
    f1_pct: Decimal


class TestCaseTypeSummary(BaseModel):
    """Per-test-case-type STP and stability breakdown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_case_type: str
    total_invoices: int
    completed_invoices: int
    crashed_invoices: int
    stp_count: int
    stp_rate_pct: Decimal


class ThresholdCheckResult(BaseModel):
    """Pass/fail verdict for a single contractual evaluation gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metric_name: str
    actual_value: Decimal
    threshold_value: Decimal
    operator: Literal[">=", "<=", "=="]
    passed: bool
    detail: str


class EvaluationMetricsReport(BaseModel):
    """Immutable, PII-free automated evaluation scorecard (FR-14, CLAUDE.md §10)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_label: str
    total_invoices: int
    completed_invoices: int
    crashed_invoices: int
    stp_count: int
    total_duration_ms: int

    # Headline contractual acceptance metrics
    header_macro_accuracy_pct: Decimal
    critical_field_min_accuracy_pct: Decimal
    line_item_accuracy_pct: Decimal
    stp_rate_pct: Decimal
    long_term_stp_objective_pct: Decimal = LONG_TERM_STP_OBJECTIVE_PCT

    # Precision / Recall / F1 (FR-14, AC-007)
    header_precision_pct: Decimal
    header_recall_pct: Decimal
    header_f1_pct: Decimal
    line_precision_pct: Decimal
    line_recall_pct: Decimal
    line_f1_pct: Decimal
    overall_precision_pct: Decimal
    overall_recall_pct: Decimal
    overall_f1_pct: Decimal

    # Breakdowns
    per_header_field: dict[str, FieldMetricSummary]
    critical_field_accuracies_pct: dict[str, Decimal]
    status_distribution: dict[str, int]
    by_test_case_type: dict[str, TestCaseTypeSummary]

    # Gate evaluation
    thresholds: EvaluationThresholds
    threshold_checks: tuple[ThresholdCheckResult, ...]
    all_thresholds_passed: bool
    failed_gates: tuple[str, ...]

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize report into a JSON-compatible dictionary with zero PII or host paths."""
        return self.model_dump(mode="json")

    def to_safe_json(self, *, indent: int = 2) -> str:
        """Serialize report into deterministic, PII-free JSON text."""
        return json.dumps(self.to_safe_dict(), indent=indent, sort_keys=False)

    def __repr__(self) -> str:
        return (
            f"EvaluationMetricsReport(dataset={self.dataset_label!r}, "
            f"invoices={self.completed_invoices}/{self.total_invoices}, "
            f"header={self.header_macro_accuracy_pct}%, "
            f"critical_min={self.critical_field_min_accuracy_pct}%, "
            f"line={self.line_item_accuracy_pct}%, "
            f"stp={self.stp_rate_pct}%, "
            f"passed={self.all_thresholds_passed})"
        )


def _verify_batch_integrity(batch: BatchEvaluationResult) -> None:
    """
    Verify aggregate counters on BatchEvaluationResult match its authoritative per-invoice results.

    Prevents tampered or inconsistent aggregate summaries from silently passing CI gates (SEC-225).
    """
    if batch.total_invoices != len(batch.results):
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'total_invoices': declared {batch.total_invoices}, "
            f"actual results length {len(batch.results)}"
        )

    recomputed_completed = 0
    recomputed_crashed = 0
    recomputed_stp = 0
    recomputed_line_matched = 0
    recomputed_line_expected = 0
    recomputed_header_matched = {name: 0 for name in HEADER_FIELD_NAMES}
    recomputed_header_total = {name: 0 for name in HEADER_FIELD_NAMES}
    recomputed_status: dict[str, int] = {}

    for res in batch.results:
        if res.routed_status is not None and res.routed_status.startswith("APPROVED_"):
            raise EvaluationIntegrityError(
                f"Disallowed approval status found in evaluation batch: {res.routed_status!r}"
            )
        if res.succeeded:
            recomputed_completed += 1
            if res.stp_achieved:
                recomputed_stp += 1
            if res.routed_status is not None:
                recomputed_status[res.routed_status] = (
                    recomputed_status.get(res.routed_status, 0) + 1
                )

            actual_h_matched = sum(1 for hc in res.header_comparisons if hc.matched)
            if (
                actual_h_matched != res.header_matched_count
                or len(res.header_comparisons) != res.header_total_count
            ):
                raise EvaluationIntegrityError(
                    f"Inconsistent per-invoice header comparison counts for {res.invoice_stem!r}"
                )
            seen_header_fields: set[str] = set()
            for hc in res.header_comparisons:
                if hc.field_name not in _HEADER_SET:
                    raise EvaluationIntegrityError(
                        f"Unknown header field in evaluation results: {hc.field_name!r}"
                    )
                if hc.field_name in seen_header_fields:
                    raise EvaluationIntegrityError(
                        f"Duplicate header field '{hc.field_name}' in {res.invoice_stem!r}"
                    )
                seen_header_fields.add(hc.field_name)
                recomputed_header_total[hc.field_name] += 1
                if hc.matched:
                    recomputed_header_matched[hc.field_name] += 1
            if seen_header_fields != _HEADER_SET:
                raise EvaluationIntegrityError(
                    f"Incomplete header comparison set for {res.invoice_stem!r}"
                )

            actual_l_matched = sum(1 for lc in res.line_comparisons if lc.matched)
            if (
                actual_l_matched != res.line_matched_count
                or len(res.line_comparisons) != res.line_total_count
            ):
                raise EvaluationIntegrityError(
                    f"Inconsistent per-invoice line comparison counts for {res.invoice_stem!r}"
                )
            recomputed_line_matched += actual_l_matched
            recomputed_line_expected += len(res.line_comparisons)
        else:
            if res.stp_achieved:
                raise EvaluationIntegrityError(
                    f"Crashed invoice {res.invoice_stem!r} cannot have stp_achieved=True"
                )
            recomputed_crashed += 1

    if batch.completed_invoices != recomputed_completed:
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'completed_invoices': declared {batch.completed_invoices}, "
            f"actual {recomputed_completed}"
        )
    if batch.crashed_invoices != recomputed_crashed:
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'crashed_invoices': declared {batch.crashed_invoices}, "
            f"actual {recomputed_crashed}"
        )
    if batch.stp_count != recomputed_stp:
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'stp_count': declared {batch.stp_count}, "
            f"actual {recomputed_stp}"
        )
    if batch.total_line_fields_matched != recomputed_line_matched:
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'total_line_fields_matched': "
            f"declared {batch.total_line_fields_matched}, actual {recomputed_line_matched}"
        )
    if batch.total_line_fields_expected != recomputed_line_expected:
        raise EvaluationIntegrityError(
            f"Inconsistent batch aggregate 'total_line_fields_expected': "
            f"declared {batch.total_line_fields_expected}, actual {recomputed_line_expected}"
        )

    expected_header_counts = {
        name: (recomputed_header_matched[name], recomputed_header_total[name])
        for name in HEADER_FIELD_NAMES
    }
    if dict(batch.per_header_field_counts) != expected_header_counts:
        raise EvaluationIntegrityError(
            "Inconsistent batch aggregate 'per_header_field_counts' compared to per-invoice results"
        )
    if dict(sorted(batch.status_distribution.items())) != dict(sorted(recomputed_status.items())):
        raise EvaluationIntegrityError(
            "Inconsistent batch aggregate 'status_distribution' compared to per-invoice results"
        )


def compute_evaluation_metrics(
    batch: BatchEvaluationResult,
    *,
    thresholds: EvaluationThresholds = DEFAULT_THRESHOLDS,
) -> EvaluationMetricsReport:
    """
    Compute full accuracy, precision, recall, F1, STP, and threshold gate verdicts from a batch run.

    Crashed invoices remain in header-accuracy and STP denominators so failures can never inflate
    reported metrics (SEC-223). Empty batches fail closed on ``batch_stability``.
    """
    _verify_batch_integrity(batch)

    total_invoices = len(batch.results)
    completed_invoices = batch.completed_invoices
    crashed_invoices = batch.crashed_invoices
    stp_count = batch.stp_count

    # Per-header-field TP/FP/FN/matched accumulators
    field_matched: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}
    field_tp: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}
    field_fp: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}
    field_fn: dict[str, int] = {name: 0 for name in HEADER_FIELD_NAMES}

    line_tp = 0
    line_fp = 0
    line_fn = 0
    line_matched = 0
    line_total = 0

    # Sanitized breakdowns
    sanitized_status_dist: dict[str, int] = {}
    type_buckets: dict[str, dict[str, int]] = {}

    for res in batch.results:
        tc_key = _sanitize_label(res.test_case_type, max_len=64, default="unknown")
        bucket = type_buckets.setdefault(
            tc_key, {"total": 0, "completed": 0, "crashed": 0, "stp": 0}
        )
        bucket["total"] += 1

        if not res.succeeded:
            bucket["crashed"] += 1
            # Count every header slot on a crashed invoice as FN so recall cannot be inflated
            for name in HEADER_FIELD_NAMES:
                field_fn[name] += 1
            continue

        bucket["completed"] += 1
        if res.stp_achieved:
            bucket["stp"] += 1

        if res.routed_status is not None:
            safe_status = _sanitize_label(res.routed_status, max_len=64, default="UNKNOWN")
            sanitized_status_dist[safe_status] = sanitized_status_dist.get(safe_status, 0) + 1

        for hc in res.header_comparisons:
            name = hc.field_name
            exp_present = hc.expected_value is not None
            pred_present = hc.predicted_value is not None
            if hc.matched:
                field_matched[name] += 1
                if exp_present:
                    field_tp[name] += 1
            else:
                if pred_present:
                    field_fp[name] += 1
                if exp_present:
                    field_fn[name] += 1

        for lc in res.line_comparisons:
            line_total += 1
            exp_present = lc.expected_value is not None
            pred_present = lc.predicted_value is not None
            if lc.matched:
                line_matched += 1
                if exp_present:
                    line_tp += 1
            else:
                if pred_present:
                    line_fp += 1
                if exp_present:
                    line_fn += 1

    # Per-header-field metric summaries (denominator = total_invoices so crashes deflate accuracy)
    per_header_field: dict[str, FieldMetricSummary] = {}
    for name in HEADER_FIELD_NAMES:
        tp = field_tp[name]
        fp = field_fp[name]
        fn = field_fn[name]
        per_header_field[name] = FieldMetricSummary(
            field_name=name,
            is_critical=name in _CRITICAL_SET,
            matched_count=field_matched[name],
            total_count=total_invoices,
            accuracy_pct=_pct(field_matched[name], total_invoices),
            precision_pct=_pct(tp, tp + fp),
            recall_pct=_pct(tp, tp + fn),
            f1_pct=_f1_pct(tp, fp, fn),
        )

    total_header_matched = sum(field_matched.values())
    total_header_slots = total_invoices * len(HEADER_FIELD_NAMES)
    header_macro_accuracy_pct = _pct(total_header_matched, total_header_slots)

    critical_field_accuracies_pct: dict[str, Decimal] = {
        name: per_header_field[name].accuracy_pct for name in CRITICAL_HEADER_FIELD_NAMES
    }
    critical_field_min_accuracy_pct = (
        min(critical_field_accuracies_pct.values()) if critical_field_accuracies_pct else _ZERO
    )

    line_item_accuracy_pct = _pct(line_matched, line_total)
    stp_rate_pct = _pct(stp_count, total_invoices)

    # Aggregate Precision / Recall / F1
    header_tp = sum(field_tp.values())
    header_fp = sum(field_fp.values())
    header_fn = sum(field_fn.values())
    header_precision_pct = _pct(header_tp, header_tp + header_fp)
    header_recall_pct = _pct(header_tp, header_tp + header_fn)
    header_f1_pct = _f1_pct(header_tp, header_fp, header_fn)

    line_precision_pct = _pct(line_tp, line_tp + line_fp)
    line_recall_pct = _pct(line_tp, line_tp + line_fn)
    line_f1_pct = _f1_pct(line_tp, line_fp, line_fn)

    overall_tp = header_tp + line_tp
    overall_fp = header_fp + line_fp
    overall_fn = header_fn + line_fn
    overall_precision_pct = _pct(overall_tp, overall_tp + overall_fp)
    overall_recall_pct = _pct(overall_tp, overall_tp + overall_fn)
    overall_f1_pct = _f1_pct(overall_tp, overall_fp, overall_fn)

    by_test_case_type: dict[str, TestCaseTypeSummary] = {
        tc_key: TestCaseTypeSummary(
            test_case_type=tc_key,
            total_invoices=stats["total"],
            completed_invoices=stats["completed"],
            crashed_invoices=stats["crashed"],
            stp_count=stats["stp"],
            stp_rate_pct=_pct(stats["stp"], stats["total"]),
        )
        for tc_key, stats in sorted(type_buckets.items())
    }

    # Evaluate all 8 contractual gates (CLAUDE.md §10)
    checks: list[ThresholdCheckResult] = [
        ThresholdCheckResult(
            metric_name="header_macro_accuracy",
            actual_value=header_macro_accuracy_pct,
            threshold_value=thresholds.header_macro_accuracy_pct,
            operator=">=",
            passed=header_macro_accuracy_pct >= thresholds.header_macro_accuracy_pct,
            detail=(
                f"Header Macro-Average Accuracy {header_macro_accuracy_pct}% "
                f"(target >= {thresholds.header_macro_accuracy_pct}%)"
            ),
        )
    ]

    for crit_field in CRITICAL_HEADER_FIELD_NAMES:
        crit_acc = critical_field_accuracies_pct[crit_field]
        checks.append(
            ThresholdCheckResult(
                metric_name=f"critical_field_{crit_field}",
                actual_value=crit_acc,
                threshold_value=thresholds.critical_field_floor_pct,
                operator=">=",
                passed=crit_acc >= thresholds.critical_field_floor_pct,
                detail=(
                    f"Critical Field '{crit_field}' Accuracy {crit_acc}% "
                    f"(floor >= {thresholds.critical_field_floor_pct}%)"
                ),
            )
        )

    checks.append(
        ThresholdCheckResult(
            metric_name="line_item_accuracy",
            actual_value=line_item_accuracy_pct,
            threshold_value=thresholds.line_item_accuracy_pct,
            operator=">=",
            passed=line_item_accuracy_pct >= thresholds.line_item_accuracy_pct,
            detail=(
                f"Line-Item Accuracy {line_item_accuracy_pct}% "
                f"(target >= {thresholds.line_item_accuracy_pct}%)"
            ),
        )
    )
    checks.append(
        ThresholdCheckResult(
            metric_name="stp_rate",
            actual_value=stp_rate_pct,
            threshold_value=thresholds.stp_rate_pct,
            operator=">=",
            passed=stp_rate_pct >= thresholds.stp_rate_pct,
            detail=(
                f"Pilot STP Rate {stp_rate_pct}% "
                f"(pilot target >= {thresholds.stp_rate_pct}%, "
                f"long-term objective {LONG_TERM_STP_OBJECTIVE_PCT}%)"
            ),
        )
    )

    stability_passed = (
        total_invoices >= thresholds.min_invoices
        and crashed_invoices <= thresholds.max_crashed_invoices
    )
    checks.append(
        ThresholdCheckResult(
            metric_name="batch_stability",
            actual_value=Decimal(crashed_invoices),
            threshold_value=Decimal(thresholds.max_crashed_invoices),
            operator="<=",
            passed=stability_passed,
            detail=(
                f"Batch Stability: {crashed_invoices} crashes across {total_invoices} invoices "
                f"(max crashes <= {thresholds.max_crashed_invoices}, "
                f"min invoices >= {thresholds.min_invoices})"
            ),
        )
    )

    failed_gates = tuple(c.metric_name for c in checks if not c.passed)
    all_passed = len(failed_gates) == 0

    dataset_label = _extract_dataset_label(batch.sample_data_dir)
    logger.info(
        "Evaluation metrics computed",
        extra={
            "dataset_label": dataset_label,
            "total_invoices": total_invoices,
            "header_macro_accuracy_pct": str(header_macro_accuracy_pct),
            "critical_field_min_accuracy_pct": str(critical_field_min_accuracy_pct),
            "line_item_accuracy_pct": str(line_item_accuracy_pct),
            "stp_rate_pct": str(stp_rate_pct),
            "all_thresholds_passed": all_passed,
        },
    )

    return EvaluationMetricsReport(
        dataset_label=dataset_label,
        total_invoices=total_invoices,
        completed_invoices=completed_invoices,
        crashed_invoices=crashed_invoices,
        stp_count=stp_count,
        total_duration_ms=batch.total_duration_ms,
        header_macro_accuracy_pct=header_macro_accuracy_pct,
        critical_field_min_accuracy_pct=critical_field_min_accuracy_pct,
        line_item_accuracy_pct=line_item_accuracy_pct,
        stp_rate_pct=stp_rate_pct,
        header_precision_pct=header_precision_pct,
        header_recall_pct=header_recall_pct,
        header_f1_pct=header_f1_pct,
        line_precision_pct=line_precision_pct,
        line_recall_pct=line_recall_pct,
        line_f1_pct=line_f1_pct,
        overall_precision_pct=overall_precision_pct,
        overall_recall_pct=overall_recall_pct,
        overall_f1_pct=overall_f1_pct,
        per_header_field=per_header_field,
        critical_field_accuracies_pct=critical_field_accuracies_pct,
        status_distribution=dict(sorted(sanitized_status_dist.items())),
        by_test_case_type=by_test_case_type,
        thresholds=thresholds,
        threshold_checks=tuple(checks),
        all_thresholds_passed=all_passed,
        failed_gates=failed_gates,
    )


def format_metrics_summary(report: EvaluationMetricsReport) -> str:
    """Render a concise, printable, PII-free ASCII scorecard for CI logs and CLI output."""
    overall_verdict = "PASS" if report.all_thresholds_passed else "FAIL"
    lines: list[str] = [
        "=" * 74,
        f"AP INVOICE AUTOMATION — EVALUATION SCORECARD [{overall_verdict}]",
        "=" * 74,
        f"Dataset:   {report.dataset_label}",
        f"Invoices:  {report.completed_invoices}/{report.total_invoices} completed "
        f"({report.crashed_invoices} crashes) in {report.total_duration_ms} ms",
        "",
        "CONTRACTUAL THRESHOLD GATES (CLAUDE.md §10)",
        "-" * 74,
    ]
    for check in report.threshold_checks:
        tag = "PASS" if check.passed else "FAIL"
        lines.append(f"  [{tag}] {check.detail}")

    lines.extend(
        [
            "",
            "EXTRACTION PRECISION / RECALL / F1 (FR-14, AC-007)",
            "-" * 74,
            f"  Header:   Precision={report.header_precision_pct}%  "
            f"Recall={report.header_recall_pct}%  F1={report.header_f1_pct}%",
            f"  Lines:    Precision={report.line_precision_pct}%  "
            f"Recall={report.line_recall_pct}%  F1={report.line_f1_pct}%",
            f"  Overall:  Precision={report.overall_precision_pct}%  "
            f"Recall={report.overall_recall_pct}%  F1={report.overall_f1_pct}%",
            "",
            "PER-HEADER-FIELD ACCURACY",
            "-" * 74,
        ]
    )
    for name in HEADER_FIELD_NAMES:
        fm = report.per_header_field[name]
        crit_marker = " *" if fm.is_critical else "  "
        lines.append(
            f"  {name:<18}{crit_marker}  "
            f"{fm.matched_count:>4}/{fm.total_count:<4}  "
            f"Acc={fm.accuracy_pct:>6}%  P={fm.precision_pct:>6}%  "
            f"R={fm.recall_pct:>6}%  F1={fm.f1_pct:>6}%"
        )

    if report.status_distribution:
        lines.extend(["", "STATUS DISTRIBUTION", "-" * 74])
        for status_name, count in report.status_distribution.items():
            lines.append(f"  {status_name:<30} {count:>5}")

    if report.by_test_case_type:
        lines.extend(["", "BREAKDOWN BY TEST CASE TYPE", "-" * 74])
        for tc_name, stats in report.by_test_case_type.items():
            lines.append(
                f"  {tc_name:<30} total={stats.total_invoices:<4} "
                f"stp={stats.stp_count:<4} ({stats.stp_rate_pct:>6}%) "
                f"crashes={stats.crashed_invoices}"
            )

    lines.append("=" * 74)
    return "\n".join(lines)


__all__ = [
    "DEFAULT_THRESHOLDS",
    "LONG_TERM_STP_OBJECTIVE_PCT",
    "EvaluationIntegrityError",
    "EvaluationMetricsReport",
    "EvaluationThresholds",
    "FieldMetricSummary",
    "TestCaseTypeSummary",
    "ThresholdCheckResult",
    "compute_evaluation_metrics",
    "format_metrics_summary",
]
