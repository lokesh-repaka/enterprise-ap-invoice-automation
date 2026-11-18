"""
Unit tests for P13-2: Automated Evaluation Metric Reporting & Threshold Gates.

Maps to FR-14, CLAUDE.md §10, BRD AC-001/AC-002/AC-004/AC-007, SEC-223..SEC-225.
Fast, deterministic, strictly offline (<0.2s).
"""

import json
from decimal import Decimal

import pytest
from pydantic import ValidationError

from src.evaluation.evaluator import (
    BatchEvaluationResult,
    FieldComparisonResult,
    InvoiceEvaluationResult,
    LineFieldComparisonResult,
)
from src.evaluation.metrics import (
    DEFAULT_THRESHOLDS,
    EvaluationIntegrityError,
    EvaluationMetricsReport,
    EvaluationThresholds,
    compute_evaluation_metrics,
    format_metrics_summary,
)
from src.extraction.schemas import (
    CRITICAL_HEADER_FIELD_NAMES,
    HEADER_FIELD_NAMES,
    LINE_ITEM_FIELD_NAMES,
)

_CRITICAL_SET = frozenset(CRITICAL_HEADER_FIELD_NAMES)


def _make_header_comparisons(
    *,
    mismatched_fields: set[str] | None = None,
    missing_predicted_fields: set[str] | None = None,
    raw_tax_id: str = "ESA98765432",
) -> tuple[FieldComparisonResult, ...]:
    mismatched = mismatched_fields or set()
    missing = missing_predicted_fields or set()
    rows: list[FieldComparisonResult] = []
    for name in HEADER_FIELD_NAMES:
        expected = raw_tax_id if name == "vendor_tax_id" else f"exp-{name}"
        if name in missing:
            predicted = None
            matched = False
        elif name in mismatched:
            predicted = f"wrong-{name}"
            matched = False
        else:
            predicted = expected
            matched = True
        rows.append(
            FieldComparisonResult(
                field_name=name,
                expected_value=expected,
                predicted_value=predicted,
                matched=matched,
                is_critical=name in _CRITICAL_SET,
                confidence=Decimal("98.50"),
            )
        )
    return tuple(rows)


def _make_line_comparisons(
    *,
    matched_lines: int = 1,
    missed_lines: int = 0,
    hallucinated_lines: int = 0,
    wrong_value_lines: int = 0,
) -> tuple[LineFieldComparisonResult, ...]:
    rows: list[LineFieldComparisonResult] = []
    line_num = 1
    for _ in range(matched_lines):
        for name in LINE_ITEM_FIELD_NAMES:
            rows.append(
                LineFieldComparisonResult(
                    line_number=line_num,
                    field_name=name,
                    expected_value="10.00",
                    predicted_value="10.00",
                    matched=True,
                    confidence=Decimal("97.00"),
                )
            )
        line_num += 1
    for _ in range(missed_lines):
        for name in LINE_ITEM_FIELD_NAMES:
            rows.append(
                LineFieldComparisonResult(
                    line_number=line_num,
                    field_name=name,
                    expected_value="10.00",
                    predicted_value=None,
                    matched=False,
                    confidence=None,
                )
            )
        line_num += 1
    for _ in range(hallucinated_lines):
        for name in LINE_ITEM_FIELD_NAMES:
            rows.append(
                LineFieldComparisonResult(
                    line_number=line_num,
                    field_name=name,
                    expected_value=None,
                    predicted_value="10.00",
                    matched=False,
                    confidence=Decimal("90.00"),
                )
            )
        line_num += 1
    for _ in range(wrong_value_lines):
        for name in LINE_ITEM_FIELD_NAMES:
            rows.append(
                LineFieldComparisonResult(
                    line_number=line_num,
                    field_name=name,
                    expected_value="10.00",
                    predicted_value="99.00",
                    matched=False,
                    confidence=Decimal("85.00"),
                )
            )
        line_num += 1
    return tuple(rows)


def _build_batch(
    invoice_results: list[InvoiceEvaluationResult],
    *,
    sample_data_dir: str = "/Users/secretuser/private/sample_data",
) -> BatchEvaluationResult:
    per_field_matched = {name: 0 for name in HEADER_FIELD_NAMES}
    per_field_total = {name: 0 for name in HEADER_FIELD_NAMES}
    status_dist: dict[str, int] = {}
    total_line_matched = 0
    total_line_expected = 0
    stp_count = 0
    completed = 0
    crashed = 0

    for res in invoice_results:
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

    return BatchEvaluationResult(
        sample_data_dir=sample_data_dir,
        total_invoices=len(invoice_results),
        completed_invoices=completed,
        crashed_invoices=crashed,
        results=tuple(invoice_results),
        per_header_field_counts={
            name: (per_field_matched[name], per_field_total[name]) for name in HEADER_FIELD_NAMES
        },
        total_line_fields_matched=total_line_matched,
        total_line_fields_expected=total_line_expected,
        stp_count=stp_count,
        status_distribution=dict(sorted(status_dist.items())),
        total_duration_ms=42,
    )


def _make_invoice_result(
    idx: int,
    *,
    succeeded: bool = True,
    stp_achieved: bool = True,
    routed_status: str = "VALIDATED",
    test_case_type: str = "standard",
    header_comps: tuple[FieldComparisonResult, ...] | None = None,
    line_comps: tuple[LineFieldComparisonResult, ...] | None = None,
) -> InvoiceEvaluationResult:
    if not succeeded:
        return InvoiceEvaluationResult(
            invoice_stem=f"INV-2026-{idx:04d}",
            invoice_filename=f"INV-2026-{idx:04d}.txt",
            test_case_type=test_case_type,
            succeeded=False,
            error_message="ValueError: evaluation failed",
            latency_ms=5,
        )
    h = header_comps if header_comps is not None else _make_header_comparisons()
    lines = line_comps if line_comps is not None else _make_line_comparisons(matched_lines=2)
    return InvoiceEvaluationResult(
        invoice_stem=f"INV-2026-{idx:04d}",
        invoice_filename=f"INV-2026-{idx:04d}.txt",
        test_case_type=test_case_type,
        succeeded=True,
        routed_status=routed_status,
        stp_achieved=stp_achieved,
        rules_passed=stp_achieved,
        header_comparisons=h,
        line_comparisons=lines,
        expected_line_count=2,
        predicted_line_count=2,
        header_matched_count=sum(1 for c in h if c.matched),
        header_total_count=len(h),
        line_matched_count=sum(1 for c in lines if c.matched),
        line_total_count=len(lines),
        model_version="mock-gpt-4o-mini",
        latency_ms=3,
    )


# ---------------------------------------------------------------------------
# 1. Core Metric Reporting & Threshold Gate Assertions (FR-14, CLAUDE.md §10)
# ---------------------------------------------------------------------------


def test_compute_metrics_perfect_batch_passes_all_gates() -> None:
    """# Tests: FR-14, AC-001, AC-002, AC-004, AC-007 — Perfect batch passes all thresholds."""
    batch = _build_batch([_make_invoice_result(i) for i in range(1, 11)])
    report: EvaluationMetricsReport = compute_evaluation_metrics(batch)

    assert report.total_invoices == 10
    assert report.completed_invoices == 10
    assert report.crashed_invoices == 0
    assert report.header_macro_accuracy_pct == Decimal("100.00")
    assert report.critical_field_min_accuracy_pct == Decimal("100.00")
    assert report.line_item_accuracy_pct == Decimal("100.00")
    assert report.stp_rate_pct == Decimal("100.00")

    assert report.overall_precision_pct == Decimal("100.00")
    assert report.overall_recall_pct == Decimal("100.00")
    assert report.overall_f1_pct == Decimal("100.00")

    assert report.all_thresholds_passed is True
    assert report.failed_gates == ()
    assert len(report.threshold_checks) == 8
    assert all(check.passed for check in report.threshold_checks)


def test_threshold_gates_pass_at_exact_boundaries_and_fail_on_single_breach() -> None:
    """# Tests: FR-14, CLAUDE.md §10 — Exact boundaries pass; any single miss fails the gate."""
    # 100 invoices crafted to hit exact contractual floors:
    # - 92% on vendor_tax_id (8 mismatches), 96% on 5 non-critical fields (or tuned to 95.00% macro)
    #   Sum across 10 header fields = 950/1000 => 95.00% macro:
    #   vendor_tax_id: 92%, vendor_name: 93%, invoice_number: 95%, invoice_date: 95%,
    #   due_date: 95%, currency: 96%, subtotal: 96%, tax_amount: 96%, total_amount: 96%, po_number: 96%
    #   (92+93+95+95+95+96+96+96+96+96 = 950 => 95.00%)
    # - Line-item accuracy: 90 matched / 100 expected => 90.00% (1 line per inv: 90 matched, 10 missed)
    # - STP: 65 / 100 => 65.00%
    mismatch_budgets = {
        "vendor_tax_id": 8,
        "vendor_name": 7,
        "invoice_number": 5,
        "invoice_date": 5,
        "due_date": 5,
        "currency": 4,
        "subtotal": 4,
        "tax_amount": 4,
        "total_amount": 4,
        "po_number": 4,
    }
    invoices: list[InvoiceEvaluationResult] = []
    for i in range(100):
        bad_fields = {f for f, count in mismatch_budgets.items() if i < count}
        lines = (
            _make_line_comparisons(matched_lines=1)
            if i < 90
            else _make_line_comparisons(matched_lines=0, missed_lines=1)
        )
        invoices.append(
            _make_invoice_result(
                i + 1,
                stp_achieved=i < 65,
                routed_status="VALIDATED" if i < 65 else "REQUIRES_REVIEW",
                header_comps=_make_header_comparisons(mismatched_fields=bad_fields),
                line_comps=lines,
            )
        )

    exact_report = compute_evaluation_metrics(_build_batch(invoices))
    assert exact_report.header_macro_accuracy_pct == Decimal("95.00")
    assert exact_report.critical_field_min_accuracy_pct == Decimal("92.00")
    assert exact_report.line_item_accuracy_pct == Decimal("90.00")
    assert exact_report.stp_rate_pct == Decimal("65.00")
    assert exact_report.all_thresholds_passed is True
    assert exact_report.failed_gates == ()

    # Breach ONLY the critical field floor (vendor_tax_id drops to 91%, while macro stays >=95%
    # by making all other 9 fields 100% -> macro = 99.10%)
    crit_breach_invoices: list[InvoiceEvaluationResult] = []
    for i in range(100):
        bad = {"vendor_tax_id"} if i < 9 else set()
        crit_breach_invoices.append(
            _make_invoice_result(
                i + 1,
                stp_achieved=True,
                header_comps=_make_header_comparisons(mismatched_fields=bad),
                line_comps=_make_line_comparisons(matched_lines=1),
            )
        )
    crit_report = compute_evaluation_metrics(_build_batch(crit_breach_invoices))
    assert crit_report.header_macro_accuracy_pct == Decimal("99.10")
    assert crit_report.critical_field_min_accuracy_pct == Decimal("91.00")
    assert crit_report.all_thresholds_passed is False
    assert crit_report.failed_gates == ("critical_field_vendor_tax_id",)

    # Breach ONLY STP (64% < 65%)
    stp_breach = [
        _make_invoice_result(
            i + 1,
            stp_achieved=i < 64,
            routed_status="VALIDATED" if i < 64 else "REQUIRES_REVIEW",
        )
        for i in range(100)
    ]
    stp_report = compute_evaluation_metrics(_build_batch(stp_breach))
    assert stp_report.stp_rate_pct == Decimal("64.00")
    assert stp_report.all_thresholds_passed is False
    assert stp_report.failed_gates == ("stp_rate",)


def test_precision_recall_f1_distinguishes_missed_hallucinated_and_wrong_fields() -> None:
    """# Tests: FR-14, AC-007 — Precision/Recall/F1 distinguish FP hallucinations vs FN misses."""
    # 1 invoice:
    # - Header: 10 fields -> 8 matched (TP=8), 1 missed/None (FN=1), 1 wrong value (FP=1, FN=1)
    #   Header Precision = 8 / (8 + 1) = 88.89%, Recall = 8 / (8 + 2) = 80.00%
    # - Lines: 1 matched (5 TP), 1 missed (5 FN), 1 hallucinated (5 FP)
    #   Line Precision = 5 / (5 + 5) = 50.00%, Recall = 5 / (5 + 5) = 50.00%, F1 = 50.00%
    header = _make_header_comparisons(
        mismatched_fields={"vendor_name"},
        missing_predicted_fields={"po_number"},
    )
    lines = _make_line_comparisons(matched_lines=1, missed_lines=1, hallucinated_lines=1)
    inv = _make_invoice_result(1, header_comps=header, line_comps=lines)
    report = compute_evaluation_metrics(_build_batch([inv]))

    assert report.header_precision_pct == Decimal("88.89")
    assert report.header_recall_pct == Decimal("80.00")
    assert report.header_f1_pct == Decimal("84.21")

    assert report.line_precision_pct == Decimal("50.00")
    assert report.line_recall_pct == Decimal("50.00")
    assert report.line_f1_pct == Decimal("50.00")

    # Overall: TP = 8+5 = 13, FP = 1+5 = 6, FN = 2+5 = 7
    # Precision = 13/19 = 68.42%, Recall = 13/20 = 65.00%, F1 = 2*68.421*65/(68.421+65) = 66.67%
    assert report.overall_precision_pct == Decimal("68.42")
    assert report.overall_recall_pct == Decimal("65.00")
    assert report.overall_f1_pct == Decimal("66.67")


# ---------------------------------------------------------------------------
# 2. Security Audit Guards (SEC-223, SEC-224, SEC-225)
# ---------------------------------------------------------------------------


def test_fail_closed_on_empty_batch_crashes_and_invalid_thresholds() -> None:
    """# Tests: FR-14, SEC-223 — Empty batch fails closed; crashes deflate denominator; invalid thresholds rejected."""
    # Empty batch MUST NOT vacuously pass
    empty_report = compute_evaluation_metrics(_build_batch([]))
    assert empty_report.total_invoices == 0
    assert empty_report.header_macro_accuracy_pct == Decimal("0.00")
    assert empty_report.line_item_accuracy_pct == Decimal("0.00")
    assert empty_report.stp_rate_pct == Decimal("0.00")
    assert empty_report.all_thresholds_passed is False
    assert "batch_stability" in empty_report.failed_gates

    # 1 crashed invoice out of 2 MUST count against header and STP denominators (50%, not 100%)
    mixed = _build_batch([_make_invoice_result(1), _make_invoice_result(2, succeeded=False)])
    mixed_report = compute_evaluation_metrics(mixed)
    assert mixed_report.completed_invoices == 1
    assert mixed_report.crashed_invoices == 1
    assert mixed_report.header_macro_accuracy_pct == Decimal("50.00")
    assert mixed_report.stp_rate_pct == Decimal("50.00")
    assert mixed_report.all_thresholds_passed is False
    assert "batch_stability" in mixed_report.failed_gates

    # Invalid thresholds (NaN, Infinity, >100, negative, booleans) MUST raise ValidationError
    for bad_value in (Decimal("NaN"), Decimal("Infinity"), Decimal("-1.00"), Decimal("100.01")):
        with pytest.raises(ValidationError):
            EvaluationThresholds(header_macro_accuracy_pct=bad_value)
    with pytest.raises(ValidationError):
        EvaluationThresholds(max_crashed_invoices=-1)
    with pytest.raises(ValidationError):
        EvaluationThresholds(max_crashed_invoices=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        EvaluationThresholds(header_macro_accuracy_pct=True)  # type: ignore[arg-type]
    assert DEFAULT_THRESHOLDS.header_macro_accuracy_pct == Decimal("95.00")


def test_report_redacts_pii_strips_host_paths_and_sanitizes_control_chars() -> None:
    """# Tests: FR-14, SEC-224 — Zero raw Tax ID PII, zero host filesystem paths, ANSI/BiDi-safe output."""
    dirty_inv = _make_invoice_result(
        1,
        test_case_type="standard\x1b[31m\x1bc\u202e\nINJECTED_LOG",
        header_comps=_make_header_comparisons(raw_tax_id="DE-SECRET-99887766"),
    )
    batch = _build_batch(
        [dirty_inv],
        sample_data_dir="/Users/lokeshrepaka/Desktop/secret_client/sample_data",
    )
    report = compute_evaluation_metrics(batch)

    safe_json = report.to_safe_json()
    summary_text = format_metrics_summary(report)
    rep_str = repr(report)

    for output in (safe_json, summary_text, rep_str):
        assert "DE-SECRET-99887766" not in output
        assert "/Users/lokeshrepaka" not in output
        assert "secret_client" not in output
        assert "\x1b" not in output
        assert "\u202e" not in output

    parsed = json.loads(safe_json)
    assert parsed["dataset_label"] == "sample_data"
    assert "standardINJECTED_LOG" in parsed["by_test_case_type"]


def test_rejects_tampered_or_inconsistent_batch_aggregate_counters() -> None:
    """# Tests: FR-14, SEC-225 — Detects and rejects forged aggregate counters & duplicate header slots."""
    good_batch = _build_batch(
        [_make_invoice_result(1, stp_achieved=False, routed_status="REQUIRES_REVIEW")]
    )

    # Forge stp_count = 1 when results actually have 0 STP invoices
    forged_stp = good_batch.model_copy(update={"stp_count": 1})
    with pytest.raises(EvaluationIntegrityError, match="stp_count"):
        compute_evaluation_metrics(forged_stp)

    # Forge crashed_invoices = 0 when total_invoices != completed + crashed
    forged_total = good_batch.model_copy(update={"total_invoices": 5})
    with pytest.raises(EvaluationIntegrityError, match="total_invoices"):
        compute_evaluation_metrics(forged_total)

    # Forge per_header_field_counts inflating matched count beyond results
    forged_header = good_batch.model_copy(
        update={
            "per_header_field_counts": {
                **good_batch.per_header_field_counts,
                "vendor_tax_id": (99, 1),
            }
        }
    )
    with pytest.raises(EvaluationIntegrityError, match="per_header_field_counts"):
        compute_evaluation_metrics(forged_header)

    # Duplicate header_comparisons slot (inflating accuracy >100%) MUST be rejected
    dup_header = _make_header_comparisons() + (_make_header_comparisons()[0],)
    dup_inv = _make_invoice_result(1, header_comps=dup_header)
    with pytest.raises(EvaluationIntegrityError, match="Duplicate header field"):
        compute_evaluation_metrics(_build_batch([dup_inv]))

    # Crashed invoice with stp_achieved=True MUST be rejected
    bad_crash = InvoiceEvaluationResult(
        invoice_stem="INV-2026-9999",
        invoice_filename="INV-2026-9999.txt",
        succeeded=False,
        stp_achieved=True,
        error_message="ValueError: evaluation failed",
    )
    with pytest.raises(EvaluationIntegrityError, match="Crashed invoice"):
        compute_evaluation_metrics(_build_batch([bad_crash]))
