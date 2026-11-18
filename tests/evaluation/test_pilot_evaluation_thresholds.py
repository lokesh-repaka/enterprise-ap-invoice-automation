"""
P13-3 · Automated Evaluation Pytest Suite — Contractual CI Threshold Gates.

Maps to FR-14, CLAUDE.md §10 & §13, BRD AC-001/AC-002/AC-004/AC-007, PRD BR-006.
Any failure in this suite MUST fail the GitHub Actions CI build and block packaging.
"""

from decimal import Decimal

import pytest

from src.evaluation.metrics import (
    DEFAULT_THRESHOLDS,
    EvaluationMetricsReport,
    EvaluationThresholdError,
    EvaluationThresholds,
    assert_evaluation_thresholds,
)
from src.extraction.schemas import CRITICAL_HEADER_FIELD_NAMES


def test_pilot_dataset_has_300_invoices_and_zero_crashes(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, CLAUDE.md §10 — Batch stability: all 300 pilot invoices complete with zero crashes."""
    assert pilot_evaluation_report.total_invoices == 300, (
        f"Expected 300 pilot invoices, evaluated {pilot_evaluation_report.total_invoices}"
    )
    assert pilot_evaluation_report.completed_invoices == 300, (
        f"Expected 300 completed invoices, got {pilot_evaluation_report.completed_invoices}"
    )
    assert pilot_evaluation_report.crashed_invoices == 0, (
        f"Batch stability gate FAILED: {pilot_evaluation_report.crashed_invoices} unhandled crashes"
    )


def test_header_macro_average_accuracy_meets_95_percent_threshold(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, AC-001, BR-006 — Header Macro-Average Accuracy >= 95.00% across 300 invoices."""
    assert (
        pilot_evaluation_report.header_macro_accuracy_pct
        >= DEFAULT_THRESHOLDS.header_macro_accuracy_pct
    ), (
        f"Header Macro-Average Accuracy {pilot_evaluation_report.header_macro_accuracy_pct}% "
        f"fell below contractual threshold {DEFAULT_THRESHOLDS.header_macro_accuracy_pct}%"
    )


def test_critical_field_hard_floor_meets_92_percent_each(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, AC-002, BR-006 — Critical Field Hard Floor >= 92.00% on each of the 4 critical fields."""
    floor = DEFAULT_THRESHOLDS.critical_field_floor_pct
    assert set(pilot_evaluation_report.critical_field_accuracies_pct.keys()) == set(
        CRITICAL_HEADER_FIELD_NAMES
    )
    for field_name in CRITICAL_HEADER_FIELD_NAMES:
        actual = pilot_evaluation_report.critical_field_accuracies_pct[field_name]
        assert actual >= floor, (
            f"Critical field '{field_name}' accuracy {actual}% fell below hard floor {floor}%"
        )
    assert pilot_evaluation_report.critical_field_min_accuracy_pct >= floor


def test_line_item_accuracy_meets_90_percent_threshold(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, BR-006, CLAUDE.md §10 — Line-Item Extraction Accuracy >= 90.00%."""
    assert (
        pilot_evaluation_report.line_item_accuracy_pct >= DEFAULT_THRESHOLDS.line_item_accuracy_pct
    ), (
        f"Line-Item Accuracy {pilot_evaluation_report.line_item_accuracy_pct}% "
        f"fell below contractual threshold {DEFAULT_THRESHOLDS.line_item_accuracy_pct}%"
    )


def test_pilot_stp_rate_meets_65_percent_threshold(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, AC-004, CLAUDE.md §10 — Pilot STP Rate >= 65.00% across 300 invoices."""
    assert pilot_evaluation_report.stp_rate_pct >= DEFAULT_THRESHOLDS.stp_rate_pct, (
        f"Pilot STP Rate {pilot_evaluation_report.stp_rate_pct}% "
        f"fell below contractual acceptance threshold {DEFAULT_THRESHOLDS.stp_rate_pct}%"
    )


def test_precision_recall_f1_and_all_contractual_gates_pass(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, AC-007 — Unified CI threshold assertion passes with strong P/R/F1 and zero self-approvals."""
    # Unified CI gate assertion — raises EvaluationThresholdError (AssertionError) on any breach
    assert_evaluation_thresholds(pilot_evaluation_report, enforce_contractual_floor=True)

    assert pilot_evaluation_report.overall_precision_pct >= Decimal("90.00")
    assert pilot_evaluation_report.overall_recall_pct >= Decimal("90.00")
    assert pilot_evaluation_report.overall_f1_pct >= Decimal("90.00")
    for status_name in pilot_evaluation_report.status_distribution:
        assert not status_name.startswith("APPROVED_"), (
            f"Evaluation pipeline must never self-approve invoices (found {status_name!r})"
        )


def test_threshold_gate_fails_loudly_when_any_metric_misses_target(
    pilot_evaluation_report: EvaluationMetricsReport,
) -> None:
    """# Tests: FR-14, SEC-226 — Proves CI gate raises EvaluationThresholdError on any breach or weakened floor."""
    # 1. Header macro accuracy drops below 95%
    low_header = pilot_evaluation_report.model_copy(
        update={"header_macro_accuracy_pct": Decimal("94.99")}
    )
    with pytest.raises(EvaluationThresholdError, match="header_macro_accuracy"):
        assert_evaluation_thresholds(low_header)

    # 2. Single critical field drops below 92%
    low_critical = pilot_evaluation_report.model_copy(
        update={
            "critical_field_accuracies_pct": {
                **pilot_evaluation_report.critical_field_accuracies_pct,
                "vendor_tax_id": Decimal("91.50"),
            },
            "critical_field_min_accuracy_pct": Decimal("91.50"),
        }
    )
    with pytest.raises(EvaluationThresholdError, match="critical_field_vendor_tax_id"):
        assert_evaluation_thresholds(low_critical)

    # 3. Line-item accuracy drops below 90%
    low_line = pilot_evaluation_report.model_copy(
        update={"line_item_accuracy_pct": Decimal("89.50")}
    )
    with pytest.raises(EvaluationThresholdError, match="line_item_accuracy"):
        assert_evaluation_thresholds(low_line)

    # 4. Pilot STP drops below 65%
    low_stp = pilot_evaluation_report.model_copy(update={"stp_rate_pct": Decimal("64.67")})
    with pytest.raises(EvaluationThresholdError, match="stp_rate"):
        assert_evaluation_thresholds(low_stp)

    # 5. Any unhandled crash fails batch stability
    crashed = pilot_evaluation_report.model_copy(update={"crashed_invoices": 1})
    with pytest.raises(EvaluationThresholdError, match="batch_stability"):
        assert_evaluation_thresholds(crashed)

    # 6. Weakening contractual thresholds below CLAUDE.md §10 floors is blocked (SEC-226)
    weakened = pilot_evaluation_report.model_copy(
        update={
            "thresholds": EvaluationThresholds(
                header_macro_accuracy_pct=Decimal("50.00"),
                critical_field_floor_pct=Decimal("50.00"),
                line_item_accuracy_pct=Decimal("50.00"),
                stp_rate_pct=Decimal("10.00"),
            )
        }
    )
    with pytest.raises(EvaluationThresholdError, match="weakened"):
        assert_evaluation_thresholds(weakened, enforce_contractual_floor=True)

    # 7. Non-finite NaN metric on forged report fails cleanly with EvaluationThresholdError (SEC-226)
    nan_header = pilot_evaluation_report.model_copy(
        update={"header_macro_accuracy_pct": Decimal("NaN")}
    )
    with pytest.raises(EvaluationThresholdError, match="header_macro_accuracy"):
        assert_evaluation_thresholds(nan_header)
