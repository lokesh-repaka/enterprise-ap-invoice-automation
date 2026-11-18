"""
Integration test for P13-4: `python -m src.evaluation.evaluator --report` CLI execution.

Maps to FR-14, CLAUDE.md §10 & §14, SEC-228, SEC-229.
Executes the real module entrypoint in a strictly offline subprocess across all 300 pilot invoices.
"""

import os
import subprocess
import sys
from pathlib import Path

SAMPLE_DATA_DIR = Path(__file__).resolve().parents[2] / "sample_data"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_python_m_evaluator_report_cli_runs_full_300_invoice_pilot() -> None:
    """# Tests: FR-14, CLAUDE.md §14 — `python -m src.evaluation.evaluator --report` prints 300-invoice scorecard."""
    env = {
        **os.environ,
        "APP_ENV": "test",
        "USE_LOCAL_SQLITE": "true",
        "USE_FAKE_REDIS": "true",
        "USE_MOCK_AOAI": "true",
        "SAMPLE_DATA_DIR": str(SAMPLE_DATA_DIR),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "src.evaluation.evaluator", "--report"],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert proc.returncode == 0, f"CLI exited {proc.returncode}; stderr={proc.stderr!r}"
    stdout = proc.stdout
    assert "AP INVOICE AUTOMATION — EVALUATION SCORECARD [PASS]" in stdout
    assert "300/300 completed (0 crashes)" in stdout
    assert "Header Macro-Average Accuracy" in stdout
    assert "Critical Field 'vendor_tax_id'" in stdout
    assert "Line-Item Accuracy" in stdout
    assert "Pilot STP Rate" in stdout
    assert "EXTRACTION PRECISION / RECALL / F1" in stdout
    assert "PER-HEADER-FIELD ACCURACY" in stdout
    assert "STATUS DISTRIBUTION" in stdout
    assert "BREAKDOWN BY TEST CASE TYPE" in stdout

    # Zero PII, host paths, stack traces, or runpy RuntimeWarnings leaked (SEC-224, SEC-229)
    assert "ESA98765432" not in stdout
    assert str(PROJECT_ROOT) not in stdout
    assert "Traceback" not in proc.stderr
    assert "RuntimeWarning" not in proc.stderr
