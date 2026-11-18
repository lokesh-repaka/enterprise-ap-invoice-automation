"""
Unit tests for P13-4: `python -m src.evaluation.evaluator --report` CLI.

Maps to FR-14, CLAUDE.md §10 & §14, SEC-228, SEC-229.
Fast, deterministic, strictly offline (<0.25s).
"""

import io
import json
import stat
from pathlib import Path

import pytest

from src.core.config import get_settings
from src.evaluation.cli import run_cli
from src.evaluation.evaluator import MAX_BATCH_INVOICES

SAMPLE_DATA_DIR = Path(__file__).resolve().parents[2] / "sample_data"


def _set_offline_env(monkeypatch: pytest.MonkeyPatch, sample_dir: Path = SAMPLE_DATA_DIR) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(sample_dir))
    get_settings.cache_clear()


def test_cli_report_mode_prints_printable_scorecard_and_returns_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """# Tests: FR-14, CLAUDE.md §14 — --report prints printable ASCII scorecard with zero PII/paths."""
    _set_offline_env(monkeypatch)
    stdout = io.StringIO()
    stderr = io.StringIO()

    try:
        code = run_cli(["--report", "--limit", "12"], stdout=stdout, stderr=stderr)
        assert code == 0
        assert stderr.getvalue() == ""

        output = stdout.getvalue()
        assert "AP INVOICE AUTOMATION — EVALUATION SCORECARD [PASS]" in output
        assert "12/12 completed (0 crashes)" in output
        assert "CONTRACTUAL THRESHOLD GATES" in output
        assert "EXTRACTION PRECISION / RECALL / F1" in output
        assert "PER-HEADER-FIELD ACCURACY" in output
        assert "STATUS DISTRIBUTION" in output
        assert "BREAKDOWN BY TEST CASE TYPE" in output
        assert "ESA98765432" not in output
        assert str(SAMPLE_DATA_DIR.parent) not in output
    finally:
        get_settings.cache_clear()


def test_cli_json_mode_and_safe_output_json_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-14, SEC-228 — --json prints valid PII-free JSON; --output-json writes mode 0600 file."""
    _set_offline_env(monkeypatch)
    out_file = tmp_path / "reports" / "eval_summary.json"
    stdout = io.StringIO()
    stderr = io.StringIO()

    try:
        code = run_cli(
            ["--report", "--json", "--limit", "12", "--output-json", str(out_file)],
            stdout=stdout,
            stderr=stderr,
        )
        assert code == 0
        assert stderr.getvalue() == ""

        parsed_stdout = json.loads(stdout.getvalue())
        assert parsed_stdout["all_thresholds_passed"] is True
        assert parsed_stdout["total_invoices"] == 12
        assert parsed_stdout["dataset_label"] == "sample_data"
        assert "ESA98765432" not in stdout.getvalue()
        assert str(SAMPLE_DATA_DIR.parent) not in stdout.getvalue()

        assert out_file.is_file()
        assert stat.S_IMODE(out_file.stat().st_mode) == 0o600
        parsed_file = json.loads(out_file.read_text(encoding="utf-8"))
        assert parsed_file == parsed_stdout
    finally:
        get_settings.cache_clear()


def test_cli_returns_exit_code_1_on_threshold_breach_and_0_with_no_fail_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-14, CLAUDE.md §10 — Exit 1 when gates fail; exit 0 when --no-fail-on-threshold is set."""
    inv_dir = tmp_path / "invoices"
    gt_dir = tmp_path / "ground_truth"
    inv_dir.mkdir()
    gt_dir.mkdir()
    (tmp_path / "vendor_master.json").write_text(
        (SAMPLE_DATA_DIR / "vendor_master.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "exchange_rates.json").write_text(
        (SAMPLE_DATA_DIR / "exchange_rates.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    # One valid invoice + one corrupt JSON invoice => crashed_invoices=1 => FAIL gate
    (inv_dir / "INV-2026-1001.txt").write_text(
        (SAMPLE_DATA_DIR / "invoices" / "INV-2026-1001.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (gt_dir / "INV-2026-1001_ground_truth.json").write_text(
        (SAMPLE_DATA_DIR / "ground_truth" / "INV-2026-1001_ground_truth.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    (inv_dir / "INV-2026-9998.txt").write_text("Broken invoice", encoding="utf-8")
    (gt_dir / "INV-2026-9998_ground_truth.json").write_text("{invalid json", encoding="utf-8")

    _set_offline_env(monkeypatch, sample_dir=tmp_path)
    try:
        out_strict = io.StringIO()
        err_strict = io.StringIO()
        code_strict = run_cli(
            ["--report", "--sample-data-dir", str(tmp_path)],
            stdout=out_strict,
            stderr=err_strict,
        )
        assert code_strict == 1
        assert "[FAIL]" in out_strict.getvalue()
        assert "1/2 completed (1 crashes)" in out_strict.getvalue()

        out_soft = io.StringIO()
        err_soft = io.StringIO()
        code_soft = run_cli(
            ["--report", "--no-fail-on-threshold", "--sample-data-dir", str(tmp_path)],
            stdout=out_soft,
            stderr=err_soft,
        )
        assert code_soft == 0
        assert "[FAIL]" in out_soft.getvalue()
    finally:
        get_settings.cache_clear()


def test_cli_blocks_symlink_dotfile_and_non_json_output_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-14, SEC-228 — --output-json blocks symlinks, dotfiles, .git/, and non-.json targets."""
    _set_offline_env(monkeypatch)
    outside_target = tmp_path / "victim.json"
    outside_target.write_text("ORIGINAL_CONTENT", encoding="utf-8")
    symlink_output = tmp_path / "link.json"
    symlink_output.symlink_to(outside_target)

    unsafe_targets = [
        symlink_output,
        tmp_path / "script.py",
        tmp_path / ".secret.json",
        tmp_path / ".git" / "config.json",
    ]
    try:
        for bad_target in unsafe_targets:
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = run_cli(
                ["--report", "--limit", "1", "--output-json", str(bad_target)],
                stdout=stdout,
                stderr=stderr,
            )
            assert code == 2, f"Expected exit 2 for unsafe output target {bad_target}"
            assert "EvaluationSecurityError" in stderr.getvalue()
            assert "Traceback" not in stderr.getvalue()

        # Verify symlink victim file was NEVER overwritten
        assert outside_target.read_text(encoding="utf-8") == "ORIGINAL_CONTENT"
    finally:
        get_settings.cache_clear()


def test_cli_sanitizes_errors_without_stack_traces_or_pii(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-14, SEC-229 — Invalid limits and missing datasets emit concise path-free stderr (exit 2)."""
    _set_offline_env(monkeypatch)
    try:
        for bad_limit in ("0", str(MAX_BATCH_INVOICES + 1)):
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = run_cli(["--report", "--limit", bad_limit], stdout=stdout, stderr=stderr)
            assert code == 2
            assert "--limit" in stderr.getvalue()
            assert "Traceback" not in stderr.getvalue()

        missing_dir = tmp_path / "secret_host_folder" / "does_not_exist"
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = run_cli(
            ["--report", "--sample-data-dir", str(missing_dir)],
            stdout=stdout,
            stderr=stderr,
        )
        assert code == 2
        assert "FileNotFoundError" in stderr.getvalue()
        assert "secret_host_folder" not in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
    finally:
        get_settings.cache_clear()
