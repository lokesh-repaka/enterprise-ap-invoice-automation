"""
Offline CLI entrypoint for ``python -m src.evaluation.evaluator --report`` (P13-4).

Covers FR-14, CLAUDE.md §10 & §14:
- Runs the offline batch evaluation harness (``InvoiceBatchEvaluator``) over ``sample_data/``
  and prints a structured, PII-free evaluation scorecard (ASCII table or JSON).
- Exits with code ``0`` when all contractual threshold gates pass (or ``--no-fail-on-threshold``
  is specified), ``1`` when any contractual threshold gate misses target, and ``2`` on invalid
  arguments, missing datasets, or security/integrity violations.

Security & Layering Invariants:
- MUST NOT be imported by production packages (CLAUDE.md §4.2).
- Strictly offline default execution (MockAOAI); zero live network calls.
- Safe ``--output-json`` writes enforce ``.json`` extension, reject dotfiles/``.git``/symlinks,
  use ``O_NOFOLLOW``, and apply restrictive ``0o600`` permissions (SEC-228, CWE-59 / CWE-22).
- Sanitized single-line stderr error reporting with zero stack traces, zero absolute host
  paths, and zero raw Vendor Tax ID PII (SEC-229, CWE-209 / CWE-532).
"""

import argparse
import asyncio
import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from src.core.config import get_settings
from src.evaluation.evaluator import (
    MAX_BATCH_INVOICES,
    EvaluationSecurityError,
    InvoiceBatchEvaluator,
)
from src.evaluation.metrics import (
    EvaluationIntegrityError,
    EvaluationThresholdError,
    assert_evaluation_thresholds,
    compute_evaluation_metrics,
    format_metrics_summary,
)

_ABS_PATH_RE = re.compile(r"(?:/[^\s:'\"]+){2,}|[A-Za-z]:\\[^\s:'\"]+")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN_OUTPUT_DIRS: frozenset[str] = frozenset({".git", ".ssh", ".aws", ".azure", ".gnupg"})


def _sanitize_error_text(raw: str) -> str:
    """Strip host filesystem paths and control characters from CLI stderr messages (SEC-229)."""
    redacted = _ABS_PATH_RE.sub("<path>", raw)
    cleaned = _CONTROL_CHAR_RE.sub(" ", redacted).strip()
    return cleaned[:240] or "evaluation error"


def _write_safe_json_report(output_path: Path, payload: str) -> Path:
    """
    Safely write a JSON evaluation report without following symlinks or overwriting non-JSON files.

    Mitigates arbitrary file overwrite and TOCTOU symlink swaps (SEC-228, CWE-59 / CWE-22 / CWE-362).
    """
    if not output_path.name or output_path.name in (".", ".."):
        raise EvaluationSecurityError("Output JSON path must name a regular .json file")
    if output_path.name.startswith("."):
        raise EvaluationSecurityError("Refusing to write evaluation report to a hidden dotfile")
    if output_path.suffix.lower() != ".json":
        raise EvaluationSecurityError("Output report path must use the '.json' file extension")
    if any(part in _FORBIDDEN_OUTPUT_DIRS for part in output_path.parts):
        raise EvaluationSecurityError(
            "Refusing to write evaluation report inside a protected dot-directory"
        )

    # Reject symlinked target or any symlinked ancestor directory
    if output_path.is_symlink():
        raise EvaluationSecurityError("Refusing to write evaluation report through a symlink")

    candidate_ancestors: list[Path] = []
    cur = output_path.parent
    while True:
        candidate_ancestors.append(cur)
        if cur == cur.parent:
            break
        cur = cur.parent
    for ancestor in reversed(candidate_ancestors):
        if ancestor.exists() and ancestor.is_symlink():
            raise EvaluationSecurityError(
                "Refusing to write evaluation report through a symlinked parent directory"
            )

    parent = output_path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    if not parent.is_dir() or parent.is_symlink():
        raise EvaluationSecurityError("Output parent path must be a non-symlink directory")
    if output_path.exists() and output_path.is_dir():
        raise EvaluationSecurityError("Output JSON path points to an existing directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(output_path, flags, 0o600)
    except OSError as exc:
        raise EvaluationSecurityError(
            f"Refusing unsafe output report target ({exc.__class__.__name__})"
        ) from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EvaluationSecurityError("Output JSON target must be a regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(payload)
            if not payload.endswith("\n"):
                fh.write("\n")
    finally:
        if fd >= 0:
            os.close(fd)

    return output_path


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for ``python -m src.evaluation.evaluator``."""
    parser = argparse.ArgumentParser(
        prog="python -m src.evaluation.evaluator",
        description=(
            "Offline Enterprise AP Invoice Automation Evaluation Harness (FR-14). "
            "Runs batch extraction + validation against ground-truth JSON and prints "
            "the contractual accuracy, precision/recall/F1, and STP scorecard."
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Print the human-readable ASCII evaluation scorecard (default output mode).",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        default=False,
        help="Print the PII-free evaluation scorecard as formatted JSON to stdout.",
    )
    parser.add_argument(
        "--sample-data-dir",
        type=str,
        default=None,
        help=(
            "Path to the dataset directory containing invoices/ and ground_truth/ "
            "(defaults to Settings.SAMPLE_DATA_DIR)."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=f"Optional invoice count ceiling (1..{MAX_BATCH_INVOICES}) for subset runs.",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Optional safe .json file path to save the PII-free evaluation scorecard (mode 0600).",
    )
    parser.add_argument(
        "--no-fail-on-threshold",
        action="store_true",
        default=False,
        help="Return exit code 0 even when one or more contractual threshold gates fail.",
    )
    return parser


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """
    Execute the evaluation CLI and return a POSIX exit code (0=pass, 1=threshold fail, 2=error).
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = build_argument_parser()

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code

    if args.limit is not None and not (1 <= args.limit <= MAX_BATCH_INVOICES):
        err.write(f"Error: --limit must be an integer within [1, {MAX_BATCH_INVOICES}]\n")
        return 2

    try:
        settings = get_settings()
        sample_dir = Path(args.sample_data_dir or settings.SAMPLE_DATA_DIR)

        evaluator = InvoiceBatchEvaluator(sample_data_dir=sample_dir, settings=settings)
        batch = asyncio.run(evaluator.run_batch(limit=args.limit))
        report = compute_evaluation_metrics(batch)

        if args.output_json is not None:
            _write_safe_json_report(Path(args.output_json), report.to_safe_json())

        if args.as_json:
            out.write(report.to_safe_json() + "\n")
        else:
            out.write(format_metrics_summary(report) + "\n")

        if args.no_fail_on_threshold:
            return 0

        try:
            assert_evaluation_thresholds(report, enforce_contractual_floor=True)
            return 0
        except EvaluationThresholdError:
            return 1
    except (
        EvaluationSecurityError,
        EvaluationIntegrityError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        err.write(f"Error ({type(exc).__name__}): {_sanitize_error_text(str(exc))}\n")
        return 2
    except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
        err.write(f"Error ({type(exc).__name__}): evaluation execution failed\n")
        return 2


__all__ = [
    "build_argument_parser",
    "run_cli",
]
