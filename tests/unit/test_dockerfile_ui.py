"""
Unit tests for P14-2: Dockerfile.ui (Streamlit hardened multi-stage image).

Maps to CLAUDE.md §4.2, §4.3, §12, §14, FR-01, N2, N8, Implementation_Planning §4, SEC-232.
Fast, offline static & security verification (<0.05s).
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_UI = PROJECT_ROOT / "Dockerfile.ui"


def _logical_instructions(text: str) -> list[str]:
    """Collapse backslash line continuations and strip comments/blank lines."""
    instructions: list[str] = []
    buffer = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            if not buffer:
                continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
        else:
            combined = (buffer + stripped).strip()
            if combined and not combined.startswith("#"):
                instructions.append(combined)
            buffer = ""
    if buffer.strip():
        instructions.append(buffer.strip())
    return instructions


def test_dockerfile_ui_exists_and_uses_multi_stage_python_311_slim() -> None:
    """# Tests: P14-2, CLAUDE.md §12 — Multi-stage build pinned to python:3.11-slim."""
    assert DOCKERFILE_UI.is_file(), "Dockerfile.ui must exist at repository root"
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))

    from_lines = [line for line in instructions if line.upper().startswith("FROM ")]
    assert len(from_lines) >= 2, "Dockerfile.ui must use a multi-stage build (builder + runtime)"
    for from_line in from_lines:
        assert "python:3.11-slim" in from_line, f"Expected python:3.11-slim base, got: {from_line}"
        assert ":latest" not in from_line.lower(), "Floating :latest tag is prohibited"

    joined = "\n".join(instructions)
    assert "AS builder" in joined
    assert "AS runtime" in joined
    assert "COPY pyproject.toml" in joined
    assert "docs/CLAUDE.md" in joined
    assert "COPY --from=builder" in joined


def test_dockerfile_ui_enforces_non_root_user_and_immutable_source() -> None:
    """# Tests: P14-2, SEC-232, CWE-250, CWE-732 — Non-root user with read-only /app/src & /opt/venv."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert "useradd" in joined or "adduser" in joined
    assert "/usr/sbin/nologin" in joined or "/sbin/nologin" in joined

    user_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("USER ")]
    cmd_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("CMD ")]
    assert user_indices and cmd_indices

    final_user = instructions[user_indices[-1]].split(maxsplit=1)[1].strip()
    assert final_user not in {"root", "0", "root:root", "0:0"}
    assert user_indices[-1] < cmd_indices[-1]
    assert "--chown=root:appgroup" in joined
    assert "chmod -R a-w /app/src" in joined


def test_dockerfile_ui_hardens_streamlit_xsrf_cors_telemetry_and_upload_cap() -> None:
    """# Tests: P14-2, FR-01, N2, SEC-232 — XSRF/CORS enabled, telemetry off, error details off, 25 MB cap."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert 'STREAMLIT_SERVER_HEADLESS="true"' in joined
    assert 'STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION="true"' in joined
    assert 'STREAMLIT_SERVER_ENABLE_CORS="true"' in joined
    assert 'STREAMLIT_BROWSER_GATHER_USAGE_STATS="false"' in joined
    assert 'STREAMLIT_CLIENT_SHOW_ERROR_DETAILS="false"' in joined
    assert 'STREAMLIT_SERVER_MAX_UPLOAD_SIZE="25"' in joined
    assert 'STREAMLIT_SERVER_FILE_WATCHER_TYPE="none"' in joined

    # Never disable XSRF or CORS protection
    assert "enableXsrfProtection=false" not in joined
    assert "enableCORS=false" not in joined


def test_dockerfile_ui_exposes_8501_healthcheck_and_exec_streamlit_cmd() -> None:
    """# Tests: P14-2, CLAUDE.md §4, §12, §14 — EXPOSE 8501, /_stcore/health HEALTHCHECK, exec CMD."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))

    expose_lines = [line for line in instructions if line.upper().startswith("EXPOSE ")]
    assert any("8501" in line for line in expose_lines), "Dockerfile.ui must EXPOSE 8501"

    health_lines = [line for line in instructions if line.upper().startswith("HEALTHCHECK ")]
    assert len(health_lines) == 1
    hc = health_lines[0]
    assert "http://127.0.0.1:8501/_stcore/health" in hc
    assert "curl" not in hc.lower() and "wget" not in hc.lower()

    cmd_lines = [line for line in instructions if line.upper().startswith("CMD ")]
    assert len(cmd_lines) == 1
    cmd = cmd_lines[0]
    assert cmd.startswith("CMD ["), "CMD must use exec JSON array form for clean SIGTERM handling"
    assert '"streamlit"' in cmd
    assert '"run"' in cmd
    assert '"src/ui/app.py"' in cmd
    assert '"--server.port=8501"' in cmd
    assert '"--server.headless=true"' in cmd


def test_dockerfile_ui_has_zero_secrets_azure_backend_creds_or_unsafe_primitives() -> None:
    """# Tests: P14-2, CLAUDE.md §4.2, §12, N8, SEC-232 — UI container has zero backend DB/Blob/AOAI secrets."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert ".[dev]" not in joined
    assert "pytest" not in joined.lower()
    assert not any(line.upper().startswith("ADD ") for line in instructions)
    assert "chmod 777" not in joined
    assert "sudo " not in joined
    assert "COPY . ." not in joined

    # UI layer must NOT declare direct Azure SQL, Blob, or OpenAI credentials (CLAUDE.md §4.2 & §12)
    for forbidden_backend_env in (
        "AZURE_SQL_SERVER",
        "AZURE_BLOB_ACCOUNT_URL",
        "AZURE_OPENAI_ENDPOINT",
        "REDIS_URL",
    ):
        assert forbidden_backend_env not in joined, (
            f"Dockerfile.ui must not configure direct backend datastore {forbidden_backend_env}"
        )

    secret_pattern = re.compile(
        r"^(?:ENV|ARG)\s+.*(?:API_KEY|SECRET|PASSWORD|CONN(?:ECTION)?_STR|ACCOUNT_KEY|TOKEN)=",
        re.IGNORECASE,
    )
    for line in instructions:
        assert not secret_pattern.match(line), f"Potential secret in Dockerfile.ui: {line}"
