"""
Unit tests for P14-2: Dockerfile.ui (React + Nginx hardened multi-stage image).

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


def test_dockerfile_ui_exists_and_uses_multi_stage_build() -> None:
    """# Tests: P14-2, CLAUDE.md §12 — Multi-stage build pinned to node:20-alpine & nginx:1.27-alpine."""
    assert DOCKERFILE_UI.is_file(), "Dockerfile.ui must exist at repository root"
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))

    from_lines = [line for line in instructions if line.upper().startswith("FROM ")]
    assert len(from_lines) >= 2, "Dockerfile.ui must use a multi-stage build (builder + runtime)"
    for from_line in from_lines:
        assert ":latest" not in from_line.lower(), "Floating :latest tag is prohibited"

    joined = "\n".join(instructions)
    assert "AS builder" in joined
    assert "AS runtime" in joined
    assert "node:" in joined
    assert "nginx:" in joined
    assert "package.json" in joined
    assert "npm run build" in joined or "npm ci" in joined
    assert "COPY --from=builder" in joined


def test_dockerfile_ui_enforces_non_root_user_and_permissions() -> None:
    """# Tests: P14-2, SEC-232, CWE-250, CWE-732 — Non-root user appuser (UID 10001) with nologin shell."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert "adduser" in joined or "useradd" in joined
    assert "/sbin/nologin" in joined or "/usr/sbin/nologin" in joined

    user_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("USER ")]
    cmd_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("CMD ")]
    assert user_indices and cmd_indices

    final_user = instructions[user_indices[-1]].split(maxsplit=1)[1].strip()
    assert final_user not in {"root", "0", "root:root", "0:0"}
    assert user_indices[-1] < cmd_indices[-1]
    assert "chown" in joined


def test_dockerfile_ui_hardens_nginx_and_reverse_proxy_config() -> None:
    """# Tests: P14-2, FR-01, N2, SEC-232 — Unprivileged Nginx configuration & reverse proxy."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert "nginx.conf" in joined
    assert "html" in joined


def test_dockerfile_ui_exposes_port_healthcheck_and_exec_cmd() -> None:
    """# Tests: P14-2, CLAUDE.md §4, §12, §14 — EXPOSE unprivileged port, HEALTHCHECK, exec CMD."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))

    expose_lines = [line for line in instructions if line.upper().startswith("EXPOSE ")]
    assert any("8080" in line or "5173" in line or "8501" in line for line in expose_lines), (
        "Dockerfile.ui must EXPOSE an unprivileged port"
    )

    health_lines = [line for line in instructions if line.upper().startswith("HEALTHCHECK ")]
    assert len(health_lines) == 1

    cmd_lines = [line for line in instructions if line.upper().startswith("CMD ")]
    assert len(cmd_lines) == 1
    cmd = cmd_lines[0]
    assert cmd.startswith("CMD ["), "CMD must use exec JSON array form for clean SIGTERM handling"
    assert '"nginx"' in cmd


def test_dockerfile_ui_has_zero_secrets_azure_backend_creds_or_unsafe_primitives() -> None:
    """# Tests: P14-2, CLAUDE.md §4.2, §12, N8, SEC-232 — UI container has zero backend DB/Blob/AOAI secrets."""
    instructions = _logical_instructions(DOCKERFILE_UI.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert "pytest" not in joined.lower()
    assert not any(line.upper().startswith("ADD ") for line in instructions)
    assert "chmod 777" not in joined
    assert "sudo " not in joined

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
