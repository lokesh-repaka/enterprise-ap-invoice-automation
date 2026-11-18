"""
Unit tests for P14-1: Dockerfile.api (FastAPI hardened multi-stage image) & .dockerignore.

Maps to CLAUDE.md §4.3, §8, §11, §14, N1, N8, Implementation_Planning §4, SEC-230, SEC-231.
Fast, offline static & security verification (<0.05s).
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_API = PROJECT_ROOT / "Dockerfile.api"
DOCKERIGNORE = PROJECT_ROOT / ".dockerignore"


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


def test_dockerfile_api_exists_and_uses_multi_stage_python_311_slim() -> None:
    """# Tests: P14-1, CLAUDE.md §11 — Multi-stage build using pinned python:3.11-slim base."""
    assert DOCKERFILE_API.is_file(), "Dockerfile.api must exist at repository root"
    instructions = _logical_instructions(DOCKERFILE_API.read_text(encoding="utf-8"))

    from_lines = [line for line in instructions if line.upper().startswith("FROM ")]
    assert len(from_lines) >= 2, "Dockerfile.api must use a multi-stage build (builder + runtime)"
    for from_line in from_lines:
        assert "python:3.11-slim" in from_line, f"Expected python:3.11-slim base, got: {from_line}"
        assert ":latest" not in from_line.lower(), "Floating :latest tag is prohibited"

    # Builder stage must install dependencies into an isolated venv and copy docs/CLAUDE.md for pyproject readme
    joined = "\n".join(instructions)
    assert "AS builder" in joined
    assert "AS runtime" in joined
    assert "COPY pyproject.toml" in joined
    assert "docs/CLAUDE.md" in joined
    assert "COPY --from=builder" in joined


def test_dockerfile_api_enforces_non_root_user_and_least_privilege() -> None:
    """# Tests: P14-1, SEC-231, CWE-250 — Creates dedicated non-root user and switches USER before CMD."""
    instructions = _logical_instructions(DOCKERFILE_API.read_text(encoding="utf-8"))
    joined = "\n".join(instructions)

    assert "useradd" in joined or "adduser" in joined, "Must create a dedicated non-root user"
    assert "/usr/sbin/nologin" in joined or "/sbin/nologin" in joined, (
        "Non-root container user must use a nologin shell"
    )

    user_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("USER ")]
    cmd_indices = [i for i, line in enumerate(instructions) if line.upper().startswith("CMD ")]
    assert user_indices, "Dockerfile.api must declare a USER instruction"
    assert cmd_indices, "Dockerfile.api must declare a CMD instruction"

    final_user = instructions[user_indices[-1]].split(maxsplit=1)[1].strip()
    assert final_user not in {"root", "0", "root:root", "0:0"}, (
        f"Final USER must be non-root, got: {final_user!r}"
    )
    assert user_indices[-1] < cmd_indices[-1], "USER must precede CMD"
    assert "--chown=root:appgroup" in joined, (
        "Runtime code/venv must be owned by root:appgroup (read-only to appuser: CWE-732)"
    )
    assert "chmod -R a-w /app/src" in joined
    assert "chmod 750 /app/data" in joined
    assert '--forwarded-allow-ips="*"' not in joined and "--forwarded-allow-ips=*" not in joined


def test_dockerfile_api_exposes_8000_healthcheck_and_exec_uvicorn_cmd() -> None:
    """# Tests: P14-1, CLAUDE.md §4, §14, SEC-231 — EXPOSE 8000, /health HEALTHCHECK, exec-form uvicorn CMD."""
    instructions = _logical_instructions(DOCKERFILE_API.read_text(encoding="utf-8"))

    expose_lines = [line for line in instructions if line.upper().startswith("EXPOSE ")]
    assert any("8000" in line for line in expose_lines), "Dockerfile.api must EXPOSE 8000"

    health_lines = [line for line in instructions if line.upper().startswith("HEALTHCHECK ")]
    assert len(health_lines) == 1, "Dockerfile.api must define a HEALTHCHECK instruction"
    hc = health_lines[0]
    assert "http://127.0.0.1:8000/health" in hc
    assert "curl" not in hc.lower() and "wget" not in hc.lower(), (
        "HEALTHCHECK should use Python stdlib urllib instead of installing curl/wget"
    )

    cmd_lines = [line for line in instructions if line.upper().startswith("CMD ")]
    assert len(cmd_lines) == 1
    cmd = cmd_lines[0]
    assert cmd.startswith("CMD ["), "CMD must use exec JSON array form for clean SIGTERM handling"
    assert '"uvicorn"' in cmd
    assert '"src.api.main:app"' in cmd
    assert '"8000"' in cmd
    assert '"--no-server-header"' in cmd


def test_dockerfile_api_has_zero_secrets_unsafe_instructions_or_dev_deps() -> None:
    """# Tests: P14-1, N1, N8, SEC-231 — Zero static secrets, zero dev deps, zero unsafe primitives."""
    content = DOCKERFILE_API.read_text(encoding="utf-8")
    instructions = _logical_instructions(content)
    joined = "\n".join(instructions)

    # No dev extras installed in production image
    assert ".[dev]" not in joined
    assert "pytest" not in joined.lower()
    assert "fakeredis" not in joined.lower()

    # Safe default env: demo auth disabled
    assert 'ENABLE_DEMO_AUTH="false"' in joined or "ENABLE_DEMO_AUTH=false" in joined

    # No dangerous Dockerfile anti-patterns
    assert not any(line.upper().startswith("ADD ") for line in instructions), (
        "Use COPY instead of ADD to prevent remote fetch or tar extraction surprises"
    )
    assert "chmod 777" not in joined
    assert "sudo " not in joined
    assert "COPY . ." not in joined, "Avoid blind 'COPY . .' that risks leaking workspace files"

    # Zero static secrets or connection strings in ENV/ARG
    secret_pattern = re.compile(
        r"^(?:ENV|ARG)\s+.*(?:API_KEY|SECRET|PASSWORD|CONN(?:ECTION)?_STR|ACCOUNT_KEY|TOKEN)=",
        re.IGNORECASE,
    )
    for line in instructions:
        assert not secret_pattern.match(line), f"Potential secret in Dockerfile.api: {line}"


def test_dockerignore_excludes_secrets_databases_git_and_internal_docs() -> None:
    """# Tests: P14-1, N8, SEC-230, CWE-200 — .dockerignore blocks secrets, DBs, .git, and internal docs."""
    assert DOCKERIGNORE.is_file(), ".dockerignore must exist at repository root"
    raw_lines = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    entries = set(raw_lines)

    required_ignores = {
        ".git",
        ".env",
        ".env.*",
        "*.db",
        "*.sqlite",
        "data/",
        "internal/",
        ".agents/",
        "tests/",
        "scratch/",
        ".venv/",
        "__pycache__/",
    }
    missing = required_ignores - entries
    assert not missing, f".dockerignore is missing required security exclusions: {sorted(missing)}"
    assert "!docs/CLAUDE.md" in entries, (
        ".dockerignore must allow docs/CLAUDE.md for pyproject.toml readme build metadata"
    )
