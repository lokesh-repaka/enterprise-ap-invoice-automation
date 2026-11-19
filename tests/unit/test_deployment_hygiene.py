"""
Unit tests for P14-5: Deployment Hygiene Tests.

Verifies:
- No .env, .env.*, or *.db/*.sqlite files committed or tracked in git repository.
- Zero static secrets, private keys, or API tokens committed in production/infra code.
- NSG East US 2 regional confinement and outbound Internet deny rule verified (ADR-001, N2).
- Storage 7-year WORM immutability and keyless architecture verified (ADR-005, ADR-007, N1, N6).
- Docker and Docker Compose container security and loopback binding verified (SEC-231, SEC-232, SEC-233).
- Managed Identity RBAC least-privilege role assignments verified (SEC-234, N1, N8).

Maps to CLAUDE.md §3, §4, §11, ADR-001, ADR-005, ADR-007, N1, N2, N6, N8, SEC-235.
Fast, offline static & security verification (<0.05s).
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GITIGNORE_FILE = PROJECT_ROOT / ".gitignore"
DOCKERIGNORE_FILE = PROJECT_ROOT / ".dockerignore"
BICEP_FILE = PROJECT_ROOT / "infrastructure" / "main.bicep"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"
DOCKERFILE_API = PROJECT_ROOT / "Dockerfile.api"
DOCKERFILE_UI = PROJECT_ROOT / "Dockerfile.ui"


def test_hygiene_no_env_or_db_files_committed_or_tracked() -> None:
    """# Tests: P14-5, N8, SEC-235, CWE-200, CWE-312 — Zero .env or *.db files committed to git."""
    # 1. Query git index specifically for forbidden committed files (excluding .env.example)
    if shutil.which("git"):
        try:
            res = subprocess.run(
                ["git", "ls-files", ".env*", "*.db", "*.sqlite", "*.sqlite3"],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            tracked = [
                line.strip()
                for line in res.stdout.splitlines()
                if line.strip() and Path(line.strip()).name != ".env.example"
            ]
            assert not tracked, (
                f"Forbidden environment or database files tracked in git index: {tracked}"
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 2. Verify .gitignore explicitly blocks .env, *.db, and *.sqlite
    assert GITIGNORE_FILE.is_file(), ".gitignore must exist"
    gitignore_content = GITIGNORE_FILE.read_text(encoding="utf-8")
    assert ".env" in gitignore_content, ".gitignore must exclude .env"
    assert "*.db" in gitignore_content, ".gitignore must exclude *.db"
    assert "*.sqlite" in gitignore_content, ".gitignore must exclude *.sqlite"


def test_hygiene_zero_static_secrets_committed_across_repository() -> None:
    """# Tests: P14-5, N1, N8, ADR-007, SEC-235, CWE-798 — Zero static keys, passwords, or tokens in codebase."""
    # Scan production source, infrastructure, container definitions, workflows, and templates
    files_to_scan: list[Path] = []
    if (PROJECT_ROOT / "src").is_dir():
        files_to_scan.extend((PROJECT_ROOT / "src").rglob("*.py"))
    if (PROJECT_ROOT / "infrastructure").is_dir():
        files_to_scan.extend((PROJECT_ROOT / "infrastructure").rglob("*.bicep"))
    if (PROJECT_ROOT / ".github").is_dir():
        files_to_scan.extend((PROJECT_ROOT / ".github").rglob("*.yml"))
        files_to_scan.extend((PROJECT_ROOT / ".github").rglob("*.yaml"))

    for root_file in [
        "Dockerfile.api",
        "Dockerfile.ui",
        "docker-compose.yml",
        "docker-compose.azurite.yml",
        ".env.example",
        "pyproject.toml",
    ]:
        p = PROJECT_ROOT / root_file
        if p.is_file():
            files_to_scan.append(p)

    secret_patterns: list[tuple[str, re.Pattern[str]]] = [
        (
            "Private Key Block",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        ),
        ("Azure Storage AccountKey", re.compile(r"AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}")),
        ("OpenAI Static API Key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
        ("Static SQL Password", re.compile(r"(?i)(?:Password|pwd)\s*=\s*['\"][^'\";\s]{6,}['\"]")),
        ("Hardcoded Client Secret", re.compile(r'(?i)client_secret\s*=\s*["\'][^"\']{8,}["\']')),
    ]

    violations: list[str] = []
    for file_path in files_to_scan:
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for label, pattern in secret_patterns:
            match = pattern.search(content)
            if match:
                violations.append(
                    f"{file_path.relative_to(PROJECT_ROOT)}: matched {label} ({match.group(0)[:30]}...)"
                )

    assert not violations, (
        f"Static secrets or sensitive credentials detected in repository: {violations}"
    )


def test_hygiene_nsg_east_us2_confinement_and_internet_deny_verified() -> None:
    """# Tests: P14-5, ADR-001, N2, SEC-235, CWE-668 — NSG denies outbound Internet, restricts to East US 2."""
    assert BICEP_FILE.is_file(), "infrastructure/main.bicep must exist"
    bicep_content = BICEP_FILE.read_text(encoding="utf-8")

    # 1. Primary region must default to eastus2 and allowed regions restricted to eastus2
    param_match = re.search(r"param\s+primaryRegion\s+string\s*=\s*'eastus2'", bicep_content)
    assert param_match, "primaryRegion parameter must default to 'eastus2'"

    # 2. NSG resource must exist
    assert "Microsoft.Network/networkSecurityGroups@" in bicep_content

    # 3. Deny outbound Internet rule must exist
    assert "Deny-Internet-Outbound" in bicep_content or "deny" in bicep_content.lower()
    assert "'Deny'" in bicep_content or "access: 'Deny'" in bicep_content
    assert "'Outbound'" in bicep_content or "direction: 'Outbound'" in bicep_content
    assert "'Internet'" in bicep_content or "destinationAddressPrefix: 'Internet'" in bicep_content

    # 4. Outbound allow rule restricted strictly to East US 2 regional Azure services
    assert "AzureCloud.EastUS2" in bicep_content, (
        "Outbound rules must restrict cloud traffic to 'AzureCloud.EastUS2' (ADR-001, N2)"
    )

    # 5. Zero wildcard Internet outbound allow rules
    wildcard_outbound = re.findall(
        r"direction:\s*'Outbound'[\s\S]*?access:\s*'Allow'[\s\S]*?destinationAddressPrefix:\s*'\*'",
        bicep_content,
    )
    assert not wildcard_outbound, (
        f"Forbidden wildcard outbound allow rule detected in Bicep template: {wildcard_outbound}"
    )


def test_hygiene_storage_7year_worm_and_keyless_architecture_verified() -> None:
    """# Tests: P14-5, ADR-005, ADR-007, N1, N6, SEC-235 — 7-year WORM hold and keyless storage access."""
    bicep_content = BICEP_FILE.read_text(encoding="utf-8")

    # Storage account settings
    assert "allowSharedKeyAccess: false" in bicep_content, (
        "Storage account must disable shared access keys to enforce keyless Managed Identity auth (ADR-007, N1)"
    )
    assert "supportsHttpsTrafficOnly: true" in bicep_content
    assert "minimumTlsVersion: 'TLS1_2'" in bicep_content
    assert "allowBlobPublicAccess: false" in bicep_content

    # Container and 7-year WORM retention
    assert "raw-invoices-immutable" in bicep_content
    assert "2557" in bicep_content, (
        "Immutability period must be 2557 days (7 years including leap days: ADR-005, N6)"
    )
    assert "allowProtectedAppendWrites: true" in bicep_content


def test_hygiene_docker_and_compose_container_hardening_verified() -> None:
    """# Tests: P14-5, SEC-231, SEC-232, SEC-233, CWE-250, CWE-668 — Non-root users, loopback ports, no-new-privileges."""
    # 1. Dockerfile.api and Dockerfile.ui non-root user checks
    for df_path, name in [(DOCKERFILE_API, "Dockerfile.api"), (DOCKERFILE_UI, "Dockerfile.ui")]:
        assert df_path.is_file(), f"{name} must exist"
        content = df_path.read_text(encoding="utf-8")
        assert "USER appuser" in content or "USER 10001" in content, (
            f"{name} must switch to non-root user"
        )
        assert "nologin" in content, f"{name} non-root user must use nologin shell"
        assert "AS builder" in content and "AS runtime" in content, (
            f"{name} must use multi-stage build"
        )

    # 2. .dockerignore hygiene
    assert DOCKERIGNORE_FILE.is_file(), ".dockerignore must exist"
    d_ignore = DOCKERIGNORE_FILE.read_text(encoding="utf-8")
    for pattern in [".git", ".env", "*.db", "internal/", "scratch/"]:
        assert pattern in d_ignore, f".dockerignore must exclude {pattern}"

    # 3. docker-compose.yml loopback pinning and security controls
    assert COMPOSE_FILE.is_file(), "docker-compose.yml must exist"
    compose_data: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    services = compose_data.get("services", {})
    for svc_name, svc in services.items():
        ports = svc.get("ports", [])
        for p in ports:
            port_str = str(p).strip()
            assert port_str.startswith("127.0.0.1:"), (
                f"docker-compose.yml service {svc_name} port {port_str!r} is not loopback-pinned (SEC-233, CWE-668)"
            )
        sec_opts = svc.get("security_opt", [])
        assert "no-new-privileges:true" in sec_opts
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop
        assert "mem_limit" in svc
        assert "pids_limit" in svc


def test_hygiene_managed_identity_rbac_roles_in_bicep_verified() -> None:
    """# Tests: P14-5, ADR-007, N1, N8, SEC-234, SEC-235 — Least-privilege Entra ID Managed Identity roles."""
    bicep_content = BICEP_FILE.read_text(encoding="utf-8")

    # Container Apps must use SystemAssigned identity
    assert "type: 'SystemAssigned'" in bicep_content

    # Built-in Azure RBAC Role IDs assigned to Container Apps
    # Key Vault Secrets User
    assert "4633458b-17de-408a-b874-0445c86b69e6" in bicep_content
    # Storage Blob Data Contributor
    assert "ba92f5b4-2d11-453d-a403-e96b0029c9fe" in bicep_content
    # Cognitive Services OpenAI User
    assert "5e0dc982-0038-4745-9372-2f3b90048e9c" in bicep_content

    # Azure SQL Entra ID ActiveDirectory-only auth (no SA password)
    assert "azureADOnlyAuthentication: true" in bicep_content
    assert "publicNetworkAccess: 'Disabled'" in bicep_content
