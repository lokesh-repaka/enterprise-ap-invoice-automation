"""
Unit and API integration tests for Demo Auth Tokens (P3-2).

Tests: N1, N8, ADR-007, FR-13, BR-029, CLAUDE.md §2, §8, §9
"""

import asyncio
import base64
import json
import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import app as main_app
from src.core.config import Settings, get_settings
from src.core.demo_auth import (
    DEMO_PERSONAS,
    DEMO_TENANT_ID,
    DemoAuthDisabledError,
    get_demo_token_validator,
    is_demo_auth_enabled,
    issue_demo_token,
    reset_demo_keypair_cache,
    resolve_demo_persona,
)
from src.core.security import EntraJWTValidator, Role


def test_demo_personas_match_claude_spec() -> None:
    """Verify exact three demo personas match CLAUDE.md §2 roles and Entra ID groups."""
    assert set(DEMO_PERSONAS.keys()) == {"sarah.clerk", "michael.manager", "dave.admin"}

    sarah = resolve_demo_persona("sarah.clerk")
    assert sarah.email == "sarah.clerk@company.com"
    assert sarah.role is Role.AP_CLERK
    assert sarah.entra_group == "AP-Clerks"

    michael = resolve_demo_persona("MICHAEL.MANAGER@COMPANY.COM")
    assert michael.username == "michael.manager"
    assert michael.role is Role.FINANCE_MANAGER
    assert michael.entra_group == "Finance-Managers"

    dave = resolve_demo_persona(" dave.admin ")
    assert dave.email == "dave.admin@company.com"
    assert dave.role is Role.SYSTEM_ADMIN
    assert dave.entra_group == "AP-Admins"

    # Unknown persona must fail closed
    with pytest.raises(ValueError, match="Unknown demo persona"):
        resolve_demo_persona("hacker.admin@company.com")


def test_issue_and_validate_demo_tokens_for_all_three_personas() -> None:
    """Verify RS256 demo tokens for all three personas validate through EntraJWTValidator."""
    dev_settings = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True)
    validator = get_demo_token_validator(settings=dev_settings)

    async def _run() -> None:
        seen_jtis: set[str] = set()
        for username, expected_email, expected_role in [
            ("sarah.clerk", "sarah.clerk@company.com", Role.AP_CLERK),
            ("michael.manager", "michael.manager@company.com", Role.FINANCE_MANAGER),
            ("dave.admin", "dave.admin@company.com", Role.SYSTEM_ADMIN),
        ]:
            token = issue_demo_token(username, settings=dev_settings)
            user = await validator.validate_token(token)
            assert user.email == expected_email
            assert user.roles == frozenset({expected_role})
            assert user.tenant_id == DEMO_TENANT_ID
            assert user.token_id is not None
            assert user.token_id not in seen_jtis
            seen_jtis.add(user.token_id)

    asyncio.run(_run())


def test_demo_auth_disabled_by_default_and_blocked_in_prod_or_staging() -> None:
    """Verify demo auth defaults to False and is hard-blocked in staging/production (CWE-489)."""
    default_settings = Settings()
    assert default_settings.ENABLE_DEMO_AUTH is False
    assert is_demo_auth_enabled(default_settings) is False

    # Even if ENABLE_DEMO_AUTH=True, non-dev environments MUST fail closed
    for blocked_env in ("prod", "production", "staging", "uat", "PREPROD", ""):
        blocked = Settings(APP_ENV=blocked_env, ENABLE_DEMO_AUTH=True)
        assert is_demo_auth_enabled(blocked) is False
        with pytest.raises(DemoAuthDisabledError):
            issue_demo_token("dave.admin", settings=blocked)
        with pytest.raises(DemoAuthDisabledError):
            get_demo_token_validator(settings=blocked)

    # Allowed environments when explicitly enabled AND USE_LOCAL_SQLITE=True
    for allowed_env in ("dev", "local", "test", "DEV"):
        allowed = Settings(APP_ENV=allowed_env, ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
        assert is_demo_auth_enabled(allowed) is True

    # Connected to real Azure SQL (USE_LOCAL_SQLITE=False) MUST hard-block demo auth even in dev (CWE-489)
    azure_sql_dev = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=False)
    assert is_demo_auth_enabled(azure_sql_dev) is False
    with pytest.raises(DemoAuthDisabledError):
        issue_demo_token("dave.admin", settings=azure_sql_dev)


def test_demo_token_ttl_bounds_enforced() -> None:
    """Verify demo token TTL is strictly bounded to [60, 7200] seconds and rejects booleans (CWE-613/20)."""
    dev_settings = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True)

    with pytest.raises(ValueError, match="ttl_seconds"):
        issue_demo_token("sarah.clerk", ttl_seconds=10, settings=dev_settings)
    with pytest.raises(ValueError, match="ttl_seconds"):
        issue_demo_token("sarah.clerk", ttl_seconds=86400, settings=dev_settings)
    with pytest.raises(ValueError, match="ttl_seconds"):
        issue_demo_token("sarah.clerk", ttl_seconds=True, settings=dev_settings)  # type: ignore[arg-type]


def test_demo_token_rejected_by_production_entra_validator() -> None:
    """Verify a demo token cannot authenticate against a real Entra ID validator."""
    dev_settings = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True)
    demo_tok = issue_demo_token("dave.admin", settings=dev_settings)

    prod_validator = EntraJWTValidator(
        settings=Settings(
            APP_ENV="production",
            ENABLE_DEMO_AUTH=False,
            AZURE_TENANT_ID="11111111-2222-3333-4444-555555555555",
            AZURE_CLIENT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
    )

    with pytest.raises(Exception) as exc_info:
        asyncio.run(prod_validator.validate_token(demo_tok))
    assert getattr(exc_info.value, "status_code", None) == 401


def test_demo_token_tampering_and_mass_assignment_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify tampered clerk demo token and extra role-override fields are blocked (CWE-347/915)."""
    dev_settings = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True)
    validator = get_demo_token_validator(settings=dev_settings)

    # 1. Tamper sarah.clerk demo token to inject system_admin role
    clerk_tok = issue_demo_token("sarah.clerk", settings=dev_settings)
    header_b64, payload_b64, sig_b64 = clerk_tok.split(".")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    decoded_payload = json.loads(base64.urlsafe_b64decode(padded))
    decoded_payload["roles"] = ["system_admin"]
    forged_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(decoded_payload).encode()).rstrip(b"=").decode()
    )
    tampered_tok = f"{header_b64}.{forged_payload_b64}.{sig_b64}"

    with pytest.raises(Exception) as exc_info:
        asyncio.run(validator.validate_token(tampered_tok))
    assert getattr(exc_info.value, "status_code", None) == 401

    # 2. Mass-assignment role override on POST /api/v1/auth/demo-token → 422
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    get_settings.cache_clear()
    client = TestClient(main_app)
    resp = client.post(
        "/api/v1/auth/demo-token",
        json={"persona": "sarah.clerk", "roles": ["system_admin"]},
    )
    assert resp.status_code == 422


def test_api_demo_token_endpoints_disabled_return_403(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify demo auth routes return 403 when disabled or in production (CWE-489)."""
    client = TestClient(main_app)

    # Default (ENABLE_DEMO_AUTH=false)
    assert client.post("/api/v1/auth/demo-token", json={"persona": "dave.admin"}).status_code == 403
    assert client.get("/api/v1/auth/demo-personas").status_code == 403

    # Production with ENABLE_DEMO_AUTH=true must STILL return 403
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    get_settings.cache_clear()
    r_prod = client.post("/api/v1/auth/demo-token", json={"persona": "dave.admin"})
    assert r_prod.status_code == 403
    assert r_prod.json() == {"detail": "Demo authentication is disabled"}
    assert client.get("/api/v1/auth/demo-personas").status_code == 403


def test_api_demo_token_end_to_end_rbac_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify end-to-end demo token issuance, /auth/me, and RBAC enforcement on /health/ready."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    get_settings.cache_clear()
    client = TestClient(main_app)

    # 1. List personas (must not expose tokens)
    personas_resp = client.get("/api/v1/auth/demo-personas")
    assert personas_resp.status_code == 200
    personas_data = personas_resp.json()["personas"]
    assert {p["username"] for p in personas_data} == {
        "sarah.clerk",
        "michael.manager",
        "dave.admin",
    }
    assert "access_token" not in personas_resp.text

    # 2. Unknown persona returns 400
    unknown_resp = client.post("/api/v1/auth/demo-token", json={"persona": "unknown.user"})
    assert unknown_resp.status_code == 400

    # 3. Mint tokens for all 3 personas and verify Cache-Control: no-store (CWE-525)
    tokens: dict[str, str] = {}
    for persona in ("sarah.clerk", "michael.manager", "dave.admin"):
        r = client.post("/api/v1/auth/demo-token", json={"persona": persona})
        assert r.status_code == 200
        assert r.headers.get("cache-control") == "no-store"
        assert r.headers.get("pragma") == "no-cache"
        body = r.json()
        assert body["token_type"] == "bearer"
        assert body["persona"] == persona
        tokens[persona] = body["access_token"]

    # 4. /api/v1/auth/me requires valid Bearer token, sets no-store headers, and returns verified claims
    assert client.get("/api/v1/auth/me").status_code == 401
    me_sarah = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['sarah.clerk']}"}
    )
    assert me_sarah.status_code == 200
    assert me_sarah.headers.get("cache-control") == "no-store"
    assert me_sarah.headers.get("pragma") == "no-cache"
    assert me_sarah.json()["email"] == "sarah.clerk@company.com"
    assert me_sarah.json()["roles"] == ["ap_clerk"]

    # 5. RBAC enforcement on GET /health/ready (system_admin only per CLAUDE.md §9)
    assert (
        client.get(
            "/health/ready", headers={"Authorization": f"Bearer {tokens['sarah.clerk']}"}
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/health/ready", headers={"Authorization": f"Bearer {tokens['michael.manager']}"}
        ).status_code
        == 403
    )
    ready_ok = client.get(
        "/health/ready", headers={"Authorization": f"Bearer {tokens['dave.admin']}"}
    )
    assert ready_ok.status_code == 200
    assert ready_ok.json()["status"] == "ready"


def test_demo_auth_uses_ephemeral_rsa_key_zero_static_secrets() -> None:
    """Verify zero static secrets in demo_auth.py and keypair rotation invalidates old tokens (N8/ADR-007)."""
    demo_auth_source = Path("src/core/demo_auth.py").read_text(encoding="utf-8")
    for forbidden in ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "HS256", "SECRET_KEY"):
        assert forbidden not in demo_auth_source

    dev_settings = Settings(APP_ENV="dev", ENABLE_DEMO_AUTH=True)
    old_token = issue_demo_token("dave.admin", settings=dev_settings)

    # Rotate ephemeral keypair → previously issued token must fail cryptographic verification
    reset_demo_keypair_cache()
    new_validator = get_demo_token_validator(settings=dev_settings)
    with pytest.raises(Exception) as exc_info:
        asyncio.run(new_validator.validate_token(old_token))
    assert getattr(exc_info.value, "status_code", None) == 401


def test_demo_auth_logs_never_leak_issued_jwt(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Verify issuing a demo token never logs the raw JWT string (CWE-532)."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    get_settings.cache_clear()
    client = TestClient(main_app)

    with caplog.at_level(logging.DEBUG):
        resp = client.post("/api/v1/auth/demo-token", json={"persona": "michael.manager"})

    assert resp.status_code == 200
    raw_token = resp.json()["access_token"]
    combined_logs = " ".join(record.getMessage() for record in caplog.records)
    assert raw_token not in combined_logs
