"""
Unit tests for Microsoft Entra ID JWT Validation and require_role() RBAC Guard.

Tests: N1, N3, N8, FR-13, BR-027, BR-029, CLAUDE.md §2, §8, §9
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Annotated, Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from src.api.main import app as main_app
from src.core.config import Settings
from src.core.security import (
    AuthenticatedUser,
    EntraJWKSClient,
    EntraJWTValidator,
    Role,
    get_token_validator,
    require_role,
)

TEST_TENANT_ID = "11111111-2222-3333-4444-555555555555"
TEST_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_ISSUER = f"https://login.microsoftonline.com/{TEST_TENANT_ID}/v2.0"


def _generate_rsa_keypair(kid: str = "test-kid-1") -> tuple[Any, dict[str, Any], bytes]:
    """Generate an ephemeral 2048-bit RSA keypair and its public JWK representation."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, jwk_dict, public_pem


def _sign_token(
    private_key: Any,
    *,
    kid: str = "test-kid-1",
    sub: str = "user-sub-001",
    oid: str = "oid-001",
    email: str = "sarah.clerk@company.com",
    name: str = "Sarah Clerk",
    roles: list[str] | None = None,
    groups: list[str] | None = None,
    iss: str = TEST_ISSUER,
    aud: str = TEST_CLIENT_ID,
    tid: str | None = TEST_TENANT_ID,
    exp_offset: int = 3600,
    iat_offset: int = 0,
    nbf_offset: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a real RS256-signed Entra ID-shaped JWT for offline testing."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "oid": oid,
        "preferred_username": email,
        "name": name,
        "iss": iss,
        "aud": aud,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    if tid is not None:
        payload["tid"] = tid
    if nbf_offset is not None:
        payload["nbf"] = now + nbf_offset
    if roles is not None:
        payload["roles"] = roles
    if groups is not None:
        payload["groups"] = groups
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _make_validator(
    jwk_keys: list[dict[str, Any]],
    *,
    tenant_id: str = TEST_TENANT_ID,
    client_id: str = TEST_CLIENT_ID,
    api_audience: str = "",
    cache_ttl: int = 3600,
    refresh_cooldown: int = 60,
) -> tuple[EntraJWTValidator, dict[str, int]]:
    """Build an offline EntraJWTValidator backed by an in-memory async JWKS fetcher."""
    fetch_counter = {"calls": 0}

    async def _mock_fetcher(_url: str) -> dict[str, Any]:
        fetch_counter["calls"] += 1
        return {"keys": list(jwk_keys)}

    settings = Settings(
        AZURE_TENANT_ID=tenant_id,
        AZURE_CLIENT_ID=client_id,
        AZURE_API_AUDIENCE=api_audience,
        ENTRA_JWKS_CACHE_TTL_SECONDS=cache_ttl,
    )
    jwks_client = EntraJWKSClient(
        tenant_id=tenant_id,
        cache_ttl_seconds=cache_ttl,
        refresh_cooldown_seconds=refresh_cooldown,
        fetcher=_mock_fetcher,
    )
    validator = EntraJWTValidator(settings=settings, jwks_client=jwks_client)
    return validator, fetch_counter


def _build_protected_test_app(validator: EntraJWTValidator) -> FastAPI:
    """Create a minimal FastAPI app with role-guarded routes for RBAC unit tests."""
    test_app = FastAPI()

    @test_app.get("/clerk-or-manager")
    async def clerk_or_manager_route(
        user: Annotated[
            AuthenticatedUser,
            Depends(require_role(Role.AP_CLERK, Role.FINANCE_MANAGER)),
        ],
    ):
        return {
            "user_id": user.user_id,
            "email": user.email,
            "roles": sorted(r.value for r in user.roles),
        }

    @test_app.get("/manager-only")
    async def manager_only_route(
        user: Annotated[AuthenticatedUser, Depends(require_role("finance_manager"))],
    ):
        return {"user_id": user.user_id}

    @test_app.get("/admin-only")
    async def admin_only_route(
        user: Annotated[AuthenticatedUser, Depends(require_role(Role.SYSTEM_ADMIN))],
    ):
        return {"user_id": user.user_id}

    test_app.dependency_overrides[get_token_validator] = lambda: validator
    return test_app


def test_valid_entra_jwt_with_app_roles() -> None:
    """Verify valid RS256 Entra ID JWT with app roles produces immutable AuthenticatedUser."""
    priv, jwk, _ = _generate_rsa_keypair("kid-primary")
    validator, _ = _make_validator([jwk])
    token = _sign_token(
        priv,
        kid="kid-primary",
        oid="entra-oid-sarah",
        email="sarah.clerk@company.com",
        name="Sarah Jenkins",
        roles=["ap_clerk"],
    )

    user = asyncio.run(validator.validate_token(token))
    assert isinstance(user, AuthenticatedUser)
    assert user.user_id == "entra-oid-sarah"
    assert user.email == "sarah.clerk@company.com"
    assert user.name == "Sarah Jenkins"
    assert user.tenant_id == TEST_TENANT_ID
    assert user.roles == frozenset({Role.AP_CLERK})
    assert user.has_role(Role.AP_CLERK)
    assert not user.has_role(Role.FINANCE_MANAGER)

    # Verify principal is immutable (frozen Pydantic model)
    with pytest.raises(Exception):
        user.roles = frozenset({Role.SYSTEM_ADMIN})  # type: ignore[misc]


def test_valid_entra_jwt_with_group_claims_mapping() -> None:
    """Verify Entra ID group names map cleanly to canonical platform roles and ignore unknown groups."""
    priv, jwk, _ = _generate_rsa_keypair("kid-groups")
    validator, _ = _make_validator([jwk])

    async def _run() -> None:
        for group_name, expected_role in [
            ("AP-Clerks", Role.AP_CLERK),
            ("Finance-Managers", Role.FINANCE_MANAGER),
            ("AP-Admins", Role.SYSTEM_ADMIN),
        ]:
            token = _sign_token(
                priv,
                kid="kid-groups",
                groups=[group_name, "All-Employees", "Unknown-Group"],
            )
            user = await validator.validate_token(token)
            assert user.roles == frozenset({expected_role})

    asyncio.run(_run())


def test_valid_entra_jwt_supports_api_uri_audience() -> None:
    """Verify Entra ID v2.0 tokens using api://{client_id} audience are accepted."""
    priv, jwk, _ = _generate_rsa_keypair("kid-aud")
    validator, _ = _make_validator([jwk])
    token = _sign_token(
        priv,
        kid="kid-aud",
        aud=f"api://{TEST_CLIENT_ID}",
        roles=["finance_manager"],
    )

    user = asyncio.run(validator.validate_token(token))
    assert user.has_role(Role.FINANCE_MANAGER)


def test_rejects_expired_jwt_and_future_nbf() -> None:
    """Verify expired tokens and not-yet-valid (nbf) tokens are rejected with 401."""
    priv, jwk, _ = _generate_rsa_keypair("kid-exp")
    validator, _ = _make_validator([jwk])

    async def _run() -> None:
        expired_token = _sign_token(priv, kid="kid-exp", exp_offset=-120, roles=["ap_clerk"])
        with pytest.raises(Exception) as exc_exp:
            await validator.validate_token(expired_token)
        assert getattr(exc_exp.value, "status_code", None) == 401

        future_nbf_token = _sign_token(priv, kid="kid-exp", nbf_offset=300, roles=["ap_clerk"])
        with pytest.raises(Exception) as exc_nbf:
            await validator.validate_token(future_nbf_token)
        assert getattr(exc_nbf.value, "status_code", None) == 401

    asyncio.run(_run())


def test_rejects_wrong_issuer_audience_or_tenant() -> None:
    """Verify cross-tenant issuer, wrong audience, or mismatched tid claim fail closed with 401."""
    priv, jwk, _ = _generate_rsa_keypair("kid-claims")
    validator, _ = _make_validator([jwk])

    wrong_iss = _sign_token(
        priv,
        kid="kid-claims",
        iss="https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0",
        roles=["system_admin"],
    )
    wrong_aud = _sign_token(
        priv,
        kid="kid-claims",
        aud="different-application-client-id",
        roles=["system_admin"],
    )
    wrong_tid = _sign_token(
        priv,
        kid="kid-claims",
        tid="99999999-9999-9999-9999-999999999999",
        roles=["system_admin"],
    )

    async def _run() -> None:
        for bad_token in (wrong_iss, wrong_aud, wrong_tid):
            with pytest.raises(Exception) as exc_info:
                await validator.validate_token(bad_token)
            assert getattr(exc_info.value, "status_code", None) == 401

    asyncio.run(_run())


def test_rejects_algorithm_confusion_alg_none_and_tampering() -> None:
    """Verify alg:none, HS256 key confusion, rogue RSA key, and payload tampering are blocked (CWE-327/347)."""
    priv, jwk, pub_pem = _generate_rsa_keypair("kid-sec")
    rogue_priv, _, _ = _generate_rsa_keypair("kid-sec")
    validator, _ = _make_validator([jwk])

    now = int(time.time())
    base_payload = {
        "sub": "attacker",
        "oid": "attacker-oid",
        "iss": TEST_ISSUER,
        "aud": TEST_CLIENT_ID,
        "tid": TEST_TENANT_ID,
        "iat": now,
        "exp": now + 3600,
        "roles": ["system_admin"],
    }

    # 1. Unsigned alg: none token
    header_b64 = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT", "kid": "kid-sec"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    payload_b64 = base64.urlsafe_b64encode(json.dumps(base_payload).encode()).rstrip(b"=").decode()
    alg_none_token = f"{header_b64}.{payload_b64}."

    # 2. Classic HS256 key confusion attack signed using public key PEM bytes via raw HMAC
    hs256_header_b64 = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT", "kid": "kid-sec"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    signing_input = f"{hs256_header_b64}.{payload_b64}".encode()
    hs256_sig_b64 = (
        base64.urlsafe_b64encode(hmac.new(pub_pem, signing_input, hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    hs256_confused_token = f"{hs256_header_b64}.{payload_b64}.{hs256_sig_b64}"

    # 3. Valid RS256 structure signed by an untrusted rogue private key sharing the same kid
    rogue_token = _sign_token(rogue_priv, kid="kid-sec", roles=["system_admin"])

    # 4. Tampered payload (clerk token mutated to system_admin without re-signing)
    legit_token = _sign_token(priv, kid="kid-sec", roles=["ap_clerk"])
    parts = legit_token.split(".")
    tampered_payload = (
        base64.urlsafe_b64encode(json.dumps(base_payload).encode()).rstrip(b"=").decode()
    )
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    async def _run() -> None:
        for attack_token in (alg_none_token, hs256_confused_token, rogue_token, tampered_token):
            with pytest.raises(Exception) as exc_info:
                await validator.validate_token(attack_token)
            assert getattr(exc_info.value, "status_code", None) == 401

    asyncio.run(_run())


def test_jwks_caching_key_rotation_and_refresh_cooldown() -> None:
    """Verify JWKS caching, seamless key rotation, and unknown-kid refresh cooldown DoS guard (CWE-400)."""
    priv1, jwk1, _ = _generate_rsa_keypair("kid-v1")
    priv2, jwk2, _ = _generate_rsa_keypair("kid-v2")
    active_keys = [jwk1]
    fetch_calls = {"count": 0}

    async def _rotating_fetcher(_url: str) -> dict[str, Any]:
        fetch_calls["count"] += 1
        return {"keys": list(active_keys)}

    settings = Settings(AZURE_TENANT_ID=TEST_TENANT_ID, AZURE_CLIENT_ID=TEST_CLIENT_ID)
    jwks_client = EntraJWKSClient(
        tenant_id=TEST_TENANT_ID,
        cache_ttl_seconds=3600,
        refresh_cooldown_seconds=60,
        fetcher=_rotating_fetcher,
    )
    validator = EntraJWTValidator(settings=settings, jwks_client=jwks_client)

    async def _run() -> None:
        tok1 = _sign_token(priv1, kid="kid-v1", roles=["ap_clerk"])
        await validator.validate_token(tok1)
        await validator.validate_token(tok1)
        assert fetch_calls["count"] == 1  # Served from cache on second call

        # Unknown kid flood within cooldown must NOT trigger repeated JWKS fetches
        unknown_tok = _sign_token(priv2, kid="kid-unknown-flood", roles=["ap_clerk"])
        for _ in range(5):
            with pytest.raises(Exception) as exc_info:
                await validator.validate_token(unknown_tok)
            assert getattr(exc_info.value, "status_code", None) == 401
        assert fetch_calls["count"] == 1  # Cooldown prevented JWKS fetch flood

        # Simulate cooldown expiry and key rotation to kid-v2
        active_keys.append(jwk2)
        jwks_client._last_refresh_monotonic -= 120.0
        tok2 = _sign_token(priv2, kid="kid-v2", roles=["finance_manager"])
        user2 = await validator.validate_token(tok2)
        assert user2.has_role(Role.FINANCE_MANAGER)
        assert fetch_calls["count"] == 2

    asyncio.run(_run())


def test_fail_closed_on_missing_or_invalid_tenant_config() -> None:
    """Verify missing or SSRF-tainted tenant_id or unconfigured client_id fails closed (CWE-918/1188)."""
    priv, _, _ = _generate_rsa_keypair("kid-cfg")
    tok = _sign_token(priv, kid="kid-cfg", roles=["system_admin"])

    async def _run() -> None:
        # Unconfigured tenant ID
        unconfigured = EntraJWTValidator(
            settings=Settings(AZURE_TENANT_ID="", AZURE_CLIENT_ID=TEST_CLIENT_ID)
        )
        with pytest.raises(Exception) as exc1:
            await unconfigured.validate_token(tok)
        assert getattr(exc1.value, "status_code", None) == 401

        # Unconfigured client_id ("system-assigned" default without AZURE_API_AUDIENCE)
        no_aud = EntraJWTValidator(
            settings=Settings(AZURE_TENANT_ID=TEST_TENANT_ID, AZURE_CLIENT_ID="system-assigned")
        )
        with pytest.raises(Exception) as exc2:
            await no_aud.validate_token(tok)
        assert getattr(exc2.value, "status_code", None) == 401

    asyncio.run(_run())

    # SSRF / path-injection attempt in tenant_id must raise ValueError in EntraJWKSClient
    with pytest.raises(ValueError):
        EntraJWKSClient(tenant_id="evil.attacker.com/keys#")


def test_require_role_allows_authorized_and_blocks_unauthorized() -> None:
    """Verify require_role() enforces strict allow-list RBAC returning 401/403 correctly (CLAUDE.md §2, §8)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-rbac")
    validator, _ = _make_validator([jwk])
    test_app = _build_protected_test_app(validator)
    client = TestClient(test_app)

    clerk_tok = _sign_token(priv, kid="kid-rbac", roles=["ap_clerk"])
    manager_tok = _sign_token(priv, kid="kid-rbac", roles=["finance_manager"])
    admin_tok = _sign_token(priv, kid="kid-rbac", roles=["system_admin"])
    no_role_tok = _sign_token(priv, kid="kid-rbac", roles=[])

    # Missing, non-Bearer, malformed, and oversized Authorization headers → 401 + WWW-Authenticate
    for headers in [
        {},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer not.a.valid.jwt"},
        {"Authorization": f"Bearer {'a' * 20000}"},
    ]:
        resp = client.get("/clerk-or-manager", headers=headers)
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"
        assert "detail" in resp.json()

    # Authorized clerk & manager pass /clerk-or-manager
    assert (
        client.get(
            "/clerk-or-manager", headers={"Authorization": f"Bearer {clerk_tok}"}
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/clerk-or-manager", headers={"Authorization": f"Bearer {manager_tok}"}
        ).status_code
        == 200
    )

    # Strict allow-list: clerk cannot access manager-only route (FR-13 / CLAUDE.md §8)
    resp_403 = client.get("/manager-only", headers={"Authorization": f"Bearer {clerk_tok}"})
    assert resp_403.status_code == 403
    assert resp_403.json() == {"detail": "Insufficient permissions"}

    # User with no valid platform roles gets 403 on protected routes
    assert (
        client.get(
            "/clerk-or-manager", headers={"Authorization": f"Bearer {no_role_tok}"}
        ).status_code
        == 403
    )

    # Admin accesses admin-only route; manager is rejected with 403
    assert (
        client.get("/admin-only", headers={"Authorization": f"Bearer {admin_tok}"}).status_code
        == 200
    )
    assert (
        client.get("/admin-only", headers={"Authorization": f"Bearer {manager_tok}"}).status_code
        == 403
    )

    # Fail-closed guard registration: empty roles or unknown role raises ValueError
    with pytest.raises(ValueError):
        require_role()
    with pytest.raises(ValueError):
        require_role("super_duper_hacker")


def test_health_ready_enforces_system_admin_rbac_while_health_stays_public() -> None:
    """Verify GET /health is public while GET /health/ready enforces system_admin RBAC (CLAUDE.md §9)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-health")
    validator, _ = _make_validator([jwk])
    main_app.dependency_overrides[get_token_validator] = lambda: validator
    try:
        client = TestClient(main_app)

        # Public liveness probe requires no auth
        assert client.get("/health").status_code == 200

        # Readiness probe requires authenticated system_admin
        assert client.get("/health/ready").status_code == 401

        clerk_tok = _sign_token(priv, kid="kid-health", roles=["ap_clerk"])
        assert (
            client.get(
                "/health/ready", headers={"Authorization": f"Bearer {clerk_tok}"}
            ).status_code
            == 403
        )

        admin_tok = _sign_token(priv, kid="kid-health", groups=["AP-Admins"])
        resp_ok = client.get("/health/ready", headers={"Authorization": f"Bearer {admin_tok}"})
        assert resp_ok.status_code == 200
        assert resp_ok.json()["status"] == "ready"
    finally:
        main_app.dependency_overrides.pop(get_token_validator, None)


def test_security_errors_and_logs_never_leak_raw_jwt(caplog: pytest.LogCaptureFixture) -> None:
    """Verify raw Bearer JWTs and internal tenant/JWKS config never leak in HTTP responses or logs (CWE-209/532)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-leak")
    validator, _ = _make_validator([jwk])
    test_app = _build_protected_test_app(validator)
    client = TestClient(test_app)

    expired_tok = _sign_token(priv, kid="kid-leak", exp_offset=-120, roles=["ap_clerk"])
    clerk_tok = _sign_token(priv, kid="kid-leak", roles=["ap_clerk"])

    with caplog.at_level(logging.DEBUG, logger="ap.core.security"):
        r401 = client.get("/admin-only", headers={"Authorization": f"Bearer {expired_tok}"})
        r403 = client.get("/admin-only", headers={"Authorization": f"Bearer {clerk_tok}"})

    assert r401.status_code == 401
    assert r403.status_code == 403

    # Neither HTTP bodies nor logs may contain raw JWT strings or internal tenant/JWKS details
    combined_responses = r401.text + " " + r403.text
    combined_logs = " ".join(record.getMessage() for record in caplog.records)

    assert expired_tok not in combined_responses
    assert clerk_tok not in combined_responses
    assert TEST_TENANT_ID not in combined_responses
    assert "login.microsoftonline.com" not in combined_responses
    assert expired_tok not in combined_logs
    assert clerk_tok not in combined_logs


def test_rejects_forbidden_jws_headers_jku_x5u_jwk_and_crit() -> None:
    """Verify tokens carrying jku, x5u, embedded jwk, or crit header extensions are rejected (CWE-347)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-hdr")
    validator, _ = _make_validator([jwk])
    now = int(time.time())
    payload = {
        "sub": "user-hdr",
        "oid": "oid-hdr",
        "iss": TEST_ISSUER,
        "aud": TEST_CLIENT_ID,
        "tid": TEST_TENANT_ID,
        "iat": now,
        "exp": now + 3600,
        "roles": ["system_admin"],
    }

    malicious_headers = [
        {"kid": "kid-hdr", "jku": "https://evil.example.com/jwks.json"},
        {"kid": "kid-hdr", "x5u": "https://evil.example.com/cert.pem"},
        {"kid": "kid-hdr", "jwk": jwk},
        {"kid": "kid-hdr", "crit": ["exp", "custom_ext"]},
    ]

    async def _run() -> None:
        for hdr in malicious_headers:
            tok = jwt.encode(payload, priv, algorithm="RS256", headers=hdr)
            with pytest.raises(Exception) as exc_info:
                await validator.validate_token(tok)
            assert getattr(exc_info.value, "status_code", None) == 401

    asyncio.run(_run())


def test_rejects_future_iat_and_blank_subject() -> None:
    """Verify tokens with future-dated iat beyond leeway or whitespace-only sub are rejected (CWE-613/20)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-iat")
    validator, _ = _make_validator([jwk])

    future_iat_tok = _sign_token(priv, kid="kid-iat", iat_offset=600, roles=["ap_clerk"])
    blank_sub_tok = _sign_token(priv, kid="kid-iat", sub="   ", oid="oid-1", roles=["ap_clerk"])

    async def _run() -> None:
        for bad_tok in (future_iat_tok, blank_sub_tok):
            with pytest.raises(Exception) as exc_info:
                await validator.validate_token(bad_tok)
            assert getattr(exc_info.value, "status_code", None) == 401

    asyncio.run(_run())


def test_jwks_rejects_non_rsa_and_empty_keyset_without_poisoning_cache() -> None:
    """Verify symmetric/oct JWKs and empty responses are rejected without wiping valid cached keys (CWE-327/400)."""
    priv, jwk, _ = _generate_rsa_keypair("kid-good")
    responses: list[dict[str, Any]] = [
        {"keys": [jwk, {"kty": "oct", "kid": "kid-sym", "k": "c2VjcmV0"}]},
        {"keys": [{"kty": "oct", "kid": "kid-sym-only", "k": "c2VjcmV0"}]},
    ]
    idx = {"i": 0}

    async def _mock_fetcher(_url: str) -> dict[str, Any]:
        res = responses[min(idx["i"], len(responses) - 1)]
        idx["i"] += 1
        return res

    settings = Settings(AZURE_TENANT_ID=TEST_TENANT_ID, AZURE_CLIENT_ID=TEST_CLIENT_ID)
    jwks_client = EntraJWKSClient(
        tenant_id=TEST_TENANT_ID,
        cache_ttl_seconds=3600,
        refresh_cooldown_seconds=1,
        fetcher=_mock_fetcher,
    )
    validator = EntraJWTValidator(settings=settings, jwks_client=jwks_client)

    async def _run() -> None:
        # Initial valid RSA key succeeds; symmetric oct key was ignored
        tok = _sign_token(priv, kid="kid-good", roles=["ap_clerk"])
        user = await validator.validate_token(tok)
        assert user.has_role(Role.AP_CLERK)
        assert "kid-sym" not in jwks_client._keys_by_kid

        # Forced refresh returning only non-RSA keys fails without wiping cached kid-good
        jwks_client._last_refresh_monotonic -= 10.0
        bad_kid_tok = _sign_token(priv, kid="kid-sym-only", roles=["ap_clerk"])
        with pytest.raises(Exception) as exc_info:
            await validator.validate_token(bad_kid_tok)
        assert getattr(exc_info.value, "status_code", None) == 401
        assert "kid-good" in jwks_client._keys_by_kid

    asyncio.run(_run())


def test_cors_blocks_untrusted_origin_reflection_with_credentials() -> None:
    """Verify untrusted Origin is not reflected in Access-Control-Allow-Origin (CWE-942)."""
    client = TestClient(main_app)

    evil_resp = client.get("/health", headers={"Origin": "https://evil.attacker.example"})
    assert evil_resp.status_code == 200
    assert evil_resp.headers.get("access-control-allow-origin") is None

    trusted_resp = client.get("/health", headers={"Origin": "http://localhost:8501"})
    assert trusted_resp.status_code == 200
    assert trusted_resp.headers.get("access-control-allow-origin") == "http://localhost:8501"
