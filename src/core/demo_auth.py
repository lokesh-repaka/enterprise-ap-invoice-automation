"""
Ephemeral Demo Authentication Tokens for Local Development and Portfolio Demos.

Provides RS256-signed Entra ID-shaped JWT tokens for the three documented demo
personas (``sarah.clerk``, ``michael.manager``, ``dave.admin``) per CLAUDE.md §2.

Security invariants:
- Zero static credentials or hardcoded secrets (N1, N8, ADR-007, CWE-798):
  uses a process-ephemeral RSA-2048 keypair generated in memory at runtime.
- Hard environment gate (CWE-489): disabled by default (``ENABLE_DEMO_AUTH=false``)
  and strictly blocked outside ``APP_ENV in {"dev", "local", "test"}``.
- Domain separation: dedicated non-routable demo tenant/client UUIDs ensure demo
  tokens can never validate against a real Microsoft Entra ID tenant.
"""

import json
import threading
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, ConfigDict

from src.core.config import Settings, get_settings
from src.core.logging import get_logger
from src.core.security import (
    ENTRA_LOGIN_ORIGIN,
    EntraJWKSClient,
    EntraJWTValidator,
    Role,
)

logger = get_logger("ap.core.demo_auth")

# Hard environment allowlist — demo auth is NEVER permitted in staging or production (CWE-489)
DEMO_AUTH_ALLOWED_ENVS: frozenset[str] = frozenset({"dev", "local", "test"})

# Dedicated non-routable RFC 4122 UUIDs isolating demo tokens from real Entra ID tenants
DEMO_TENANT_ID: str = "00000000-0000-4000-8000-000000000001"
DEMO_CLIENT_ID: str = "00000000-0000-4000-8000-000000000002"
DEMO_ISSUER: str = f"{ENTRA_LOGIN_ORIGIN}{DEMO_TENANT_ID}/v2.0"

# Bounded demo token TTL (prevents immortal or invalid-TTL tokens — CWE-613)
DEMO_TOKEN_MIN_TTL_SECONDS: int = 60
DEMO_TOKEN_DEFAULT_TTL_SECONDS: int = 3600
DEMO_TOKEN_MAX_TTL_SECONDS: int = 7200


class DemoAuthDisabledError(PermissionError):
    """Raised when demo auth is requested while disabled or outside dev/local/test."""


class DemoPersona(BaseModel):
    """Immutable definition of an authorised demo persona (CLAUDE.md §2)."""

    model_config = ConfigDict(frozen=True)

    username: str
    email: str
    name: str
    user_id: str
    role: Role
    entra_group: str


# Canonical demo personas from CLAUDE.md §2 and PRD §2
DEMO_PERSONAS: dict[str, DemoPersona] = {
    "sarah.clerk": DemoPersona(
        username="sarah.clerk",
        email="sarah.clerk@company.com",
        name="Sarah Jenkins",
        user_id="demo-oid-sarah-clerk",
        role=Role.AP_CLERK,
        entra_group="AP-Clerks",
    ),
    "michael.manager": DemoPersona(
        username="michael.manager",
        email="michael.manager@company.com",
        name="Michael Chen",
        user_id="demo-oid-michael-manager",
        role=Role.FINANCE_MANAGER,
        entra_group="Finance-Managers",
    ),
    "dave.admin": DemoPersona(
        username="dave.admin",
        email="dave.admin@company.com",
        name="Dave Miller",
        user_id="demo-oid-dave-admin",
        role=Role.SYSTEM_ADMIN,
        entra_group="AP-Admins",
    ),
}

_PERSONA_LOOKUP: dict[str, DemoPersona] = {
    **{k.lower(): v for k, v in DEMO_PERSONAS.items()},
    **{v.email.lower(): v for v in DEMO_PERSONAS.values()},
}


def is_demo_auth_enabled(settings: Settings | None = None) -> bool:
    """
    Return True ONLY when ALL three safety gates hold:
    1. ``ENABLE_DEMO_AUTH`` is explicitly True,
    2. ``APP_ENV`` is in ``{"dev", "local", "test"}``, AND
    3. ``USE_LOCAL_SQLITE`` is True (blocks demo auth whenever connected to Azure SQL).
    """
    cfg = settings or get_settings()
    if not cfg.ENABLE_DEMO_AUTH or not cfg.USE_LOCAL_SQLITE:
        return False
    return cfg.APP_ENV.strip().lower() in DEMO_AUTH_ALLOWED_ENVS


def resolve_demo_persona(identifier: str) -> DemoPersona:
    """Resolve a demo persona by short username or full email, failing closed if unknown."""
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("Unknown demo persona")
    normalized = identifier.strip().lower()
    persona = _PERSONA_LOOKUP.get(normalized)
    if persona is None:
        raise ValueError("Unknown demo persona")
    return persona


_KEYPAIR_LOCK = threading.Lock()
_CACHED_KEYPAIR: tuple[Any, dict[str, Any], str] | None = None
_CACHED_VALIDATORS: dict[tuple[str, int], EntraJWTValidator] = {}


def _get_ephemeral_demo_keypair() -> tuple[Any, dict[str, Any], str]:
    """
    Generate and cache a process-ephemeral 2048-bit RSA keypair in memory (thread-safe).

    Zero static credentials exist in source control, configuration, or disk (N8 / ADR-007).
    """
    global _CACHED_KEYPAIR
    with _KEYPAIR_LOCK:
        if _CACHED_KEYPAIR is None:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            kid = f"demo-rsa-{uuid.uuid4().hex[:12]}"
            jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
            jwk_dict["kid"] = kid
            jwk_dict["use"] = "sig"
            jwk_dict["alg"] = "RS256"
            _CACHED_KEYPAIR = (private_key, jwk_dict, kid)
        return _CACHED_KEYPAIR


def reset_demo_keypair_cache() -> None:
    """Rotate the in-memory ephemeral demo RSA keypair, invalidating prior demo tokens."""
    global _CACHED_KEYPAIR
    with _KEYPAIR_LOCK:
        _CACHED_KEYPAIR = None
        _CACHED_VALIDATORS.clear()


def issue_demo_token(
    persona: str,
    *,
    ttl_seconds: int = DEMO_TOKEN_DEFAULT_TTL_SECONDS,
    settings: Settings | None = None,
) -> str:
    """
    Issue a short-lived RS256-signed Entra ID-shaped JWT for an authorised demo persona.

    Raises:
        DemoAuthDisabledError: if demo auth is disabled or APP_ENV is not dev/local/test.
        ValueError: if persona is unknown or ttl_seconds is outside [60, 7200].
    """
    cfg = settings or get_settings()
    if not is_demo_auth_enabled(cfg):
        raise DemoAuthDisabledError("Demo authentication is disabled")

    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not (DEMO_TOKEN_MIN_TTL_SECONDS <= ttl_seconds <= DEMO_TOKEN_MAX_TTL_SECONDS)
    ):
        raise ValueError(
            f"ttl_seconds must be between {DEMO_TOKEN_MIN_TTL_SECONDS} and {DEMO_TOKEN_MAX_TTL_SECONDS}"
        )

    resolved = resolve_demo_persona(persona)
    private_key, _, kid = _get_ephemeral_demo_keypair()

    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": resolved.user_id,
        "oid": resolved.user_id,
        "preferred_username": resolved.email,
        "name": resolved.name,
        "roles": [resolved.role.value],
        "groups": [resolved.entra_group],
        "iss": DEMO_ISSUER,
        "aud": DEMO_CLIENT_ID,
        "tid": DEMO_TENANT_ID,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    logger.info(
        "Issued ephemeral RS256 demo token",
        extra={"demo_persona": resolved.username, "role": resolved.role.value},
    )
    return token


def get_demo_token_validator(settings: Settings | None = None) -> EntraJWTValidator:
    """Return a cached EntraJWTValidator verifying ephemeral demo RS256 tokens (dev/local/test only)."""
    cfg = settings or get_settings()
    if not is_demo_auth_enabled(cfg):
        raise DemoAuthDisabledError("Demo authentication is disabled")

    _, jwk_dict, kid = _get_ephemeral_demo_keypair()
    cache_key = (kid, cfg.ENTRA_JWT_CLOCK_SKEW_SECONDS)

    with _KEYPAIR_LOCK:
        cached = _CACHED_VALIDATORS.get(cache_key)
        if cached is not None:
            return cached

        jwk_snapshot = dict(jwk_dict)

        async def _in_memory_jwks_fetcher(_url: str) -> dict[str, Any]:
            return {"keys": [dict(jwk_snapshot)]}

        demo_settings = Settings(
            AZURE_TENANT_ID=DEMO_TENANT_ID,
            AZURE_CLIENT_ID=DEMO_CLIENT_ID,
            AZURE_API_AUDIENCE=DEMO_CLIENT_ID,
            ENTRA_JWT_CLOCK_SKEW_SECONDS=cfg.ENTRA_JWT_CLOCK_SKEW_SECONDS,
        )
        jwks_client = EntraJWKSClient(
            tenant_id=DEMO_TENANT_ID,
            cache_ttl_seconds=3600,
            refresh_cooldown_seconds=60,
            fetcher=_in_memory_jwks_fetcher,
        )
        validator = EntraJWTValidator(settings=demo_settings, jwks_client=jwks_client)
        _CACHED_VALIDATORS[cache_key] = validator
        return validator
