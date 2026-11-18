"""
Microsoft Entra ID JWT Validation and Role-Based Access Control (RBAC).

Implements keyless, asymmetric (RS256) JWT verification against Microsoft Entra ID
v2.0 JWKS discovery endpoints and FastAPI route-level RBAC guards via
``require_role()`` per CLAUDE.md §2, §8, §9, and ADR-007.
"""

import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable, Iterable
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Any

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict

from src.core.config import Settings, get_settings
from src.core.logging import get_logger

logger = get_logger("ap.core.security")

# Strict asymmetric algorithm allowlist (prevents alg:none and HS256 key confusion — CWE-327/347)
ALLOWED_JWT_ALGORITHMS: tuple[str, ...] = ("RS256",)

# Disallowed / unsupported JWS header parameters (prevents embedded-key / URL injection & RFC 7515 crit bypass — CWE-347)
FORBIDDEN_JWT_HEADERS: frozenset[str] = frozenset({"jku", "x5u", "jwk", "crit"})

# Bounded Bearer token and JWKS payload sizes to prevent CPU/memory DoS (CWE-400)
MAX_BEARER_TOKEN_BYTES: int = 16_384
MAX_JWKS_RESPONSE_BYTES: int = 262_144
MAX_JWKS_KEYS: int = 64

# Network timeout and refresh cooldown for Entra ID JWKS discovery (CWE-400)
JWKS_FETCH_TIMEOUT_SECONDS: float = 5.0
DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS: int = 60
ENTRA_LOGIN_ORIGIN: str = "https://login.microsoftonline.com/"

# Strict UUID pattern for Entra ID Tenant ID to prevent SSRF / URL path injection (CWE-918)
TENANT_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# HTTPBearer with auto_error=False guarantees RFC 6750 401 Unauthorized (never 403 on missing auth)
_bearer_scheme = HTTPBearer(auto_error=False)

JWKSFetcher = Callable[[str], Awaitable[dict[str, Any]]]


class Role(StrEnum):
    """Canonical RBAC roles defined in CLAUDE.md §2."""

    AP_CLERK = "ap_clerk"
    FINANCE_MANAGER = "finance_manager"
    SYSTEM_ADMIN = "system_admin"


# Mapping from Microsoft Entra ID security group names to canonical platform roles (CLAUDE.md §2)
ENTRA_GROUP_TO_ROLE: dict[str, Role] = {
    "AP-Clerks": Role.AP_CLERK,
    "Finance-Managers": Role.FINANCE_MANAGER,
    "AP-Admins": Role.SYSTEM_ADMIN,
}

_CANONICAL_ROLE_VALUES: dict[str, Role] = {role.value: role for role in Role}


def parse_role(value: Role | str) -> Role:
    """Resolve a Role enum or canonical role string, failing closed on unknown values."""
    if isinstance(value, Role):
        return value
    if isinstance(value, str) and value in _CANONICAL_ROLE_VALUES:
        return _CANONICAL_ROLE_VALUES[value]
    raise ValueError(f"Unknown RBAC role: {value!r}")


def extract_roles_from_claims(claims: dict[str, Any]) -> frozenset[Role]:
    """
    Extract canonical platform roles from Entra ID ``roles`` and ``groups`` claims.

    Ignores unrecognized role/group names and malformed non-list claim types (fail-closed).
    """
    resolved: set[Role] = set()

    raw_roles = claims.get("roles")
    if isinstance(raw_roles, list):
        for item in raw_roles:
            if not isinstance(item, str):
                continue
            if item in _CANONICAL_ROLE_VALUES:
                resolved.add(_CANONICAL_ROLE_VALUES[item])
            elif item in ENTRA_GROUP_TO_ROLE:
                resolved.add(ENTRA_GROUP_TO_ROLE[item])

    raw_groups = claims.get("groups")
    if isinstance(raw_groups, list):
        for item in raw_groups:
            if isinstance(item, str) and item in ENTRA_GROUP_TO_ROLE:
                resolved.add(ENTRA_GROUP_TO_ROLE[item])

    return frozenset(resolved)


class AuthenticatedUser(BaseModel):
    """Immutable authenticated user principal derived from a verified Entra ID JWT."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    subject: str
    email: str = ""
    name: str = ""
    tenant_id: str
    roles: frozenset[Role] = frozenset()
    token_id: str | None = None
    expires_at: int | None = None

    def has_role(self, role: Role | str) -> bool:
        """Return True if the principal holds the specified canonical role."""
        return parse_role(role) in self.roles

    def has_any_role(self, roles: Iterable[Role | str]) -> bool:
        """Return True if the principal holds at least one of the specified roles."""
        allowed = {parse_role(r) for r in roles}
        return bool(self.roles.intersection(allowed))


def _unauthorized(detail: str = "Invalid or expired authentication token") -> HTTPException:
    """Construct a standard RFC 6750 401 Unauthorized exception without leaking internals."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(detail: str = "Insufficient permissions") -> HTTPException:
    """Construct a standard 403 Forbidden exception without leaking role matrices."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
    )


async def _default_jwks_fetcher(url: str) -> dict[str, Any]:
    """Fetch Microsoft Entra ID JWKS JSON over HTTPS with strict host pin, size cap, and no redirects."""
    if not url.startswith(ENTRA_LOGIN_ORIGIN):
        raise ValueError("Refusing to fetch JWKS from non-Entra ID origin")

    async with httpx.AsyncClient(
        timeout=JWKS_FETCH_TIMEOUT_SECONDS,
        follow_redirects=False,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        if len(response.content) > MAX_JWKS_RESPONSE_BYTES:
            raise ValueError("JWKS response exceeded maximum permitted size")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("JWKS endpoint returned non-object JSON payload")
        return payload


class EntraJWKSClient:
    """
    Async caching JWKS client for Microsoft Entra ID v2.0 public signing keys.

    Enforces strict tenant UUID validation (SSRF defence), RSA-only key parsing,
    TTL caching, and refresh cooldown rate-limiting to prevent unknown-kid DoS.
    """

    def __init__(
        self,
        tenant_id: str,
        *,
        cache_ttl_seconds: int = 3600,
        refresh_cooldown_seconds: int = DEFAULT_JWKS_REFRESH_COOLDOWN_SECONDS,
        fetcher: JWKSFetcher | None = None,
    ) -> None:
        clean_tenant = tenant_id.strip().lower()
        if not TENANT_ID_PATTERN.match(clean_tenant):
            raise ValueError("Invalid AZURE_TENANT_ID format; expected canonical UUID")

        self._tenant_id = clean_tenant
        self._jwks_uri = f"{ENTRA_LOGIN_ORIGIN}{clean_tenant}/discovery/v2.0/keys"
        self._cache_ttl_seconds = max(60, cache_ttl_seconds)
        self._refresh_cooldown_seconds = max(1, refresh_cooldown_seconds)
        self._fetcher: JWKSFetcher = fetcher or _default_jwks_fetcher

        self._lock = asyncio.Lock()
        self._keys_by_kid: dict[str, Any] = {}
        self._expires_at_monotonic: float = 0.0
        self._last_refresh_monotonic: float = 0.0

    @property
    def jwks_uri(self) -> str:
        """Return the validated Entra ID v2.0 JWKS discovery URI."""
        return self._jwks_uri

    async def get_signing_key(self, kid: str) -> Any | None:
        """Retrieve RSA public signing key by ``kid``, refreshing cache safely if needed."""
        now = time.monotonic()
        if now < self._expires_at_monotonic and kid in self._keys_by_kid:
            return self._keys_by_kid[kid]

        async with self._lock:
            now = time.monotonic()
            # Re-check cache inside lock to avoid thundering herd
            if now < self._expires_at_monotonic:
                if kid in self._keys_by_kid:
                    return self._keys_by_kid[kid]
                # Unknown kid while cache is still fresh: respect cooldown before forced refresh
                if (now - self._last_refresh_monotonic) < self._refresh_cooldown_seconds:
                    return None

            await self._refresh_keys_locked(now)
            return self._keys_by_kid.get(kid)

    async def _refresh_keys_locked(self, now: float) -> None:
        """Fetch and parse RSA signing keys from JWKS endpoint while holding ``_lock``."""
        payload = await self._fetcher(self._jwks_uri)
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list):
            raise ValueError("JWKS response missing 'keys' list")

        parsed_keys: dict[str, Any] = {}
        for key_dict in raw_keys[:MAX_JWKS_KEYS]:
            if not isinstance(key_dict, dict):
                continue
            # Strictly accept RSA signature keys only (reject symmetric/oct or encryption keys)
            if key_dict.get("kty") != "RSA":
                continue
            key_use = key_dict.get("use")
            if key_use is not None and key_use != "sig":
                continue
            kid = key_dict.get("kid")
            if not isinstance(kid, str) or not kid.strip():
                continue
            try:
                parsed_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
            except Exception:
                logger.warning("Skipping malformed RSA JWK entry during JWKS refresh")

        if not parsed_keys:
            raise ValueError("JWKS response contained no valid RSA signing keys")

        self._keys_by_kid = parsed_keys
        self._last_refresh_monotonic = now
        self._expires_at_monotonic = now + self._cache_ttl_seconds


class EntraJWTValidator:
    """
    Validates Microsoft Entra ID v2.0 RS256 Bearer JWTs and constructs
    immutable ``AuthenticatedUser`` principals.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        jwks_client: EntraJWKSClient | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._clock_skew_seconds = self._settings.ENTRA_JWT_CLOCK_SKEW_SECONDS

        tenant_id = self._settings.AZURE_TENANT_ID.strip().lower()
        self._tenant_id = tenant_id if TENANT_ID_PATTERN.match(tenant_id) else ""
        self._allowed_audiences = self._resolve_audiences(self._settings)
        self._expected_issuer = (
            f"{ENTRA_LOGIN_ORIGIN}{self._tenant_id}/v2.0" if self._tenant_id else ""
        )

        if jwks_client is not None:
            self._jwks_client: EntraJWKSClient | None = jwks_client
        elif self._tenant_id:
            self._jwks_client = EntraJWKSClient(
                tenant_id=self._tenant_id,
                cache_ttl_seconds=self._settings.ENTRA_JWKS_CACHE_TTL_SECONDS,
            )
        else:
            self._jwks_client = None

    @staticmethod
    def _resolve_audiences(settings: Settings) -> list[str]:
        """Resolve allowed JWT audience values, returning empty list if unconfigured."""
        explicit_aud = settings.AZURE_API_AUDIENCE.strip()
        if explicit_aud:
            return [explicit_aud]

        client_id = settings.AZURE_CLIENT_ID.strip()
        if client_id and client_id != "system-assigned":
            return [client_id, f"api://{client_id}"]

        return []

    @property
    def is_configured(self) -> bool:
        """Return True only when tenant ID, JWKS client, and audience are validly configured."""
        return bool(self._tenant_id and self._jwks_client and self._allowed_audiences)

    async def validate_token(self, token: str) -> AuthenticatedUser:
        """
        Cryptographically verify an Entra ID Bearer JWT and return ``AuthenticatedUser``.

        Fails closed with HTTP 401 on any configuration gap, cryptographic error,
        or claim mismatch. Never logs or returns raw JWT contents.
        """
        if not self.is_configured or self._jwks_client is None:
            logger.warning("Entra ID JWT validation rejected: identity provider not configured")
            raise _unauthorized()

        if not isinstance(token, str) or not token.strip():
            raise _unauthorized()

        if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
            logger.warning("Entra ID JWT validation rejected: oversized bearer token")
            raise _unauthorized()

        # Compact JWS must contain exactly 3 dot-separated segments
        if token.count(".") != 2:
            raise _unauthorized()

        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            logger.warning("Entra ID JWT validation rejected: malformed token header")
            raise _unauthorized() from None

        # Reject unsupported or key-injection header parameters (RFC 7515 §4.1.11 / CWE-347)
        if any(param in unverified_header for param in FORBIDDEN_JWT_HEADERS):
            logger.warning("Entra ID JWT validation rejected: forbidden header parameter present")
            raise _unauthorized()

        alg = unverified_header.get("alg")
        if alg not in ALLOWED_JWT_ALGORITHMS:
            logger.warning("Entra ID JWT validation rejected: disallowed signing algorithm")
            raise _unauthorized()

        kid = unverified_header.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            logger.warning("Entra ID JWT validation rejected: missing kid header")
            raise _unauthorized()

        try:
            signing_key = await self._jwks_client.get_signing_key(kid)
        except (httpx.HTTPError, ValueError) as exc:
            logger.error(
                "Entra ID JWKS key lookup failed",
                extra={"error_type": type(exc).__name__},
            )
            raise _unauthorized() from None

        if signing_key is None:
            logger.warning("Entra ID JWT validation rejected: unknown signing key id")
            raise _unauthorized()

        try:
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=list(ALLOWED_JWT_ALGORITHMS),
                audience=self._allowed_audiences,
                issuer=self._expected_issuer,
                leeway=self._clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.PyJWTError as exc:
            logger.warning(
                "Entra ID JWT verification failed",
                extra={"error_type": type(exc).__name__},
            )
            raise _unauthorized() from None

        # Defense-in-depth tenant isolation check (CWE-290)
        token_tid = claims.get("tid")
        if not isinstance(token_tid, str) or token_tid.strip().lower() != self._tenant_id:
            logger.warning("Entra ID JWT validation rejected: tenant claim mismatch")
            raise _unauthorized()

        # Reject future-dated iat claims beyond configured clock skew (CWE-613)
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or iat > (time.time() + self._clock_skew_seconds):
            logger.warning("Entra ID JWT validation rejected: invalid iat timestamp")
            raise _unauthorized()

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            logger.warning("Entra ID JWT validation rejected: missing subject claim")
            raise _unauthorized()

        oid = claims.get("oid")
        user_id = oid.strip() if isinstance(oid, str) and oid.strip() else subject.strip()

        email = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or ""
        if not isinstance(email, str):
            email = ""

        display_name = claims.get("name")
        if not isinstance(display_name, str) or not display_name.strip():
            display_name = email or user_id

        jti = claims.get("jti")
        exp = claims.get("exp")

        return AuthenticatedUser(
            user_id=user_id,
            subject=subject,
            email=email,
            name=display_name,
            tenant_id=self._tenant_id,
            roles=extract_roles_from_claims(claims),
            token_id=jti if isinstance(jti, str) else None,
            expires_at=int(exp) if isinstance(exp, (int, float)) else None,
        )


@lru_cache(maxsize=4)
def _cached_validator(
    tenant_id: str,
    client_id: str,
    api_audience: str,
    cache_ttl: int,
    clock_skew: int,
) -> EntraJWTValidator:
    """Cache EntraJWTValidator instances keyed by security settings so JWKS cache persists."""
    scoped_settings = Settings(
        AZURE_TENANT_ID=tenant_id,
        AZURE_CLIENT_ID=client_id,
        AZURE_API_AUDIENCE=api_audience,
        ENTRA_JWKS_CACHE_TTL_SECONDS=cache_ttl,
        ENTRA_JWT_CLOCK_SKEW_SECONDS=clock_skew,
    )
    return EntraJWTValidator(settings=scoped_settings)


def get_token_validator() -> EntraJWTValidator:
    """FastAPI dependency provider returning the active EntraJWTValidator singleton."""
    settings = get_settings()
    return _cached_validator(
        settings.AZURE_TENANT_ID,
        settings.AZURE_CLIENT_ID,
        settings.AZURE_API_AUDIENCE,
        settings.ENTRA_JWKS_CACHE_TTL_SECONDS,
        settings.ENTRA_JWT_CLOCK_SKEW_SECONDS,
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    validator: Annotated[EntraJWTValidator, Depends(get_token_validator)],
) -> AuthenticatedUser:
    """Extract and validate the Bearer JWT from the Authorization header."""
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not credentials.credentials.strip()
    ):
        raise _unauthorized("Authentication required")

    return await validator.validate_token(credentials.credentials)


def require_role(*allowed_roles: Role | str) -> Callable[..., Awaitable[AuthenticatedUser]]:
    """
    FastAPI dependency factory enforcing strict allow-list RBAC on a route.

    Usage::

        @app.get("/health/ready")
        async def readiness(
            user: Annotated[AuthenticatedUser, Depends(require_role(Role.SYSTEM_ADMIN))]
        ):
            ...

    Raises ``ValueError`` at route registration time if ``allowed_roles`` is empty
    or contains an unknown role name (fail-closed).
    """
    if not allowed_roles:
        raise ValueError("require_role() requires at least one allowed role")

    required_roles = frozenset(parse_role(role) for role in allowed_roles)

    async def _role_guard(
        user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    ) -> AuthenticatedUser:
        if not user.has_any_role(required_roles):
            logger.warning(
                "RBAC authorization denied for authenticated user",
                extra={"user_id": user.user_id},
            )
            raise _forbidden()
        return user

    return _role_guard
