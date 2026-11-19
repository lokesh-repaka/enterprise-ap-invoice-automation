"""
Redis-Backed Sliding-Window Rate Limiter Middleware (P3-3).

Enforces per-client request rate limits using atomic Redis Sorted Set (ZSET)
transactions (`MULTI/EXEC`), eliminating fixed-window boundary bursts and
supporting 100% offline isolation via ``fakeredis.aioredis`` when
``USE_FAKE_REDIS=true`` (CLAUDE.md §11, §13).

Security controls:
- Trusted-proxy-only ``X-Forwarded-For`` parsing with rightmost untrusted IP
  selection and IP format validation (prevents IP spoofing: CWE-290 / CWE-348).
- SHA-256 hashed Redis keys (prevents Redis key injection & raw IP storage: CWE-74 / CWE-532).
- Rejected 429 entries are immediately evicted via ``ZREM`` so attackers cannot
  bloat Redis memory or permanently lock out legitimate window recovery (CWE-400).
- Fail-closed by default (``RATE_LIMIT_FAIL_OPEN=false`` → HTTP 503) with bounded
  Redis socket timeouts (CWE-636).
"""

import hashlib
import ipaddress
import math
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:
    import fakeredis.aioredis
except ImportError:  # pragma: no cover
    fakeredis = None  # type: ignore[assignment]
import redis.asyncio as aioredis
from fastapi import status
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.core.config import Settings, get_settings
from src.core.logging import get_logger

logger = get_logger("ap.api.rate_limit")

# Lightweight liveness probe exempt strictly for GET/HEAD (CORS preflights handled by outer CORSMiddleware)
EXEMPT_HEALTH_PATHS: frozenset[str] = frozenset({"/health"})
EXEMPT_HEALTH_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# Upper bounds on X-Forwarded-For parsing to prevent header CPU DoS (CWE-400)
MAX_XFF_HEADER_LENGTH: int = 1024
MAX_XFF_HOPS: int = 16

# Bounded Redis connection timeouts for production Azure Cache for Redis
REDIS_SOCKET_TIMEOUT_SECONDS: float = 2.0

_STORE_LOCK = threading.Lock()
_SHARED_FAKE_REDIS: Any | None = None
_SHARED_REAL_REDIS: aioredis.Redis | None = None
_SHARED_REAL_REDIS_URL: str | None = None


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a single sliding-window rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: int
    retry_after: int


def _canonicalize_ip(candidate: str) -> str | None:
    """
    Validate and canonicalize an IPv4/IPv6 address string.

    Unwraps IPv4-mapped IPv6 addresses (``::ffff:198.51.100.10`` -> ``198.51.100.10``)
    and compresses IPv6 forms so alternate notations map to the exact same bucket (CWE-290).
    """
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _normalize_proxy_entry(entry: str) -> str:
    """Normalize trusted proxy entry, canonicalizing valid IPs while preserving test host tokens."""
    stripped = entry.strip()
    canonical = _canonicalize_ip(stripped)
    return canonical if canonical is not None else stripped


def extract_client_ip(
    peer_ip: str,
    xff_header: str | None,
    trusted_proxies: frozenset[str],
) -> str:
    """
    Resolve and canonicalize the client IP address without trusting spoofed ``X-Forwarded-For``.

    Only honours ``X-Forwarded-For`` when ``peer_ip`` is explicitly listed in
    ``trusted_proxies``. Walks the forwarded chain right-to-left, skipping trusted
    proxies, and selects the rightmost syntactically valid untrusted IP in canonical form.
    """
    raw_peer = peer_ip.strip() if isinstance(peer_ip, str) and peer_ip.strip() else "unknown"
    clean_peer = _canonicalize_ip(raw_peer) or raw_peer
    normalized_proxies = frozenset(_normalize_proxy_entry(p) for p in trusted_proxies)

    if not xff_header or clean_peer not in normalized_proxies:
        return clean_peer

    if len(xff_header) > MAX_XFF_HEADER_LENGTH:
        return clean_peer

    raw_hops = [part.strip() for part in xff_header.split(",") if part.strip()]
    if not raw_hops or len(raw_hops) > MAX_XFF_HOPS:
        return clean_peer

    for hop in reversed(raw_hops):
        canonical_hop = _canonicalize_ip(hop)
        if canonical_hop is None:
            return clean_peer
        if canonical_hop in normalized_proxies:
            continue
        return canonical_hop

    return clean_peer


def build_rate_limit_key(client_ip: str, scope: str = "api") -> str:
    """Construct an injection-proof, hashed Redis key for a client identifier (CWE-74/532)."""
    safe_scope = "api" if not scope.isalnum() else scope
    digest = hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:32]
    return f"ap:ratelimit:{safe_scope}:{digest}"


def get_rate_limit_redis_client(settings: Settings | None = None) -> Any:
    """Return the configured async Redis client (FakeRedis when USE_FAKE_REDIS=True)."""
    global _SHARED_FAKE_REDIS, _SHARED_REAL_REDIS, _SHARED_REAL_REDIS_URL
    cfg = settings or get_settings()

    with _STORE_LOCK:
        if cfg.USE_FAKE_REDIS:
            if fakeredis is None:
                raise RuntimeError("fakeredis package is required when USE_FAKE_REDIS=true")
            if _SHARED_FAKE_REDIS is None:
                _SHARED_FAKE_REDIS = fakeredis.aioredis.FakeRedis(decode_responses=True)
            return _SHARED_FAKE_REDIS

        if _SHARED_REAL_REDIS is None or _SHARED_REAL_REDIS_URL != cfg.REDIS_URL:
            _SHARED_REAL_REDIS = aioredis.from_url(
                cfg.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
                socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            )
            _SHARED_REAL_REDIS_URL = cfg.REDIS_URL
        return _SHARED_REAL_REDIS


def reset_rate_limit_store() -> None:
    """Reset the in-memory FakeRedis rate-limit store (used for test isolation)."""
    global _SHARED_FAKE_REDIS
    with _STORE_LOCK:
        _SHARED_FAKE_REDIS = None


class RedisRateLimiter:
    """Atomic sliding-window rate limiter backed by a Redis Sorted Set (ZSET)."""

    def __init__(
        self,
        redis_client: Any,
        *,
        max_requests: int = 100,
        window_seconds: int = 60,
        clock_fn: Callable[[], float] | None = None,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")
        self._redis = redis_client
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._clock_fn = clock_fn or time.time

    async def check_rate_limit(self, key: str) -> RateLimitResult:
        """Evaluate and record a request against the sliding window atomically."""
        now = self._clock_fn()
        now_ms = int(now * 1000)
        window_ms = self._window_seconds * 1000
        cutoff_ms = now_ms - window_ms
        member = f"{now_ms}:{uuid.uuid4().hex}"

        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, "-inf", cutoff_ms)
            pipe.zadd(key, {member: now_ms})
            pipe.zcard(key)
            pipe.zrange(key, 0, 0, withscores=True)
            pipe.pexpire(key, window_ms + 1000)
            _, _, count, oldest_entries, _ = await pipe.execute()

        oldest_ms = int(oldest_entries[0][1]) if oldest_entries else now_ms

        if count > self._max_requests:
            # Evict the rejected attempt so floods cannot bloat Redis memory or extend lockouts
            await self._redis.zrem(key, member)
            remaining_ms = max(1, (oldest_ms + window_ms) - now_ms)
            retry_after = min(self._window_seconds, max(1, math.ceil(remaining_ms / 1000)))
            return RateLimitResult(
                allowed=False,
                limit=self._max_requests,
                remaining=0,
                reset_at=int(now) + retry_after,
                retry_after=retry_after,
            )

        remaining = max(0, self._max_requests - int(count))
        reset_at = math.ceil((oldest_ms + window_ms) / 1000)
        return RateLimitResult(
            allowed=True,
            limit=self._max_requests,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=0,
        )


class RedisRateLimiterMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware enforcing Redis-backed sliding-window rate limits.

    Always returns ``{"detail": "<message>"}`` on HTTP 429/503 per CLAUDE.md §11.
    """

    def __init__(
        self,
        app: Any,
        *,
        redis_client: Any | None = None,
        max_requests: int | None = None,
        window_seconds: int | None = None,
        enabled: bool | None = None,
        fail_open: bool | None = None,
        trusted_proxies: list[str] | None = None,
        clock_fn: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(app)
        self._explicit_redis = redis_client
        self._explicit_max_requests = max_requests
        self._explicit_window_seconds = window_seconds
        self._explicit_enabled = enabled
        self._explicit_fail_open = fail_open
        self._explicit_trusted_proxies = (
            frozenset(p.strip() for p in trusted_proxies if p.strip())
            if trusted_proxies is not None
            else None
        )
        self._clock_fn = clock_fn

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in EXEMPT_HEALTH_PATHS and request.method in EXEMPT_HEALTH_METHODS:
            return await call_next(request)

        settings = get_settings()
        enabled = (
            self._explicit_enabled
            if self._explicit_enabled is not None
            else settings.RATE_LIMIT_ENABLED
        )
        if not enabled:
            return await call_next(request)

        max_requests = (
            self._explicit_max_requests
            if self._explicit_max_requests is not None
            else settings.RATE_LIMIT_REQUESTS
        )
        window_seconds = (
            self._explicit_window_seconds
            if self._explicit_window_seconds is not None
            else settings.RATE_LIMIT_WINDOW_SECONDS
        )
        fail_open = (
            self._explicit_fail_open
            if self._explicit_fail_open is not None
            else settings.RATE_LIMIT_FAIL_OPEN
        )
        trusted_proxies = (
            self._explicit_trusted_proxies
            if self._explicit_trusted_proxies is not None
            else frozenset(p.strip() for p in settings.TRUSTED_PROXY_IPS if p.strip())
        )

        peer_ip = request.client.host if request.client and request.client.host else "unknown"
        client_ip = extract_client_ip(
            peer_ip=peer_ip,
            xff_header=request.headers.get("X-Forwarded-For"),
            trusted_proxies=trusted_proxies,
        )
        redis_key = build_rate_limit_key(client_ip, scope="api")
        redis_client = (
            self._explicit_redis
            if self._explicit_redis is not None
            else get_rate_limit_redis_client(settings)
        )
        limiter = RedisRateLimiter(
            redis_client=redis_client,
            max_requests=max_requests,
            window_seconds=window_seconds,
            clock_fn=self._clock_fn,
        )

        try:
            result = await limiter.check_rate_limit(redis_key)
        except (RedisError, OSError) as exc:
            if fail_open:
                logger.warning(
                    "Rate limiter Redis backend unavailable; failing open",
                    extra={"error_type": type(exc).__name__},
                )
                return await call_next(request)

            logger.error(
                "Rate limiter Redis backend unavailable; failing closed with 503",
                extra={"error_type": type(exc).__name__},
            )
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Rate limiting service unavailable"},
                headers={"Retry-After": "5"},
            )

        rate_headers = {
            "X-RateLimit-Limit": str(result.limit),
            "X-RateLimit-Remaining": str(result.remaining),
            "X-RateLimit-Reset": str(result.reset_at),
        }

        if not result.allowed:
            logger.warning(
                "HTTP request rejected due to rate limit exceeded",
                extra={
                    "http_method": request.method,
                    "http_path": request.url.path,
                    "retry_after": result.retry_after,
                },
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please retry later."},
                headers={**rate_headers, "Retry-After": str(result.retry_after)},
            )

        response: Response = await call_next(request)
        for header_name, header_val in rate_headers.items():
            response.headers[header_name] = header_val
        return response
