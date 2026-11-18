"""
Unit and Middleware Integration Tests for Redis Rate Limiter (P3-3).

Tests: N5, CLAUDE.md §11, §16, CWE-770, CWE-290, CWE-348, CWE-636, CWE-74
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis.exceptions import RedisError

from src.api.main import app as main_app
from src.api.middleware import RequestIDMiddleware
from src.api.rate_limit import (
    RedisRateLimiterMiddleware,
    extract_client_ip,
    reset_rate_limit_store,
)


def _build_rate_limited_app(
    *,
    redis_client: object | None = None,
    max_requests: int = 3,
    window_seconds: int = 60,
    enabled: bool = True,
    fail_open: bool = False,
    trusted_proxies: list[str] | None = None,
    clock_fn=None,
) -> tuple[FastAPI, fakeredis.aioredis.FakeRedis]:
    """Create a minimal FastAPI app wrapped with RequestIDMiddleware and RedisRateLimiterMiddleware."""
    fake = (
        redis_client
        if redis_client is not None
        else fakeredis.aioredis.FakeRedis(decode_responses=True)
    )
    test_app = FastAPI()

    @test_app.get("/health")
    async def health():
        return {"status": "healthy"}

    @test_app.get("/health/ready")
    async def health_ready():
        return {"status": "ready"}

    @test_app.get("/api/v1/ping")
    async def ping():
        return {"ok": True}

    test_app.add_middleware(
        RedisRateLimiterMiddleware,
        redis_client=fake,
        max_requests=max_requests,
        window_seconds=window_seconds,
        enabled=enabled,
        fail_open=fail_open,
        trusted_proxies=trusted_proxies or [],
        clock_fn=clock_fn,
    )
    test_app.add_middleware(RequestIDMiddleware)
    return test_app, fake


def test_rate_limiter_allows_within_limit_and_sets_headers() -> None:
    """Verify requests within limit succeed with accurate X-RateLimit-* headers."""
    test_app, _ = _build_rate_limited_app(max_requests=3, window_seconds=60)
    client = TestClient(test_app)

    for expected_remaining in (2, 1, 0):
        resp = client.get("/api/v1/ping")
        assert resp.status_code == 200
        assert resp.headers["x-ratelimit-limit"] == "3"
        assert resp.headers["x-ratelimit-remaining"] == str(expected_remaining)
        assert int(resp.headers["x-ratelimit-reset"]) > 0


def test_rate_limiter_blocks_excess_requests_with_429_and_bounded_zset() -> None:
    """Verify excess requests return 429 with Retry-After, X-Request-ID, and no Redis ZSET bloat."""
    test_app, fake = _build_rate_limited_app(max_requests=3, window_seconds=60)
    client = TestClient(test_app)

    for _ in range(3):
        assert client.get("/api/v1/ping").status_code == 200

    # Flood 5 excess requests — all must return 429 and NOT grow the ZSET past 3 entries
    for _ in range(5):
        resp = client.get("/api/v1/ping")
        assert resp.status_code == 429
        assert resp.json() == {"detail": "Rate limit exceeded. Please retry later."}
        assert resp.headers["x-ratelimit-limit"] == "3"
        assert resp.headers["x-ratelimit-remaining"] == "0"
        assert int(resp.headers["retry-after"]) >= 1
        assert "x-request-id" in resp.headers

    async def _check_zset_size() -> int:
        keys = await fake.keys("ap:ratelimit:*")
        assert len(keys) == 1
        return await fake.zcard(keys[0])

    assert asyncio.run(_check_zset_size()) == 3


def test_sliding_window_prevents_boundary_burst_and_recovers_after_expiry() -> None:
    """Verify true sliding window prevents fixed-window boundary bursts and recovers cleanly."""
    current_time = {"now": 1000.0}
    test_app, _ = _build_rate_limited_app(
        max_requests=2,
        window_seconds=60,
        clock_fn=lambda: current_time["now"],
    )
    client = TestClient(test_app)

    # Send 2 requests near the end of minute 1 (t=1050, t=1055)
    current_time["now"] = 1050.0
    assert client.get("/api/v1/ping").status_code == 200
    current_time["now"] = 1055.0
    assert client.get("/api/v1/ping").status_code == 200

    # At t=1065 (only 15s after first request), a naive fixed-window limiter would reset;
    # sliding window MUST still reject with 429!
    current_time["now"] = 1065.0
    blocked = client.get("/api/v1/ping")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) == 45  # 1050 + 60 - 1065 = 45s

    # At t=1111 (61s after t=1050), first slot expired → request succeeds!
    current_time["now"] = 1111.0
    recovered = client.get("/api/v1/ping")
    assert recovered.status_code == 200
    assert recovered.headers["x-ratelimit-remaining"] == "0"


def test_health_get_exempt_while_post_health_options_and_ready_enforced() -> None:
    """Verify GET /health is exempt while POST /health, non-CORS OPTIONS, and /health/ready are limited."""
    test_app, _ = _build_rate_limited_app(max_requests=1, window_seconds=60)
    client = TestClient(test_app)

    # GET /health stays exempt across repeated probes
    for _ in range(5):
        r = client.get("/health")
        assert r.status_code == 200
        assert "x-ratelimit-limit" not in r.headers

    # /health/ready, POST /health, and arbitrary non-CORS OPTIONS are strictly rate-limited
    assert client.get("/health/ready").status_code == 200
    assert client.get("/health/ready").status_code == 429
    assert client.post("/health").status_code == 429
    assert client.options("/api/v1/ping").status_code == 429


def test_ipv6_and_ipv4_mapped_canonicalization_blocks_bucket_evasion() -> None:
    """Verify alternate IPv6 and IPv4-mapped IPv6 forms share one canonical rate-limit bucket (CWE-290)."""
    test_app, _ = _build_rate_limited_app(
        max_requests=2,
        window_seconds=60,
        trusted_proxies=["testclient"],
    )
    client = TestClient(test_app)

    # Equivalent IPv6 notations for the exact same host share one bucket
    assert client.get("/api/v1/ping", headers={"X-Forwarded-For": "2001:db8::1"}).status_code == 200
    assert (
        client.get(
            "/api/v1/ping",
            headers={"X-Forwarded-For": "2001:0DB8:0000:0000:0000:0000:0000:0001"},
        ).status_code
        == 200
    )
    assert (
        client.get("/api/v1/ping", headers={"X-Forwarded-For": "2001:db8:0:0::1"}).status_code
        == 429
    )

    # Equivalent IPv4 and IPv4-mapped IPv6 notations share one bucket
    assert (
        client.get("/api/v1/ping", headers={"X-Forwarded-For": "198.51.100.10"}).status_code == 200
    )
    assert (
        client.get("/api/v1/ping", headers={"X-Forwarded-For": "::ffff:198.51.100.10"}).status_code
        == 200
    )
    assert (
        client.get("/api/v1/ping", headers={"X-Forwarded-For": "::FFFF:198.51.100.10"}).status_code
        == 429
    )


def test_xff_spoofing_blocked_for_untrusted_peers() -> None:
    """Verify rotating X-Forwarded-For headers from untrusted peers cannot bypass throttling (CWE-290/348)."""
    test_app, _ = _build_rate_limited_app(max_requests=2, window_seconds=60, trusted_proxies=[])
    client = TestClient(test_app)

    assert client.get("/api/v1/ping", headers={"X-Forwarded-For": "203.0.113.1"}).status_code == 200
    assert client.get("/api/v1/ping", headers={"X-Forwarded-For": "203.0.113.2"}).status_code == 200
    # Rotating to a 3rd spoofed IP still hits 429 because TestClient peer is untrusted
    assert client.get("/api/v1/ping", headers={"X-Forwarded-For": "203.0.113.3"}).status_code == 429


def test_xff_honored_only_from_trusted_proxy_using_rightmost_untrusted_ip() -> None:
    """Verify trusted proxy uses rightmost non-trusted XFF IP so spoofed leftmost IPs fail (CWE-348)."""
    test_app, _ = _build_rate_limited_app(
        max_requests=2,
        window_seconds=60,
        trusted_proxies=["testclient", "10.0.1.5"],
    )
    client = TestClient(test_app)

    # Client A spoofs leftmost XFF IP across requests, but rightmost untrusted IP stays 198.51.100.10
    assert (
        client.get(
            "/api/v1/ping", headers={"X-Forwarded-For": "1.1.1.1, 198.51.100.10, 10.0.1.5"}
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/api/v1/ping", headers={"X-Forwarded-For": "2.2.2.2, 198.51.100.10, 10.0.1.5"}
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/api/v1/ping", headers={"X-Forwarded-For": "3.3.3.3, 198.51.100.10, 10.0.1.5"}
        ).status_code
        == 429
    )

    # Distinct Client B behind the same trusted proxy has an independent bucket
    assert (
        client.get(
            "/api/v1/ping", headers={"X-Forwarded-For": "198.51.100.20, 10.0.1.5"}
        ).status_code
        == 200
    )


def test_redis_key_hashing_prevents_key_injection_and_raw_ip_storage() -> None:
    """Verify client identifiers are SHA-256 hashed before forming Redis keys (CWE-74/532)."""
    test_app, fake = _build_rate_limited_app(
        max_requests=5,
        window_seconds=60,
        trusted_proxies=["testclient"],
    )
    client = TestClient(test_app)

    # Malicious crafted XFF header (invalid IP format should fall back safely, and key is hashed)
    resp = client.get("/api/v1/ping", headers={"X-Forwarded-For": "127.0.0.1:admin\r\nFLUSHALL"})
    assert resp.status_code == 200

    async def _inspect_keys() -> list[str]:
        return await fake.keys("ap:ratelimit:*")

    keys = asyncio.run(_inspect_keys())
    assert len(keys) == 1
    key = keys[0]
    assert key.startswith("ap:ratelimit:api:")
    assert "FLUSHALL" not in key
    assert "\r" not in key
    assert "\n" not in key
    assert "127.0.0.1" not in key
    assert "testclient" not in key
    assert len(key.rsplit(":", 1)[1]) == 32


def test_extract_client_ip_sanitizes_invalid_xff_entries() -> None:
    """Verify extract_client_ip ignores malformed XFF values and falls back to peer IP."""
    assert (
        extract_client_ip(
            peer_ip="10.0.0.1",
            xff_header="not-an-ip, 198.51.100.42",
            trusted_proxies=frozenset({"10.0.0.1"}),
        )
        == "198.51.100.42"
    )
    assert (
        extract_client_ip(
            peer_ip="10.0.0.1",
            xff_header="malicious;payload",
            trusted_proxies=frozenset({"10.0.0.1"}),
        )
        == "10.0.0.1"
    )


def test_redis_failure_fail_closed_by_default_and_optional_fail_open() -> None:
    """Verify Redis outage returns 503 when fail_open=False (default) and 200 when fail_open=True (CWE-636)."""
    broken_redis = MagicMock()
    broken_pipeline = MagicMock()
    broken_pipeline.__aenter__ = AsyncMock(return_value=broken_pipeline)
    broken_pipeline.__aexit__ = AsyncMock(return_value=False)
    broken_pipeline.execute = AsyncMock(side_effect=RedisError("Redis connection refused"))
    broken_redis.pipeline.return_value = broken_pipeline

    closed_app, _ = _build_rate_limited_app(redis_client=broken_redis, fail_open=False)
    r_closed = TestClient(closed_app).get("/api/v1/ping")
    assert r_closed.status_code == 503
    assert r_closed.json() == {"detail": "Rate limiting service unavailable"}
    assert "retry-after" in r_closed.headers
    assert "Redis connection refused" not in r_closed.text

    open_app, _ = _build_rate_limited_app(redis_client=broken_redis, fail_open=True)
    r_open = TestClient(open_app).get("/api/v1/ping")
    assert r_open.status_code == 200


def test_rate_limit_disabled_bypasses_enforcement() -> None:
    """Verify RATE_LIMIT_ENABLED=false disables throttling cleanly."""
    test_app, _ = _build_rate_limited_app(max_requests=1, window_seconds=60, enabled=False)
    client = TestClient(test_app)

    for _ in range(4):
        r = client.get("/api/v1/ping")
        assert r.status_code == 200
        assert "x-ratelimit-limit" not in r.headers


def test_main_app_wires_rate_limiter_with_request_id_and_exempt_health() -> None:
    """Verify production FastAPI app mounts RedisRateLimiterMiddleware with FakeRedis in offline mode."""
    reset_rate_limit_store()
    client = TestClient(main_app)

    # /health is exempt
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert "x-ratelimit-limit" not in r_health.headers
    assert "x-request-id" in r_health.headers

    # /api/v1/auth/me is rate-limited (even when unauthenticated 401)
    r_me = client.get("/api/v1/auth/me")
    assert r_me.status_code == 401
    assert "x-ratelimit-limit" in r_me.headers
    assert "x-ratelimit-remaining" in r_me.headers
    assert "x-request-id" in r_me.headers
