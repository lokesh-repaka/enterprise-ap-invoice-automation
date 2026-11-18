"""
HTTP Audit Middleware — request_id and Verified Actor Propagation (P3-4).

Executes inside ``RequestIDMiddleware`` and ``CORSMiddleware`` and outside
``RedisRateLimiterMiddleware`` so every API request, authentication denial
(401/403), rate-limit block (429), and unhandled server error (500) produces an
immutable structured audit record linked to the active ``request_id`` and
cryptographically verified ``actor_id`` (CLAUDE.md §8, N3).
"""

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.core.logging import audit_actor_ctx, get_logger, mask_pii, request_id_ctx

logger = get_logger("ap.api.audit")

_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
MAX_AUDITED_PATH_LENGTH: int = 256


def _sanitize_audit_path(raw_path: str) -> str:
    """Mask PII before stripping control chars (preserving word boundaries) and cap length."""
    masked = mask_pii(raw_path)
    return _CONTROL_CHAR_RE.sub("", masked)[:MAX_AUDITED_PATH_LENGTH]


def _classify_audit_outcome(status_code: int) -> str:
    """Map HTTP response status code to a canonical security/audit outcome."""
    if status_code in (401, 403):
        return "AUTH_DENIED"
    if status_code == 429:
        return "RATE_LIMITED"
    if 200 <= status_code < 400:
        return "SUCCESS"
    if 400 <= status_code < 500:
        return "CLIENT_ERROR"
    return "SERVER_ERROR"


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Propagates ``request_id`` and ``audit_actor_ctx`` per HTTP request and emits
    structured security audit events without logging credentials or request bodies.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = request_id_ctx.get() or getattr(request.state, "request_id", "")
        request.state.request_id = req_id

        # Reset actor state & ContextVar per request to prevent cross-request bleed (CWE-362)
        request.state.audit_actor = "anonymous"
        actor_token = audit_actor_ctx.set("anonymous")
        start = time.perf_counter()
        method = request.method
        raw_path = request.url.path
        safe_path = _sanitize_audit_path(raw_path)

        try:
            response: Response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            actor_id = getattr(request.state, "audit_actor", None) or audit_actor_ctx.get()
            logger.error(
                f"Audit event: {method} {safe_path} -> 500 (SERVER_ERROR)",
                extra={
                    "audit_request_id": req_id,
                    "actor_id": actor_id,
                    "http_method": method,
                    "http_path": safe_path,
                    "http_status": 500,
                    "audit_outcome": "SERVER_ERROR",
                    "duration_ms": duration_ms,
                    "error_type": type(exc).__name__,
                    "audit_timestamp": datetime.now(UTC).isoformat(),
                },
            )
            raise
        else:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            actor_id = getattr(request.state, "audit_actor", None) or audit_actor_ctx.get()
            status_code = response.status_code
            outcome = _classify_audit_outcome(status_code)

            # Skip noisy successful liveness probes; audit all API calls and non-200 events
            if not (raw_path == "/health" and method in ("GET", "HEAD") and status_code == 200):
                log_fn = (
                    logger.warning
                    if outcome in ("AUTH_DENIED", "RATE_LIMITED", "SERVER_ERROR")
                    else logger.info
                )
                log_fn(
                    f"Audit event: {method} {safe_path} -> {status_code} ({outcome})",
                    extra={
                        "audit_request_id": req_id,
                        "actor_id": actor_id,
                        "http_method": method,
                        "http_path": safe_path,
                        "http_status": status_code,
                        "audit_outcome": outcome,
                        "duration_ms": duration_ms,
                        "audit_timestamp": datetime.now(UTC).isoformat(),
                    },
                )
            return response
        finally:
            audit_actor_ctx.reset(actor_token)
