"""
FastAPI Request Tracing and Diagnostic Middleware.

Injects unique request_id into ContextVar, logs structured JSON request lifecycle,
and ensures X-Request-ID response header propagation (CLAUDE.md §11).
"""

import re
import time
import uuid
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.core.logging import get_logger, request_id_ctx

logger = get_logger("ap.api.middleware")

# Strict allowlist for client-supplied X-Request-ID to block CRLF/log injection (CWE-113/117)
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _resolve_request_id(header_value: str | None) -> str:
    """Preserve valid client X-Request-ID or mint a fresh UUID4 if missing/tainted."""
    if isinstance(header_value, str) and _SAFE_REQUEST_ID_RE.match(header_value):
        return header_value
    return f"req-{uuid.uuid4()}"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Propagates validated X-Request-ID header or generates a UUID4 for end-to-end tracing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = _resolve_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = req_id
        token = request_id_ctx.set(req_id)

        start_time = time.perf_counter()
        method = request.method
        path = request.url.path

        try:
            response: Response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Log request outcome (exclude health checks from spamming logs)
            if not path.startswith("/health"):
                logger.info(
                    f"{method} {path} completed with status {response.status_code} in {duration_ms}ms",
                    extra={
                        "http_method": method,
                        "http_path": path,
                        "http_status": response.status_code,
                        "duration_ms": duration_ms,
                    },
                )

            # Propagate back in response headers
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_ctx.reset(token)
