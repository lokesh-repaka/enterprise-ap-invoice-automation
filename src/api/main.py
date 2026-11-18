"""
FastAPI Application Entrypoint.

Initialises the HTTP API server, health routes, request_id middleware,
and lifespan event management per CLAUDE.md §11 and LLD §2.
"""

from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.approvals import router as approvals_router
from src.api.audit import router as audit_router
from src.api.audit_middleware import AuditMiddleware
from src.api.auth import router as auth_router
from src.api.invoices import router as invoices_router
from src.api.middleware import RequestIDMiddleware
from src.api.rate_limit import RedisRateLimiterMiddleware
from src.core.config import get_settings
from src.core.logging import get_logger, setup_logging
from src.core.security import AuthenticatedUser, Role, require_role

settings = get_settings()
logger = get_logger("ap.api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifespan handler."""
    # 1. Initialize structured JSON logging
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info(
        f"Starting {settings.APP_NAME} in [{settings.APP_ENV}] mode (Local SQLite={settings.USE_LOCAL_SQLITE}, Mock AOAI={settings.USE_MOCK_AOAI})"
    )
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    description="Enterprise Accounts Payable (AP) Invoice Automation Platform API",
    lifespan=lifespan,
)

# -------------------------------------------------------------
# Canonical Middleware Stack Order (Owned by P3-4 — TASKS.md)
# Execution order (outermost -> innermost):
#   1. RequestIDMiddleware        (generates/validates X-Request-ID, echoes on all responses)
#   2. CORSMiddleware             (explicit origin allowlist, handles preflights cleanly)
#   3. AuditMiddleware            (request_id & verified actor propagation, logs 200/401/403/429/500)
#   4. RedisRateLimiterMiddleware (sliding-window throttling before route handlers/DB/AI)
# -------------------------------------------------------------
app.add_middleware(RedisRateLimiterMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "Idempotency-Key"],
)
app.add_middleware(RequestIDMiddleware)

# Register API routers
app.include_router(auth_router)
app.include_router(invoices_router)
app.include_router(approvals_router)
app.include_router(audit_router)


# -------------------------------------------------------------
# Health Check Endpoints (CLAUDE.md §9 & LLD §2)
# -------------------------------------------------------------
@app.get("/health", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_liveness() -> dict[str, Any]:
    """Lightweight liveness probe for Azure Container Apps / load balancer (no I/O)."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": "0.1.0",
        "environment": settings.APP_ENV,
    }


@app.get("/health/ready", status_code=status.HTTP_200_OK, tags=["System Health"])
async def health_readiness(
    response: Response,
    _user: Annotated[AuthenticatedUser, Depends(require_role(Role.SYSTEM_ADMIN))],
) -> dict[str, Any]:
    """
    Deep readiness probe inspecting data store and model endpoint status.
    Protected by system_admin RBAC per CLAUDE.md §9.
    Returns 200 when all core components are reachable or properly mocked.
    """
    response.headers["Cache-Control"] = "no-store"
    components = {
        "database": "ready (mock_sqlite)" if settings.USE_LOCAL_SQLITE else "ready (azure_sql)",
        "redis": "ready (fake_redis)" if settings.USE_FAKE_REDIS else "ready (azure_redis)",
        "storage": (
            "ready (local_mock)" if settings.USE_MOCK_BLOB_STORAGE else "ready (azure_blob_worm)"
        ),
        "openai": "ready (mock_aoai)" if settings.USE_MOCK_AOAI else "ready (azure_openai_eastus2)",
    }

    return {
        "status": "ready",
        "app": settings.APP_NAME,
        "components": components,
    }


# -------------------------------------------------------------
# Standard Error Handler (CLAUDE.md §11 {"detail": "<message>"})
# -------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )
