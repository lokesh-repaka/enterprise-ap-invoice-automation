"""
Authentication and Local Demo Persona Token Routes (P3-2).

Exposes:
- ``GET /api/v1/auth/me`` — Returns authenticated principal claims (Entra ID or demo JWT).
- ``GET /api/v1/auth/demo-personas`` — Lists authorised demo personas (dev/local/test only).
- ``POST /api/v1/auth/demo-token`` — Mints an ephemeral RS256 demo JWT (dev/local/test only).

Demo routes are hard-gated by ``ENABLE_DEMO_AUTH=true`` AND ``APP_ENV in {"dev", "local", "test"}``.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from src.core.config import get_settings
from src.core.demo_auth import (
    DEMO_PERSONAS,
    DEMO_TOKEN_DEFAULT_TTL_SECONDS,
    DEMO_TOKEN_MAX_TTL_SECONDS,
    DEMO_TOKEN_MIN_TTL_SECONDS,
    DemoAuthDisabledError,
    is_demo_auth_enabled,
    issue_demo_token,
    resolve_demo_persona,
)
from src.core.security import AuthenticatedUser, get_current_user

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class DemoTokenRequest(BaseModel):
    """Strict request schema for demo token issuance (forbids arbitrary role overrides: CWE-915)."""

    model_config = ConfigDict(extra="forbid")

    persona: str = Field(..., min_length=1, max_length=128)
    ttl_seconds: StrictInt = Field(
        default=DEMO_TOKEN_DEFAULT_TTL_SECONDS,
        ge=DEMO_TOKEN_MIN_TTL_SECONDS,
        le=DEMO_TOKEN_MAX_TTL_SECONDS,
    )


class DemoTokenResponse(BaseModel):
    """OAuth 2.0 Bearer token payload returned for an authorised demo persona."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    persona: str
    email: str
    name: str
    role: str


class DemoPersonaPublic(BaseModel):
    """Public metadata for an available demo persona (never includes credentials/tokens)."""

    username: str
    email: str
    name: str
    role: str
    entra_group: str


class DemoPersonasResponse(BaseModel):
    """Response envelope listing authorised demo personas."""

    personas: list[DemoPersonaPublic]


class AuthenticatedUserResponse(BaseModel):
    """Authenticated caller identity returned by ``GET /api/v1/auth/me``."""

    user_id: str
    email: str
    name: str
    tenant_id: str
    roles: list[str]


def _require_demo_auth_enabled() -> None:
    """Fail-closed dependency guarding demo auth routes outside enabled dev/local/test."""
    if not is_demo_auth_enabled(get_settings()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo authentication is disabled",
        )


@router.get(
    "/demo-personas",
    response_model=DemoPersonasResponse,
    status_code=status.HTTP_200_OK,
)
async def list_demo_personas(
    _: Annotated[None, Depends(_require_demo_auth_enabled)],
) -> DemoPersonasResponse:
    """List the three authorised demo personas (disabled in staging/production)."""
    return DemoPersonasResponse(
        personas=[
            DemoPersonaPublic(
                username=p.username,
                email=p.email,
                name=p.name,
                role=p.role.value,
                entra_group=p.entra_group,
            )
            for p in DEMO_PERSONAS.values()
        ]
    )


@router.post(
    "/demo-token",
    response_model=DemoTokenResponse,
    status_code=status.HTTP_200_OK,
)
async def create_demo_token(
    payload: DemoTokenRequest,
    response: Response,
    _: Annotated[None, Depends(_require_demo_auth_enabled)],
) -> DemoTokenResponse:
    """
    Mint a short-lived RS256 demo token for sarah.clerk, michael.manager, or dave.admin.

    Sets RFC 6749 §5.1 ``Cache-Control: no-store`` and ``Pragma: no-cache`` headers.
    """
    settings = get_settings()
    try:
        persona = resolve_demo_persona(payload.persona)
        token = issue_demo_token(
            persona.username,
            ttl_seconds=payload.ttl_seconds,
            settings=settings,
        )
    except DemoAuthDisabledError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo authentication is disabled",
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown demo persona",
        ) from None

    # RFC 6749 §5.1: Prevent intermediary/browser caching of Bearer tokens (CWE-525)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return DemoTokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=payload.ttl_seconds,
        persona=persona.username,
        email=persona.email,
        name=persona.name,
        role=persona.role.value,
    )


@router.get(
    "/me",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_200_OK,
)
async def get_authenticated_me(
    response: Response,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> AuthenticatedUserResponse:
    """Return the verified identity and RBAC roles of the current Bearer token holder."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return AuthenticatedUserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.name,
        tenant_id=user.tenant_id,
        roles=sorted(r.value for r in user.roles),
    )
