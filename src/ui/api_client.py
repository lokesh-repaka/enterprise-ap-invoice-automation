"""
Typed HTTP API Client for the Streamlit UI (P11-1).

Single authorized transport bridge between ``src/ui/`` and the FastAPI backend
(``CLAUDE.md §4.2, §9, §12``). Wraps ``httpx.Client`` with strict Pydantic v2 response
validation across every backend endpoint:
- Health: ``GET /health``, ``GET /health/ready``
- Auth: ``GET /api/v1/auth/demo-personas``, ``POST /api/v1/auth/demo-token``, ``GET /api/v1/auth/me``
- Invoices: ``POST /api/v1/invoices/upload``, ``GET /api/v1/invoices/{id}``,
  ``GET /api/v1/invoices/exceptions``, ``POST /api/v1/invoices/{id}/revalidate``
- Approvals: ``POST /api/v1/invoices/{id}/approve``
- Audit: ``GET /api/v1/invoices/{id}/audit``

Security & Layering Invariants:
- Zero imports from ``src/database``, ``src/storage``, ``src/extraction``, ``src/validation``,
  ``src/services``, ``sqlalchemy``, ``redis``, ``openai``, or ``azure.*`` (CLAUDE.md §4.2).
- Validates ``base_url`` strictly (HTTP/HTTPS only, zero embedded credentials, HTTPS required
  outside loopback/internal Docker service hosts) and disables automatic redirect following
  (``follow_redirects=False``) to prevent Bearer token exfiltration (SEC-187, CWE-601/918).
- Validates ``invoice_id`` path segments and rejects CRLF in headers before sending (SEC-188,
  CWE-22/113).
- Redacts Bearer tokens from ``__repr__`` and logs, and caps response bodies at 10 MB (SEC-189,
  CWE-400/532).
"""

import os
import re
from collections.abc import Sequence
from datetime import date
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import (
    ExceptionQueueResponse,
    InvoiceApprovalRequest,
    InvoiceApprovalResponse,
    InvoiceAuditTrailResponse,
    InvoiceDetailResponse,
    InvoiceRevalidateRequest,
    InvoiceRevalidateResponse,
    InvoiceUploadResponse,
)
from src.core.logging import get_logger

logger = get_logger("ap.ui.api_client")

DEFAULT_API_BASE_URL: str = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS: float = 30.0
MIN_TIMEOUT_SECONDS: float = 0.1
MAX_TIMEOUT_SECONDS: float = 120.0
DEFAULT_CONNECT_TIMEOUT_SECONDS: float = 5.0
MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024
MAX_CLIENT_UPLOAD_BYTES: int = 25 * 1024 * 1024

_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
_LOCAL_PLAIN_HTTP_HOSTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "::1", "api", "fastapi", "ap-api"}
)


# ---------------------------------------------------------------------------
# Typed Auth Response Schemas (Mirroring src/api/auth.py without importing router)
# ---------------------------------------------------------------------------


class DemoPersonaPublic(BaseModel):
    """Public metadata for an authorised demo persona."""

    model_config = ConfigDict(frozen=True)

    username: str
    email: str
    name: str
    role: str
    entra_group: str


class DemoPersonasResponse(BaseModel):
    """Response envelope for ``GET /api/v1/auth/demo-personas``."""

    model_config = ConfigDict(frozen=True)

    personas: list[DemoPersonaPublic]


class DemoTokenResponse(BaseModel):
    """OAuth 2.0 Bearer token response for ``POST /api/v1/auth/demo-token``."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    persona: str
    email: str
    name: str
    role: str


class AuthenticatedUserResponse(BaseModel):
    """Authenticated caller identity returned by ``GET /api/v1/auth/me``."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    email: str
    name: str
    tenant_id: str
    roles: list[str]


# ---------------------------------------------------------------------------
# Typed API Client Exceptions
# ---------------------------------------------------------------------------


class APIClientError(Exception):
    """Base exception for all FastAPI backend HTTP or transport errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: Any = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.request_id = request_id


class APIAuthenticationError(APIClientError):
    """Raised on HTTP 401 Unauthorized."""


class APIAuthorizationError(APIClientError):
    """Raised on HTTP 403 Forbidden."""


class APINotFoundError(APIClientError):
    """Raised on HTTP 404 Not Found."""


class APIConflictError(APIClientError):
    """Raised on HTTP 409 Conflict."""


class APIValidationError(APIClientError):
    """Raised on HTTP 400/413/415/422 client validation failure."""


class APIRateLimitError(APIClientError):
    """Raised on HTTP 429 Too Many Requests."""


class APIServiceUnavailableError(APIClientError):
    """Raised on HTTP 5xx or network transport outage."""


# ---------------------------------------------------------------------------
# Validation Helpers (SEC-187, SEC-188)
# ---------------------------------------------------------------------------


def validate_api_base_url(raw_url: str) -> str:
    """Validate backend base URL against SSRF, credential smuggling, and cleartext remote HTTP (SEC-187)."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("base_url must be a non-empty URL")
    if _CONTROL_CHAR_RE.search(raw_url):
        raise ValueError("base_url contains disallowed control characters")
    cleaned = raw_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url must use http:// or https:// scheme")
    if not parsed.hostname:
        raise ValueError("base_url must include a valid hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain query parameters or fragments")
    host = parsed.hostname.lower()
    if parsed.scheme == "http" and host not in _LOCAL_PLAIN_HTTP_HOSTS:
        raise ValueError(
            f"Plain HTTP base_url is permitted only for local/internal hosts (got '{host}'); use https://"
        )
    return cleaned


def _validate_invoice_id(invoice_id: str) -> str:
    if not isinstance(invoice_id, str) or not _INVOICE_ID_RE.match(invoice_id):
        raise ValueError("Invalid invoice_id format")
    return invoice_id


def _validate_header_value(value: str, *, field_name: str, max_length: int = 8192) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if _CONTROL_CHAR_RE.search(value):
        raise ValueError(f"{field_name} contains disallowed control characters")
    cleaned = value.strip()
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    return cleaned


def _extract_error_detail(response: httpx.Response) -> tuple[str, Any]:
    """Parse structured FastAPI {'detail': ...} error message safely without raising."""
    try:
        data = response.json()
    except ValueError:
        text = response.text.strip()[:300]
        return text or f"HTTP {response.status_code}", text
    if isinstance(data, dict) and "detail" in data:
        detail = data["detail"]
        if isinstance(detail, str):
            return detail, detail
        if isinstance(detail, list) and detail:
            first = detail[0]
            if isinstance(first, dict) and "msg" in first:
                return str(first["msg"]), detail
        return str(detail), detail
    return f"HTTP {response.status_code}", data


# ---------------------------------------------------------------------------
# Typed Synchronous HTTP API Client (for Streamlit Pages)
# ---------------------------------------------------------------------------


class APInvoiceAPIClient:
    """
    Typed synchronous ``httpx`` client covering every FastAPI backend route (P11-1).

    Safe for Streamlit execution: bounded timeouts, ``follow_redirects=False``,
    strict URL/path validation, redacted ``__repr__``, and typed Pydantic responses.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        access_token: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_url = base_url or os.getenv("API_BASE_URL", DEFAULT_API_BASE_URL)
        self._base_url = validate_api_base_url(resolved_url)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not (MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS)
        ):
            raise ValueError(
                f"timeout_seconds must be within [{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]"
            )
        self._access_token: str | None = None
        if access_token is not None:
            self.set_access_token(access_token)

        timeout = httpx.Timeout(
            timeout=timeout_seconds,
            connect=min(DEFAULT_CONNECT_TIMEOUT_SECONDS, timeout_seconds),
        )
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
        )

    @property
    def base_url(self) -> str:
        """Validated backend API base URL."""
        return self._base_url

    @property
    def is_authenticated(self) -> bool:
        """Return True if a Bearer token is currently attached."""
        return self._access_token is not None

    def set_access_token(self, token: str | None) -> None:
        """Attach or clear the active Bearer JWT (validates against CRLF injection: SEC-188)."""
        if token is None:
            self._access_token = None
            return
        self._access_token = _validate_header_value(
            token, field_name="access_token", max_length=16_384
        )

    def close(self) -> None:
        """Close the underlying ``httpx.Client`` connection pool."""
        self._client.close()

    def __enter__(self) -> "APInvoiceAPIClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        # SEC-189 (CWE-532): Never include raw Bearer token in string representation
        return (
            f"<APInvoiceAPIClient(base_url={self._base_url!r}, "
            f"authenticated={self.is_authenticated})>"
        )

    def _build_headers(
        self,
        *,
        extra_headers: dict[str, str] | None = None,
        request_id: str | None = None,
    ) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        if request_id is not None:
            headers["X-Request-ID"] = _validate_header_value(
                request_id, field_name="request_id", max_length=128
            )
        if extra_headers:
            for k, v in extra_headers.items():
                headers[k] = _validate_header_value(v, field_name=k, max_length=256)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: list[tuple[str, str]] | dict[str, Any] | None = None,
        json_body: Any = None,
        files: Any = None,
        data: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        request_id: str | None = None,
    ) -> httpx.Response:
        headers = self._build_headers(extra_headers=extra_headers, request_id=request_id)
        try:
            response = self._client.request(
                method=method,
                url=path,
                params=params,
                json=json_body,
                files=files,
                data=data,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.error(
                "Backend API transport failure",
                extra={"method": method, "path": path, "error_type": type(exc).__name__},
            )
            raise APIServiceUnavailableError(
                "Backend API service is temporarily unreachable",
                status_code=503,
            ) from None

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise APIClientError(
                f"Backend response exceeded maximum permitted size ({MAX_RESPONSE_BYTES} bytes)",
                status_code=response.status_code,
                request_id=response.headers.get("X-Request-ID"),
            )

        if 200 <= response.status_code < 300:
            return response

        req_id = response.headers.get("X-Request-ID")
        msg, raw_detail = _extract_error_detail(response)
        status_code = response.status_code

        if status_code == 401:
            raise APIAuthenticationError(msg, status_code=401, detail=raw_detail, request_id=req_id)
        if status_code == 403:
            raise APIAuthorizationError(msg, status_code=403, detail=raw_detail, request_id=req_id)
        if status_code == 404:
            raise APINotFoundError(msg, status_code=404, detail=raw_detail, request_id=req_id)
        if status_code == 409:
            raise APIConflictError(msg, status_code=409, detail=raw_detail, request_id=req_id)
        if status_code in (400, 413, 415, 422):
            raise APIValidationError(
                msg, status_code=status_code, detail=raw_detail, request_id=req_id
            )
        if status_code == 429:
            raise APIRateLimitError(msg, status_code=429, detail=raw_detail, request_id=req_id)
        if status_code >= 500:
            raise APIServiceUnavailableError(
                msg, status_code=status_code, detail=raw_detail, request_id=req_id
            )
        raise APIClientError(msg, status_code=status_code, detail=raw_detail, request_id=req_id)

    # ------------------------------------------------------------------
    # System Health Endpoints
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Call ``GET /health`` liveness probe."""
        resp = self._request("GET", "/health")
        return dict(resp.json())

    def health_ready(self) -> dict[str, Any]:
        """Call ``GET /health/ready`` deep readiness probe (requires ``system_admin``)."""
        resp = self._request("GET", "/health/ready")
        return dict(resp.json())

    # ------------------------------------------------------------------
    # Authentication & Demo Persona Endpoints
    # ------------------------------------------------------------------

    def list_demo_personas(self) -> DemoPersonasResponse:
        """Call ``GET /api/v1/auth/demo-personas``."""
        resp = self._request("GET", "/api/v1/auth/demo-personas")
        return DemoPersonasResponse.model_validate(resp.json())

    def issue_demo_token(
        self,
        persona: str,
        *,
        ttl_seconds: int = 3600,
        set_active_token: bool = True,
    ) -> DemoTokenResponse:
        """Call ``POST /api/v1/auth/demo-token`` and optionally activate the returned Bearer JWT."""
        resp = self._request(
            "POST",
            "/api/v1/auth/demo-token",
            json_body={"persona": persona, "ttl_seconds": ttl_seconds},
        )
        token_resp = DemoTokenResponse.model_validate(resp.json())
        if set_active_token:
            self.set_access_token(token_resp.access_token)
        return token_resp

    def get_me(self) -> AuthenticatedUserResponse:
        """Call ``GET /api/v1/auth/me``."""
        resp = self._request("GET", "/api/v1/auth/me")
        return AuthenticatedUserResponse.model_validate(resp.json())

    # ------------------------------------------------------------------
    # Invoice Intake, Read & Exception Queue Endpoints
    # ------------------------------------------------------------------

    def upload_invoice(
        self,
        filename: str,
        content: bytes,
        *,
        content_type: str | None = None,
        vendor_id: str | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> InvoiceUploadResponse:
        """Call ``POST /api/v1/invoices/upload`` with multipart file payload."""
        clean_filename = _validate_header_value(filename, field_name="filename", max_length=255)
        if "/" in clean_filename or "\\" in clean_filename or ".." in clean_filename:
            raise ValueError("filename must not contain path separators or traversal segments")
        if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
            raise ValueError("Uploaded file content must be non-empty bytes")
        if len(content) > MAX_CLIENT_UPLOAD_BYTES:
            raise ValueError(
                f"Uploaded file exceeds maximum client limit of {MAX_CLIENT_UPLOAD_BYTES} bytes"
            )
        extra_headers: dict[str, str] = {}
        if idempotency_key is not None:
            extra_headers["Idempotency-Key"] = _validate_header_value(
                idempotency_key, field_name="idempotency_key", max_length=128
            )
        form_data: dict[str, Any] | None = {"vendor_id": vendor_id} if vendor_id else None
        file_tuple = (
            (clean_filename, content, content_type) if content_type else (clean_filename, content)
        )
        resp = self._request(
            "POST",
            "/api/v1/invoices/upload",
            files={"file": file_tuple},
            data=form_data,
            extra_headers=extra_headers or None,
            request_id=request_id,
        )
        return InvoiceUploadResponse.model_validate(resp.json())

    def get_invoice(
        self,
        invoice_id: str,
        *,
        request_id: str | None = None,
    ) -> InvoiceDetailResponse:
        """Call ``GET /api/v1/invoices/{invoice_id}``."""
        clean_id = _validate_invoice_id(invoice_id)
        resp = self._request("GET", f"/api/v1/invoices/{clean_id}", request_id=request_id)
        return InvoiceDetailResponse.model_validate(resp.json())

    def list_exceptions(
        self,
        *,
        statuses: Sequence[str] | None = None,
        vendor_id: str | None = None,
        vendor_name: str | None = None,
        invoice_number: str | None = None,
        currency: str | None = None,
        min_amount: Decimal | None = None,
        max_amount: Decimal | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
        max_confidence: Decimal | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        limit: int = 50,
        offset: int = 0,
        request_id: str | None = None,
    ) -> ExceptionQueueResponse:
        """Call ``GET /api/v1/invoices/exceptions`` with typed filters and pagination."""
        params: list[tuple[str, str]] = [
            ("sort_by", sort_by),
            ("sort_order", sort_order),
            ("limit", str(limit)),
            ("offset", str(offset)),
        ]
        if statuses:
            for st in statuses:
                params.append(("status", st))
        if vendor_id:
            params.append(("vendor_id", vendor_id))
        if vendor_name:
            params.append(("vendor_name", vendor_name))
        if invoice_number:
            params.append(("invoice_number", invoice_number))
        if currency:
            params.append(("currency", currency))
        if min_amount is not None:
            params.append(("min_amount", str(min_amount)))
        if max_amount is not None:
            params.append(("max_amount", str(max_amount)))
        if date_from is not None:
            params.append(("date_from", date_from.isoformat()))
        if date_to is not None:
            params.append(("date_to", date_to.isoformat()))
        if max_confidence is not None:
            params.append(("max_confidence", str(max_confidence)))

        resp = self._request(
            "GET", "/api/v1/invoices/exceptions", params=params, request_id=request_id
        )
        return ExceptionQueueResponse.model_validate(resp.json())

    # ------------------------------------------------------------------
    # Re-Validation, Approval & Immutable Audit Trail Endpoints (Phase 9)
    # ------------------------------------------------------------------

    def revalidate_invoice(
        self,
        invoice_id: str,
        payload: InvoiceRevalidateRequest,
        *,
        request_id: str | None = None,
    ) -> InvoiceRevalidateResponse:
        """Call ``POST /api/v1/invoices/{invoice_id}/revalidate``."""
        clean_id = _validate_invoice_id(invoice_id)
        resp = self._request(
            "POST",
            f"/api/v1/invoices/{clean_id}/revalidate",
            json_body=payload.model_dump(mode="json", exclude_none=True),
            request_id=request_id,
        )
        return InvoiceRevalidateResponse.model_validate(resp.json())

    def approve_invoice(
        self,
        invoice_id: str,
        payload: InvoiceApprovalRequest | None = None,
        *,
        request_id: str | None = None,
    ) -> InvoiceApprovalResponse:
        """Call ``POST /api/v1/invoices/{invoice_id}/approve``."""
        clean_id = _validate_invoice_id(invoice_id)
        body = payload.model_dump(mode="json", exclude_none=True) if payload is not None else {}
        resp = self._request(
            "POST",
            f"/api/v1/invoices/{clean_id}/approve",
            json_body=body,
            request_id=request_id,
        )
        return InvoiceApprovalResponse.model_validate(resp.json())

    def get_invoice_audit(
        self,
        invoice_id: str,
        *,
        action_types: Sequence[str] | None = None,
        user_id: str | None = None,
        limit: int = 200,
        offset: int = 0,
        request_id: str | None = None,
    ) -> InvoiceAuditTrailResponse:
        """Call ``GET /api/v1/invoices/{invoice_id}/audit``."""
        clean_id = _validate_invoice_id(invoice_id)
        params: list[tuple[str, str]] = [("limit", str(limit)), ("offset", str(offset))]
        if action_types:
            for act in action_types:
                params.append(("action_type", act))
        if user_id:
            params.append(("user_id", user_id))

        resp = self._request(
            "GET",
            f"/api/v1/invoices/{clean_id}/audit",
            params=params,
            request_id=request_id,
        )
        return InvoiceAuditTrailResponse.model_validate(resp.json())


__all__ = [
    "APIAuthenticationError",
    "APIAuthorizationError",
    "APIClientError",
    "APIConflictError",
    "APInvoiceAPIClient",
    "APINotFoundError",
    "APIRateLimitError",
    "APIServiceUnavailableError",
    "APIValidationError",
    "AuthenticatedUserResponse",
    "DEFAULT_API_BASE_URL",
    "DemoPersonaPublic",
    "DemoPersonasResponse",
    "DemoTokenResponse",
    "MAX_RESPONSE_BYTES",
    "validate_api_base_url",
]
