"""
Unit tests for FastAPI Application Skeleton, Health Routes, and Middleware.

Tests: N3, N5, FR-01
"""

from fastapi.testclient import TestClient

from src.api.main import app
from src.core.security import AuthenticatedUser, Role, get_current_user

client = TestClient(app)


def test_health_liveness_probe():
    """Verify GET /health returns 200 and healthy status without external I/O."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "app" in data


def test_health_readiness_probe():
    """Verify GET /health/ready checks service components and reports readiness for system_admin."""
    admin_user = AuthenticatedUser(
        user_id="oid-dave-admin",
        subject="sub-dave-admin",
        email="dave.admin@company.com",
        name="Dave Admin",
        tenant_id="11111111-2222-3333-4444-555555555555",
        roles=frozenset({Role.SYSTEM_ADMIN}),
    )
    app.dependency_overrides[get_current_user] = lambda: admin_user
    try:
        response = client.get("/health/ready")
    finally:
        app.dependency_overrides.pop(get_current_user, None)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "components" in data
    assert "database" in data["components"]
    assert "redis" in data["components"]
    assert "storage" in data["components"]
    assert "openai" in data["components"]


def test_request_id_middleware_generated():
    """Verify X-Request-ID header is generated and returned if not provided in request."""
    response = client.get("/health")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    request_id = response.headers["x-request-id"]
    assert len(request_id) > 10


def test_request_id_middleware_preserved():
    """Verify custom X-Request-ID is preserved and propagated back in response."""
    custom_id = "req-custom-invoice-8888"
    response = client.get("/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("x-request-id") == custom_id


def test_error_response_standard_format():
    """Verify 404 responses follow the {'detail': '<message>'} standard schema."""
    response = client.get("/non-existent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
