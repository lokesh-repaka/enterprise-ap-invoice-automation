"""
Unit tests validating the offline pytest harness and mock fixtures.

Tests: N1, N8, FR-01, FR-03
"""
import json
import os


def test_offline_environment_variables():
    """Verify strict offline environment variables are active per CLAUDE.md §13."""
    assert os.environ.get("USE_LOCAL_SQLITE") == "true"
    assert os.environ.get("USE_FAKE_REDIS") == "true"
    assert os.environ.get("USE_MOCK_AOAI") == "true"
    assert os.environ.get("SAMPLE_DATA_DIR") == "./sample_data"


def test_fake_redis_fixture(fake_redis):
    """Verify fake_redis provides an isolated in-memory Redis client."""
    # Key-value operations
    fake_redis.set("invoice:test:1001", "processing")
    assert fake_redis.get("invoice:test:1001") == "processing"

    # List/Queue operations for background tasks
    fake_redis.rpush("queue:invoices", "INV-1001")
    fake_redis.rpush("queue:invoices", "INV-1002")
    assert fake_redis.llen("queue:invoices") == 2
    assert fake_redis.lpop("queue:invoices") == "INV-1001"


def test_mock_aoai_client_fixture(mock_aoai_client):
    """Verify mock Azure OpenAI client returns valid structured JSON matching schema."""
    response = mock_aoai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Extract invoice"}],
    )

    content = response.choices[0].message.content
    assert content is not None
    data = json.loads(content)

    assert "header" in data
    assert "line_items" in data
    assert "invoice_number" in data["header"]
    assert "total_amount" in data["header"]
    assert len(data["line_items"]) > 0


def test_mock_blob_client_fixture(mock_blob_client):
    """Verify mock Azure Blob client operates completely in-memory."""
    container = mock_blob_client.get_container_client("raw-invoices-immutable")
    blob = container.get_blob_client("INV-2026-1001.pdf")

    result = blob.upload_blob(b"sample bytes", overwrite=True)
    assert "etag" in result
    assert "mockblob" in blob.url


def test_client_fixture_integration(client):
    """Verify client fixture communicates with FastAPI endpoints cleanly."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
