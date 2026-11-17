"""
Root test configuration and offline fixtures for Enterprise AP Automation.

Enforces zero-network offline isolation per CLAUDE.md §13:
  USE_LOCAL_SQLITE=true, USE_FAKE_REDIS=true, USE_MOCK_AOAI=true
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import fakeredis
import pytest
from fastapi.testclient import TestClient

# -------------------------------------------------------------
# 1. Enforce Offline Isolation Before App Imports (CLAUDE.md §13)
# -------------------------------------------------------------
os.environ["USE_LOCAL_SQLITE"] = "true"
os.environ["USE_FAKE_REDIS"] = "true"
os.environ["USE_MOCK_AOAI"] = "true"
os.environ["SAMPLE_DATA_DIR"] = "./sample_data"
os.environ["HIGH_VALUE_THRESHOLD_USD"] = "10000.00"
os.environ["PO_VARIANCE_TOLERANCE_PERCENT"] = "5.0"
os.environ["LINE_ROUNDING_TOLERANCE"] = "0.02"
os.environ["INVOICE_ROUNDING_TOLERANCE"] = "0.05"

from src.api.main import app  # noqa: E402
from src.core.config import Settings, get_settings  # noqa: E402


@pytest.fixture(autouse=True)
def clean_settings():
    """Ensure clean cached settings singleton for each test."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_settings() -> Settings:
    """Return fresh Settings instance with test defaults."""
    return get_settings()


@pytest.fixture
def fake_redis():
    """Provide isolated in-memory FakeRedis client."""
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def client() -> TestClient:
    """Provide FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def sample_ground_truth() -> dict:
    """Load a representative ground-truth JSON from sample_data/ground_truth/."""
    sample_file = Path("./sample_data/ground_truth/INV-2026-1001_ground_truth.json")
    if sample_file.is_file():
        with open(sample_file, encoding="utf-8") as f:
            return json.load(f)

    # Fallback synthetic invoice structure if sample_data is not generated
    return {
        "invoice_metadata": {
            "invoice_number": "INV-2026-1001",
            "composite_hash": "mock_composite_hash_64_characters_long_for_offline_testing_1234",
            "test_case_type": "standard",
        },
        "header": {
            "vendor_name": "Apex Global Logistics Inc",
            "vendor_tax_id": "US-12-3456789",
            "invoice_number": "INV-2026-1001",
            "invoice_date": "02/05/2026",
            "due_date": "03/07/2026",
            "po_number": "PO-9000-2001",
            "subtotal": 1250.00,
            "tax_amount": 100.00,
            "total_amount": 1350.00,
            "currency": "USD",
        },
        "line_items": [
            {
                "description": "Heavy Duty Steel Fasteners",
                "quantity": 10,
                "unit_price": 12.50,
                "line_total": 125.00,
                "tax_rate": 0.08,
            }
        ],
    }


@pytest.fixture
def mock_aoai_client(sample_ground_truth):
    """
    Mock Azure OpenAI client mimicking chat.completions.create with structured JSON.
    Guarantees no real network/API calls are made during tests (N1, N8).
    """
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_choice = MagicMock()
    mock_message = MagicMock()

    # Model returns JSON string matching ground-truth structure
    mock_message.content = json.dumps(sample_ground_truth)
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    mock_response.usage.prompt_tokens = 450
    mock_response.usage.completion_tokens = 180
    mock_response.usage.total_tokens = 630

    mock_client.chat.completions.create.return_value = mock_response
    return mock_client


@pytest.fixture
def mock_blob_client():
    """
    Mock Azure Blob Storage client mimicking container and blob upload/download.
    Operates 100% in-memory without Azure credentials.
    """
    mock_service = MagicMock()
    mock_container = MagicMock()
    mock_blob = MagicMock()

    mock_blob.upload_blob.return_value = {"etag": "mock-etag-12345"}
    mock_blob.download_blob.return_value.readall.return_value = b"%PDF-1.4 Mock Invoice Content"
    mock_blob.url = "https://mockblob.blob.core.windows.net/raw-invoices-immutable/mock-file.pdf"

    mock_container.get_blob_client.return_value = mock_blob
    mock_service.get_container_client.return_value = mock_container
    return mock_service
