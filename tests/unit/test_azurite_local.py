"""
Unit and Security Hygiene Tests for Azurite Local Emulator Setup (P4-2).

Tests: GAP-002, ADR-005, ADR-007, N1, N6, N8, CWE-489, CWE-522, CWE-668, CWE-798, CWE-918
"""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import ResourceExistsError

from src.core.config import Settings
from src.storage.azurite import (
    DEFAULT_AZURITE_BLOB_URL,
    check_azurite_reachable,
    create_azurite_worm_client,
    ensure_worm_container,
    is_azurite_enabled,
    validate_azurite_url,
)
from src.storage.blob_client import (
    AzureBlobWORMClient,
    BlobAlreadyExistsError,
    BlobStorageConfigurationError,
    get_blob_worm_client,
    reset_blob_client_cache,
)


def test_azurite_disabled_by_default_and_hard_blocked_in_staging_or_prod() -> None:
    """Verify Azurite defaults to False and is hard-blocked outside local dev/test (CWE-489)."""
    default_settings = Settings()
    assert default_settings.USE_AZURITE_EMULATOR is False
    assert is_azurite_enabled(default_settings) is False

    # Blocked in staging/production even when USE_AZURITE_EMULATOR=True
    for blocked_env in ("staging", "prod", "production", "uat"):
        blocked = Settings(APP_ENV=blocked_env, USE_AZURITE_EMULATOR=True, USE_LOCAL_SQLITE=True)
        assert is_azurite_enabled(blocked) is False
        with pytest.raises(BlobStorageConfigurationError):
            create_azurite_worm_client(settings=blocked)

    # Blocked when connected to real Azure SQL (USE_LOCAL_SQLITE=False) even in dev
    azure_sql_dev = Settings(APP_ENV="dev", USE_AZURITE_EMULATOR=True, USE_LOCAL_SQLITE=False)
    assert is_azurite_enabled(azure_sql_dev) is False
    with pytest.raises(BlobStorageConfigurationError):
        create_azurite_worm_client(settings=azure_sql_dev)

    # Allowed when explicitly enabled in dev/local/test with local SQLite
    for allowed_env in ("dev", "local", "test"):
        allowed = Settings(APP_ENV=allowed_env, USE_AZURITE_EMULATOR=True, USE_LOCAL_SQLITE=True)
        assert is_azurite_enabled(allowed) is True


def test_validate_azurite_url_pins_loopback_and_blocks_ssrf() -> None:
    """Verify Azurite URL strictly pins loopback/compose hosts on port 10000 (CWE-918/522)."""
    assert (
        validate_azurite_url("http://127.0.0.1:10000/devstoreaccount1") == DEFAULT_AZURITE_BLOB_URL
    )
    assert (
        validate_azurite_url("http://localhost:10000/devstoreaccount1/")
        == "http://localhost:10000/devstoreaccount1/"
    )
    assert (
        validate_azurite_url("http://azurite:10000/devstoreaccount1")
        == "http://azurite:10000/devstoreaccount1/"
    )

    for bad_url in (
        "",
        "http://169.254.169.254:10000/devstoreaccount1/",  # Azure IMDS SSRF
        "http://0.0.0.0:10000/devstoreaccount1/",
        "http://evil.attacker.example:10000/devstoreaccount1/",
        "http://127.0.0.1:8000/devstoreaccount1/",  # Wrong port
        "https://127.0.0.1:10000/devstoreaccount1/?sig=leaked",
        "http://user:pass@127.0.0.1:10000/devstoreaccount1/",
    ):
        with pytest.raises(ValueError, match="Invalid Azurite"):
            validate_azurite_url(bad_url)
        with pytest.raises(ValueError, match="Invalid Azurite"):
            check_azurite_reachable(bad_url)


def test_ensure_worm_container_is_idempotent() -> None:
    """Verify ensure_worm_container creates container once and ignores ResourceExistsError cleanly."""
    mock_service = MagicMock()
    mock_container = MagicMock()
    mock_service.get_container_client.return_value = mock_container

    # First run creates container -> returns True
    assert ensure_worm_container(mock_service, "raw-invoices-immutable") is True
    mock_container.create_container.assert_called_once()

    # Second run hits ResourceExistsError -> idempotently returns False
    mock_container.create_container.side_effect = ResourceExistsError("Container already exists")
    assert ensure_worm_container(mock_service, "raw-invoices-immutable") is False


def test_create_azurite_worm_client_requires_credential_and_passes_smoke_flow() -> None:
    """Verify create_azurite_worm_client fails closed without credential and completes INV-SMOKE-01 flow."""
    dev_settings = Settings(
        APP_ENV="dev",
        USE_LOCAL_SQLITE=True,
        USE_MOCK_BLOB_STORAGE=False,
        USE_AZURITE_EMULATOR=True,
        AZURITE_BLOB_URL=DEFAULT_AZURITE_BLOB_URL,
        AZURE_BLOB_WORM_CONTAINER="raw-invoices-immutable",
    )

    # Missing credential/env key without injected service client must fail closed
    with pytest.raises(BlobStorageConfigurationError, match="credential"):
        create_azurite_worm_client(settings=dev_settings)

    # Smoke flow with injected mock Azurite BlobServiceClient enforcing overwrite=False
    store: dict[str, bytes] = {}
    mock_service = MagicMock()
    mock_container = MagicMock()

    def _get_blob_client(blob: str):
        bc = MagicMock()
        bc.url = f"{DEFAULT_AZURITE_BLOB_URL}raw-invoices-immutable/{blob}"

        def _upload(data: bytes, *, overwrite: bool = False, **kwargs):
            if not overwrite and blob in store:
                raise ResourceExistsError("BlobAlreadyExists")
            store[blob] = data
            return {"etag": '"azurite-etag-1"'}

        def _download(**kwargs):
            stream = MagicMock()
            stream.properties.size = len(store[blob])
            stream.readall.return_value = store[blob]
            return stream

        bc.upload_blob.side_effect = _upload
        bc.download_blob.side_effect = _download
        bc.exists.side_effect = lambda **kw: blob in store
        return bc

    mock_container.get_blob_client.side_effect = _get_blob_client
    mock_service.get_container_client.return_value = mock_container

    client = create_azurite_worm_client(
        settings=dev_settings,
        blob_service_client=mock_service,
        ensure_container=True,
    )
    assert isinstance(client, AzureBlobWORMClient)
    assert client.account_url == DEFAULT_AZURITE_BLOB_URL
    mock_container.create_container.assert_called_once()

    smoke_pdf = b"%PDF-1.4 INV-SMOKE-01 Azurite Local Smoke Test Document"
    res = client.upload_raw_invoice(
        invoice_id="inv-smoke-01",
        filename="INV-SMOKE-01.pdf",
        data=smoke_pdf,
        content_type="application/pdf",
    )
    assert res.sha256_hash == hashlib.sha256(smoke_pdf).hexdigest()
    assert client.download_blob(res.blob_name) == smoke_pdf

    # WORM write-once check
    with pytest.raises(BlobAlreadyExistsError):
        client.upload_raw_invoice("inv-smoke-01", "INV-SMOKE-01.pdf", b"%PDF-1.4 overwrite")

    # Extraction JSON round-trip
    json_res = client.upload_extraction_json("inv-smoke-01", {"invoice_number": "INV-SMOKE-01"})
    assert json.loads(client.download_blob(json_res.blob_name).decode("utf-8")) == {
        "invoice_number": "INV-SMOKE-01"
    }


def test_get_blob_worm_client_routes_to_azurite_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify get_blob_worm_client selects Azurite when mock=False and azurite=True in dev."""
    reset_blob_client_cache()
    monkeypatch.setenv("KV_STUB_AZURITE_ACCOUNT_KEY", "ephemeral-local-dev-key-value")

    azurite_settings = Settings(
        APP_ENV="dev",
        USE_LOCAL_SQLITE=True,
        USE_MOCK_BLOB_STORAGE=False,
        USE_AZURITE_EMULATOR=True,
        AZURITE_BLOB_URL=DEFAULT_AZURITE_BLOB_URL,
    )

    # Patch ensure_worm_container so unit test never touches a live TCP socket
    from src.storage import azurite as azurite_mod

    monkeypatch.setattr(azurite_mod, "ensure_worm_container", lambda _svc, _name: True)
    client = get_blob_worm_client(azurite_settings)
    assert isinstance(client, AzureBlobWORMClient)
    assert client.account_url == DEFAULT_AZURITE_BLOB_URL
    reset_blob_client_cache()


def test_azurite_compose_and_makefile_hygiene() -> None:
    """Verify docker-compose.azurite.yml binds loopback-only 127.0.0.1:10000 and Makefile has targets (CWE-668)."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    compose_path = repo_root / "docker-compose.azurite.yml"
    assert compose_path.is_file(), "docker-compose.azurite.yml is missing"

    compose_text = compose_path.read_text(encoding="utf-8")
    assert "mcr.microsoft.com/azure-storage/azurite:" in compose_text
    assert ":latest" not in compose_text, "Docker image tag must be pinned, not :latest"
    assert "127.0.0.1:10000:10000" in compose_text, (
        "Azurite must bind strictly to loopback 127.0.0.1:10000 (CWE-668)"
    )
    assert "azurite_data" in compose_text
    assert "no-new-privileges:true" in compose_text
    assert "cap_drop:" in compose_text
    assert "AccountKey=" not in compose_text

    makefile_text = (repo_root / "Makefile").read_text(encoding="utf-8")
    assert "run-azurite:" in makefile_text
    assert "stop-azurite:" in makefile_text

    # Zero static Azurite emulator key embedded in src/storage/azurite.py (ADR-007 / N8)
    azurite_src = (repo_root / "src" / "storage" / "azurite.py").read_text(encoding="utf-8")
    assert "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq" not in azurite_src
    assert "AccountKey=" not in azurite_src
