"""
Unit and Security Tests for Azure Blob WORM Client with Managed Identity Auth (P4-1).

Tests: N1, N6, N8, FR-01, ADR-005, ADR-007, BR-026, BR-030, CWE-22, CWE-113, CWE-400, CWE-489, CWE-522, CWE-918
"""

import hashlib
import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

from src.core.config import Settings
from src.storage.blob_client import (
    MAX_BLOB_SIZE_BYTES,
    AzureBlobWORMClient,
    BlobAlreadyExistsError,
    BlobNotFoundError,
    BlobStorageConfigurationError,
    BlobUploadResult,
    InMemoryWORMBlobClient,
    build_extraction_json_blob_name,
    build_raw_invoice_blob_name,
    get_blob_worm_client,
    reset_blob_client_cache,
    validate_blob_account_url,
    validate_container_name,
)

VALID_ACCOUNT_URL = "https://stapautomationeastus2.blob.core.windows.net/"
VALID_CONTAINER = "raw-invoices-immutable"


def _make_mock_service_client() -> tuple[MagicMock, dict[str, bytes]]:
    """Build an in-memory mock Azure BlobServiceClient enforcing overwrite=False WORM semantics."""
    store: dict[str, bytes] = {}
    mock_service = MagicMock()
    mock_container = MagicMock()

    def _get_blob_client(blob: str):
        blob_client = MagicMock()
        blob_client.url = f"{VALID_ACCOUNT_URL}{VALID_CONTAINER}/{blob}"

        def _upload_blob(data: bytes, *, overwrite: bool = False, **kwargs):
            if not overwrite and blob in store:
                raise ResourceExistsError("The specified blob already exists.")
            store[blob] = data
            return {"etag": f'"etag-{len(data)}"'}

        def _download_blob(**kwargs):
            if blob not in store:
                raise ResourceNotFoundError("The specified blob does not exist.")
            stream = MagicMock()
            stream.properties.size = len(store[blob])
            stream.readall.return_value = store[blob]
            return stream

        def _exists(**kwargs) -> bool:
            return blob in store

        blob_client.upload_blob.side_effect = _upload_blob
        blob_client.download_blob.side_effect = _download_blob
        blob_client.exists.side_effect = _exists
        return blob_client

    mock_container.get_blob_client.side_effect = _get_blob_client
    mock_service.get_container_client.return_value = mock_container
    return mock_service, store


def test_worm_client_uploads_raw_invoice_and_extraction_json_with_sha256_integrity() -> None:
    """Verify raw invoice and JSON uploads compute exact SHA-256, enforce overwrite=False, and round-trip."""
    pdf_bytes = b"%PDF-1.4 Synthetic Enterprise Invoice Payload"
    expected_sha = hashlib.sha256(pdf_bytes).hexdigest()
    extraction_payload = {"invoice_number": "INV-2026-1001", "total_amount": "1350.00"}

    mock_service, _ = _make_mock_service_client()
    azure_client = AzureBlobWORMClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
        blob_service_client=mock_service,
    )
    mem_client = InMemoryWORMBlobClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
    )

    for client in (azure_client, mem_client):
        raw_res = client.upload_raw_invoice(
            invoice_id="inv-1001",
            filename="INV-2026-1001.pdf",
            data=pdf_bytes,
            content_type="application/pdf",
            metadata={"VendorID": "VEND-1001"},
        )
        assert isinstance(raw_res, BlobUploadResult)
        assert raw_res.blob_name == "raw-invoices/inv-1001/INV-2026-1001.pdf"
        assert raw_res.container_name == VALID_CONTAINER
        assert raw_res.size_bytes == len(pdf_bytes)
        assert raw_res.sha256_hash == expected_sha
        assert raw_res.content_type == "application/pdf"
        assert client.blob_exists(raw_res.blob_name) is True
        assert client.download_blob(raw_res.blob_name) == pdf_bytes

        json_res = client.upload_extraction_json(
            invoice_id="inv-1001",
            payload=extraction_payload,
        )
        assert json_res.blob_name == "json-extractions/inv-1001/extraction.json"
        assert json_res.content_type == "application/json"
        downloaded_json = json.loads(client.download_blob(json_res.blob_name).decode("utf-8"))
        assert downloaded_json == extraction_payload


def test_worm_immutability_blocks_overwrite_and_exposes_no_delete_api() -> None:
    """Verify WORM clients prohibit overwrites and expose zero delete/overwrite methods (ADR-005/N6)."""
    mock_service, _ = _make_mock_service_client()
    azure_client = AzureBlobWORMClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
        blob_service_client=mock_service,
    )
    mem_client = InMemoryWORMBlobClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
    )

    for client in (azure_client, mem_client):
        # Strictly Write-Once, Read-Many API surface
        for forbidden_method in ("delete", "delete_blob", "overwrite", "overwrite_blob", "update"):
            assert not hasattr(client, forbidden_method)

        original = b"%PDF-1.4 Original Immutable Invoice"
        tampered = b"%PDF-1.4 Tampered Replacement Invoice"

        res = client.upload_raw_invoice("inv-worm-1", "invoice.pdf", original)
        with pytest.raises(BlobAlreadyExistsError):
            client.upload_raw_invoice("inv-worm-1", "invoice.pdf", tampered)

        # Original bytes MUST remain intact after rejected overwrite
        assert client.download_blob(res.blob_name) == original


def test_blob_account_url_and_container_validation_blocks_ssrf_and_sas_tokens() -> None:
    """Verify storage account URL pins strictly to HTTPS *.blob.core.windows.net/ (CWE-918/522/798)."""
    assert (
        validate_blob_account_url("https://stapautomationeastus2.blob.core.windows.net")
        == VALID_ACCOUNT_URL
    )
    assert validate_container_name("raw-invoices-immutable") == "raw-invoices-immutable"

    for bad_url in (
        "",
        "http://stapautomationeastus2.blob.core.windows.net/",
        "https://stapautomationeastus2.blob.core.windows.net/?sv=2022&sig=leaked",
        "https://user:pass@stapautomationeastus2.blob.core.windows.net/",
        "https://evil.attacker.example/",
        "https://stap.blob.core.windows.net.evil.example/",
        "https://UPPERCASE.blob.core.windows.net/",
        "https://ab.blob.core.windows.net/",
        "https://stapautomationeastus2.blob.core.windows.net/extra-path",
    ):
        with pytest.raises(ValueError, match="Invalid Azure Blob account URL"):
            validate_blob_account_url(bad_url)

    for bad_container in ("", "ab", "UPPER-CASE", "bad--double", "-leading", "trailing-", "a/b"):
        with pytest.raises(ValueError, match="Invalid Azure Blob container name"):
            validate_container_name(bad_container)


def test_blob_path_sanitization_blocks_path_traversal_and_control_chars() -> None:
    """Verify invoice IDs, filenames, and blob paths reject path traversal and injection (CWE-22)."""
    assert (
        build_raw_invoice_blob_name("inv_001-a", "invoice_2026.pdf")
        == "raw-invoices/inv_001-a/invoice_2026.pdf"
    )
    assert (
        build_extraction_json_blob_name("inv_001-a") == "json-extractions/inv_001-a/extraction.json"
    )

    # Invalid invoice_id attempts
    for bad_id in ("", "../escape", "inv/nested", "inv\\win", "inv with space", "inv\x00null"):
        with pytest.raises(ValueError):
            build_raw_invoice_blob_name(bad_id, "invoice.pdf")
        with pytest.raises(ValueError):
            build_extraction_json_blob_name(bad_id)

    # Path traversal in filename must be rejected
    for bad_name in ("", "..", "../etc/passwd", "dir/file.pdf", "dir\\file.pdf", "bad\r\n.pdf"):
        with pytest.raises(ValueError):
            build_raw_invoice_blob_name("inv-100", bad_name)

    # Traversal on download_blob / blob_exists must be rejected
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)
    for bad_blob in (
        "",
        "../secret.pdf",
        "/leading/slash.pdf",
        "raw-invoices/../other.pdf",
        "a\\b",
    ):
        with pytest.raises(ValueError):
            mem.download_blob(bad_blob)
        with pytest.raises(ValueError):
            mem.blob_exists(bad_blob)


def test_blob_upload_and_download_enforce_empty_and_25mb_size_bounds() -> None:
    """Verify empty payloads and >25 MB uploads/downloads are rejected cleanly (FR-01/CWE-400)."""
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)

    with pytest.raises(ValueError, match="empty"):
        mem.upload_raw_invoice("inv-empty", "empty.pdf", b"")

    oversized = b"0" * (MAX_BLOB_SIZE_BYTES + 1)
    with pytest.raises(ValueError, match="maximum"):
        mem.upload_raw_invoice("inv-huge", "huge.pdf", oversized)

    # Simulate a 4 GB remote blob rejected via properties.size BEFORE readall() is ever called (CWE-400)
    mock_service = MagicMock()
    mock_blob = MagicMock()
    mock_stream = MagicMock()
    mock_stream.properties.size = 4 * 1024 * 1024 * 1024
    mock_blob.download_blob.return_value = mock_stream
    mock_service.get_container_client.return_value.get_blob_client.return_value = mock_blob
    azure_client = AzureBlobWORMClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
        blob_service_client=mock_service,
    )
    with pytest.raises(ValueError, match="maximum"):
        azure_client.download_blob("raw-invoices/inv-huge/huge.pdf")
    mock_stream.readall.assert_not_called()
    assert mock_blob.download_blob.call_args.kwargs["length"] == MAX_BLOB_SIZE_BYTES + 1


def test_content_type_validation_blocks_crlf_and_active_web_scripts() -> None:
    """Verify Content-Type header rejects CRLF injection and active browser scripts (CWE-113/434)."""
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)

    for bad_ct in (
        "application/pdf\r\nX-Injected: evil",
        "text/html",
        "image/svg+xml",
        "application/javascript",
        "application/pdf; charset=utf-8",
        "not-a-mime",
    ):
        with pytest.raises(ValueError, match="content_type"):
            mem.upload_raw_invoice("inv-ct-bad", "doc.pdf", b"%PDF-1.4", content_type=bad_ct)


def test_azure_blob_client_keyless_managed_identity_and_not_found_handling() -> None:
    """Verify zero static connection strings in blob_client.py and clean BlobNotFoundError (ADR-007)."""
    source = Path("src/storage/blob_client.py").read_text(encoding="utf-8")
    for forbidden in ("from_connection_string", "AccountKey=", "SharedAccessSignature", "?sig="):
        assert forbidden not in source

    mock_service, _ = _make_mock_service_client()
    client = AzureBlobWORMClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
        blob_service_client=mock_service,
    )

    assert client.blob_exists("raw-invoices/inv-missing/missing.pdf") is False
    with pytest.raises(BlobNotFoundError):
        client.download_blob("raw-invoices/inv-missing/missing.pdf")


def test_metadata_sanitization_blocks_crlf_and_invalid_azure_keys() -> None:
    """Verify Azure Blob metadata validation rejects CRLF injection and invalid keys (CWE-113/74)."""
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)

    # Valid metadata passes
    res = mem.upload_raw_invoice(
        "inv-meta-1",
        "clean.pdf",
        b"%PDF-1.4 valid",
        metadata={"VendorID": "VEND-1001", "UploadTimestamp": "2026-11-18T00:00:00Z"},
    )
    assert res.size_bytes == 14

    # Invalid metadata keys or CRLF/non-ASCII values rejected
    for bad_meta in (
        {"bad-key": "ok"},
        {"123numeric": "ok"},
        {"VendorID": "VEND-1\r\nX-Injected: evil"},
        {"VendorID": "non-ascii-\u00e9"},
    ):
        with pytest.raises(ValueError, match="metadata"):
            mem.upload_raw_invoice("inv-meta-bad", "bad.pdf", b"%PDF-1.4", metadata=bad_meta)


def test_get_blob_worm_client_blocks_mock_storage_in_production_and_staging() -> None:
    """Verify USE_MOCK_BLOB_STORAGE=True is hard-blocked outside local dev/test (CWE-489)."""
    reset_blob_client_cache()

    dev_client = get_blob_worm_client(
        Settings(APP_ENV="dev", USE_MOCK_BLOB_STORAGE=True, USE_LOCAL_SQLITE=True)
    )
    assert isinstance(dev_client, InMemoryWORMBlobClient)

    for blocked_env in ("staging", "prod", "production", "uat"):
        with pytest.raises(BlobStorageConfigurationError):
            get_blob_worm_client(Settings(APP_ENV=blocked_env, USE_MOCK_BLOB_STORAGE=True))

    with pytest.raises(BlobStorageConfigurationError):
        get_blob_worm_client(
            Settings(APP_ENV="dev", USE_MOCK_BLOB_STORAGE=True, USE_LOCAL_SQLITE=False)
        )

    # Production with valid account URL returns keyless AzureBlobWORMClient (lazy init, zero network)
    prod_client = get_blob_worm_client(
        Settings(
            APP_ENV="production",
            USE_MOCK_BLOB_STORAGE=False,
            USE_LOCAL_SQLITE=False,
            AZURE_BLOB_ACCOUNT_URL=VALID_ACCOUNT_URL,
            AZURE_BLOB_WORM_CONTAINER=VALID_CONTAINER,
        )
    )
    assert isinstance(prod_client, AzureBlobWORMClient)
    assert prod_client.account_url == VALID_ACCOUNT_URL
    reset_blob_client_cache()


def test_blob_client_logs_never_leak_raw_file_bytes_or_tax_ids(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify storage logs emit only safe metadata and never raw document content or Tax IDs (CWE-532)."""
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)
    secret_payload = b"%PDF-1.4 CONFIDENTIAL BANK IBAN DE89370400440532013000 US-12-3456789"

    with caplog.at_level(logging.DEBUG, logger="ap.storage.blob_client"):
        res = mem.upload_raw_invoice("inv-log-1", "secret.pdf", secret_payload)
        _ = mem.download_blob(res.blob_name)

    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "DE89370400440532013000" not in combined_logs
    assert "US-12-3456789" not in combined_logs
    assert "CONFIDENTIAL" not in combined_logs
