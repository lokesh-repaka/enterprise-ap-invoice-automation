"""
Unit, Integration, and Security Tests for Azure Blob Metadata Tagging (P4-4).

Tests: CLAUDE.md §4.2, §7.2, §7.3, FR-01, ADR-005, N6, CWE-113, CWE-200, CWE-345, CWE-354, CWE-359, CWE-400
"""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import urlparse

import pytest
from azure.core.exceptions import ResourceNotFoundError
from azure.core.pipeline.transport import HttpResponse, HttpTransport
from azure.storage.blob import BlobServiceClient

from src.storage.blob_client import (
    AzureBlobWORMClient,
    BlobNotFoundError,
    InMemoryWORMBlobClient,
)
from src.storage.metadata import (
    DEFAULT_UNKNOWN_VENDOR_ID,
    MAX_TOTAL_METADATA_BYTES,
    METADATA_KEY_FILE_HASH,
    METADATA_KEY_UPLOAD_TIMESTAMP,
    METADATA_KEY_VENDOR_ID,
    BlobMetadataError,
    BlobMetadataIntegrityError,
    InvoiceBlobMetadata,
    build_invoice_blob_metadata,
    merge_invoice_blob_metadata,
    parse_invoice_blob_metadata,
    verify_blob_metadata_integrity,
)

VALID_ACCOUNT_URL = "https://stapautomationeastus2.blob.core.windows.net/"
VALID_CONTAINER = "raw-invoices-immutable"


def test_build_invoice_blob_metadata_produces_canonical_azure_tags() -> None:
    """Verify canonical VendorID, UploadTimestamp (UTC Z), and SHA-256 FileHash tags."""
    payload = b"%PDF-1.4 Enterprise AP Invoice"
    expected_hash = hashlib.sha256(payload).hexdigest()

    # Default vendor_id falls back cleanly to UNKNOWN with current UTC timestamp
    default_meta = build_invoice_blob_metadata(payload)
    assert isinstance(default_meta, InvoiceBlobMetadata)
    assert default_meta.vendor_id == DEFAULT_UNKNOWN_VENDOR_ID
    assert default_meta.file_hash == expected_hash
    assert default_meta.upload_timestamp.tzinfo is not None

    azure_dict = default_meta.to_azure_metadata()
    assert set(azure_dict.keys()) == {
        METADATA_KEY_VENDOR_ID,
        METADATA_KEY_UPLOAD_TIMESTAMP,
        METADATA_KEY_FILE_HASH,
    }
    assert azure_dict["VendorID"] == "UNKNOWN"
    assert azure_dict["FileHash"] == expected_hash
    assert azure_dict["UploadTimestamp"].endswith("Z")

    # Explicit vendor_id + non-UTC aware timezone normalizes cleanly to UTC Z
    cet = timezone(timedelta(hours=2))
    explicit_ts = datetime(2026, 11, 18, 12, 30, 45, tzinfo=cet)
    explicit_meta = build_invoice_blob_metadata(
        payload,
        vendor_id="VND-DE-004",
        upload_timestamp=explicit_ts,
        expected_file_hash=expected_hash.upper(),
    )
    assert explicit_meta.vendor_id == "VND-DE-004"
    assert explicit_meta.to_azure_metadata()["UploadTimestamp"] == "2026-11-18T10:30:45Z"

    # Mismatched expected_file_hash must fail closed with integrity error (CWE-345)
    with pytest.raises(BlobMetadataIntegrityError, match="FileHash"):
        build_invoice_blob_metadata(payload, expected_file_hash="0" * 64)


def test_parse_invoice_blob_metadata_handles_azure_lowercase_and_pascalcase_keys() -> None:
    """Verify parser supports Azure REST lowercased keys and PascalCase while rejecting invalid/conflicting tags."""
    sample_hash = hashlib.sha256(b"invoice-bytes").hexdigest()
    pascal = {
        "VendorID": "VND-US-001",
        "UploadTimestamp": "2026-11-18T08:15:00Z",
        "FileHash": sample_hash,
    }
    azure_lower = {
        "vendorid": "VND-US-001",
        "uploadtimestamp": "2026-11-18T08:15:00+00:00",
        "filehash": sample_hash,
    }

    parsed_pascal = parse_invoice_blob_metadata(pascal)
    parsed_lower = parse_invoice_blob_metadata(azure_lower)
    assert parsed_pascal == parsed_lower
    assert parsed_lower.vendor_id == "VND-US-001"
    assert parsed_lower.upload_timestamp == datetime(2026, 11, 18, 8, 15, 0, tzinfo=UTC)
    assert parsed_lower.file_hash == sample_hash

    # Missing required tag
    with pytest.raises(BlobMetadataError, match="missing"):
        parse_invoice_blob_metadata(
            {"VendorID": "VND-001", "UploadTimestamp": "2026-11-18T00:00:00Z"}
        )

    # Conflicting case-variant keys (parser differential attack)
    with pytest.raises(BlobMetadataError, match="duplicate"):
        parse_invoice_blob_metadata({**pascal, "vendorid": "VND-EVIL"})

    # Malformed hash or timestamp
    with pytest.raises(BlobMetadataError, match="FileHash"):
        parse_invoice_blob_metadata({**pascal, "FileHash": "not-a-sha256"})
    with pytest.raises(BlobMetadataError, match="UploadTimestamp"):
        parse_invoice_blob_metadata({**pascal, "UploadTimestamp": "2026-11-18 08:15:00"})


def test_verify_blob_metadata_integrity_detects_bit_flip_tampering() -> None:
    """Verify SHA-256 constant-time integrity check detects any payload tampering (CWE-354)."""
    original = b"%PDF-1.4 Immutable Invoice Content"
    meta = build_invoice_blob_metadata(original, vendor_id="VND-UK-002").to_azure_metadata()

    verified = verify_blob_metadata_integrity(original, meta)
    assert verified.vendor_id == "VND-UK-002"

    tampered = b"%PDF-1.4 Immutable Invoice ContenX"
    with pytest.raises(BlobMetadataIntegrityError, match="integrity"):
        verify_blob_metadata_integrity(tampered, meta)


def test_merge_invoice_blob_metadata_blocks_reserved_key_overrides_and_case_collisions() -> None:
    """Verify extra tags merge cleanly while reserved security/audit tags cannot be overridden."""
    base = build_invoice_blob_metadata(b"payload", vendor_id="VND-ES-003")
    merged = merge_invoice_blob_metadata(base, {"InvoiceID": "inv-1001", "SourceChannel": "api"})
    assert merged["VendorID"] == "VND-ES-003"
    assert merged["InvoiceID"] == "inv-1001"
    assert merged["SourceChannel"] == "api"
    assert "UploadTimestamp" in merged and "FileHash" in merged

    # Reserved tag override attempts (exact and case-variant)
    for bad_extra in (
        {"VendorID": "VND-SPOOF"},
        {"vendorid": "VND-SPOOF"},
        {"FileHash": "a" * 64},
        {"filehash": "a" * 64},
        {"UploadTimestamp": "2020-01-01T00:00:00Z"},
        {"UPLOADTIMESTAMP": "2020-01-01T00:00:00Z"},
    ):
        with pytest.raises(BlobMetadataError, match="reserved"):
            merge_invoice_blob_metadata(base, bad_extra)

    # Case-colliding extra keys
    with pytest.raises(BlobMetadataError, match="duplicate"):
        merge_invoice_blob_metadata(base, {"SourceChannel": "api", "sourcechannel": "email"})


def test_metadata_rejects_naive_timestamps_and_invalid_vendor_ids() -> None:
    """Verify naive datetimes and unsafe VendorID values fail closed."""
    with pytest.raises(BlobMetadataError, match="timezone"):
        build_invoice_blob_metadata(
            b"data",
            vendor_id="VND-001",
            upload_timestamp=datetime(2026, 11, 18, 12, 0, 0),
        )

    for bad_vendor in ("", "../escape", "VND 001", "VND\r\nX-Evil: 1", "V" * 65, "VND/001"):
        with pytest.raises(BlobMetadataError, match="VendorID"):
            build_invoice_blob_metadata(b"data", vendor_id=bad_vendor)


def test_metadata_blocks_pii_keys_crlf_injection_and_azure_8kb_header_limit() -> None:
    """Verify PII/secret keys, CRLF values, and >8 KB total Azure header payloads are rejected (CWE-113/359/400)."""
    base = build_invoice_blob_metadata(b"data", vendor_id="VND-001")

    for forbidden_pii_key in (
        "TaxID",
        "tax_id",
        "VendorTaxId",
        "IBAN",
        "BankAccount",
        "bank_account_number",
        "SSN",
        "Password",
        "ClientSecret",
        "ApiKey",
        "AccessToken",
    ):
        with pytest.raises(BlobMetadataError, match="PII|sensitive|forbidden"):
            merge_invoice_blob_metadata(base, {forbidden_pii_key: "REDACTED"})

    with pytest.raises(BlobMetadataError, match="metadata"):
        merge_invoice_blob_metadata(base, {"SourceChannel": "api\r\nX-Injected: evil"})

    # Exceed Azure Storage's 8 KB (8192-byte) total metadata ceiling within the 32-entry limit (3 + 29 = 32)
    oversized_extra = {f"LongMetadataKeyNameForBudgetCheck_{i:02d}": "A" * 256 for i in range(29)}
    assert sum(len(k) + len(v) for k, v in oversized_extra.items()) > MAX_TOTAL_METADATA_BYTES
    with pytest.raises(BlobMetadataError, match="8192|size|budget"):
        merge_invoice_blob_metadata(base, oversized_extra)


def test_worm_clients_auto_tag_uploads_and_expose_read_only_get_blob_metadata() -> None:
    """Verify AzureBlobWORMClient & InMemoryWORMBlobClient auto-tag VendorID/UploadTimestamp/FileHash."""
    pdf_bytes = b"%PDF-1.4 Auto-Tagged Invoice"
    expected_sha = hashlib.sha256(pdf_bytes).hexdigest()
    fixed_ts = datetime(2026, 11, 18, 9, 0, 0, tzinfo=UTC)

    # Mock Azure SDK client tracking uploaded metadata & returning it via get_blob_properties()
    stored_meta: dict[str, dict[str, str]] = {}
    mock_service = MagicMock()
    mock_container = MagicMock()

    def _get_blob_client(blob: str):
        bc = MagicMock()
        bc.url = f"{VALID_ACCOUNT_URL}{VALID_CONTAINER}/{blob}"

        def _upload(data: bytes, **kwargs):
            # Simulate Azure REST API lowercasing metadata keys on storage
            stored_meta[blob] = {k.lower(): v for k, v in (kwargs.get("metadata") or {}).items()}
            return {"etag": '"etag-meta-1"'}

        def _props(**kwargs):
            if blob not in stored_meta:
                raise ResourceNotFoundError("not found")
            props = MagicMock()
            props.metadata = dict(stored_meta[blob])
            return props

        bc.upload_blob.side_effect = _upload
        bc.get_blob_properties.side_effect = _props
        return bc

    mock_container.get_blob_client.side_effect = _get_blob_client
    mock_service.get_container_client.return_value = mock_container

    azure_client = AzureBlobWORMClient(
        account_url=VALID_ACCOUNT_URL,
        container_name=VALID_CONTAINER,
        blob_service_client=mock_service,
    )
    mem_client = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)

    for client in (azure_client, mem_client):
        # Strictly no mutable metadata APIs on WORM clients
        for forbidden in ("set_blob_metadata", "update_blob_metadata", "delete_blob_metadata"):
            assert not hasattr(client, forbidden)

        res = client.upload_raw_invoice(
            invoice_id="inv-tag-1",
            filename="invoice.pdf",
            data=pdf_bytes,
            content_type="application/pdf",
            vendor_id="VND-US-010",
            upload_timestamp=fixed_ts,
            metadata={"SourceChannel": "portal"},
        )
        assert res.metadata["VendorID"] == "VND-US-010"
        assert res.metadata["UploadTimestamp"] == "2026-11-18T09:00:00Z"
        assert res.metadata["FileHash"] == expected_sha
        assert res.metadata["SourceChannel"] == "portal"

        fetched = client.get_blob_metadata(res.blob_name)
        verified = verify_blob_metadata_integrity(pdf_bytes, fetched)
        assert verified.vendor_id == "VND-US-010"
        assert verified.upload_timestamp == fixed_ts
        assert verified.file_hash == expected_sha

        # Defensive copy check: mutating returned dict must not mutate stored metadata
        fetched["VendorID"] = "TAMPERED"
        assert (
            parse_invoice_blob_metadata(client.get_blob_metadata(res.blob_name)).vendor_id
            == "VND-US-010"
        )

        # Extraction JSON upload also receives canonical VendorID, UploadTimestamp, FileHash
        json_res = client.upload_extraction_json(
            invoice_id="inv-tag-1",
            payload={"invoice_number": "INV-1"},
            vendor_id="VND-US-010",
            upload_timestamp=fixed_ts,
        )
        assert json_res.metadata["VendorID"] == "VND-US-010"
        assert json_res.metadata["FileHash"] == json_res.sha256_hash

        with pytest.raises(BlobNotFoundError):
            client.get_blob_metadata("raw-invoices/missing/doc.pdf")


def test_worm_client_blocks_spoofed_file_hash_and_conflicting_vendor_metadata() -> None:
    """Verify WORM upload rejects spoofed FileHash, invalid UploadTimestamp, and conflicting VendorID."""
    mem = InMemoryWORMBlobClient(VALID_ACCOUNT_URL, VALID_CONTAINER)
    payload = b"%PDF-1.4 Genuine Payload"

    with pytest.raises(BlobMetadataIntegrityError, match="FileHash"):
        mem.upload_raw_invoice("inv-spoof-1", "doc.pdf", payload, metadata={"FileHash": "0" * 64})
    assert mem.blob_exists("raw-invoices/inv-spoof-1/doc.pdf") is False

    with pytest.raises(BlobMetadataError, match="VendorID"):
        mem.upload_raw_invoice(
            "inv-spoof-2",
            "doc.pdf",
            payload,
            vendor_id="VND-001",
            metadata={"VendorID": "VND-999"},
        )

    with pytest.raises(BlobMetadataError, match="UploadTimestamp"):
        mem.upload_raw_invoice(
            "inv-spoof-3",
            "doc.pdf",
            payload,
            metadata={"UploadTimestamp": "not-an-iso-timestamp"},
        )


def test_metadata_wire_protocol_roundtrip_with_real_azure_sdk_x_ms_meta_headers() -> None:
    """Verify real Azure SDK sends x-ms-meta-VendorID/UploadTimestamp/FileHash and parses lowercased HEAD response."""

    class _BytesIter:
        def __init__(self, body: bytes, resp: HttpResponse) -> None:
            self._body = body
            self.response = resp
            self.content_length = len(body)
            self._done = False

        def __iter__(self) -> Iterator[bytes]:
            return self

        def __next__(self) -> bytes:
            if self._done or not self._body:
                raise StopIteration
            self._done = True
            return self._body

    class _Resp(HttpResponse):
        def __init__(
            self, req: Any, status: int, body: bytes = b"", headers: dict[str, str] | None = None
        ):
            super().__init__(request=req, internal_response=None)
            self.status_code = status
            self.reason = "OK"
            self.headers = {"Content-Length": str(len(body)), **(headers or {})}
            self._body = body

        def body(self) -> bytes:
            return self._body

        def stream_download(self, pipeline: Any, **kwargs: Any) -> Iterator[bytes]:
            return _BytesIter(self._body, self)

    class _MetaTransport(HttpTransport):
        def __init__(self) -> None:
            self.blobs: dict[str, tuple[bytes, dict[str, str]]] = {}
            self.captured_put_headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def open(self):
            return None

        def close(self):
            return None

        def send(self, request: Any, **kwargs: Any) -> _Resp:
            path = urlparse(request.url).path.lstrip("/")
            if request.method == "PUT":
                body = request.data if isinstance(request.data, bytes) else b"".join(request.data)
                meta_headers = {
                    k.lower(): str(v)
                    for k, v in request.headers.items()
                    if k.lower().startswith("x-ms-meta-")
                }
                self.captured_put_headers = dict(request.headers)
                self.blobs[path] = (body, meta_headers)
                return _Resp(request, 201, headers={"ETag": '"wire-etag-1"'})
            if request.method == "HEAD":
                body, meta_headers = self.blobs[path]
                return _Resp(
                    request,
                    200,
                    headers={
                        "Content-Length": str(len(body)),
                        "ETag": '"wire-etag-1"',
                        "x-ms-blob-type": "BlockBlob",
                        **meta_headers,
                    },
                )
            body, meta_headers = self.blobs[path]
            status_code = (
                206 if "x-ms-range" in request.headers or "Range" in request.headers else 200
            )
            return _Resp(
                request,
                status_code,
                body=body,
                headers={
                    "ETag": '"wire-etag-1"',
                    "Content-Range": f"bytes 0-{len(body) - 1}/{len(body)}",
                    **meta_headers,
                },
            )

    transport = _MetaTransport()
    svc = BlobServiceClient(
        account_url="http://127.0.0.1:10000/devstoreaccount1",
        credential={"account_name": "devstoreaccount1", "account_key": "dGVzdGtleQ=="},
        transport=transport,
    )
    client = AzureBlobWORMClient(
        account_url="http://127.0.0.1:10000/devstoreaccount1/",
        container_name=VALID_CONTAINER,
        blob_service_client=svc,
        allow_local_emulator=True,
    )

    payload = b"%PDF-1.4 Real SDK Wire Metadata Smoke"
    fixed_ts = datetime(2026, 11, 18, 10, 0, 0, tzinfo=UTC)
    res = client.upload_raw_invoice(
        invoice_id="inv-wire-1",
        filename="INV-WIRE-01.pdf",
        data=payload,
        content_type="application/pdf",
        vendor_id="VND-UK-009",
        upload_timestamp=fixed_ts,
    )

    lower_put = {k.lower(): v for k, v in transport.captured_put_headers.items()}
    assert lower_put["x-ms-meta-vendorid"] == "VND-UK-009"
    assert lower_put["x-ms-meta-uploadtimestamp"] == "2026-11-18T10:00:00Z"
    assert lower_put["x-ms-meta-filehash"] == hashlib.sha256(payload).hexdigest()

    fetched_meta = client.get_blob_metadata(res.blob_name)
    verified = verify_blob_metadata_integrity(client.download_blob(res.blob_name), fetched_meta)
    assert verified.vendor_id == "VND-UK-009"
    assert verified.upload_timestamp == fixed_ts
    assert verified.file_hash == hashlib.sha256(payload).hexdigest()
    assert res.uploaded_at == fixed_ts


def test_metadata_blocks_pii_and_secrets_in_values_plus_whitespace_trimming_differentials() -> None:
    """Verify IBAN/JWT/SAS secrets inside innocent metadata keys and leading/trailing spaces fail closed."""
    base = build_invoice_blob_metadata(b"payload", vendor_id="VND-DE-001")

    # PII / credential payloads smuggled inside innocent-looking keys (CWE-200 / CWE-359)
    for bad_value in (
        "DE89370400440532013000",
        "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
        "AccountKey=fakebase64value==",
        "https://storage.example/blob?sv=2023&sig=leaked",
    ):
        with pytest.raises(BlobMetadataError, match="sensitive/PII"):
            merge_invoice_blob_metadata(base, {"Notes": bad_value})

    # Leading/trailing whitespace or empty values (Azure HTTP header trimming differential — CWE-113/20)
    for bad_ws in ("", "   ", " leading", "trailing "):
        with pytest.raises(BlobMetadataError, match="Invalid metadata value"):
            merge_invoice_blob_metadata(base, {"SourceChannel": bad_ws})
