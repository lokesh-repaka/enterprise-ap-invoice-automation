"""
Integration Smoke Test for Azurite Local Emulator & Azure Blob REST Wire Protocol (P4-2).

Exercises the real ``azure.storage.blob.BlobServiceClient`` SDK pipeline end-to-end
over an in-process ``HttpTransport`` implementing the Azurite Blob REST API (zero TCP
sockets or Docker daemon required in offline CI), verifying:
  1. Idempotent container creation (``PUT ?restype=container`` -> 201 then 409).
  2. Real Azure SDK SharedKey signing & ``If-None-Match: *`` WORM header on upload.
  3. ``INV-SMOKE-01.pdf`` and ``extraction.json`` upload & byte-for-byte download.
  4. ``409 BlobAlreadyExists`` XML response mapped to ``BlobAlreadyExistsError``.
  5. Optional live Docker Azurite smoke test when ``RUN_LIVE_AZURITE_SMOKE=true``.

Tests: GAP-002, ADR-005, FR-01, N6, Implementation_Planning §6.3
"""

import base64
import hashlib
import json
import os
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from azure.core.pipeline.transport import HttpResponse, HttpTransport
from azure.storage.blob import BlobServiceClient

from src.core.config import Settings
from src.storage.azurite import (
    DEFAULT_AZURITE_BLOB_URL,
    check_azurite_reachable,
    create_azurite_worm_client,
    ensure_worm_container,
)
from src.storage.blob_client import AzureBlobWORMClient, BlobAlreadyExistsError


class _BytesStreamIterator:
    """Mutable iterator object compatible with Azure SDK's ``deserialize_blob_stream``."""

    def __init__(self, payload: bytes, response: HttpResponse) -> None:
        self._payload = payload
        self.response = response
        self.content_length = len(payload)
        self._consumed = False

    def __iter__(self) -> "_BytesStreamIterator":
        return self

    def __next__(self) -> bytes:
        if self._consumed or not self._payload:
            raise StopIteration
        self._consumed = True
        return self._payload


class _InMemoryAzureHttpResponse(HttpResponse):
    """Minimal ``azure.core.pipeline.transport.HttpResponse`` backed by bytes in memory."""

    def __init__(
        self,
        request: Any,
        status_code: int,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(request=request, internal_response=None)
        self.status_code = status_code
        self.reason = "OK" if status_code < 400 else "Error"
        self.headers = {
            "Content-Length": str(len(body)),
            "x-ms-request-id": "azurite-smoke-req-001",
            "x-ms-version": "2023-11-03",
            **(headers or {}),
        }
        self._body = body

    def body(self) -> bytes:
        return self._body

    def stream_download(self, pipeline: Any, **kwargs: Any) -> Iterator[bytes]:
        return _BytesStreamIterator(self._body, self)


class _InProcessAzuriteTransport(HttpTransport):
    """
    In-process ``HttpTransport`` simulating Azurite's Azure Blob Storage REST protocol.

    Executes the full ``azure-storage-blob`` serialization, SharedKey auth signing,
    WORM ``If-None-Match: *`` enforcement, and XML error deserialization with zero sockets.
    """

    def __init__(self) -> None:
        self.containers: set[str] = set()
        self.blobs: dict[tuple[str, str], tuple[bytes, str]] = {}
        self.received_if_none_match: list[str | None] = []
        self.received_auth_schemes: list[str] = []

    def __enter__(self) -> "_InProcessAzuriteTransport":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    @staticmethod
    def _split_path(url: str) -> tuple[str, str, str]:
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        account = parts[0] if len(parts) >= 1 else ""
        container = parts[1] if len(parts) >= 2 else ""
        blob = "/".join(parts[2:]) if len(parts) >= 3 else ""
        return account, container, blob

    def send(self, request: Any, **kwargs: Any) -> _InMemoryAzureHttpResponse:
        parsed = urlparse(request.url)
        qs = parse_qs(parsed.query)
        _, container, blob = self._split_path(request.url)
        auth_header = request.headers.get("Authorization", "")
        if auth_header:
            self.received_auth_schemes.append(auth_header.split(" ", 1)[0])

        method = request.method.upper()
        if method == "PUT":
            if qs.get("restype") == ["container"] and not blob:
                if container in self.containers:
                    return _InMemoryAzureHttpResponse(
                        request,
                        409,
                        b"<Error><Code>ContainerAlreadyExists</Code></Error>",
                        {
                            "Content-Type": "application/xml",
                            "x-ms-error-code": "ContainerAlreadyExists",
                        },
                    )
                self.containers.add(container)
                return _InMemoryAzureHttpResponse(request, 201, b"", {"ETag": '"container-etag-1"'})

            raw_body = request.data
            if isinstance(raw_body, (bytes, bytearray)):
                body = bytes(raw_body)
            elif raw_body is None:
                body = b""
            else:
                body = b"".join(raw_body)

            if_none_match = request.headers.get("If-None-Match")
            self.received_if_none_match.append(if_none_match)
            key = (container, blob)
            if if_none_match == "*" and key in self.blobs:
                return _InMemoryAzureHttpResponse(
                    request,
                    409,
                    b"<Error><Code>BlobAlreadyExists</Code></Error>",
                    {"Content-Type": "application/xml", "x-ms-error-code": "BlobAlreadyExists"},
                )

            ct = request.headers.get("Content-Type", "application/octet-stream")
            self.blobs[key] = (body, ct)
            return _InMemoryAzureHttpResponse(
                request, 201, b"", {"ETag": f'"blob-etag-{len(body)}"'}
            )

        if method == "GET":
            entry = self.blobs.get((container, blob))
            if entry is None:
                return _InMemoryAzureHttpResponse(
                    request,
                    404,
                    b"<Error><Code>BlobNotFound</Code></Error>",
                    {"Content-Type": "application/xml", "x-ms-error-code": "BlobNotFound"},
                )
            data, ct = entry
            status_code = (
                206 if "x-ms-range" in request.headers or "Range" in request.headers else 200
            )
            return _InMemoryAzureHttpResponse(
                request,
                status_code,
                data,
                {
                    "Content-Type": ct,
                    "ETag": f'"blob-etag-{len(data)}"',
                    "Content-Range": f"bytes 0-{len(data) - 1}/{len(data)}",
                },
            )

        if method == "HEAD":
            entry = self.blobs.get((container, blob))
            if entry is None:
                return _InMemoryAzureHttpResponse(
                    request, 404, b"", {"x-ms-error-code": "BlobNotFound"}
                )
            data, ct = entry
            return _InMemoryAzureHttpResponse(
                request,
                200,
                b"",
                {
                    "Content-Length": str(len(data)),
                    "Content-Type": ct,
                    "ETag": f'"blob-etag-{len(data)}"',
                    "x-ms-blob-type": "BlockBlob",
                },
            )

        return _InMemoryAzureHttpResponse(request, 405, b"")


def test_azurite_wire_protocol_smoke_upload_download_and_worm_lock() -> None:
    """
    End-to-end Azure Blob SDK wire-protocol smoke test (zero sockets, 100% real SDK).

    Verifies:
      1. Idempotent WORM container creation (201 then 409 ignored).
      2. INV-SMOKE-01.pdf upload transmits ``If-None-Match: *`` and ``SharedKey`` signing.
      3. Duplicate upload receives HTTP 409 BlobAlreadyExists -> ``BlobAlreadyExistsError``.
      4. Extraction JSON upload & download round-trips deterministically.
    """
    transport = _InProcessAzuriteTransport()
    ephemeral_shared_key = base64.b64encode(os.urandom(32)).decode("ascii")
    sdk_service = BlobServiceClient(
        account_url=DEFAULT_AZURITE_BLOB_URL,
        credential={"account_name": "devstoreaccount1", "account_key": ephemeral_shared_key},
        transport=transport,
    )

    # 1. Idempotent container bootstrap (201 then 409 ignored)
    assert ensure_worm_container(sdk_service, "raw-invoices-immutable") is True
    assert ensure_worm_container(sdk_service, "raw-invoices-immutable") is False

    client = AzureBlobWORMClient(
        account_url=DEFAULT_AZURITE_BLOB_URL,
        container_name="raw-invoices-immutable",
        blob_service_client=sdk_service,
        allow_local_emulator=True,
    )

    # 2. Upload INV-SMOKE-01.pdf
    smoke_pdf = b"%PDF-1.4 INV-SMOKE-01 Real Azure SDK Wire Protocol Smoke Test"
    raw_res = client.upload_raw_invoice(
        invoice_id="inv-smoke-01",
        filename="INV-SMOKE-01.pdf",
        data=smoke_pdf,
        content_type="application/pdf",
        metadata={"VendorID": "VEND-1001"},
    )
    assert raw_res.sha256_hash == hashlib.sha256(smoke_pdf).hexdigest()
    assert "*" in transport.received_if_none_match
    assert "SharedKey" in transport.received_auth_schemes

    # 3. Verify HEAD existence and GET download integrity
    assert client.blob_exists(raw_res.blob_name) is True
    assert client.download_blob(raw_res.blob_name) == smoke_pdf

    # 4. Verify WORM overwrite denial (409 BlobAlreadyExists -> BlobAlreadyExistsError)
    with pytest.raises(BlobAlreadyExistsError):
        client.upload_raw_invoice("inv-smoke-01", "INV-SMOKE-01.pdf", b"%PDF-1.4 forged")
    assert client.download_blob(raw_res.blob_name) == smoke_pdf

    # 5. Upload and download extraction JSON
    payload = {"invoice_number": "INV-SMOKE-01", "total_amount": "1350.00", "currency": "USD"}
    json_res = client.upload_extraction_json("inv-smoke-01", payload)
    assert json.loads(client.download_blob(json_res.blob_name).decode("utf-8")) == payload


@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_AZURITE_SMOKE", "").lower() != "true",
    reason="Live Docker Azurite smoke test runs when RUN_LIVE_AZURITE_SMOKE=true",
)
def test_live_docker_azurite_emulator_smoke() -> None:
    """Optional live smoke test against a running local Docker Azurite container (127.0.0.1:10000)."""
    assert check_azurite_reachable(DEFAULT_AZURITE_BLOB_URL), (
        "Azurite emulator is not reachable on 127.0.0.1:10000. Run 'make run-azurite' first."
    )
    settings = Settings(
        APP_ENV="dev",
        USE_LOCAL_SQLITE=True,
        USE_MOCK_BLOB_STORAGE=False,
        USE_AZURITE_EMULATOR=True,
        AZURITE_BLOB_URL=DEFAULT_AZURITE_BLOB_URL,
    )
    client = create_azurite_worm_client(settings=settings, ensure_container=True)
    smoke_bytes = b"%PDF-1.4 LIVE AZURITE SMOKE"
    inv_id = f"inv-live-{os.urandom(4).hex()}"
    res = client.upload_raw_invoice(
        inv_id, "INV-SMOKE-01.pdf", smoke_bytes, content_type="application/pdf"
    )
    assert client.download_blob(res.blob_name) == smoke_bytes
