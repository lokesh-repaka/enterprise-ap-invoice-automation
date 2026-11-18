"""
Unit, Integration, and Security Tests for Invoice Upload API (P5-1).

Tests: FR-01, BR-001, GAP-004, CLAUDE.md §4.1, §9, §11, CWE-22, CWE-94, CWE-113, CWE-200, CWE-400, CWE-434, CWE-532, CWE-636
"""

import asyncio
import hashlib
import io
import json
import logging
import zipfile
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import fitz
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from redis.exceptions import RedisError

from src.api.invoices import (
    INVOICE_QUEUE_KEY,
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
    guard_upload_content_length,
    reset_upload_dependencies,
)
from src.api.main import app
from src.core.config import Settings, get_settings
from src.core.demo_auth import issue_demo_token, reset_demo_keypair_cache
from src.database.models import Base, Vendor
from src.database.repositories import AuditLogRepository, InvoiceRepository, VendorRepository
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import (
    MAX_BLOB_SIZE_BYTES,
    BlobStorageError,
    InMemoryWORMBlobClient,
)
from src.storage.metadata import verify_blob_metadata_integrity


def _make_pdf(*, text: str = "Synthetic Invoice #1001", user_password: str | None = None) -> bytes:
    """Create a genuine in-memory PDF via PyMuPDF."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    try:
        if user_password is not None:
            return doc.tobytes(
                encryption=fitz.PDF_ENCRYPT_AES_256,
                user_pw=user_password,
                owner_pw="owner-secret",
            )
        return doc.tobytes()
    finally:
        doc.close()


def _make_image(fmt: str) -> bytes:
    """Create a genuine small in-memory PNG or JPEG via PyMuPDF."""
    doc = fitz.open()
    try:
        page = doc.new_page(width=48, height=48)
        return page.get_pixmap().tobytes(output=fmt)
    finally:
        doc.close()


def _make_xlsx() -> bytes:
    """Create a minimal valid OOXML XLSX archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
    return buf.getvalue()


def _demo_auth_headers(username: str) -> dict[str, str]:
    """Mint an ephemeral RS256 demo token for the given persona."""
    settings = Settings(APP_ENV="test", ENABLE_DEMO_AUTH=True, USE_LOCAL_SQLITE=True)
    token = issue_demo_token(username, settings=settings)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def upload_env(monkeypatch: pytest.MonkeyPatch):
    """Provide isolated in-memory SQLite DB, WORM Blob client, FakeRedis, and demo auth enabled."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    session_factory = create_session_factory(engine)

    async def _init_schema() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init_schema())

    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis

    try:
        yield {
            "client": TestClient(app),
            "session_factory": session_factory,
            "blob_client": blob_client,
            "redis": fake_redis,
            "engine": engine,
        }
    finally:
        app.dependency_overrides.clear()
        reset_demo_keypair_cache()
        get_settings.cache_clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())


def test_upload_valid_pdf_png_jpeg_xlsx_returns_202_writes_worm_blob_sql_audit_and_redis_job(
    upload_env: dict,
) -> None:
    """Verify FR-01 formats return 202 Accepted and persist WORM Blob, SQL Invoice, AuditLog, and Redis job."""
    client: TestClient = upload_env["client"]
    blob_client: InMemoryWORMBlobClient = upload_env["blob_client"]
    fake_redis = upload_env["redis"]
    session_factory = upload_env["session_factory"]
    headers = {**_demo_auth_headers("sarah.clerk"), "X-Request-ID": "req-upload-e2e-001"}

    samples = [
        ("INV-1001.pdf", _make_pdf(), "application/pdf"),
        ("scan.png", _make_image("png"), "image/png"),
        ("photo.jpg", _make_image("jpeg"), "image/jpeg"),
        (
            "schedule.xlsx",
            _make_xlsx(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    ]

    invoice_ids: list[str] = []
    for fname, raw_bytes, mime in samples:
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            files={"file": (fname, raw_bytes, mime)},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        inv_id = body["invoice_id"]
        invoice_ids.append(inv_id)

        assert resp.headers["Location"] == f"/api/v1/invoices/{inv_id}"
        assert resp.headers["X-Request-ID"] == "req-upload-e2e-001"
        assert body["status"] == "UPLOADED"
        assert body["queued"] is True
        assert body["filename"] == fname
        assert body["detected_mime"] == mime
        assert body["size_bytes"] == len(raw_bytes)
        assert body["file_hash"] == hashlib.sha256(raw_bytes).hexdigest()
        assert body["vendor_id"] == "UNKNOWN"
        assert body["request_id"] == "req-upload-e2e-001"

        # 1. Verify WORM Blob bytes + canonical metadata integrity (P4-1 + P4-4)
        blob_name = f"raw-invoices/{inv_id}/{fname}"
        assert blob_client.blob_exists(blob_name) is True
        stored_bytes = blob_client.download_blob(blob_name)
        assert stored_bytes == raw_bytes
        verified_meta = verify_blob_metadata_integrity(
            stored_bytes, blob_client.get_blob_metadata(blob_name)
        )
        assert verified_meta.vendor_id == "UNKNOWN"
        assert verified_meta.file_hash == body["file_hash"]

    # 2. Verify SQL Invoice rows & immutable INGEST AuditLogs (P2-3 + P3-4)
    async def _verify_sql_and_redis() -> None:
        async with session_factory() as session:
            inv_repo = InvoiceRepository(session)
            audit_repo = AuditLogRepository(session)
            for inv_id in invoice_ids:
                inv = await inv_repo.get_by_id(inv_id)
                assert inv is not None
                assert inv.status == "UPLOADED"
                assert inv.blob_raw_url is not None and inv_id in inv.blob_raw_url

                logs = await audit_repo.get_by_invoice_id(inv_id)
                assert len(logs) == 1
                assert logs[0].action_type == "INGEST"
                assert logs[0].user_id == "demo-oid-sarah-clerk"

        # 3. Verify Redis FIFO queue received all 4 jobs in order
        queued_items = await fake_redis.lrange(INVOICE_QUEUE_KEY, 0, -1)
        assert len(queued_items) == len(samples)
        for idx, raw_item in enumerate(queued_items):
            job = json.loads(raw_item)
            assert job["invoice_id"] == invoice_ids[idx]
            assert job["uploaded_by"] == "demo-oid-sarah-clerk"
            assert job["request_id"] == "req-upload-e2e-001"
            assert job["vendor_id"] == "UNKNOWN"

    asyncio.run(_verify_sql_and_redis())


def test_upload_with_known_active_vendor_id_links_vendor_and_tags_blob(upload_env: dict) -> None:
    """Verify valid active vendor_id links SQL Vendor FK and Blob VendorID tag; unknown/inactive returns 422."""
    client: TestClient = upload_env["client"]
    session_factory = upload_env["session_factory"]
    blob_client: InMemoryWORMBlobClient = upload_env["blob_client"]
    fake_redis = upload_env["redis"]
    headers = _demo_auth_headers("sarah.clerk")

    async def _seed_vendors() -> None:
        async with session_factory() as session:
            repo = VendorRepository(session)
            await repo.create(
                Vendor(
                    vendor_tax_id="US-12-3456789",
                    vendor_id="VEND-1001",
                    vendor_name="Acme Technologies Inc.",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    is_active=True,
                )
            )
            await repo.create(
                Vendor(
                    vendor_tax_id="US-99-0000000",
                    vendor_id="VEND-INACTIVE",
                    vendor_name="Deactivated Corp",
                    country_code="US",
                    date_format_locale="MM/DD/YYYY",
                    default_currency="USD",
                    tax_scheme="US_SALES_TAX",
                    is_active=False,
                )
            )

    asyncio.run(_seed_vendors())

    pdf_bytes = _make_pdf()
    resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        data={"vendor_id": "VEND-1001"},
        files={"file": ("acme_inv.pdf", pdf_bytes, "application/pdf")},
    )
    assert resp.status_code == 202, resp.text
    inv_id = resp.json()["invoice_id"]
    assert resp.json()["vendor_id"] == "VEND-1001"
    assert (
        blob_client.get_blob_metadata(f"raw-invoices/{inv_id}/acme_inv.pdf")["VendorID"]
        == "VEND-1001"
    )

    async def _check_sql() -> None:
        async with session_factory() as session:
            inv = await InvoiceRepository(session).get_by_id(inv_id)
            assert inv is not None
            assert inv.vendor_tax_id == "US-12-3456789"
            assert inv.vendor_name == "Acme Technologies Inc."

    asyncio.run(_check_sql())

    # Unknown or inactive vendor_id must fail closed with 422 and zero side effects
    for bad_vid in ("VEND-DOES-NOT-EXIST", "VEND-INACTIVE"):
        bad_resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            data={"vendor_id": bad_vid},
            files={"file": ("nope.pdf", pdf_bytes, "application/pdf")},
        )
        assert bad_resp.status_code == 422

    assert asyncio.run(fake_redis.llen(INVOICE_QUEUE_KEY)) == 1


def test_upload_rbac_allows_ap_clerk_and_finance_manager_but_blocks_unauth_and_system_admin(
    upload_env: dict,
) -> None:
    """Verify RBAC enforces CLAUDE.md §9: ap_clerk & finance_manager allowed; unauth=401, system_admin=403."""
    client: TestClient = upload_env["client"]
    pdf_bytes = _make_pdf()

    # Unauthenticated -> 401
    unauth = client.post(
        "/api/v1/invoices/upload",
        files={"file": ("inv.pdf", pdf_bytes, "application/pdf")},
    )
    assert unauth.status_code == 401
    assert "Bearer" in unauth.headers.get("WWW-Authenticate", "")

    # system_admin -> 403 Forbidden (separation of duties)
    admin_resp = client.post(
        "/api/v1/invoices/upload",
        headers=_demo_auth_headers("dave.admin"),
        files={"file": ("inv.pdf", pdf_bytes, "application/pdf")},
    )
    assert admin_resp.status_code == 403

    # ap_clerk & finance_manager -> 202 Accepted
    for persona in ("sarah.clerk", "michael.manager"):
        ok_resp = client.post(
            "/api/v1/invoices/upload",
            headers=_demo_auth_headers(persona),
            files={"file": (f"{persona}.pdf", pdf_bytes, "application/pdf")},
        )
        assert ok_resp.status_code == 202


def test_upload_rejects_oversized_file_with_413_via_bounded_chunk_reader(upload_env: dict) -> None:
    """Verify uploads exceeding 25 MB abort early with HTTP 413 and zero storage/queue writes (FR-01/CWE-400)."""
    client: TestClient = upload_env["client"]
    fake_redis = upload_env["redis"]
    headers = _demo_auth_headers("sarah.clerk")

    oversized = b"%PDF-1.4" + b"0" * MAX_BLOB_SIZE_BYTES
    resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("huge.pdf", oversized, "application/pdf")},
    )
    assert resp.status_code == 413
    assert "detail" in resp.json()
    assert asyncio.run(fake_redis.llen(INVOICE_QUEUE_KEY)) == 0


def test_upload_rejects_tiff_spoofed_mime_and_password_protected_pdf_with_415_and_422(
    upload_env: dict,
) -> None:
    """Verify TIFF (GAP-004), spoofed HTML, locked PDF, and active-JS PDF return 415/422 with zero side effects."""
    client: TestClient = upload_env["client"]
    fake_redis = upload_env["redis"]
    headers = _demo_auth_headers("sarah.clerk")

    # 1. TIFF by extension & magic bytes -> 415
    tiff_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("scan.tiff", b"II*\x00\x08\x00\x00\x00" + b"\x00" * 16, "image/tiff")},
    )
    assert tiff_resp.status_code == 415
    assert "TIFF" in tiff_resp.json()["detail"]

    # 2. HTML disguised as PDF -> 415
    spoof_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("evil.pdf", b"<html><script>alert(1)</script></html>", "application/pdf")},
    )
    assert spoof_resp.status_code == 415

    # 3. Password-protected PDF -> 422
    locked_pdf = _make_pdf(user_password="secret-pw")
    pw_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("locked.pdf", locked_pdf, "application/pdf")},
    )
    assert pw_resp.status_code == 422
    assert "Password-protected" in pw_resp.json()["detail"]

    # 4. Active /JavaScript PDF -> 422
    doc_js = fitz.open()
    doc_js.new_page().insert_text((72, 72), "JS trap")
    js_xref = doc_js.get_new_xref()
    doc_js.update_object(js_xref, "<< /S /JavaScript /JS (app.alert(1)) >>")
    doc_js.xref_set_key(doc_js.pdf_catalog(), "OpenAction", f"{js_xref} 0 R")
    js_pdf = doc_js.tobytes()
    doc_js.close()

    js_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("js_trap.pdf", js_pdf, "application/pdf")},
    )
    assert js_resp.status_code == 422

    assert asyncio.run(fake_redis.llen(INVOICE_QUEUE_KEY)) == 0


def test_upload_blocks_path_traversal_and_invalid_vendor_id_form_inputs(upload_env: dict) -> None:
    """Verify traversal filenames and malicious vendor_id form fields fail closed with 422 (CWE-22/113)."""
    client: TestClient = upload_env["client"]
    headers = _demo_auth_headers("sarah.clerk")
    pdf_bytes = _make_pdf()

    for bad_name in ("../../etc/passwd.pdf", "nested/evil.pdf", "inv\r\n.pdf"):
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            files={"file": (bad_name, pdf_bytes, "application/pdf")},
        )
        assert resp.status_code == 422

    for bad_vid in ("../VEND", "VND\r\nX-Injected: 1", "' OR 1=1--"):
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            data={"vendor_id": bad_vid},
            files={"file": ("clean.pdf", pdf_bytes, "application/pdf")},
        )
        assert resp.status_code == 422


def test_upload_fails_closed_with_503_when_blob_storage_or_redis_queue_is_unavailable(
    upload_env: dict,
) -> None:
    """Verify Blob or Redis failures return 503 with generic messages and never false 202 (CWE-636/209)."""
    client: TestClient = upload_env["client"]
    headers = _demo_auth_headers("sarah.clerk")
    pdf_bytes = _make_pdf()

    # 1. Failing Blob client -> 503 (no internal traceback leaked)
    broken_blob = MagicMock()
    broken_blob.upload_raw_invoice.side_effect = BlobStorageError("internal-storage-secret-detail")
    app.dependency_overrides[get_upload_blob_client] = lambda: broken_blob

    blob_fail = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("inv.pdf", pdf_bytes, "application/pdf")},
    )
    assert blob_fail.status_code == 503
    assert "internal-storage-secret-detail" not in blob_fail.json()["detail"]

    # Restore working Blob client, break Redis rpush -> 503 (never lies with 202)
    app.dependency_overrides[get_upload_blob_client] = lambda: upload_env["blob_client"]
    broken_redis = AsyncMock()
    broken_redis.rpush.side_effect = RedisError("redis-password-leak-detail")
    app.dependency_overrides[get_upload_redis_client] = lambda: broken_redis

    redis_fail = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("inv2.pdf", pdf_bytes, "application/pdf")},
    )
    assert redis_fail.status_code == 503
    assert "redis-password-leak-detail" not in redis_fail.json()["detail"]


def test_upload_logs_never_leak_raw_file_bytes_or_tax_ids(
    upload_env: dict,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify upload route logs emit only safe metadata and never raw document PII (CWE-532)."""
    client: TestClient = upload_env["client"]
    headers = _demo_auth_headers("sarah.clerk")
    secret_pdf = _make_pdf(text="TAX ID US-12-3456789 IBAN DE89370400440532013000 SECRET_TOKEN")

    with caplog.at_level(logging.DEBUG, logger="ap"):
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            files={"file": ("pii_invoice.pdf", secret_pdf, "application/pdf")},
        )
    assert resp.status_code == 202

    combined = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined
    assert "DE89370400440532013000" not in combined
    assert "SECRET_TOKEN" not in combined


def test_upload_rejects_oversized_or_malformed_content_length_empty_files_and_long_filenames(
    upload_env: dict,
) -> None:
    """Verify Content-Length DoS guard, empty uploads, and null/overlong filenames fail closed (CWE-400/20)."""
    client: TestClient = upload_env["client"]
    headers = _demo_auth_headers("sarah.clerk")

    # Direct pre-parse Content-Length guard tests (413 oversized, 400 negative/non-numeric)
    fake_req_big = MagicMock()
    fake_req_big.headers = {"content-length": str(500 * 1024 * 1024)}
    with pytest.raises(HTTPException) as exc_big:
        guard_upload_content_length(fake_req_big)
    assert exc_big.value.status_code == 413

    for bad_cl in ("-5", "not-a-number"):
        fake_req_bad = MagicMock()
        fake_req_bad.headers = {"content-length": bad_cl}
        with pytest.raises(HTTPException) as exc_bad:
            guard_upload_content_length(fake_req_bad)
        assert exc_bad.value.status_code == 400

    # Empty 0-byte upload -> 422
    empty_resp = client.post(
        "/api/v1/invoices/upload",
        headers=headers,
        files={"file": ("empty.pdf", b"", "application/pdf")},
    )
    assert empty_resp.status_code == 422

    # Null-byte and >128-char filenames -> 422
    pdf_bytes = _make_pdf()
    for bad_name in ("inv\x00.pdf", f"{'a' * 200}.pdf"):
        resp = client.post(
            "/api/v1/invoices/upload",
            headers=headers,
            files={"file": (bad_name, pdf_bytes, "application/pdf")},
        )
        assert resp.status_code == 422


def test_upload_blocks_fake_redis_in_production_and_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify USE_FAKE_REDIS=true is hard-blocked outside dev/local/test (CWE-489)."""
    for env in ("staging", "production", "prod"):
        monkeypatch.setenv("APP_ENV", env)
        monkeypatch.setenv("USE_FAKE_REDIS", "true")
        get_settings.cache_clear()
        reset_upload_dependencies()
        with pytest.raises(HTTPException) as exc_info:
            get_upload_redis_client()
        assert exc_info.value.status_code == 503
    reset_upload_dependencies()
    get_settings.cache_clear()


def test_upload_sets_no_store_cache_control_and_keyless_blob_url(upload_env: dict) -> None:
    """Verify 202 upload receipt sets Cache-Control: no-store and returns keyless blob URL (CWE-525)."""
    client: TestClient = upload_env["client"]
    resp = client.post(
        "/api/v1/invoices/upload",
        headers=_demo_auth_headers("sarah.clerk"),
        files={"file": ("receipt_check.pdf", _make_pdf(), "application/pdf")},
    )
    assert resp.status_code == 202
    assert resp.headers.get("Cache-Control") == "no-store"
    blob_url = resp.json()["blob_url"]
    assert blob_url.startswith("https://")
    assert "?" not in blob_url and "sig=" not in blob_url
