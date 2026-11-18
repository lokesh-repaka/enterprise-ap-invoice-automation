"""
Unit and Security Tests for the Ingestion Dashboard UI (P11-2).

Tests: FR-01, BR-001, GAP-004, P11-2, CLAUDE.md §4.2, §12, §16, PRD Screen 1
"""

import ast
import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from src.ui.api_client import APInvoiceAPIClient, APIRateLimitError
from src.ui.app import render_app
from src.ui.ingestion_dashboard import (
    ALLOWED_UPLOAD_EXTENSIONS,
    MAX_BATCH_FILES_PER_SUBMISSION,
    MAX_BATCH_TOTAL_BYTES,
    MAX_POLL_INTERVAL_SECONDS,
    MAX_POLL_ITEMS_PER_CYCLE,
    MAX_TRACKED_BATCH_ITEMS,
    MIN_POLL_INTERVAL_SECONDS,
    BatchInvoiceItem,
    IngestionDashboardController,
    PendingUploadFile,
    build_status_table_rows,
    compute_upload_idempotency_key,
    derive_detection_mode,
    format_file_size,
    render_ingestion_dashboard,
    sanitize_display_text,
    summarize_batch,
    validate_client_file,
    validate_poll_interval,
    validate_vendor_selection,
)


class _StatefulMockAPITransport(httpx.BaseTransport):
    """Fast in-memory HTTP transport mimicking all FastAPI routes used by the Ingestion Dashboard."""

    def __init__(self) -> None:
        self.invoices: dict[str, dict[str, Any]] = {}
        self.idem_to_id: dict[str, str] = {}
        self._counter = 0

    def set_invoice_state(self, invoice_id: str, status: str, confidence: str = "0.00") -> None:
        self.invoices[invoice_id]["status"] = status
        self.invoices[invoice_id]["confidence_macro_avg"] = confidence

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        now_iso = datetime(2026, 2, 15, 10, 30, 0, tzinfo=UTC).isoformat()

        if request.method == "GET" and path == "/health":
            return httpx.Response(200, json={"status": "healthy"}, request=request)

        if request.method == "GET" and path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"}, request=request)

        if request.method == "GET" and path == "/api/v1/auth/demo-personas":
            return httpx.Response(
                200,
                json={
                    "personas": [
                        {
                            "username": "sarah.clerk",
                            "email": "sarah.clerk@company.com",
                            "name": "Sarah Jenkins",
                            "role": "ap_clerk",
                            "entra_group": "AP-Clerks",
                        },
                        {
                            "username": "michael.manager",
                            "email": "michael.manager@company.com",
                            "name": "Michael Chen",
                            "role": "finance_manager",
                            "entra_group": "Finance-Managers",
                        },
                        {
                            "username": "dave.admin",
                            "email": "dave.admin@company.com",
                            "name": "Dave Patel",
                            "role": "system_admin",
                            "entra_group": "AP-Admins",
                        },
                    ]
                },
                request=request,
            )

        if request.method == "POST" and path == "/api/v1/auth/demo-token":
            return httpx.Response(
                200,
                json={
                    "access_token": "mock.demo.token",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "persona": "sarah.clerk",
                    "email": "sarah.clerk@company.com",
                    "name": "Sarah Jenkins",
                    "role": "ap_clerk",
                },
                request=request,
            )

        if request.method == "POST" and path == "/api/v1/invoices/upload":
            raw_body = request.read()
            idem_key = (
                request.headers.get("Idempotency-Key") or hashlib.sha256(raw_body).hexdigest()
            )
            # Extract filename & content-type from multipart headers
            body_text = raw_body.decode("latin-1", errors="ignore")
            filename = "invoice.pdf"
            if 'filename="' in body_text:
                filename = body_text.split('filename="', 1)[1].split('"', 1)[0]
            detected_mime = "image/png" if filename.lower().endswith(".png") else "application/pdf"
            vendor_id = "V-001" if 'name="vendor_id"' in body_text else "UNKNOWN"

            if idem_key in self.idem_to_id:
                existing_id = self.idem_to_id[idem_key]
                rec = self.invoices[existing_id]
                return httpx.Response(
                    200,
                    json={
                        "invoice_id": existing_id,
                        "status": rec["status"],
                        "queued": False,
                        "deduplicated": True,
                        "idempotency_key": idem_key,
                        "filename": filename,
                        "detected_mime": detected_mime,
                        "size_bytes": len(raw_body),
                        "file_hash": hashlib.sha256(raw_body).hexdigest(),
                        "blob_url": f"https://mockblob.blob.core.windows.net/raw/{existing_id}",
                        "vendor_id": vendor_id,
                        "uploaded_at": now_iso,
                    },
                    request=request,
                )

            self._counter += 1
            inv_id = f"inv-dash-{self._counter:03d}"
            self.idem_to_id[idem_key] = inv_id
            self.invoices[inv_id] = {
                "invoice_id": inv_id,
                "vendor_id": vendor_id,
                "vendor_tax_id": "US-12-3456789",
                "vendor_name": "Acme Technologies Inc.",
                "invoice_number": f"PENDING-{inv_id}",
                "total_amount": "0.00",
                "currency": "USD",
                "confidence_macro_avg": "0.00",
                "status": "UPLOADED",
                "created_at": now_iso,
                "updated_at": now_iso,
                "lines": [],
                "audit_event_count": 1,
            }
            return httpx.Response(
                202,
                json={
                    "invoice_id": inv_id,
                    "status": "UPLOADED",
                    "queued": True,
                    "deduplicated": False,
                    "idempotency_key": idem_key,
                    "filename": filename,
                    "detected_mime": detected_mime,
                    "size_bytes": len(raw_body),
                    "file_hash": hashlib.sha256(raw_body).hexdigest(),
                    "blob_url": f"https://mockblob.blob.core.windows.net/raw/{inv_id}",
                    "vendor_id": vendor_id,
                    "uploaded_at": now_iso,
                },
                request=request,
            )

        if request.method == "GET" and path.startswith("/api/v1/invoices/"):
            inv_id = path.rsplit("/", 1)[-1]
            if inv_id in self.invoices:
                return httpx.Response(200, json=self.invoices[inv_id], request=request)
            return httpx.Response(404, json={"detail": "Not found"}, request=request)

        return httpx.Response(404, json={"detail": "Unhandled route"}, request=request)


class _FakeColumn:
    def __init__(self, parent: "_FakeStreamlit") -> None:
        self._parent = parent

    def __enter__(self) -> "_FakeColumn":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self._parent.metrics[label] = value

    def button(self, label: str, **kwargs: Any) -> bool:
        return self._parent.button(label, **kwargs)

    def checkbox(self, label: str, value: bool = False, **kwargs: Any) -> bool:
        return self._parent.checkbox(label, value=value, **kwargs)

    def slider(self, label: str, min_value: float, max_value: float, value: float, **kwargs: Any):
        return self._parent.slider(label, min_value, max_value, value, **kwargs)

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return self._parent.selectbox(label, options, index=index, **kwargs)

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._parent.text_input(label, value=value, **kwargs)

    def caption(self, text: str) -> None:
        self._parent.captions.append(text)


class _FakeStreamlit:
    """Minimal headless Streamlit stub verifying P11-2 UI rendering offline."""

    def __init__(
        self,
        *,
        uploaded_files: list[Any] | None = None,
        button_clicks: set[str] | None = None,
        selected_persona: str = "sarah.clerk",
    ) -> None:
        self.session_state: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.dataframes: list[Any] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.infos: list[str] = []
        self.successes: list[str] = []
        self.captions: list[str] = []
        self.titles: list[str] = []
        self.subheaders: list[str] = []
        self._uploaded_files = uploaded_files or []
        self._button_clicks = button_clicks or set()
        self._selected_persona = selected_persona
        self.sidebar = self

    def set_page_config(self, **kwargs: Any) -> None:
        self.page_config = kwargs

    def title(self, text: str) -> None:
        self.titles.append(text)

    def header(self, text: str) -> None:
        self.titles.append(text)

    def subheader(self, text: str) -> None:
        self.subheaders.append(text)

    def markdown(self, text: str, **kwargs: Any) -> None:
        assert not kwargs.get("unsafe_allow_html"), "unsafe_allow_html is forbidden in src/ui/"

    def caption(self, text: str) -> None:
        self.captions.append(text)

    def info(self, text: str) -> None:
        self.infos.append(text)

    def warning(self, text: str) -> None:
        self.warnings.append(text)

    def error(self, text: str) -> None:
        self.errors.append(text)

    def success(self, text: str) -> None:
        self.successes.append(text)

    def divider(self) -> None:
        return None

    def columns(self, spec: Any) -> list[_FakeColumn]:
        count = spec if isinstance(spec, int) else len(spec)
        return [_FakeColumn(self) for _ in range(count)]

    def file_uploader(self, label: str, **kwargs: Any) -> list[Any]:
        self.last_uploader_kwargs = kwargs
        return list(self._uploaded_files)

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if self._selected_persona in options:
            return self._selected_persona
        return options[index]

    def radio(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return options[index]

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return value

    def button(self, label: str, **kwargs: Any) -> bool:
        return label in self._button_clicks

    def checkbox(self, label: str, value: bool = False, **kwargs: Any) -> bool:
        return value

    def slider(self, label: str, min_value: float, max_value: float, value: float, **kwargs: Any):
        return value

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self.dataframes.append(data)

    def rerun(self) -> None:
        return None


class _FakeUploadedFile:
    def __init__(self, name: str, data: bytes, file_type: str = "application/pdf") -> None:
        self.name = name
        self._data = data
        self.type = file_type

    def getvalue(self) -> bytes:
        return self._data


# ---------------------------------------------------------------------------
# Tests: FR-01, BR-001, GAP-004 — Client-side upload validation
# ---------------------------------------------------------------------------


def test_client_file_and_vendor_validation() -> None:
    """Validate allowed extensions, 25 MB limit, GAP-004 TIFF block, traversal & vendor rules."""
    assert ALLOWED_UPLOAD_EXTENSIONS == ("pdf", "jpg", "jpeg", "png", "xlsx")

    assert validate_client_file("invoice_001.pdf", b"%PDF-1.4 sample") == "invoice_001.pdf"
    assert validate_client_file("scan.PNG", b"\x89PNG\r\n\x1a\n") == "scan.PNG"
    assert validate_client_file("sheet.xlsx", b"PK\x03\x04") == "sheet.xlsx"

    with pytest.raises(ValueError, match="TIFF"):
        validate_client_file("scan.tiff", b"II*\x00")
    with pytest.raises(ValueError, match="TIFF"):
        validate_client_file("scan.TIF", b"MM\x00*")

    for bad_name in ("malware.exe", "xss.svg", "page.html", "noext"):
        with pytest.raises(ValueError):
            validate_client_file(bad_name, b"hello")

    for bad_name in (
        "../secret.pdf",
        "dir/invoice.pdf",
        "dir\\invoice.pdf",
        "inv\r\n.pdf",
        "inv\u202efdp.exe",
    ):
        with pytest.raises(ValueError):
            validate_client_file(bad_name, b"%PDF-1.4")

    with pytest.raises(ValueError, match="empty"):
        validate_client_file("empty.pdf", b"")
    with pytest.raises(ValueError, match="25"):
        validate_client_file("huge.pdf", b"x" * (25 * 1024 * 1024 + 1))

    assert validate_vendor_selection(None) is None
    assert validate_vendor_selection("") is None
    assert validate_vendor_selection("Auto-Detect") is None
    assert validate_vendor_selection("V-001") == "V-001"
    for bad_vendor in ("../etc", "V-001; DROP TABLE", "V\r\n001", "a" * 65):
        with pytest.raises(ValueError):
            validate_vendor_selection(bad_vendor)

    assert validate_poll_interval(3.0) == 3.0
    assert validate_poll_interval(MIN_POLL_INTERVAL_SECONDS) == MIN_POLL_INTERVAL_SECONDS
    assert validate_poll_interval(MAX_POLL_INTERVAL_SECONDS) == MAX_POLL_INTERVAL_SECONDS
    with pytest.raises(ValueError):
        validate_poll_interval(0.1)
    with pytest.raises(ValueError):
        validate_poll_interval(120.0)


# ---------------------------------------------------------------------------
# Tests: FR-01, CLAUDE.md §16.6 — Multi-file upload & idempotent replay
# ---------------------------------------------------------------------------


def test_submit_batch_multi_file_idempotency_and_partial_error() -> None:
    """Multi-file drag-and-drop upload handles mixed valid/invalid files and idempotent replay."""
    transport = _StatefulMockAPITransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        client.issue_demo_token("sarah.clerk")
        controller = IngestionDashboardController(client)

        pdf_bytes = b"%PDF-1.4 batch item 1"
        png_bytes = b"\x89PNG\r\n\x1a\n batch item 2"
        batch = [
            PendingUploadFile(
                filename="acme_inv1.pdf", content=pdf_bytes, content_type="application/pdf"
            ),
            PendingUploadFile(
                filename="scan_inv2.png", content=png_bytes, content_type="image/png"
            ),
            PendingUploadFile(
                filename="legacy.tiff", content=b"II*\x00", content_type="image/tiff"
            ),
        ]

        items = controller.submit_batch(batch, vendor_id="V-001", user_roles=["ap_clerk"])
        assert len(items) == 3
        by_name = {item.filename: item for item in items}

        assert by_name["acme_inv1.pdf"].status == "UPLOADED"
        assert by_name["acme_inv1.pdf"].invoice_id == "inv-dash-001"
        assert by_name["acme_inv1.pdf"].detection_mode == "PDF Document"
        assert by_name["acme_inv1.pdf"].deduplicated is False
        assert by_name["acme_inv1.pdf"].idempotency_key == compute_upload_idempotency_key(
            pdf_bytes, vendor_id="V-001"
        )

        assert by_name["scan_inv2.png"].status == "UPLOADED"
        assert by_name["scan_inv2.png"].detection_mode == "Scanned Image"

        assert by_name["legacy.tiff"].status == "UPLOAD_FAILED"
        assert by_name["legacy.tiff"].invoice_id is None
        assert "TIFF" in (by_name["legacy.tiff"].error_message or "")

        replayed_items = controller.submit_batch(
            [
                PendingUploadFile(
                    filename="acme_inv1.pdf", content=pdf_bytes, content_type="application/pdf"
                )
            ],
            vendor_id="V-001",
            existing_items=items,
            user_roles=["ap_clerk"],
        )
        assert len(replayed_items) == 3
        replayed_pdf = next(i for i in replayed_items if i.filename == "acme_inv1.pdf")
        assert replayed_pdf.invoice_id == "inv-dash-001"
        assert replayed_pdf.deduplicated is True


# ---------------------------------------------------------------------------
# Tests: PRD Screen 1 — Batch summary metrics & live status table formatting
# ---------------------------------------------------------------------------


def test_batch_summary_metrics_and_table_rows() -> None:
    """Verify Active Batch Summary counts and Live Status Table columns."""
    now = datetime(2026, 2, 15, 10, 30, 0, tzinfo=UTC)
    items = [
        BatchInvoiceItem(
            invoice_id="inv-1",
            filename="a.pdf",
            size_bytes=512,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-001",
            status="UPLOADED",
        ),
        BatchInvoiceItem(
            invoice_id="inv-2",
            filename="b.png",
            size_bytes=2048,
            uploaded_at=now,
            detected_mime="image/png",
            detection_mode="Scanned Image",
            vendor_id="V-002",
            status="EXTRACTING",
        ),
        BatchInvoiceItem(
            invoice_id="inv-3",
            filename="c.xlsx",
            size_bytes=3 * 1024 * 1024,
            uploaded_at=now,
            detected_mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            detection_mode="Excel Spreadsheet",
            vendor_id="V-003",
            status="VALIDATED",
            confidence_macro_avg=Decimal("96.40"),
            deduplicated=True,
        ),
        BatchInvoiceItem(
            invoice_id="inv-4",
            filename="d.pdf",
            size_bytes=10240,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-004",
            status="REJECTED_TAX_MISMATCH",
            confidence_macro_avg=Decimal("82.10"),
        ),
        BatchInvoiceItem(
            invoice_id=None,
            filename="bad.tiff",
            size_bytes=100,
            uploaded_at=now,
            detected_mime=None,
            detection_mode="Unsupported",
            vendor_id="UNKNOWN",
            status="UPLOAD_FAILED",
            error_message="TIFF files are not supported (GAP-004)",
        ),
    ]

    summary = summarize_batch(items)
    assert summary.total_uploaded == 4
    assert summary.processing == 2
    assert summary.passed == 1
    assert summary.needs_review == 1
    assert summary.failed == 1
    assert summary.deduplicated_count == 1

    assert format_file_size(512) == "512 B"
    assert format_file_size(2048) == "2.0 KB"
    assert format_file_size(3 * 1024 * 1024) == "3.00 MB"
    assert derive_detection_mode("application/pdf") == "PDF Document"
    assert derive_detection_mode("image/jpeg") == "Scanned Image"
    assert (
        derive_detection_mode("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        == "Excel Spreadsheet"
    )

    rows = build_status_table_rows(items)
    assert len(rows) == 5
    required_cols = {
        "Invoice ID",
        "File Name",
        "File Size",
        "Upload Time",
        "Detection Mode",
        "Real-Time Status",
        "Confidence",
        "Vendor",
        "Notes",
        "Route",
    }
    assert required_cols.issubset(rows[0].keys())
    assert rows[2]["Confidence"] == "96.4%"
    assert "Replayed" in rows[2]["Notes"]
    assert rows[2]["Route"] == "/workbench/inv-3"
    assert rows[4]["Invoice ID"] == "—"


# ---------------------------------------------------------------------------
# Tests: Live polling loop transitions, terminal skip, max cycles, and 429 backoff
# ---------------------------------------------------------------------------


def test_live_polling_updates_status_and_stops_when_terminal() -> None:
    """Live polling calls GET /invoices/{id} only for in-progress rows and halts once terminal."""
    transport = _StatefulMockAPITransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        client.issue_demo_token("sarah.clerk")
        controller = IngestionDashboardController(client)

        items = controller.submit_batch(
            [
                PendingUploadFile(
                    filename="poll_me.pdf",
                    content=b"%PDF-1.4 poll",
                    content_type="application/pdf",
                )
            ],
            vendor_id="V-001",
            user_roles=["ap_clerk"],
        )
        invoice_id = items[0].invoice_id
        assert invoice_id is not None

        transport.set_invoice_state(invoice_id, "EXTRACTING")
        updated1, result1 = controller.poll_batch_once(items, poll_cycle_count=0)
        assert result1.polled_count == 1
        assert result1.updated_count == 1
        assert result1.remaining_in_progress == 1
        assert result1.should_continue_polling is True
        assert updated1[0].status == "EXTRACTING"

        _, capped_result = controller.poll_batch_once(
            updated1, poll_cycle_count=59, max_poll_cycles=60
        )
        assert capped_result.should_continue_polling is False

        transport.set_invoice_state(invoice_id, "VALIDATED", "95.25")
        updated2, result2 = controller.poll_batch_once(updated1, poll_cycle_count=1)
        assert result2.polled_count == 1
        assert result2.updated_count == 1
        assert result2.remaining_in_progress == 0
        assert result2.should_continue_polling is False
        assert updated2[0].status == "VALIDATED"
        assert updated2[0].confidence_macro_avg == Decimal("95.25")

        _, result3 = controller.poll_batch_once(updated2, poll_cycle_count=2)
        assert result3.polled_count == 0
        assert result3.should_continue_polling is False


def test_live_polling_backs_off_on_rate_limit() -> None:
    """HTTP 429 rate-limit during polling pauses auto-poll gracefully without crashing."""

    class _RateLimitedClient:
        def get_invoice(self, invoice_id: str) -> Any:
            raise APIRateLimitError("Rate limit exceeded", status_code=429)

    controller = IngestionDashboardController(_RateLimitedClient())  # type: ignore[arg-type]
    now = datetime.now(UTC)
    items = [
        BatchInvoiceItem(
            invoice_id="inv-429",
            filename="rate_limited.pdf",
            size_bytes=1024,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-001",
            status="UPLOADED",
        )
    ]

    updated, result = controller.poll_batch_once(items)
    assert result.polled_count == 1
    assert result.should_continue_polling is False
    assert "inv-429" in result.errors
    assert "429" in result.errors["inv-429"] or "rate" in result.errors["inv-429"].lower()
    assert updated[0].status == "UPLOADED"


# ---------------------------------------------------------------------------
# Tests: RBAC guard, Batch DoS cap, & Session State Memory cap
# ---------------------------------------------------------------------------


def test_role_guard_and_batch_caps() -> None:
    """Enforce upload RBAC, 50-file per-submission cap, and 500-row session cap."""
    transport = _StatefulMockAPITransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = IngestionDashboardController(client)
        sample = PendingUploadFile(filename="a.pdf", content=b"%PDF-1.4 sample")

        with pytest.raises(PermissionError, match="ap_clerk"):
            controller.submit_batch([sample], user_roles=["system_admin"])
        with pytest.raises(PermissionError):
            controller.submit_batch([sample], user_roles=[])

        too_many = [
            PendingUploadFile(filename=f"f{i}.pdf", content=b"%PDF-1.4")
            for i in range(MAX_BATCH_FILES_PER_SUBMISSION + 1)
        ]
        with pytest.raises(ValueError, match=str(MAX_BATCH_FILES_PER_SUBMISSION)):
            controller.submit_batch(too_many, user_roles=["ap_clerk"])

        now = datetime.now(UTC)
        existing = [
            BatchInvoiceItem(
                invoice_id=f"old-{i}",
                filename=f"old_{i}.pdf",
                size_bytes=100,
                uploaded_at=now,
                detected_mime="application/pdf",
                detection_mode="PDF Document",
                vendor_id="V-001",
                status="VALIDATED",
            )
            for i in range(MAX_TRACKED_BATCH_ITEMS)
        ]
        merged = controller.submit_batch([sample], existing_items=existing, user_roles=["ap_clerk"])
        assert len(merged) == MAX_TRACKED_BATCH_ITEMS


# ---------------------------------------------------------------------------
# Tests: Security — XSS, CSV formula injection, bidi spoofing, & secret redaction
# ---------------------------------------------------------------------------


def test_display_sanitization_blocks_xss_formula_and_bidi() -> None:
    """Neutralize CSV formula prefixes, HTML/unclosed tags, path routes, control/bidi, and tokens (SEC-191)."""
    assert not sanitize_display_text("=CMD|' /C calc'!A0").startswith("=")
    assert not sanitize_display_text("+SUM(A1:A2)").startswith("+")
    assert not sanitize_display_text("-1+1").startswith("-")
    assert not sanitize_display_text("@HYPERLINK()").startswith("@")
    cleaned_html = sanitize_display_text("<script>alert(1)</script><img src=x onerror=alert(1)")
    assert "<" not in cleaned_html and ">" not in cleaned_html
    cleaned_bidi = sanitize_display_text("inv\u202e\r\n.pdf")
    assert "\u202e" not in cleaned_bidi
    assert "\r" not in cleaned_bidi and "\n" not in cleaned_bidi

    now = datetime.now(UTC)
    malicious_item = BatchInvoiceItem(
        invoice_id="../../admin",
        filename='=HYPERLINK("http://evil.com").pdf',
        size_bytes=256,
        uploaded_at=now,
        detected_mime="application/pdf",
        detection_mode="PDF Document",
        vendor_id="V-001",
        status="UPLOAD_FAILED",
        error_message="Bearer eyJhbGciOiJSUzI1NiJ9.secret.sig failed",
    )
    rows = build_status_table_rows([malicious_item])
    assert not rows[0]["File Name"].startswith("=")
    assert "eyJhbGciOiJSUzI1NiJ9" not in rows[0]["Notes"]
    # SEC-191: malformed invoice_id must never produce a traversal route
    assert rows[0]["Invoice ID"] == "—"
    assert rows[0]["Route"] == "—"


def test_security_batch_bytes_cap_poll_cap_and_session_isolation() -> None:
    """Verify SEC-192 (100 MB batch cap), SEC-193 (session purge & unauth guard), SEC-194 (poll caps)."""
    transport = _StatefulMockAPITransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = IngestionDashboardController(client)

        # SEC-192: 5 x 21 MB = 105 MB > 100 MB cumulative batch cap rejected pre-upload
        oversized_batch = [
            PendingUploadFile(filename=f"big_{i}.pdf", content=b"x" * (21 * 1024 * 1024))
            for i in range(5)
        ]
        assert sum(len(f.content) for f in oversized_batch) > MAX_BATCH_TOTAL_BYTES
        with pytest.raises(ValueError, match="100 MB"):
            controller.submit_batch(oversized_batch, user_roles=["ap_clerk"])

        # SEC-194: Polling caps requests per cycle at MAX_POLL_ITEMS_PER_CYCLE and clamps max_poll_cycles
        now = datetime.now(UTC)
        many_in_progress = [
            BatchInvoiceItem(
                invoice_id=f"inv-p-{i}",
                filename=f"f_{i}.pdf",
                size_bytes=128,
                uploaded_at=now,
                detected_mime="application/pdf",
                detection_mode="PDF Document",
                vendor_id="V-001",
                status="UPLOADED",
            )
            for i in range(MAX_POLL_ITEMS_PER_CYCLE + 10)
        ]
        _, poll_res = controller.poll_batch_once(
            many_in_progress, poll_cycle_count=60, max_poll_cycles=10_000
        )
        assert poll_res.polled_count == MAX_POLL_ITEMS_PER_CYCLE
        assert poll_res.should_continue_polling is False

        # SEC-193: Unauthenticated user fails closed (cannot upload); Sign Out purges batch_items
        unauth_st = _FakeStreamlit(
            uploaded_files=[_FakeUploadedFile("unauth.pdf", b"%PDF-1.4", "application/pdf")],
            button_clicks={"Upload Selected Invoices"},
        )
        render_app(api_client=client, st_module=unauth_st)
        assert unauth_st.metrics["Total Uploaded"] == 0
        assert any("read-only" in msg.lower() for msg in unauth_st.infos)

        signout_st = _FakeStreamlit(button_clicks={"Sign Out"})
        signout_st.session_state["user_email"] = "sarah.clerk@company.com"
        signout_st.session_state["user_roles"] = ["ap_clerk"]
        signout_st.session_state["access_token"] = "mock.token"
        signout_st.session_state["batch_items"] = many_in_progress[:2]
        render_app(api_client=client, st_module=signout_st)
        assert "batch_items" not in signout_st.session_state
        assert "access_token" not in signout_st.session_state
        assert client.is_authenticated is False


# ---------------------------------------------------------------------------
# Tests: Headless Streamlit renderer smoke test + AST layering hygiene
# ---------------------------------------------------------------------------


def test_streamlit_renderer_and_app_shell_smoke() -> None:
    """Render Ingestion Dashboard and main app shell headlessly."""
    transport = _StatefulMockAPITransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        fake_st = _FakeStreamlit(
            uploaded_files=[_FakeUploadedFile("headless.pdf", b"%PDF-1.4 ui", "application/pdf")],
            button_clicks={
                "Sign In as Demo Persona",
                "Upload Selected Invoices",
                "Refresh Status Now",
            },
            selected_persona="sarah.clerk",
        )

        render_app(api_client=client, st_module=fake_st)

        assert any("Ingestion Dashboard" in t for t in fake_st.titles)
        assert "Total Uploaded" in fake_st.metrics
        assert fake_st.metrics["Total Uploaded"] == 1
        assert fake_st.metrics["Processing"] == 1
        assert len(fake_st.dataframes) >= 1
        assert len(fake_st.dataframes[-1]) == 1
        assert fake_st.dataframes[-1][0]["File Name"] == "headless.pdf"

        fake_st_direct = _FakeStreamlit()
        render_ingestion_dashboard(client, st_module=fake_st_direct)
        assert "Total Uploaded" in fake_st_direct.metrics


def test_ui_modules_obey_layering_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2 & §12: src/ui/ must not import backend internals or use unsafe_allow_html."""
    forbidden_prefixes = (
        "src.database",
        "src.storage",
        "src.extraction",
        "src.validation",
        "src.services",
        "sqlalchemy",
        "redis",
        "fakeredis",
        "openai",
        "azure",
    )
    for rel_path in ("src/ui/ingestion_dashboard.py", "src/ui/app.py"):
        source = Path(rel_path).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"Forbidden import in {rel_path}: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_prefixes), (
                    f"Forbidden import in {rel_path}: {node.module}"
                )
            elif isinstance(node, ast.keyword) and node.arg == "unsafe_allow_html":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    raise AssertionError(f"unsafe_allow_html=True is forbidden in {rel_path}")
