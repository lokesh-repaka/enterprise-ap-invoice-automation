"""
Unit and Security Tests for the Review Workbench UI (P11-3).

Tests: FR-12, BR-004, BR-005, BR-016, BR-017, PRD Screen 2, CLAUDE.md §4.2, §12, P11-3
"""

import ast
import json
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import fitz
import httpx
import pytest

from src.api.schemas.invoices import (
    InvoiceDetailResponse,
    InvoiceLineResponse,
    ReasonCode,
)
from src.ui.api_client import APInvoiceAPIClient
from src.ui.app import PAGE_WORKBENCH, render_app
from src.ui.review_workbench import (
    EDITABLE_HEADER_FIELDS,
    EDITABLE_LINE_FIELDS,
    MAX_PREVIEW_BYTES,
    MAX_PREVIEW_ZOOM,
    MIN_PREVIEW_ZOOM,
    REVALIDATE_ALLOWED_ROLES,
    HeaderFormDraft,
    LineFormDraft,
    ReviewWorkbenchController,
    build_editable_line_rows,
    build_revalidate_request,
    can_approve_in_workbench,
    can_revalidate_in_workbench,
    classify_confidence_cue,
    extract_safe_document_url,
    mask_tax_id,
    render_document_preview,
    render_review_workbench,
)


def _make_multipage_pdf(pages: int = 2) -> bytes:
    doc = fitz.open()
    for idx in range(pages):
        page = doc.new_page(width=80, height=100)
        page.insert_text((8, 20), f"Page {idx + 1}")
    raw = doc.tobytes()
    doc.close()
    return raw


def _make_sample_invoice_detail(
    *,
    invoice_id: str = "inv-wb-001",
    status: str = "REJECTED_TAX_MISMATCH",
    total_amount: Decimal = Decimal("1050.00"),
    total_amount_usd: Decimal = Decimal("1050.00"),
    confidence: Decimal = Decimal("88.00"),
    blob_raw_url: str | None = "https://mockblob.blob.core.windows.net/raw/inv-wb-001.pdf",
) -> InvoiceDetailResponse:
    now = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    return InvoiceDetailResponse(
        invoice_id=invoice_id,
        vendor_id="V-001",
        vendor_tax_id="US-12-3456789",
        vendor_name="Acme Technologies Inc.",
        invoice_number="INV-WB-2026-001",
        invoice_date=date(2026, 2, 10),
        due_date=date(2026, 3, 10),
        po_number="PO-WB-100",
        subtotal=Decimal("1000.00"),
        total_tax_amount=Decimal("50.00"),
        total_amount=total_amount,
        currency="USD",
        total_amount_usd=total_amount_usd,
        confidence_macro_avg=confidence,
        status=status,
        blob_raw_url=blob_raw_url,
        blob_json_url=None,
        created_at=now,
        updated_at=now,
        lines=[
            InvoiceLineResponse(
                line_id="line-1",
                line_number=1,
                description="Enterprise Cloud Plan",
                quantity=Decimal("10.0000"),
                unit_price=Decimal("100.0000"),
                line_total=Decimal("1000.00"),
                line_tax_rate=Decimal("0.0800"),
                confidence_score=Decimal("88.00"),
            )
        ],
        audit_event_count=2,
    )


class _WorkbenchMockTransport(httpx.BaseTransport):
    """Fast in-memory HTTP transport for Review Workbench unit tests."""

    def __init__(self, initial_invoice: InvoiceDetailResponse | None = None) -> None:
        self.invoice = initial_invoice or _make_sample_invoice_detail()
        self.last_revalidate_body: dict[str, Any] | None = None
        self.last_approve_body: dict[str, Any] | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == "/health":
            return httpx.Response(200, json={"status": "healthy"}, request=request)
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
                        }
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
        if request.method == "GET" and path == f"/api/v1/invoices/{self.invoice.invoice_id}":
            return httpx.Response(200, json=self.invoice.model_dump(mode="json"), request=request)
        if (
            request.method == "POST"
            and path == f"/api/v1/invoices/{self.invoice.invoice_id}/revalidate"
        ):
            payload = json.loads(request.read().decode("utf-8"))
            self.last_revalidate_body = payload
            prev_status = self.invoice.status
            updates: dict[str, Any] = {
                "status": "VALIDATED",
                "confidence_macro_avg": Decimal("95.00"),
                "audit_event_count": self.invoice.audit_event_count + 1,
            }
            edited_fields: list[str] = []
            if "header_edits" in payload:
                for k, v in payload["header_edits"].items():
                    updates[k] = (
                        Decimal(str(v))
                        if k in ("subtotal", "total_tax_amount", "total_amount")
                        else v
                    )
                    edited_fields.append(k)
            if payload.get("is_reverse_charge"):
                edited_fields.append("is_reverse_charge")
            self.invoice = self.invoice.model_copy(update=updates)
            return httpx.Response(
                200,
                json={
                    "invoice_id": self.invoice.invoice_id,
                    "previous_status": prev_status,
                    "status": "VALIDATED",
                    "is_revalidated": True,
                    "validation_summary": {
                        "line_arithmetic_valid": True,
                        "invoice_total_valid": True,
                        "tax_valid": True,
                        "date_valid": True,
                        "all_passed": True,
                        "currency_converted_amount_usd": str(self.invoice.total_amount),
                        "active_exceptions": [],
                    },
                    "confidence_tier": "VALIDATED",
                    "confidence_macro_avg": "95.00",
                    "eligible_for_clerk_approval": True,
                    "requires_manager_approval": False,
                    "audit_event_id": "aud-reval-001",
                    "edited_fields": edited_fields or ["total_tax_amount"],
                },
                request=request,
            )
        if (
            request.method == "POST"
            and path == f"/api/v1/invoices/{self.invoice.invoice_id}/approve"
        ):
            payload = json.loads(request.read().decode("utf-8") or "{}")
            self.last_approve_body = payload
            prev_status = self.invoice.status
            self.invoice = self.invoice.model_copy(
                update={
                    "status": "APPROVED_CLERK",
                    "audit_event_count": self.invoice.audit_event_count + 1,
                }
            )
            return httpx.Response(
                200,
                json={
                    "invoice_id": self.invoice.invoice_id,
                    "previous_status": prev_status,
                    "status": "APPROVED_CLERK",
                    "approved_by": "sarah.clerk@company.com",
                    "approver_role": "ap_clerk",
                    "total_amount": str(self.invoice.total_amount),
                    "currency": self.invoice.currency,
                    "total_amount_usd": str(self.invoice.total_amount),
                    "high_value_threshold_usd": "10000.00",
                    "requires_manager_approval": False,
                    "audit_event_id": "aud-app-001",
                    "approved_at": datetime(2026, 2, 15, 11, 0, 0, tzinfo=UTC).isoformat(),
                },
                request=request,
            )
        return httpx.Response(404, json={"detail": "Not found"}, request=request)


class _FakeCol:
    def __init__(self, st: "_FakeWorkbenchStreamlit") -> None:
        self._st = st

    def __enter__(self) -> "_FakeCol":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self._st.metrics[label] = value

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._st.text_input(label, value=value, **kwargs)

    def number_input(self, label: str, value: Any = 0, **kwargs: Any) -> Any:
        return self._st.number_input(label, value=value, **kwargs)

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return self._st.selectbox(label, options, index=index, **kwargs)

    def checkbox(self, label: str, value: bool = False, **kwargs: Any) -> bool:
        return self._st.checkbox(label, value=value, **kwargs)

    def slider(self, label: str, min_value: float, max_value: float, value: float, **kwargs: Any):
        return self._st.slider(label, min_value, max_value, value, **kwargs)

    def button(self, label: str, **kwargs: Any) -> bool:
        return self._st.button(label, **kwargs)

    def image(self, img: bytes, **kwargs: Any) -> None:
        self._st.images.append(img)

    def caption(self, text: str) -> None:
        self._st.captions.append(text)

    def subheader(self, text: str) -> None:
        self._st.subheaders.append(text)

    def info(self, text: str) -> None:
        self._st.infos.append(text)

    def warning(self, text: str) -> None:
        self._st.warnings.append(text)

    def error(self, text: str) -> None:
        self._st.errors.append(text)

    def success(self, text: str) -> None:
        self._st.successes.append(text)

    def data_editor(self, data: Any, **kwargs: Any) -> Any:
        return self._st.data_editor(data, **kwargs)

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self._st.dataframes.append(data)


class _FakeWorkbenchStreamlit:
    """Headless Streamlit stub for testing split-screen Review Workbench rendering."""

    def __init__(
        self,
        *,
        text_overrides: dict[str, str] | None = None,
        button_clicks: set[str] | None = None,
        selected_page: str = PAGE_WORKBENCH,
        checkbox_overrides: dict[str, bool] | None = None,
        selectbox_overrides: dict[str, Any] | None = None,
        uploaded_preview: Any = None,
    ) -> None:
        self.session_state: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.images: list[bytes] = []
        self.dataframes: list[Any] = []
        self.titles: list[str] = []
        self.subheaders: list[str] = []
        self.captions: list[str] = []
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.successes: list[str] = []
        self._text_overrides = text_overrides or {}
        self._button_clicks = button_clicks or set()
        self._selected_page = selected_page
        self._checkbox_overrides = checkbox_overrides or {}
        self._selectbox_overrides = selectbox_overrides or {}
        self._uploaded_preview = uploaded_preview
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
        assert not kwargs.get("unsafe_allow_html"), "unsafe_allow_html is forbidden"

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

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self.metrics[label] = value

    def columns(self, spec: Any) -> list[_FakeCol]:
        count = spec if isinstance(spec, int) else len(spec)
        return [_FakeCol(self) for _ in range(count)]

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._text_overrides.get(label, value)

    def text_area(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._text_overrides.get(label, value)

    def number_input(self, label: str, value: Any = 0, **kwargs: Any) -> Any:
        return value

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if label in self._selectbox_overrides:
            return self._selectbox_overrides[label]
        return options[index]

    def radio(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if self._selected_page in options:
            return self._selected_page
        return options[index]

    def checkbox(self, label: str, value: bool = False, **kwargs: Any) -> bool:
        return self._checkbox_overrides.get(label, value)

    def slider(self, label: str, min_value: float, max_value: float, value: float, **kwargs: Any):
        return value

    def button(self, label: str, **kwargs: Any) -> bool:
        return label in self._button_clicks

    def file_uploader(self, label: str, **kwargs: Any) -> Any:
        return self._uploaded_preview

    def image(self, img: bytes, **kwargs: Any) -> None:
        self.images.append(img)

    def data_editor(self, data: Any, **kwargs: Any) -> Any:
        self.dataframes.append(data)
        return data

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self.dataframes.append(data)


# ---------------------------------------------------------------------------
# Tests: Confidence Cues & Tax ID PII Masking
# ---------------------------------------------------------------------------


def test_confidence_cue_and_tax_id_masking() -> None:
    """Verify CLAUDE.md §12 tri-tier confidence color cues and Tax ID masking."""
    green = classify_confidence_cue(Decimal("94.50"))
    assert green.tier == "HIGH"
    assert green.hex_color == "#22c55e"

    yellow = classify_confidence_cue(Decimal("85.00"))
    assert yellow.tier == "REVIEW"
    assert yellow.hex_color == "#fef08a"

    low = classify_confidence_cue(Decimal("79.99"))
    assert low.tier == "LOW"
    assert low.hex_color in ("#f97316", "#ef4444")

    assert mask_tax_id("US-12-3456789") == "***-**-6789"
    assert mask_tax_id("DE123") == "***-**-E123"
    assert mask_tax_id("AB") == "***"


# ---------------------------------------------------------------------------
# Tests: Split-Screen PDF / Image Document Viewer & Bounds Guards
# ---------------------------------------------------------------------------


def test_pdf_preview_renderer_and_security_guards() -> None:
    """Render multi-page PDF safely with zoom/page bounds; block oversized/corrupt payloads."""
    pdf_bytes = _make_multipage_pdf(pages=3)

    page0 = render_document_preview(pdf_bytes, filename="inv.pdf", page_index=0, zoom=1.5)
    assert page0.page_count == 3
    assert page0.page_index == 0
    assert page0.png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert page0.zoom == 1.5

    # Out-of-range page index clamps safely; zoom clamps to [MIN_PREVIEW_ZOOM, MAX_PREVIEW_ZOOM]
    clamped = render_document_preview(pdf_bytes, filename="inv.pdf", page_index=99, zoom=10.0)
    assert clamped.page_index == 2
    assert clamped.zoom == MAX_PREVIEW_ZOOM

    low_zoom = render_document_preview(pdf_bytes, filename="inv.pdf", page_index=-5, zoom=0.05)
    assert low_zoom.page_index == 0
    assert low_zoom.zoom == MIN_PREVIEW_ZOOM

    # Empty, oversized (>25 MB), disallowed extensions (TIFF/SVG), NaN zoom, and corrupt payloads fail closed (SEC-195)
    with pytest.raises(ValueError, match="empty"):
        render_document_preview(b"", filename="inv.pdf")
    with pytest.raises(ValueError, match="25"):
        render_document_preview(b"x" * (MAX_PREVIEW_BYTES + 1), filename="inv.pdf")
    with pytest.raises(ValueError, match="TIFF"):
        render_document_preview(pdf_bytes, filename="scan.tiff")
    with pytest.raises(ValueError, match="Unsupported preview"):
        render_document_preview(pdf_bytes, filename="xss.svg")
    with pytest.raises(ValueError, match="zoom"):
        render_document_preview(pdf_bytes, filename="inv.pdf", zoom=float("nan"))
    with pytest.raises(ValueError, match="corrupt|render|unsupported"):
        render_document_preview(b"not-a-pdf-at-all", filename="inv.pdf")


# ---------------------------------------------------------------------------
# Tests: FR-12, BR-016, BR-017, P9-4 — Smart Diff Builder & No-Op Guard
# ---------------------------------------------------------------------------


def test_build_revalidate_request_smart_diff_and_noop_prevention() -> None:
    """Emit only actually modified fields; block client-side no-op, missing OTHER comment, and invalid tax flag combos."""
    detail = _make_sample_invoice_detail()
    unchanged_header = HeaderFormDraft.from_invoice(detail)
    unchanged_lines = [LineFormDraft.from_line(line) for line in detail.lines]

    # Unchanged draft (even with different decimal scale "1000" vs "1000.00") is rejected as no-op
    same_scale_header = unchanged_header.model_copy(update={"subtotal": "1000"})
    with pytest.raises(ValueError, match="[Nn]o changes|[Nn]o-op"):
        build_revalidate_request(
            detail,
            header_draft=same_scale_header,
            line_drafts=unchanged_lines,
            reason_code=ReasonCode.OCR_MISREAD,
        )

    # ReasonCode.OTHER requires non-empty comment
    edited_header = unchanged_header.model_copy(
        update={"total_tax_amount": "80.00", "total_amount": "1080.00"}
    )
    with pytest.raises(ValueError, match="comment"):
        build_revalidate_request(
            detail,
            header_draft=edited_header,
            line_drafts=unchanged_lines,
            reason_code=ReasonCode.OTHER,
            comment="   ",
        )

    # is_reverse_charge requires TAX_CODE_OVERRIDE or OTHER
    with pytest.raises(ValueError, match="TAX_CODE_OVERRIDE"):
        build_revalidate_request(
            detail,
            header_draft=unchanged_header,
            line_drafts=unchanged_lines,
            reason_code=ReasonCode.OCR_MISREAD,
            is_reverse_charge=True,
        )

    # Smart diff emits ONLY changed header + line fields (omitting untouched fields!)
    edited_lines = [
        unchanged_lines[0].model_copy(update={"unit_price": "100.0000", "line_tax_rate": "0.0800"})
    ]
    req = build_revalidate_request(
        detail,
        header_draft=edited_header,
        line_drafts=edited_lines,
        reason_code=ReasonCode.OCR_MISREAD,
        comment="Corrected 8% US sales tax",
    )
    assert req.header_edits is not None
    assert req.header_edits.total_tax_amount == Decimal("80.00")
    assert req.header_edits.total_amount == Decimal("1080.00")
    assert req.header_edits.subtotal is None  # untouched!
    assert req.header_edits.invoice_number is None  # untouched!
    assert req.line_edits == []  # untouched!

    # Line-only edit emits only the changed line column
    line_changed = [unchanged_lines[0].model_copy(update={"description": "Cloud Plan Pro"})]
    req_line = build_revalidate_request(
        detail,
        header_draft=unchanged_header,
        line_drafts=line_changed,
        reason_code=ReasonCode.OCR_MISREAD,
    )
    assert req_line.header_edits is None
    assert len(req_line.line_edits) == 1
    assert req_line.line_edits[0].description == "Cloud Plan Pro"
    assert req_line.line_edits[0].quantity is None


# ---------------------------------------------------------------------------
# Tests: Controller Load -> Re-Validate -> Approve Flow
# ---------------------------------------------------------------------------


def test_workbench_controller_load_revalidate_and_approve() -> None:
    """Exercise full load -> edit -> Re-Validate -> Approve flow via APInvoiceAPIClient."""
    transport = _WorkbenchMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ReviewWorkbenchController(client)

        invoice = controller.load_invoice("inv-wb-001")
        assert invoice.status == "REJECTED_TAX_MISMATCH"

        header = HeaderFormDraft.from_invoice(invoice).model_copy(
            update={"total_tax_amount": "80.00", "total_amount": "1080.00"}
        )
        lines = [LineFormDraft.from_line(line) for line in invoice.lines]

        reval_resp, refreshed = controller.submit_revalidation(
            invoice,
            header_draft=header,
            line_drafts=lines,
            reason_code=ReasonCode.OCR_MISREAD,
            comment="Fixed tax misread",
            user_roles=["ap_clerk"],
        )
        assert reval_resp.status == "VALIDATED"
        assert reval_resp.validation_summary.all_passed is True
        assert refreshed.status == "VALIDATED"
        assert transport.last_revalidate_body is not None
        assert transport.last_revalidate_body["reason_code"] == "OCR_MISREAD"

        approve_resp, approved_inv = controller.submit_approval(
            refreshed,
            user_roles=["ap_clerk"],
            high_value_threshold_usd=Decimal("10000.00"),
        )
        assert approve_resp.status == "APPROVED_CLERK"
        assert approved_inv.status == "APPROVED_CLERK"


# ---------------------------------------------------------------------------
# Tests: RBAC & Role-Aware Approval Visibility (CLAUDE.md §12)
# ---------------------------------------------------------------------------


def test_workbench_rbac_and_approval_visibility_guards() -> None:
    """Enforce edit RBAC, hide Approve for ap_clerk > $10k, and block editing terminal invoices."""
    assert REVALIDATE_ALLOWED_ROLES == frozenset({"ap_clerk", "finance_manager"})

    low_val_valid = _make_sample_invoice_detail(
        status="VALIDATED",
        total_amount=Decimal("2500.00"),
        total_amount_usd=Decimal("2500.00"),
        confidence=Decimal("95.00"),
    )
    high_val_valid = _make_sample_invoice_detail(
        status="REQUIRES_MANAGER_APPROVAL",
        total_amount=Decimal("15000.00"),
        total_amount_usd=Decimal("15000.00"),
        confidence=Decimal("96.00"),
    )
    already_approved = _make_sample_invoice_detail(status="APPROVED_CLERK")

    # Re-validate permissions
    assert can_revalidate_in_workbench(low_val_valid, ["ap_clerk"]) is True
    assert can_revalidate_in_workbench(low_val_valid, ["finance_manager"]) is True
    assert can_revalidate_in_workbench(low_val_valid, ["system_admin"]) is False
    assert can_revalidate_in_workbench(low_val_valid, []) is False
    assert can_revalidate_in_workbench(already_approved, ["ap_clerk"]) is False

    # Approval visibility (CLAUDE.md §12: hide Approve for ap_clerk when total > $10,000)
    assert can_approve_in_workbench(low_val_valid, ["ap_clerk"], Decimal("10000.00")) is True
    assert can_approve_in_workbench(high_val_valid, ["ap_clerk"], Decimal("10000.00")) is False
    assert (
        can_approve_in_workbench(high_val_valid, ["finance_manager"], Decimal("10000.00")) is True
    )
    assert can_approve_in_workbench(low_val_valid, ["system_admin"], Decimal("10000.00")) is False
    assert can_approve_in_workbench(already_approved, ["ap_clerk"], Decimal("10000.00")) is False

    # Controller hard-enforces RBAC before calling backend
    transport = _WorkbenchMockTransport(high_val_valid)
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ReviewWorkbenchController(client)
        with pytest.raises(PermissionError, match="ap_clerk|finance_manager"):
            controller.submit_revalidation(
                low_val_valid,
                header_draft=HeaderFormDraft.from_invoice(low_val_valid).model_copy(
                    update={"po_number": "PO-NEW"}
                ),
                line_drafts=[LineFormDraft.from_line(line) for line in low_val_valid.lines],
                reason_code=ReasonCode.OCR_MISREAD,
                user_roles=["system_admin"],
            )
        with pytest.raises(PermissionError, match="Finance Manager|10000|approval"):
            controller.submit_approval(
                high_val_valid,
                user_roles=["ap_clerk"],
                high_value_threshold_usd=Decimal("10000.00"),
            )


# ---------------------------------------------------------------------------
# Tests: Security — Allowlist, URL/SSRF Guard, Formula Sanitization & Bounds
# ---------------------------------------------------------------------------


def test_workbench_security_sanitization_and_ssrf_guards() -> None:
    """Verify allowlisted fields, safe URL filtering, line sanitization, and invoice_id validation."""
    assert "status" not in EDITABLE_HEADER_FIELDS
    assert "confidence_macro_avg" not in EDITABLE_HEADER_FIELDS
    assert "vendor_tax_id" not in EDITABLE_HEADER_FIELDS
    assert "confidence_score" not in EDITABLE_LINE_FIELDS

    # Unsafe blob URL schemes rejected (anti-XSS / anti-SSRF / anti-local-file)
    assert (
        extract_safe_document_url("https://storage.blob.core.windows.net/raw/inv.pdf") is not None
    )
    assert extract_safe_document_url("javascript:alert(1)") is None
    assert extract_safe_document_url("file:///etc/passwd") is None
    assert extract_safe_document_url("http://169.254.169.254/latest/meta-data/") is None
    assert extract_safe_document_url("data:text/html,<script>alert(1)</script>") is None

    # Malicious line description sanitized for display table
    detail = _make_sample_invoice_detail()
    malicious_line = detail.lines[0].model_copy(
        update={"description": "=CMD|' /C calc'!A0 <script>alert(1)</script>"}
    )
    rows = build_editable_line_rows([malicious_line])
    assert "<script>" not in rows[0]["Description"]
    assert not rows[0]["Description"].startswith("=")

    # Invalid invoice_id blocked before HTTP call
    transport = _WorkbenchMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ReviewWorkbenchController(client)
        with pytest.raises(ValueError, match="invoice_id"):
            controller.load_invoice("../../etc/passwd")

    # SEC-196: duplicate line_number in line_drafts rejected, and non-USD with unknown USD total fails closed for clerk
    line_draft = LineFormDraft.from_line(detail.lines[0]).model_copy(
        update={"description": "Edited"}
    )
    with pytest.raises(ValueError, match="Duplicate line_number"):
        build_revalidate_request(
            detail,
            header_draft=HeaderFormDraft.from_invoice(detail),
            line_drafts=[line_draft, line_draft],
            reason_code=ReasonCode.OCR_MISREAD,
        )
    eur_no_usd = detail.model_copy(
        update={
            "status": "VALIDATED",
            "currency": "EUR",
            "total_amount_usd": None,
            "confidence_macro_avg": Decimal("96.00"),
        }
    )
    assert can_approve_in_workbench(eur_no_usd, ["ap_clerk"], Decimal("10000.00")) is False


# ---------------------------------------------------------------------------
# Tests: Headless Streamlit Split-Screen Renderer + AST Layering Hygiene
# ---------------------------------------------------------------------------


def test_streamlit_workbench_split_screen_renderer_smoke() -> None:
    """Render Review Workbench split-screen via direct call and main app shell."""
    transport = _WorkbenchMockTransport()
    pdf_bytes = _make_multipage_pdf(pages=2)

    class _FakePreviewUpload:
        name = "inv-wb-001.pdf"

        def getvalue(self) -> bytes:
            return pdf_bytes

    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        fake_st = _FakeWorkbenchStreamlit(
            text_overrides={
                "Invoice ID to Review": "inv-wb-001",
                "Total Tax Amount": "80.00",
                "Total Amount": "1080.00",
                "Audit Comment (mandatory for OTHER)": "Fixed US 8% sales tax",
            },
            button_clicks={"Sign In as Demo Persona", "Load Invoice", "Re-Validate"},
            selected_page=PAGE_WORKBENCH,
            uploaded_preview=_FakePreviewUpload(),
        )
        render_app(api_client=client, st_module=fake_st)

        assert any("Review Workbench" in t for t in fake_st.titles)
        assert len(fake_st.images) == 1
        assert fake_st.images[0].startswith(b"\x89PNG\r\n\x1a\n")
        assert transport.last_revalidate_body is not None
        assert any("Re-validated" in s or "VALIDATED" in s for s in fake_st.successes)

        # Direct renderer call with pre-selected invoice_id
        direct_st = _FakeWorkbenchStreamlit()
        render_review_workbench(
            client,
            invoice_id="inv-wb-001",
            st_module=direct_st,
            user_roles=["ap_clerk"],
            document_bytes=pdf_bytes,
            document_filename="inv-wb-001.pdf",
        )
        assert len(direct_st.images) == 1
        assert "Status" in direct_st.metrics


def test_review_workbench_obeys_layering_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2 & §12: src/ui/review_workbench.py and app.py have zero forbidden imports or unsafe HTML."""
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
    for rel_path in ("src/ui/review_workbench.py", "src/ui/app.py"):
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
