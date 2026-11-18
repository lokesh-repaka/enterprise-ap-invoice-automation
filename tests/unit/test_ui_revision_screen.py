"""
Unit and Security Tests for the Revision Comparison Screen UI (P11-5).

Tests: FR-10, PRD Screen 4, CLAUDE.md §4.2, §12, §16.1, P11-5
"""

import ast
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import fitz
import httpx
import pytest

from src.api.schemas.invoices import InvoiceDetailResponse, InvoiceLineResponse
from src.ui.api_client import APInvoiceAPIClient
from src.ui.app import PAGE_REVISION, render_app
from src.ui.revision_screen import (
    DECISION_ALLOWED_ROLES,
    HIGHLIGHT_FINANCIAL_HEX,
    HIGHLIGHT_TEXT_HEX,
    HIGHLIGHT_UNCHANGED_HEX,
    MAX_DECISION_HISTORY,
    RevisionComparisonController,
    RevisionDecision,
    build_header_diff_rows,
    build_line_diff_rows,
    can_decide_revision,
    compute_revision_diff,
    detect_revision_markers,
    render_revision_comparison,
)


def _make_pdf(label: str) -> bytes:
    doc = fitz.open()
    page = doc.new_page(width=80, height=100)
    page.insert_text((8, 20), label)
    out = doc.tobytes()
    doc.close()
    return out


def _make_invoice(
    *,
    invoice_id: str,
    invoice_number: str,
    vendor_id: str = "V-001",
    vendor_tax_id: str = "US-12-3456789",
    vendor_name: str = "Acme Technologies Inc.",
    subtotal: Decimal = Decimal("1000.00"),
    tax: Decimal = Decimal("80.00"),
    total: Decimal = Decimal("1080.00"),
    currency: str = "USD",
    status: str = "APPROVED_CLERK",
    po_number: str = "PO-2026-100",
    lines: list[InvoiceLineResponse] | None = None,
) -> InvoiceDetailResponse:
    now = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    default_lines = [
        InvoiceLineResponse(
            line_id=f"{invoice_id}-l1",
            line_number=1,
            description="Enterprise Cloud Plan",
            quantity=Decimal("10.0000"),
            unit_price=Decimal("100.0000"),
            line_total=Decimal("1000.00"),
            line_tax_rate=Decimal("0.0800"),
            confidence_score=Decimal("95.00"),
        )
    ]
    return InvoiceDetailResponse(
        invoice_id=invoice_id,
        vendor_id=vendor_id,
        vendor_tax_id=vendor_tax_id,
        vendor_name=vendor_name,
        invoice_number=invoice_number,
        invoice_date=date(2026, 2, 10),
        due_date=date(2026, 3, 10),
        po_number=po_number,
        subtotal=subtotal,
        total_tax_amount=tax,
        total_amount=total,
        currency=currency,
        total_amount_usd=total,
        confidence_macro_avg=Decimal("94.50"),
        status=status,
        blob_raw_url=f"https://mockblob.blob.core.windows.net/raw/{invoice_id}.pdf",
        blob_json_url=None,
        created_at=now,
        updated_at=now,
        lines=lines if lines is not None else default_lines,
        audit_event_count=3,
    )


class _RevisionMockTransport(httpx.BaseTransport):
    """Fast in-memory HTTP transport simulating original + revision GET and audit routes."""

    def __init__(
        self,
        original: InvoiceDetailResponse | None = None,
        revision: InvoiceDetailResponse | None = None,
    ) -> None:
        self.original = original or _make_invoice(
            invoice_id="inv-orig-001",
            invoice_number="INV-2026-1001",
            status="APPROVED_CLERK",
        )
        self.revision = revision or _make_invoice(
            invoice_id="inv-rev-002",
            invoice_number="INV-2026-1001-REV",
            subtotal=Decimal("1200.00"),
            tax=Decimal("96.00"),
            total=Decimal("1296.00"),
            status="FLAGGED_POTENTIAL_REVISION",
            lines=[
                InvoiceLineResponse(
                    line_id="rev-l1",
                    line_number=1,
                    description="Enterprise Cloud Plan",
                    quantity=Decimal("12.0000"),
                    unit_price=Decimal("100.0000"),
                    line_total=Decimal("1200.00"),
                    line_tax_rate=Decimal("0.0800"),
                    confidence_score=Decimal("93.00"),
                )
            ],
        )

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
        if request.method == "GET" and path == f"/api/v1/invoices/{self.original.invoice_id}":
            return httpx.Response(200, json=self.original.model_dump(mode="json"), request=request)
        if request.method == "GET" and path == f"/api/v1/invoices/{self.revision.invoice_id}":
            return httpx.Response(200, json=self.revision.model_dump(mode="json"), request=request)
        if request.method == "GET" and path == f"/api/v1/invoices/{self.original.invoice_id}/audit":
            return httpx.Response(
                200,
                json={
                    "invoice_id": self.original.invoice_id,
                    "invoice_number": self.original.invoice_number,
                    "current_status": self.original.status,
                    "immutable": True,
                    "total_events": 1,
                    "limit": 200,
                    "offset": 0,
                    "filters_applied": {"action_type": ["APPROVE"]},
                    "events": [
                        {
                            "audit_id": "aud-orig-app-1",
                            "invoice_id": self.original.invoice_id,
                            "user_id": "sarah.clerk@company.com",
                            "action_type": "APPROVE",
                            "field_name": "status",
                            "previous_value": "VALIDATED",
                            "new_value": "APPROVED_CLERK",
                            "reason_code": None,
                            "comment": "Approved original invoice",
                            "timestamp": datetime(2026, 2, 11, 14, 30, 0, tzinfo=UTC).isoformat(),
                        }
                    ],
                },
                request=request,
            )
        return httpx.Response(404, json={"detail": "Not found"}, request=request)


class _FakeCol:
    def __init__(self, st: "_FakeRevisionStreamlit") -> None:
        self._st = st

    def __enter__(self) -> "_FakeCol":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self._st.metrics[label] = value

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._st.text_input(label, value=value, **kwargs)

    def button(self, label: str, **kwargs: Any) -> bool:
        return self._st.button(label, **kwargs)

    def subheader(self, text: str) -> None:
        self._st.subheaders.append(text)

    def caption(self, text: str) -> None:
        self._st.captions.append(text)

    def info(self, text: str) -> None:
        self._st.infos.append(text)

    def warning(self, text: str) -> None:
        self._st.warnings.append(text)

    def error(self, text: str) -> None:
        self._st.errors.append(text)

    def success(self, text: str) -> None:
        self._st.successes.append(text)

    def image(self, img: bytes, **kwargs: Any) -> None:
        self._st.images.append(img)

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self._st.dataframes.append(data)


class _FakeRevisionStreamlit:
    """Minimal headless Streamlit stub verifying P11-5 Revision Comparison rendering."""

    def __init__(
        self,
        *,
        text_overrides: dict[str, str] | None = None,
        button_clicks: set[str] | None = None,
        selected_page: str = PAGE_REVISION,
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
        self.rendered_buttons: list[str] = []
        self._text_overrides = text_overrides or {}
        self._button_clicks = button_clicks or set()
        self._selected_page = selected_page
        self.sidebar = self

    def set_page_config(self, **kwargs: Any) -> None:
        self.page_config = kwargs

    def title(self, text: str) -> None:
        self.titles.append(text)

    def header(self, text: str) -> None:
        self.titles.append(text)

    def subheader(self, text: str) -> None:
        self.subheaders.append(text)

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

    def columns(self, spec: Any) -> list[_FakeCol]:
        count = spec if isinstance(spec, int) else len(spec)
        return [_FakeCol(self) for _ in range(count)]

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._text_overrides.get(label, value)

    def text_area(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._text_overrides.get(label, value)

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return options[index]

    def radio(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if self._selected_page in options:
            return self._selected_page
        return options[index]

    def button(self, label: str, **kwargs: Any) -> bool:
        self.rendered_buttons.append(label)
        return label in self._button_clicks

    def file_uploader(self, label: str, **kwargs: Any) -> Any:
        return None

    def image(self, img: bytes, **kwargs: Any) -> None:
        self.images.append(img)

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self.dataframes.append(data)


# ---------------------------------------------------------------------------
# Tests: FR-10 Revision Markers, Header & Line-Item Diff Engine
# ---------------------------------------------------------------------------


def test_detect_revision_markers_and_base_number_matching() -> None:
    """Detect -REV, v2, -R1, AMENDED revision markers and base invoice number parity."""
    m1 = detect_revision_markers("INV-2026-1001", "INV-2026-1001-REV")
    assert m1.has_revision_marker is True
    assert "-REV" in m1.detected_markers
    assert m1.same_base_invoice_number is True

    m2 = detect_revision_markers("INV-2026-1001", "INV-2026-1001 v2")
    assert m2.has_revision_marker is True
    assert m2.same_base_invoice_number is True

    m3 = detect_revision_markers("INV-2026-1001", "INV-2026-1001")
    assert m3.has_revision_marker is False
    assert m3.same_base_invoice_number is True

    m4 = detect_revision_markers("INV-2026-1001", "INV-2026-9999-REV")
    assert m4.has_revision_marker is True
    assert m4.same_base_invoice_number is False


def test_compute_revision_diff_header_lines_and_financial_highlights() -> None:
    """Highlight text diffs in yellow (#fef08a), financial/line diffs in red (#ef4444), and compute deltas."""
    orig = _make_invoice(invoice_id="inv-orig-1", invoice_number="INV-2026-500")
    rev = _make_invoice(
        invoice_id="inv-rev-2",
        invoice_number="INV-2026-500-REV",
        po_number="PO-2026-100",
        subtotal=Decimal("1250.00"),
        tax=Decimal("100.00"),
        total=Decimal("1350.00"),
        status="FLAGGED_POTENTIAL_REVISION",
        lines=[
            InvoiceLineResponse(
                line_id="l1",
                line_number=1,
                description="Enterprise Cloud Plan",
                quantity=Decimal("12.0000"),
                unit_price=Decimal("100.0000"),
                line_total=Decimal("1200.00"),
                line_tax_rate=Decimal("0.0800"),
                confidence_score=Decimal("94.00"),
            ),
            InvoiceLineResponse(
                line_id="l2",
                line_number=2,
                description="Priority Support Add-on",
                quantity=Decimal("1.0000"),
                unit_price=Decimal("50.0000"),
                line_total=Decimal("50.00"),
                line_tax_rate=Decimal("0.0800"),
                confidence_score=Decimal("96.00"),
            ),
        ],
    )

    diff = compute_revision_diff(orig, rev)
    assert diff.same_vendor is True
    assert diff.is_exact_duplicate_candidate is False
    assert diff.total_amount_delta == Decimal("270.00")
    assert diff.tax_amount_delta == Decimal("20.00")
    assert diff.percentage_delta == Decimal("25.00")
    assert diff.modified_header_count >= 4  # invoice_number, subtotal, tax, total, status
    assert diff.modified_line_count == 2  # line 1 modified + line 2 added

    hdr_by_field = {h.field_name: h for h in diff.header_diffs}
    assert hdr_by_field["Invoice Number"].highlight_hex == HIGHLIGHT_TEXT_HEX
    assert hdr_by_field["Total Amount"].highlight_hex == HIGHLIGHT_FINANCIAL_HEX
    assert hdr_by_field["PO Number"].highlight_hex == HIGHLIGHT_UNCHANGED_HEX

    line_by_num = {ln.line_number: ln for ln in diff.line_diffs}
    assert line_by_num[1].change_type == "MODIFIED"
    assert line_by_num[1].line_total_delta == Decimal("200.00")
    assert line_by_num[1].highlight_hex == HIGHLIGHT_FINANCIAL_HEX
    assert line_by_num[2].change_type == "ADDED"
    assert line_by_num[2].line_total_delta == Decimal("50.00")

    hdr_rows = build_header_diff_rows(diff.header_diffs)
    line_rows = build_line_diff_rows(diff.line_diffs)
    assert len(hdr_rows) == len(diff.header_diffs)
    assert len(line_rows) == 2


def test_exact_duplicate_candidate_and_cross_vendor_detection() -> None:
    """Detect exact duplicates (zero delta, identical lines) and flag cross-vendor mismatches."""
    orig = _make_invoice(invoice_id="inv-a", invoice_number="INV-100")
    dup = _make_invoice(invoice_id="inv-b", invoice_number="INV-100", status="DUPLICATE_INVOICE")
    dup_diff = compute_revision_diff(orig, dup)
    assert dup_diff.same_vendor is True
    assert dup_diff.is_exact_duplicate_candidate is True
    assert dup_diff.total_amount_delta == Decimal("0.00")

    other_vendor = _make_invoice(
        invoice_id="inv-c",
        invoice_number="INV-100-REV",
        vendor_id="V-002",
        vendor_tax_id="US-99-9999999",
        vendor_name="GlobalTech LLC",
        status="FLAGGED_POTENTIAL_REVISION",
    )
    cross_diff = compute_revision_diff(orig, other_vendor)
    assert cross_diff.same_vendor is False
    assert cross_diff.is_exact_duplicate_candidate is False

    # SEC-201: Two invoices with placeholder vendor_id="UNKNOWN" and different Tax IDs must NOT match
    unk_a = _make_invoice(
        invoice_id="inv-u1", invoice_number="INV-100", vendor_id="UNKNOWN", vendor_tax_id="US-11"
    )
    unk_b = _make_invoice(
        invoice_id="inv-u2",
        invoice_number="INV-100-REV",
        vendor_id="UNKNOWN",
        vendor_tax_id="DE-22",
        status="FLAGGED_POTENTIAL_REVISION",
    )
    assert compute_revision_diff(unk_a, unk_b).same_vendor is False


# ---------------------------------------------------------------------------
# Tests: Controller Pair Loading, Approval Audit Metadata & Decision Controls
# ---------------------------------------------------------------------------


def test_controller_loads_pair_and_original_approval_audit() -> None:
    """Load side-by-side pair via API client and extract original approving clerk & timestamp."""
    transport = _RevisionMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = RevisionComparisonController(client)
        pair = controller.load_comparison_pair("inv-orig-001", "inv-rev-002")

        assert pair.original.invoice_id == "inv-orig-001"
        assert pair.revision.invoice_id == "inv-rev-002"
        assert pair.original_approved_by == "sarah.clerk@company.com"
        assert pair.original_approved_at is not None
        assert pair.diff.total_amount_delta == Decimal("216.00")

        # Self-comparison and invalid IDs rejected before HTTP calls
        with pytest.raises(ValueError, match="different"):
            controller.load_comparison_pair("inv-orig-001", "inv-orig-001")
        with pytest.raises(ValueError, match="invoice_id"):
            controller.load_comparison_pair("../../etc/passwd", "inv-rev-002")


def test_revision_decisions_rbac_cross_vendor_and_history_cap() -> None:
    """Enforce RBAC (fail-closed), mandatory comments, cross-vendor block, and history bounds."""
    assert DECISION_ALLOWED_ROLES == frozenset({"ap_clerk", "finance_manager"})

    transport = _RevisionMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = RevisionComparisonController(client)
        pair = controller.load_comparison_pair("inv-orig-001", "inv-rev-002")

        assert can_decide_revision(pair.revision, ["ap_clerk"]) is True
        assert can_decide_revision(pair.revision, ["finance_manager"]) is True
        assert can_decide_revision(pair.revision, ["system_admin"]) is False
        assert can_decide_revision(pair.revision, []) is False
        assert can_decide_revision(pair.original, ["ap_clerk"]) is False  # APPROVED_CLERK

        # Confirm authorized revision -> routes to workbench with superseding reference (never directly approves!)
        history, rec = controller.record_decision(
            pair.original,
            pair.revision,
            decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
            comment="Vendor confirmed revised line quantity via email",
            user_roles=["ap_clerk"],
        )
        assert rec.decision == RevisionDecision.CONFIRM_AUTHORIZED_REVISION
        assert rec.handoff_route == "/workbench/inv-rev-002"
        assert rec.recommended_status == "REVALIDATING"
        assert len(history) == 1

        # Reject unauthorized duplicate
        history2, rej = controller.record_decision(
            pair.original,
            pair.revision,
            decision=RevisionDecision.REJECT_UNAUTHORIZED_DUPLICATE,
            comment="Duplicate re-submission of already paid invoice",
            existing_decisions=history,
            user_roles=["finance_manager"],
        )
        assert rej.recommended_status == "REJECTED_DUPLICATE"
        assert len(history2) == 2

        # RBAC fail-closed (None, system_admin) & short comment rejected
        with pytest.raises(PermissionError):
            controller.record_decision(
                pair.original,
                pair.revision,
                decision=RevisionDecision.REJECT_UNAUTHORIZED_DUPLICATE,
                comment="Valid comment text",
                user_roles=None,
            )
        with pytest.raises(PermissionError):
            controller.record_decision(
                pair.original,
                pair.revision,
                decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
                comment="Valid comment text",
                user_roles=["system_admin"],
            )
        with pytest.raises(ValueError, match="comment"):
            controller.record_decision(
                pair.original,
                pair.revision,
                decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
                comment="no",
                user_roles=["ap_clerk"],
            )

        # Cross-vendor CONFIRM_AUTHORIZED_REVISION hard-blocked
        other_vendor_rev = pair.revision.model_copy(
            update={"vendor_tax_id": "DE-999999999", "vendor_id": "V-006"}
        )
        with pytest.raises(ValueError, match="vendor"):
            controller.record_decision(
                pair.original,
                other_vendor_rev,
                decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
                comment="Trying to supersede across vendors",
                user_roles=["ap_clerk"],
            )

        # Decision history stays bounded at MAX_DECISION_HISTORY
        capped, _ = controller.record_decision(
            pair.original,
            pair.revision,
            decision=RevisionDecision.REJECT_UNAUTHORIZED_DUPLICATE,
            comment="Duplicate check entry",
            existing_decisions=[rec] * MAX_DECISION_HISTORY,
            user_roles=["ap_clerk"],
        )
        assert len(capped) == MAX_DECISION_HISTORY


# ---------------------------------------------------------------------------
# Tests: Security — XSS, CSV Formula Neutralization & PII Masking
# ---------------------------------------------------------------------------


def test_revision_diff_sanitizes_xss_formulas_and_tokens() -> None:
    """Neutralize CSV formulas, HTML tags, and JWT leaks in header & line diff tables."""
    orig = _make_invoice(
        invoice_id="inv-orig-s",
        invoice_number='=CMD|" /C calc"!A0',
        po_number="<script>alert(1)</script>PO-1",
    )
    rev = _make_invoice(
        invoice_id="inv-rev-s",
        invoice_number='=CMD|" /C calc"!A0-REV',
        po_number="Bearer eyJhbGciOiJSUzI1NiJ9.a.b",
        status="FLAGGED_POTENTIAL_REVISION",
        lines=[
            InvoiceLineResponse(
                line_id="l1",
                line_number=1,
                description="+SUM(A1:A5) <img src=x>",
                quantity=Decimal("10.0000"),
                unit_price=Decimal("100.0000"),
                line_total=Decimal("1000.00"),
                line_tax_rate=Decimal("0.0800"),
                confidence_score=Decimal("90.00"),
            )
        ],
    )
    diff = compute_revision_diff(orig, rev)
    hdr_rows = build_header_diff_rows(diff.header_diffs)
    line_rows = build_line_diff_rows(diff.line_diffs)

    inv_row = next(r for r in hdr_rows if r["Field"] == "Invoice Number")
    po_row = next(r for r in hdr_rows if r["Field"] == "PO Number")
    assert not inv_row["Original Value"].startswith("=")
    assert "<script>" not in po_row["Original Value"]
    assert "eyJhbGciOiJSUzI1NiJ9" not in po_row["Incoming Revision"]
    assert not line_rows[0]["Revision Description"].startswith("+")
    assert "<img" not in line_rows[0]["Revision Description"]


# ---------------------------------------------------------------------------
# Tests: Headless Streamlit Renderer & AST Layering Hygiene
# ---------------------------------------------------------------------------


def test_streamlit_revision_renderer_and_app_shell_smoke() -> None:
    """Render Revision Comparison screen via app shell and direct entrypoint with PDF previews."""
    transport = _RevisionMockTransport()
    orig_pdf = _make_pdf("Original INV-1001")
    rev_pdf = _make_pdf("Revised INV-1001-REV")

    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        st_app = _FakeRevisionStreamlit(
            text_overrides={
                "Original Approved Invoice ID": "inv-orig-001",
                "Incoming Revision Invoice ID": "inv-rev-002",
                "Decision Audit Comment (mandatory)": "Vendor authorized revised quantity",
            },
            button_clicks={
                "Sign In as Demo Persona",
                "Compare Invoices",
                "Confirm as Authorized Revision (Supersede Old)",
            },
            selected_page=PAGE_REVISION,
        )
        render_app(api_client=client, st_module=st_app)

        assert any("Revision Comparison" in t for t in st_app.titles)
        assert "Total Delta" in st_app.metrics
        assert len(st_app.dataframes) >= 2  # header diff table + line diff table
        assert any("Authorized Revision" in s for s in st_app.successes)

        # Direct call with side-by-side PDF previews & system_admin (decision buttons hidden!)
        st_admin = _FakeRevisionStreamlit()
        render_revision_comparison(
            client,
            original_invoice_id="inv-orig-001",
            revision_invoice_id="inv-rev-002",
            st_module=st_admin,
            user_roles=["system_admin"],
            original_document_bytes=orig_pdf,
            revision_document_bytes=rev_pdf,
        )
        assert len(st_admin.images) == 2
        assert "Confirm as Authorized Revision (Supersede Old)" not in st_admin.rendered_buttons
        assert "Reject as Unauthorized Duplicate" not in st_admin.rendered_buttons


def test_revision_screen_obeys_layering_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2 & §12: src/ui/revision_screen.py and app.py obey layering with zero unsafe HTML."""
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
    for rel_path in ("src/ui/revision_screen.py", "src/ui/app.py"):
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
