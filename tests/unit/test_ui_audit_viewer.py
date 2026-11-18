"""
Unit and Security Tests for the Immutable Audit Trail Viewer UI (P11-6).

Tests: PRD Screen 5, N3, N6, N8, BR-031, CLAUDE.md §4.2, §12, §16.9, P11-6
"""

import ast
import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from src.api.schemas.invoices import AuditEventResponse, InvoiceAuditTrailResponse
from src.ui.api_client import APInvoiceAPIClient
from src.ui.app import PAGE_AUDIT, render_app
from src.ui.audit_viewer import (
    AUDIT_VIEW_ALLOWED_ROLES,
    CANONICAL_AUDIT_ACTION_TYPES,
    MAX_AUDIT_LIMIT,
    SENSITIVE_DISPLAY_FIELDS,
    AuditTrailFilter,
    AuditTrailViewerController,
    build_chronological_timeline_rows,
    can_view_audit_trail,
    export_audit_trail_csv,
    export_audit_trail_json,
    render_audit_trail_viewer,
    summarize_audit_trail,
    validate_audit_filter,
)


def _make_sample_audit_trail(
    *,
    invoice_id: str = "inv-aud-001",
    events: list[AuditEventResponse] | None = None,
) -> InvoiceAuditTrailResponse:
    default_events = [
        AuditEventResponse(
            audit_id="aud-1",
            invoice_id=invoice_id,
            user_id="sarah.clerk@company.com",
            action_type="INGEST",
            field_name="status",
            previous_value=None,
            new_value="UPLOADED",
            reason_code=None,
            comment="Raw PDF stored in WORM blob",
            timestamp=datetime(2026, 2, 15, 9, 0, 0, tzinfo=UTC),
        ),
        AuditEventResponse(
            audit_id="aud-2",
            invoice_id=invoice_id,
            user_id="system",
            action_type="EXTRACTION",
            field_name="confidence_macro_avg",
            previous_value=None,
            new_value="88.00",
            reason_code=None,
            comment="gpt-4o-mini v2024-05-01-preview",
            timestamp=datetime(2026, 2, 15, 9, 0, 12, tzinfo=UTC),
        ),
        AuditEventResponse(
            audit_id="aud-3",
            invoice_id=invoice_id,
            user_id="sarah.clerk@company.com",
            action_type="EDIT",
            field_name="total_tax_amount",
            previous_value="50.00",
            new_value="80.00",
            reason_code="OCR_MISREAD",
            comment="Corrected US 8% sales tax",
            timestamp=datetime(2026, 2, 15, 9, 5, 0, tzinfo=UTC),
        ),
        AuditEventResponse(
            audit_id="aud-4",
            invoice_id=invoice_id,
            user_id="sarah.clerk@company.com",
            action_type="REVALIDATE",
            field_name="status",
            previous_value="REJECTED_TAX_MISMATCH",
            new_value="VALIDATED",
            reason_code="OCR_MISREAD",
            comment="All deterministic rules passed",
            timestamp=datetime(2026, 2, 15, 9, 5, 2, tzinfo=UTC),
        ),
        AuditEventResponse(
            audit_id="aud-5",
            invoice_id=invoice_id,
            user_id="sarah.clerk@company.com",
            action_type="APPROVE",
            field_name="status",
            previous_value="VALIDATED",
            new_value="APPROVED_CLERK",
            reason_code=None,
            comment="One-click clerk approval",
            timestamp=datetime(2026, 2, 15, 9, 6, 0, tzinfo=UTC),
        ),
    ]
    chosen = events if events is not None else default_events
    return InvoiceAuditTrailResponse(
        invoice_id=invoice_id,
        invoice_number="INV-AUD-2026-001",
        current_status="APPROVED_CLERK",
        immutable=True,
        total_events=len(chosen),
        limit=200,
        offset=0,
        filters_applied={},
        events=chosen,
    )


class _AuditMockTransport(httpx.BaseTransport):
    """Fast in-memory HTTP transport simulating GET /api/v1/invoices/{id}/audit."""

    def __init__(self, trail: InvoiceAuditTrailResponse | None = None) -> None:
        self.trail = trail or _make_sample_audit_trail()
        self.last_query_params: list[tuple[str, str]] = []

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
                            "username": "dave.admin",
                            "email": "dave.admin@company.com",
                            "name": "Dave Patel",
                            "role": "system_admin",
                            "entra_group": "AP-Admins",
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
                    "persona": "dave.admin",
                    "email": "dave.admin@company.com",
                    "name": "Dave Patel",
                    "role": "system_admin",
                },
                request=request,
            )
        if request.method == "GET" and path == f"/api/v1/invoices/{self.trail.invoice_id}/audit":
            self.last_query_params = list(request.url.params.multi_items())
            action_types = set(request.url.params.get_list("action_type"))
            user_id = request.url.params.get("user_id")
            filtered = [
                ev
                for ev in self.trail.events
                if (not action_types or ev.action_type in action_types)
                and (not user_id or ev.user_id == user_id)
            ]
            payload = self.trail.model_copy(
                update={"events": filtered, "total_events": len(filtered)}
            ).model_dump(mode="json")
            return httpx.Response(200, json=payload, request=request)
        return httpx.Response(404, json={"detail": "Not found"}, request=request)


class _FakeCol:
    def __init__(self, st: "_FakeAuditStreamlit") -> None:
        self._st = st

    def __enter__(self) -> "_FakeCol":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self._st.metrics[label] = value

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._st.text_input(label, value=value, **kwargs)

    def multiselect(
        self, label: str, options: list[Any], default: list[Any] | None = None, **kwargs: Any
    ):
        return self._st.multiselect(label, options, default=default, **kwargs)

    def button(self, label: str, **kwargs: Any) -> bool:
        return self._st.button(label, **kwargs)

    def download_button(self, label: str, data: Any, **kwargs: Any) -> bool:
        self._st.downloads[label] = data
        return False


class _FakeAuditStreamlit:
    """Headless Streamlit stub verifying immutable Audit Trail Viewer rendering."""

    def __init__(
        self,
        *,
        text_overrides: dict[str, str] | None = None,
        button_clicks: set[str] | None = None,
        selected_page: str = PAGE_AUDIT,
    ) -> None:
        self.session_state: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.dataframes: list[Any] = []
        self.downloads: dict[str, Any] = {}
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

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return options[index]

    def multiselect(
        self, label: str, options: list[Any], default: list[Any] | None = None, **kwargs: Any
    ):
        return list(default or [])

    def radio(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if self._selected_page in options:
            return self._selected_page
        return options[index]

    def button(self, label: str, **kwargs: Any) -> bool:
        return label in self._button_clicks

    def download_button(self, label: str, data: Any, **kwargs: Any) -> bool:
        self.downloads[label] = data
        return False

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self.dataframes.append(data)


# ---------------------------------------------------------------------------
# Tests: Audit Filter Validation & RBAC
# ---------------------------------------------------------------------------


def test_audit_filter_validation_and_rbac() -> None:
    """Verify 3-role RBAC, canonical action_type allowlist, user_id, and pagination bounds."""
    assert AUDIT_VIEW_ALLOWED_ROLES == frozenset({"ap_clerk", "finance_manager", "system_admin"})
    assert len(CANONICAL_AUDIT_ACTION_TYPES) == 9

    assert can_view_audit_trail(["ap_clerk"]) is True
    assert can_view_audit_trail(["finance_manager"]) is True
    assert can_view_audit_trail(["system_admin"]) is True
    assert can_view_audit_trail([]) is False
    assert can_view_audit_trail(None) is False

    clean = validate_audit_filter(
        AuditTrailFilter(
            invoice_id="inv-aud-001",
            action_types=("edit", "APPROVE"),
            user_id="sarah.clerk@company.com",
            limit=50,
            offset=0,
        )
    )
    assert clean.action_types == ("EDIT", "APPROVE")

    with pytest.raises(ValueError, match="invoice_id"):
        validate_audit_filter(AuditTrailFilter(invoice_id="../../etc/passwd"))
    with pytest.raises(ValueError, match="action_type"):
        validate_audit_filter(
            AuditTrailFilter(invoice_id="inv-aud-001", action_types=("DELETE_AUDIT",))
        )
    with pytest.raises(ValueError, match="user_id"):
        validate_audit_filter(AuditTrailFilter(invoice_id="inv-aud-001", user_id="bad\r\nactor"))
    with pytest.raises(ValueError, match="limit"):
        validate_audit_filter(AuditTrailFilter(invoice_id="inv-aud-001", limit=MAX_AUDIT_LIMIT + 1))


# ---------------------------------------------------------------------------
# Tests: Chronological Timeline Ordering, Summary Metrics & Controller
# ---------------------------------------------------------------------------


def test_chronological_timeline_ordering_and_summary() -> None:
    """Timeline enforces oldest-to-newest chronological sorting and accurate KPI summary."""
    trail = _make_sample_audit_trail()
    # Pass out-of-order events to prove viewer always renders chronological order
    reversed_events = list(reversed(trail.events))
    rows = build_chronological_timeline_rows(reversed_events)

    assert len(rows) == 5
    assert [r["Seq #"] for r in rows] == [1, 2, 3, 4, 5]
    assert [r["Action"] for r in rows] == [
        "INGEST",
        "EXTRACTION",
        "EDIT",
        "REVALIDATE",
        "APPROVE",
    ]
    assert rows[2]["Change"] == "50.00 -> 80.00"
    assert rows[2]["Reason Code"] == "OCR_MISREAD"

    summary = summarize_audit_trail(trail)
    assert summary.total_events == 5
    assert summary.manual_edits == 1
    assert summary.revalidations == 1
    assert summary.approvals == 1
    assert summary.immutable is True


def test_audit_controller_fetch_and_rbac_enforcement() -> None:
    """AuditTrailViewerController enforces RBAC and forwards filters to GET /invoices/{id}/audit."""
    transport = _AuditMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = AuditTrailViewerController(client)

        with pytest.raises(PermissionError):
            controller.load_audit_trail(AuditTrailFilter(invoice_id="inv-aud-001"), user_roles=[])
        with pytest.raises(PermissionError):
            controller.load_audit_trail(AuditTrailFilter(invoice_id="inv-aud-001"), user_roles=None)

        trail = controller.load_audit_trail(
            AuditTrailFilter(
                invoice_id="inv-aud-001",
                action_types=("EDIT", "APPROVE"),
                user_id="sarah.clerk@company.com",
            ),
            user_roles=["system_admin"],
        )
        assert trail.immutable is True
        assert trail.total_events == 2
        assert ("action_type", "EDIT") in transport.last_query_params
        assert ("action_type", "APPROVE") in transport.last_query_params
        assert ("user_id", "sarah.clerk@company.com") in transport.last_query_params


# ---------------------------------------------------------------------------
# Tests: Security — PII Masking, XSS/Formula Neutralization & Safe Exports
# ---------------------------------------------------------------------------


def test_audit_viewer_redacts_pii_tokens_and_neutralizes_csv_export() -> None:
    """Mask sensitive fields, redact Bearer JWTs, and neutralize CSV formulas in timeline & exports."""
    assert "vendor_tax_id" in SENSITIVE_DISPLAY_FIELDS
    assert "iban" in SENSITIVE_DISPLAY_FIELDS

    sensitive_events = [
        AuditEventResponse(
            audit_id="aud-sec-1",
            invoice_id="inv-aud-sec",
            user_id="sarah.clerk@company.com",
            action_type="EDIT",
            field_name="vendor_tax_id",
            previous_value="US-12-3456789",
            new_value="DE-998877665",
            reason_code="OCR_MISREAD",
            comment='=CMD|" /C calc"!A0 <script>alert(1)</script> Bearer eyJhbGciOiJSUzI1NiJ9.a.b',
            timestamp=datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC),
        ),
        AuditEventResponse(
            audit_id="aud-sec-2",
            invoice_id="inv-aud-sec",
            user_id="sarah.clerk@company.com",
            action_type="EDIT",
            field_name="invoice.iban",
            previous_value="DE89370400440532013000",
            new_value="DE44500105175407324931",
            reason_code="OTHER",
            comment="+SUM(A1:A5) updated vendor bank DE89370400440532013000 SSN 123-45-6789",
            timestamp=datetime(2026, 2, 15, 10, 1, 0, tzinfo=UTC),
        ),
    ]
    trail = _make_sample_audit_trail(invoice_id="inv-aud-sec", events=sensitive_events)

    rows = build_chronological_timeline_rows(trail.events)
    # Raw Tax ID, IBAN, and inline SSN must never appear in display rows (SEC-204)
    assert "US-12-3456789" not in rows[0]["Change"]
    assert "DE-998877665" not in rows[0]["Change"]
    assert "DE89370400440532013000" not in rows[1]["Change"]
    assert "DE89370400440532013000" not in rows[1]["Comment"]
    assert "123-45-6789" not in rows[1]["Comment"]
    assert "REDACTED" in rows[0]["Change"]
    assert "REDACTED" in rows[1]["Change"]
    assert not rows[0]["Comment"].startswith("=")
    assert "<script>" not in rows[0]["Comment"]
    assert "eyJhbGciOiJSUzI1NiJ9" not in rows[0]["Comment"]

    # CSV export is formula-safe and PII-masked
    csv_text = export_audit_trail_csv(trail)
    parsed_csv = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(parsed_csv) == 2
    assert not parsed_csv[0]["Comment"].startswith("=")
    assert not parsed_csv[1]["Comment"].startswith("+")
    assert "US-12-3456789" not in csv_text
    assert "eyJhbGciOiJSUzI1NiJ9" not in csv_text

    # JSON export preserves immutability metadata and masks PII
    json_data = json.loads(export_audit_trail_json(trail))
    assert json_data["immutable"] is True
    assert "US-12-3456789" not in json.dumps(json_data)
    assert "DE89370400440532013000" not in json.dumps(json_data)


# ---------------------------------------------------------------------------
# Tests: Headless Streamlit Immutable Renderer & AST Immutability/Layering Check
# ---------------------------------------------------------------------------


def test_streamlit_audit_viewer_renderer_and_app_shell_smoke() -> None:
    """Render Audit Trail Viewer via app shell (as system_admin) and direct entrypoint."""
    transport = _AuditMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        st_app = _FakeAuditStreamlit(
            text_overrides={"Invoice ID": "inv-aud-001"},
            button_clicks={"Sign In as Demo Persona", "Load Audit Trail"},
            selected_page=PAGE_AUDIT,
        )
        render_app(api_client=client, st_module=st_app)

        assert any("Audit Trail Viewer" in t for t in st_app.titles)
        assert st_app.metrics["Total Events"] == 5
        assert st_app.metrics["Manual Edits"] == 1
        assert len(st_app.dataframes) >= 1
        assert "Download Immutable Audit CSV" in st_app.downloads
        assert "Download Immutable Audit JSON" in st_app.downloads

        # Unauthenticated caller fails closed without querying audit endpoint
        st_unauth = _FakeAuditStreamlit(text_overrides={"Invoice ID": "inv-aud-001"})
        render_audit_trail_viewer(
            client, invoice_id="inv-aud-001", st_module=st_unauth, user_roles=[]
        )
        assert len(st_unauth.dataframes) == 0
        assert any("sign in" in msg.lower() for msg in st_unauth.infos)


def test_audit_viewer_obeys_layering_immutability_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2, §12 & §16.9: zero backend imports, zero unsafe_allow_html, and zero data_editor."""
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
    for rel_path in ("src/ui/audit_viewer.py", "src/ui/app.py"):
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
            # Enforce read-only immutability on audit_viewer.py (no data_editor!)
            if rel_path == "src/ui/audit_viewer.py" and isinstance(node, ast.Attribute):
                assert node.attr != "data_editor", (
                    "Audit Trail Viewer must be strictly immutable (data_editor forbidden)"
                )
