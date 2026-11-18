"""
Unit and Security Tests for the Human Exception Queue UI (P11-4).

Tests: PRD Screen 3, FR-04, FR-09, FR-10, FR-11, FR-13, CLAUDE.md §4.2, §12, §16.1, P11-4
"""

import ast
import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from src.api.schemas.invoices import ExceptionQueueItem
from src.ui.api_client import APInvoiceAPIClient, APIRateLimitError
from src.ui.app import PAGE_EXCEPTIONS, render_app
from src.ui.exception_queue import (
    ALLOWED_SORT_COLUMNS,
    BULK_APPROVE_ALLOWED_ROLES,
    BULK_ASSIGN_ALLOWED_ROLES,
    CANONICAL_EXCEPTION_STATUSES,
    EXCEPTION_TYPE_PRESETS,
    MAX_BULK_SELECTION,
    ExceptionQueueController,
    ExceptionQueueFilter,
    build_exception_queue_rows,
    can_bulk_approve_exceptions,
    can_bulk_assign_exceptions,
    classify_exception_urgency,
    format_elapsed_time,
    render_exception_queue,
    resolve_exception_preset,
    summarize_exception_queue,
    validate_queue_filter,
)


def _make_exc_item(
    *,
    invoice_id: str = "inv-exc-001",
    invoice_number: str = "INV-2026-1010",
    vendor_id: str = "V-001",
    vendor_name: str = "Acme Technologies Inc.",
    total_amount: Decimal = Decimal("1050.00"),
    currency: str = "USD",
    total_amount_usd: Decimal | None = Decimal("1050.00"),
    confidence: Decimal = Decimal("84.50"),
    status: str = "REJECTED_TAX_MISMATCH",
    created_at: datetime | None = None,
) -> ExceptionQueueItem:
    return ExceptionQueueItem(
        invoice_id=invoice_id,
        invoice_number=invoice_number,
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        total_amount=total_amount,
        currency=currency,
        total_amount_usd=total_amount_usd,
        confidence_macro_avg=confidence,
        status=status,
        invoice_date=date(2026, 2, 10),
        created_at=created_at or datetime(2026, 2, 15, 8, 0, 0, tzinfo=UTC),
    )


class _ExceptionQueueMockTransport(httpx.BaseTransport):
    """Fast in-memory HTTP transport simulating /exceptions, /invoices/{id}, and /approve."""

    def __init__(
        self,
        items: list[ExceptionQueueItem] | None = None,
        *,
        rate_limit_get: bool = False,
        persona_role: str = "finance_manager",
    ) -> None:
        self.items = (
            list(items)
            if items is not None
            else [
                _make_exc_item(
                    invoice_id="inv-tax-1",
                    status="REJECTED_TAX_MISMATCH",
                    confidence=Decimal("92.00"),
                ),
                _make_exc_item(
                    invoice_id="inv-low-2",
                    invoice_number="INV-2026-2002",
                    status="REQUIRES_REVIEW",
                    confidence=Decimal("84.00"),
                ),
                _make_exc_item(
                    invoice_id="inv-dup-3",
                    invoice_number="INV-2026-3003",
                    status="DUPLICATE_INVOICE",
                    confidence=Decimal("97.00"),
                ),
                _make_exc_item(
                    invoice_id="inv-mgr-4",
                    invoice_number="INV-2026-4004",
                    total_amount=Decimal("15000.00"),
                    total_amount_usd=Decimal("15000.00"),
                    status="REQUIRES_MANAGER_APPROVAL",
                    confidence=Decimal("95.50"),
                ),
            ]
        )
        self.rate_limit_get = rate_limit_get
        self.persona_role = persona_role
        self.last_query_params: list[tuple[str, str]] = []
        self.approved_ids: list[str] = []

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
                            "username": "michael.manager"
                            if self.persona_role == "finance_manager"
                            else "sarah.clerk",
                            "email": f"{self.persona_role}@company.com",
                            "name": "Demo User",
                            "role": self.persona_role,
                            "entra_group": "Finance-Managers",
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
                    "persona": "michael.manager"
                    if self.persona_role == "finance_manager"
                    else "sarah.clerk",
                    "email": f"{self.persona_role}@company.com",
                    "name": "Demo User",
                    "role": self.persona_role,
                },
                request=request,
            )
        if request.method == "GET" and path == "/api/v1/invoices/exceptions":
            self.last_query_params = list(request.url.params.multi_items())
            statuses = request.url.params.get_list("status")
            filtered = [item for item in self.items if not statuses or item.status in statuses]
            return httpx.Response(
                200,
                json={
                    "items": [i.model_dump(mode="json") for i in filtered],
                    "total": len(filtered),
                    "limit": int(request.url.params.get("limit", "50")),
                    "offset": int(request.url.params.get("offset", "0")),
                    "filters_applied": {"status": statuses} if statuses else {},
                },
                request=request,
            )
        if request.method == "GET" and path.startswith("/api/v1/invoices/"):
            if self.rate_limit_get:
                return httpx.Response(429, json={"detail": "Rate limit exceeded"}, request=request)
            inv_id = path.rsplit("/", 1)[-1]
            match = next((i for i in self.items if i.invoice_id == inv_id), None)
            if match is None:
                return httpx.Response(404, json={"detail": "Invoice not found"}, request=request)
            return httpx.Response(
                200,
                json={
                    "invoice_id": match.invoice_id,
                    "vendor_id": match.vendor_id,
                    "vendor_tax_id": "US-12-3456789",
                    "vendor_name": match.vendor_name,
                    "invoice_number": match.invoice_number,
                    "total_amount": str(match.total_amount),
                    "currency": match.currency,
                    "total_amount_usd": str(match.total_amount_usd or match.total_amount),
                    "confidence_macro_avg": str(match.confidence_macro_avg),
                    "status": match.status,
                    "created_at": match.created_at.isoformat(),
                    "updated_at": match.created_at.isoformat(),
                    "lines": [],
                    "audit_event_count": 2,
                },
                request=request,
            )
        if request.method == "POST" and path.endswith("/approve"):
            inv_id = path.split("/")[-2]
            _ = json.loads(request.read().decode("utf-8") or "{}")
            match = next((i for i in self.items if i.invoice_id == inv_id), None)
            if match is None:
                return httpx.Response(404, json={"detail": "Not found"}, request=request)
            self.approved_ids.append(inv_id)
            return httpx.Response(
                200,
                json={
                    "invoice_id": match.invoice_id,
                    "previous_status": match.status,
                    "status": "APPROVED_MANAGER",
                    "approved_by": "michael.manager@company.com",
                    "approver_role": "finance_manager",
                    "total_amount": str(match.total_amount),
                    "currency": match.currency,
                    "total_amount_usd": str(match.total_amount_usd or match.total_amount),
                    "high_value_threshold_usd": "10000.00",
                    "requires_manager_approval": True,
                    "approved_at": datetime(2026, 2, 15, 12, 0, 0, tzinfo=UTC).isoformat(),
                    "audit_event_id": f"aud-{inv_id}",
                },
                request=request,
            )
        return httpx.Response(404, json={"detail": "Unhandled"}, request=request)


class _FakeCol:
    def __init__(self, st: "_FakeExceptionStreamlit") -> None:
        self._st = st

    def __enter__(self) -> "_FakeCol":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def metric(self, label: str, value: Any, delta: Any = None) -> None:
        self._st.metrics[label] = value

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return self._st.selectbox(label, options, index=index, **kwargs)

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._st.text_input(label, value=value, **kwargs)

    def multiselect(
        self, label: str, options: list[Any], default: list[Any] | None = None, **kwargs: Any
    ):
        return self._st.multiselect(label, options, default=default, **kwargs)

    def button(self, label: str, **kwargs: Any) -> bool:
        return self._st.button(label, **kwargs)

    def number_input(self, label: str, value: Any = 0, **kwargs: Any) -> Any:
        return value


class _FakeExceptionStreamlit:
    """Minimal headless Streamlit stub verifying P11-4 Exception Queue rendering."""

    def __init__(
        self,
        *,
        selected_ids: list[str] | None = None,
        button_clicks: set[str] | None = None,
        text_overrides: dict[str, str] | None = None,
        selectbox_overrides: dict[str, Any] | None = None,
        selected_page: str = PAGE_EXCEPTIONS,
    ) -> None:
        self.session_state: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.dataframes: list[Any] = []
        self.titles: list[str] = []
        self.subheaders: list[str] = []
        self.captions: list[str] = []
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.successes: list[str] = []
        self.rendered_buttons: list[str] = []
        self._selected_ids = selected_ids or []
        self._button_clicks = button_clicks or set()
        self._text_overrides = text_overrides or {}
        self._selectbox_overrides = selectbox_overrides or {}
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

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if label in self._selectbox_overrides:
            return self._selectbox_overrides[label]
        return options[index]

    def radio(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        if self._selected_page in options:
            return self._selected_page
        return options[index]

    def text_input(self, label: str, value: str = "", **kwargs: Any) -> str:
        return self._text_overrides.get(label, value)

    def multiselect(
        self, label: str, options: list[Any], default: list[Any] | None = None, **kwargs: Any
    ):
        if "Select Invoices" in label:
            return [x for x in self._selected_ids if x in options]
        return list(default or [])

    def button(self, label: str, **kwargs: Any) -> bool:
        self.rendered_buttons.append(label)
        return label in self._button_clicks

    def dataframe(self, data: Any, **kwargs: Any) -> None:
        self.dataframes.append(data)


# ---------------------------------------------------------------------------
# Tests: PRD Screen 3 Exception Type Presets & Filter Validation
# ---------------------------------------------------------------------------


def test_exception_type_presets_and_filter_validation() -> None:
    """Verify PRD Screen 3 presets and strict filter input validation."""
    assert "All Exceptions" in EXCEPTION_TYPE_PRESETS
    assert "Tax Mismatch" in EXCEPTION_TYPE_PRESETS
    assert "Low Confidence" in EXCEPTION_TYPE_PRESETS
    assert "Duplicate / Revision" in EXCEPTION_TYPE_PRESETS
    assert "High Value / Manager Escalation" in EXCEPTION_TYPE_PRESETS
    assert ALLOWED_SORT_COLUMNS == frozenset(
        {"created_at", "total_amount", "confidence_macro_avg", "invoice_date"}
    )

    tax_f = resolve_exception_preset("Tax Mismatch")
    assert tax_f.statuses == ("REJECTED_TAX_MISMATCH",)

    dup_f = resolve_exception_preset("Duplicate / Revision")
    assert set(dup_f.statuses) == {"DUPLICATE_INVOICE", "FLAGGED_POTENTIAL_REVISION"}

    low_f = resolve_exception_preset("Low Confidence")
    assert set(low_f.statuses) == {"REQUIRES_REVIEW", "REQUIRES_APPROVAL"}
    assert low_f.max_confidence == Decimal("89.99")

    mgr_f = resolve_exception_preset("High Value / Manager Escalation")
    assert mgr_f.statuses == ("REQUIRES_MANAGER_APPROVAL",)

    # Invalid filters fail closed
    with pytest.raises(ValueError, match="status"):
        validate_queue_filter(ExceptionQueueFilter(statuses=("APPROVED_CLERK",)))
    with pytest.raises(ValueError, match="currency"):
        validate_queue_filter(ExceptionQueueFilter(currency="US1"))
    with pytest.raises(ValueError, match="min_amount"):
        validate_queue_filter(
            ExceptionQueueFilter(min_amount=Decimal("5000"), max_amount=Decimal("100"))
        )
    with pytest.raises(ValueError, match="date_from"):
        validate_queue_filter(
            ExceptionQueueFilter(date_from=date(2026, 3, 1), date_to=date(2026, 2, 1))
        )
    with pytest.raises(ValueError, match="sort_by"):
        validate_queue_filter(ExceptionQueueFilter(sort_by="vendor_tax_id"))
    with pytest.raises(ValueError, match="limit"):
        validate_queue_filter(ExceptionQueueFilter(limit=500))
    assert len(CANONICAL_EXCEPTION_STATUSES) == 7


# ---------------------------------------------------------------------------
# Tests: Confidence Colour Coding, Urgency, Elapsed Time & Queue Grid Rows
# ---------------------------------------------------------------------------


def test_queue_grid_confidence_colours_urgency_and_elapsed_time() -> None:
    """Verify tri-tier confidence colours, urgency levels, elapsed queue time, and routes."""
    now = datetime(2026, 2, 15, 12, 30, 0, tzinfo=UTC)
    items = [
        _make_exc_item(
            invoice_id="inv-1",
            status="REJECTED_TAX_MISMATCH",
            confidence=Decimal("94.00"),
            created_at=now - timedelta(hours=3, minutes=15),
        ),
        _make_exc_item(
            invoice_id="inv-2",
            status="REQUIRES_REVIEW",
            confidence=Decimal("84.50"),
            created_at=now - timedelta(minutes=42),
        ),
        _make_exc_item(
            invoice_id="inv-3",
            status="FLAGGED_POTENTIAL_REVISION",
            confidence=Decimal("71.20"),
            created_at=now - timedelta(days=2, hours=4),
        ),
    ]

    assert classify_exception_urgency(items[0]) == "CRITICAL"
    assert classify_exception_urgency(items[1]) == "MEDIUM"
    assert classify_exception_urgency(items[2]) == "CRITICAL"  # <80% elevates to CRITICAL

    assert format_elapsed_time(now - timedelta(seconds=30), now=now) == "<1m"
    assert format_elapsed_time(now - timedelta(minutes=42), now=now) == "42m"
    assert format_elapsed_time(now - timedelta(hours=3, minutes=15), now=now) == "3h 15m"
    assert format_elapsed_time(now - timedelta(days=2, hours=4), now=now) == "2d 4h"

    rows = build_exception_queue_rows(
        items, assignments={"inv-1": "sarah.clerk@company.com"}, now=now
    )
    assert len(rows) == 3
    assert rows[0]["Confidence Color"] == "#22c55e"
    assert rows[1]["Confidence Color"] == "#fef08a"
    assert rows[2]["Confidence Color"] == "#ef4444"
    assert rows[0]["Assigned Clerk"] == "sarah.clerk@company.com"
    assert rows[0]["Route"] == "/workbench/inv-1"
    assert rows[2]["Route"] == "/revision/inv-3"
    assert rows[0]["Elapsed Time"] == "3h 15m"


# ---------------------------------------------------------------------------
# Tests: Controller Query, Summary & Bulk Actions
# ---------------------------------------------------------------------------


def test_exception_queue_controller_query_and_summary() -> None:
    """Verify controller queries GET /invoices/exceptions with filters and computes summary KPIs."""
    transport = _ExceptionQueueMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ExceptionQueueController(client)

        all_resp = controller.fetch_queue(resolve_exception_preset("All Exceptions"))
        assert all_resp.total == 4
        summary = summarize_exception_queue(all_resp.items)
        assert summary.total_in_queue == 4
        assert summary.tax_mismatches == 1
        assert summary.duplicates_and_revisions == 1
        assert summary.manager_escalations == 1

        tax_resp = controller.fetch_queue(resolve_exception_preset("Tax Mismatch"))
        assert tax_resp.total == 1
        assert tax_resp.items[0].invoice_id == "inv-tax-1"
        assert ("status", "REJECTED_TAX_MISMATCH") in transport.last_query_params


def test_bulk_assign_clerk_and_validation_guards() -> None:
    """Enforce RBAC, 50-item bulk cap, and strict invoice_id/assignee validation on bulk assign."""
    assert BULK_ASSIGN_ALLOWED_ROLES == frozenset({"ap_clerk", "finance_manager"})
    assert can_bulk_assign_exceptions(["ap_clerk"]) is True
    assert can_bulk_assign_exceptions(["system_admin"]) is False

    transport = _ExceptionQueueMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ExceptionQueueController(client)
        updated, result = controller.bulk_assign_to_clerk(
            ["inv-tax-1", "inv-low-2"],
            assignee="sarah.clerk@company.com",
            existing_assignments={},
            user_roles=["ap_clerk"],
        )
        assert result.succeeded_ids == ["inv-tax-1", "inv-low-2"]
        assert updated["inv-tax-1"] == "sarah.clerk@company.com"

        with pytest.raises(PermissionError):
            controller.bulk_assign_to_clerk(
                ["inv-tax-1"], assignee="sarah.clerk@company.com", user_roles=["system_admin"]
            )
        with pytest.raises(ValueError, match=str(MAX_BULK_SELECTION)):
            controller.bulk_assign_to_clerk(
                [f"inv-{i}" for i in range(MAX_BULK_SELECTION + 1)],
                assignee="sarah.clerk@company.com",
                user_roles=["ap_clerk"],
            )
        with pytest.raises(ValueError, match="invoice_id"):
            controller.bulk_assign_to_clerk(
                ["../../etc/passwd"], assignee="sarah.clerk@company.com", user_roles=["ap_clerk"]
            )
        for bad_assignee in ("bad\r\nuser", "+formula@co.com", "@formula", "-admin"):
            with pytest.raises(ValueError, match="assignee"):
                controller.bulk_assign_to_clerk(
                    ["inv-tax-1"], assignee=bad_assignee, user_roles=["ap_clerk"]
                )


def test_bulk_refresh_status_and_rate_limit_backoff() -> None:
    """Bulk refresh polls selected invoices, isolates 404s, and stops cleanly on HTTP 429."""
    transport = _ExceptionQueueMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ExceptionQueueController(client)
        refreshed, result = controller.bulk_refresh_status(
            ["inv-tax-1", "inv-missing-999"], user_roles=["ap_clerk"]
        )
        assert "inv-tax-1" in refreshed
        assert result.succeeded_ids == ["inv-tax-1"]
        assert "inv-missing-999" in result.errors

    # Rate limit backoff stops remaining calls
    rl_transport = _ExceptionQueueMockTransport(rate_limit_get=True)
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=rl_transport) as client:
        controller = ExceptionQueueController(client)
        _, rl_result = controller.bulk_refresh_status(
            ["inv-tax-1", "inv-low-2"], user_roles=["ap_clerk"]
        )
        assert rl_result.rate_limited is True
        assert len(rl_result.errors) == 1  # stopped after first 429


def test_bulk_manager_approve_rbac_and_status_safety() -> None:
    """Only finance_manager may bulk-approve, and non-approvable exception statuses are skipped."""
    assert BULK_APPROVE_ALLOWED_ROLES == frozenset({"finance_manager"})
    assert can_bulk_approve_exceptions(["finance_manager"]) is True
    assert can_bulk_approve_exceptions(["ap_clerk"]) is False
    assert can_bulk_approve_exceptions(["system_admin"]) is False

    transport = _ExceptionQueueMockTransport()
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=transport) as client:
        controller = ExceptionQueueController(client)
        queue_items = controller.fetch_queue().items

        # ap_clerk, system_admin, and omitted user_roles hard-blocked (SEC-198 fail-closed)
        with pytest.raises(PermissionError, match="finance_manager"):
            controller.bulk_manager_approve(
                ["inv-mgr-4"], queue_items=queue_items, user_roles=["ap_clerk"]
            )
        with pytest.raises(PermissionError, match="finance_manager"):
            controller.bulk_manager_approve(
                ["inv-mgr-4"], queue_items=queue_items, user_roles=["system_admin"]
            )
        with pytest.raises(PermissionError, match="finance_manager"):
            controller.bulk_manager_approve(["inv-mgr-4"], queue_items=queue_items, user_roles=None)

        # finance_manager approves REQUIRES_MANAGER_APPROVAL while safely skipping DUPLICATE_INVOICE & REJECTED_TAX_MISMATCH
        res = controller.bulk_manager_approve(
            ["inv-mgr-4", "inv-dup-3", "inv-tax-1"],
            queue_items=queue_items,
            comment="Quarter-end manager batch sign-off",
            user_roles=["finance_manager"],
        )
        assert res.succeeded_ids == ["inv-mgr-4"]
        assert set(res.skipped_ids) == {"inv-dup-3", "inv-tax-1"}
        assert transport.approved_ids == ["inv-mgr-4"]


# ---------------------------------------------------------------------------
# Tests: Security — Formula Injection, XSS, Token Redaction & Route Blocking
# ---------------------------------------------------------------------------


def test_security_sanitization_xss_formula_and_route_traversal() -> None:
    """Neutralize CSV formulas, HTML tags, Bearer tokens, and path traversal routes in queue rows."""
    malicious = _make_exc_item(
        invoice_id="../../admin",
        invoice_number='=CMD|" /C calc"!A0',
        vendor_name="<script>alert(1)</script>Bearer eyJhbGciOiJSUzI1NiJ9.a.b",
    )
    rows = build_exception_queue_rows([malicious])
    assert rows[0]["Invoice ID"] == "—"
    assert rows[0]["Route"] == "—"
    assert not rows[0]["Invoice Number"].startswith("=")
    assert "<script>" not in rows[0]["Vendor"]
    assert "eyJhbGciOiJSUzI1NiJ9" not in rows[0]["Vendor"]

    # Ensure APIRateLimitError is imported cleanly and handled
    assert issubclass(APIRateLimitError, Exception)


# ---------------------------------------------------------------------------
# Tests: Headless Streamlit Renderer & AST Layering Hygiene
# ---------------------------------------------------------------------------


def test_streamlit_exception_queue_renderer_and_app_shell_smoke() -> None:
    """Render Human Exception Queue via app shell and direct call; verify role-aware bulk button."""
    # 1. Manager sees Bulk Manager Approve button and can assign & approve
    mgr_transport = _ExceptionQueueMockTransport(persona_role="finance_manager")
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=mgr_transport) as client:
        st_mgr = _FakeExceptionStreamlit(
            selected_ids=["inv-mgr-4", "inv-tax-1"],
            button_clicks={"Sign In as Demo Persona", "Assign Selected", "Bulk Manager Approve"},
            text_overrides={"Assign To Clerk": "sarah.clerk@company.com"},
            selected_page=PAGE_EXCEPTIONS,
        )
        render_app(api_client=client, st_module=st_mgr)

        assert any("Human Exception Queue" in t for t in st_mgr.titles)
        assert st_mgr.metrics["Total in Queue"] == 4
        assert "Bulk Manager Approve" in st_mgr.rendered_buttons
        assert mgr_transport.approved_ids == ["inv-mgr-4"]
        assert len(st_mgr.dataframes) >= 1

    # 2. AP Clerk must NEVER see Bulk Manager Approve button (CLAUDE.md §12)
    clerk_transport = _ExceptionQueueMockTransport(persona_role="ap_clerk")
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=clerk_transport) as client:
        st_clerk = _FakeExceptionStreamlit(selected_ids=["inv-mgr-4"])
        render_exception_queue(client, st_module=st_clerk, user_roles=["ap_clerk"])
        assert "Bulk Manager Approve" not in st_clerk.rendered_buttons
        assert st_clerk.metrics["Total in Queue"] == 4


def test_exception_queue_obeys_layering_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2 & §12: src/ui/exception_queue.py and app.py obey layering with zero unsafe HTML."""
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
    for rel_path in ("src/ui/exception_queue.py", "src/ui/app.py"):
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
