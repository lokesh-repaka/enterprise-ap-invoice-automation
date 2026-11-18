"""
Unit and Security Tests for Confidence Colour Coding & Role-Aware UI (P11-7).

Tests: FR-04, FR-13, BR-007, BR-014, CLAUDE.md §2, §4.2, §12, §16.1, §16.8, P11-7
"""

import ast
import json
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from src.api.schemas.invoices import InvoiceDetailResponse, InvoiceLineResponse
from src.core.config import get_settings
from src.ui.api_client import APInvoiceAPIClient
from src.ui.ingestion_dashboard import BatchInvoiceItem, build_status_table_rows
from src.ui.review_workbench import render_review_workbench
from src.ui.theme_rbac import (
    CONFIDENCE_AMBER_HEX,
    CONFIDENCE_GREEN_HEX,
    CONFIDENCE_RED_HEX,
    CONFIDENCE_YELLOW_HEX,
    build_confidence_color_map,
    classify_confidence_cue,
    evaluate_invoice_ui_capabilities,
    get_role_badge,
)


def _make_invoice(
    *,
    invoice_id: str = "inv-rbac-001",
    status: str = "VALIDATED",
    total_amount: Decimal = Decimal("2500.00"),
    currency: str = "USD",
    total_amount_usd: Decimal | None = Decimal("2500.00"),
    confidence: Decimal = Decimal("95.00"),
) -> InvoiceDetailResponse:
    now = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    return InvoiceDetailResponse(
        invoice_id=invoice_id,
        vendor_id="V-001",
        vendor_tax_id="US-12-3456789",
        vendor_name="Acme Technologies Inc.",
        invoice_number="INV-RBAC-2026-001",
        invoice_date=date(2026, 2, 10),
        due_date=date(2026, 3, 10),
        po_number="PO-RBAC-100",
        subtotal=total_amount,
        total_tax_amount=Decimal("0.00"),
        total_amount=total_amount,
        currency=currency,
        total_amount_usd=total_amount_usd,
        confidence_macro_avg=confidence,
        status=status,
        blob_raw_url=None,
        blob_json_url=None,
        created_at=now,
        updated_at=now,
        lines=[
            InvoiceLineResponse(
                line_id="l1",
                line_number=1,
                description="Enterprise Suite",
                quantity=Decimal("1.0000"),
                unit_price=total_amount,
                line_total=total_amount,
                line_tax_rate=Decimal("0.0000"),
                confidence_score=confidence,
            )
        ],
        audit_event_count=2,
    )


class _RBACWorkbenchTransport(httpx.BaseTransport):
    def __init__(self, invoice: InvoiceDetailResponse) -> None:
        self.invoice = invoice
        self.approve_called = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path == f"/api/v1/invoices/{self.invoice.invoice_id}":
            return httpx.Response(200, json=self.invoice.model_dump(mode="json"), request=request)
        if (
            request.method == "POST"
            and path == f"/api/v1/invoices/{self.invoice.invoice_id}/approve"
        ):
            self.approve_called = True
            _ = json.loads(request.read().decode("utf-8") or "{}")
            prev = self.invoice.status
            self.invoice = self.invoice.model_copy(update={"status": "APPROVED_MANAGER"})
            return httpx.Response(
                200,
                json={
                    "invoice_id": self.invoice.invoice_id,
                    "previous_status": prev,
                    "status": "APPROVED_MANAGER",
                    "approved_by": "michael.manager@company.com",
                    "approver_role": "finance_manager",
                    "total_amount": str(self.invoice.total_amount),
                    "currency": self.invoice.currency,
                    "total_amount_usd": str(
                        self.invoice.total_amount_usd or self.invoice.total_amount
                    ),
                    "high_value_threshold_usd": "10000.00",
                    "requires_manager_approval": True,
                    "approved_at": datetime(2026, 2, 15, 11, 0, 0, tzinfo=UTC).isoformat(),
                    "audit_event_id": "aud-mgr-1",
                },
                request=request,
            )
        return httpx.Response(404, json={"detail": "Not found"}, request=request)


class _FakeCol:
    def __init__(self, st: "_FakeRBACStreamlit") -> None:
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
        return None

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


class _FakeRBACStreamlit:
    def __init__(self, *, button_clicks: set[str] | None = None) -> None:
        self.session_state: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.captions: list[str] = []
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.successes: list[str] = []
        self.rendered_buttons: list[str] = []
        self._button_clicks = button_clicks or set()

    def title(self, text: str) -> None:
        return None

    def subheader(self, text: str) -> None:
        return None

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
        return value

    def text_area(self, label: str, value: str = "", **kwargs: Any) -> str:
        return value

    def selectbox(self, label: str, options: list[Any], index: int = 0, **kwargs: Any) -> Any:
        return options[index]

    def checkbox(self, label: str, value: bool = False, **kwargs: Any) -> bool:
        return value

    def file_uploader(self, label: str, **kwargs: Any) -> Any:
        return None

    def data_editor(self, data: Any, **kwargs: Any) -> Any:
        return data

    def button(self, label: str, **kwargs: Any) -> bool:
        self.rendered_buttons.append(label)
        return label in self._button_clicks


# ---------------------------------------------------------------------------
# Tests: FR-04, CLAUDE.md §12 — Confidence Colour Coding & Fail-Closed Parsing
# ---------------------------------------------------------------------------


def test_confidence_colour_coding_tri_tier_boundaries_and_fail_closed() -> None:
    """Verify exact Green/Light-Yellow/Red boundaries and fail-closed handling of corrupt scores."""
    assert CONFIDENCE_GREEN_HEX == "#22c55e"
    assert CONFIDENCE_YELLOW_HEX == "#fef08a"
    assert CONFIDENCE_AMBER_HEX == "#f97316"
    assert CONFIDENCE_RED_HEX == "#ef4444"

    # Exact boundaries
    assert classify_confidence_cue(Decimal("100.00")).hex_color == "#22c55e"
    assert classify_confidence_cue(Decimal("90.00")).hex_color == "#22c55e"
    assert classify_confidence_cue(Decimal("89.99")).hex_color == "#fef08a"
    assert classify_confidence_cue(Decimal("80.00")).hex_color == "#fef08a"
    assert classify_confidence_cue(Decimal("79.99")).hex_color == "#ef4444"
    assert classify_confidence_cue(Decimal("0.00")).hex_color == "#ef4444"

    # Corrupt / forged / NaN / Inf / bool / out-of-range scores fail closed to LOW (#ef4444), NEVER green!
    for bad_score in (
        None,
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        -10,
        150,
        "abc",
    ):
        cue = classify_confidence_cue(bad_score)  # type: ignore[arg-type]
        assert cue.tier == "LOW"
        assert cue.hex_color == "#ef4444"

    color_map = build_confidence_color_map([Decimal("95.0"), Decimal("85.0"), Decimal("72.0")])
    assert color_map == {0: "#22c55e", 1: "#fef08a", 2: "#ef4444"}


# ---------------------------------------------------------------------------
# Tests: FR-13, CLAUDE.md §12 — Hide Approve Button for ap_clerk > $10,000
# ---------------------------------------------------------------------------


def test_role_aware_approve_hidden_for_clerk_above_10k_and_subcent_precision() -> None:
    """Approve button is strictly hidden for ap_clerk at $10,000.01+ and shown for finance_manager."""
    exact_10k = _make_invoice(
        total_amount=Decimal("10000.00"), total_amount_usd=Decimal("10000.00")
    )
    over_10k = _make_invoice(total_amount=Decimal("10000.01"), total_amount_usd=Decimal("10000.01"))
    eur_over_10k = _make_invoice(
        total_amount=Decimal("9500.00"), currency="EUR", total_amount_usd=Decimal("10355.00")
    )
    eur_missing_fx = _make_invoice(
        total_amount=Decimal("500.00"), currency="EUR", total_amount_usd=None
    )

    # $10,000.00 inclusive -> clerk allowed
    cap_exact = evaluate_invoice_ui_capabilities(exact_10k, ["ap_clerk"])
    assert cap_exact.show_approve_button is True
    assert cap_exact.approve_button_label == "Approve (One-Click)"
    assert cap_exact.approve_hidden_reason is None

    # $10,000.01 -> HIDDEN for ap_clerk with clear escalation reason
    cap_over_clerk = evaluate_invoice_ui_capabilities(over_10k, ["ap_clerk"])
    assert cap_over_clerk.show_approve_button is False
    assert cap_over_clerk.approve_button_label is None
    assert cap_over_clerk.approve_hidden_reason is not None
    assert "Finance Manager" in cap_over_clerk.approve_hidden_reason

    # $10,000.01 -> SHOWN for finance_manager
    cap_over_mgr = evaluate_invoice_ui_capabilities(over_10k, ["finance_manager"])
    assert cap_over_mgr.show_approve_button is True
    assert cap_over_mgr.approve_button_label == "Approve (Finance Manager)"

    # Non-USD FX-converted > $10,000 -> HIDDEN for ap_clerk, SHOWN for finance_manager
    assert evaluate_invoice_ui_capabilities(eur_over_10k, ["ap_clerk"]).show_approve_button is False
    assert (
        evaluate_invoice_ui_capabilities(eur_over_10k, ["finance_manager"]).show_approve_button
        is True
    )

    # Non-USD missing FX conversion -> fail-closed HIDDEN for ap_clerk
    assert (
        evaluate_invoice_ui_capabilities(eur_missing_fx, ["ap_clerk"]).show_approve_button is False
    )

    # SEC-207: Stale lower total_amount_usd on a >$10k USD invoice must still HIDE Approve for ap_clerk
    stale_usd_high = _make_invoice(
        total_amount=Decimal("15000.00"),
        currency="USD",
        total_amount_usd=Decimal("500.00"),
    )
    assert (
        evaluate_invoice_ui_capabilities(stale_usd_high, ["ap_clerk"]).show_approve_button is False
    )

    # SEC-207: Non-finite / negative threshold fails closed (never shows Approve)
    assert (
        evaluate_invoice_ui_capabilities(
            exact_10k, ["ap_clerk"], high_value_threshold_usd=Decimal("NaN")
        ).show_approve_button
        is False
    )


def test_role_aware_approve_hidden_for_po_variance_credit_note_low_conf_and_admin() -> None:
    """Enforce PO variance >5%, credit-note negative total, <90% confidence, and strict role allowlist."""
    inv = _make_invoice(total_amount=Decimal("5300.00"), total_amount_usd=Decimal("5300.00"))
    # 6% PO variance (> 5%) -> hidden for ap_clerk, shown for finance_manager
    cap_po_clerk = evaluate_invoice_ui_capabilities(inv, ["ap_clerk"], po_amount=Decimal("5000.00"))
    assert cap_po_clerk.show_approve_button is False
    assert "PO variance" in (cap_po_clerk.approve_hidden_reason or "")
    assert (
        evaluate_invoice_ui_capabilities(
            inv, ["finance_manager"], po_amount=Decimal("5000.00")
        ).show_approve_button
        is True
    )

    # Exact 5% PO variance ($5250 vs $5000) -> still within tolerance for ap_clerk
    inv_5pct = _make_invoice(total_amount=Decimal("5250.00"), total_amount_usd=Decimal("5250.00"))
    assert (
        evaluate_invoice_ui_capabilities(
            inv_5pct, ["ap_clerk"], po_amount=Decimal("5000.00")
        ).show_approve_button
        is True
    )

    # Credit note (negative total) -> hidden for ap_clerk even if status spoofed to VALIDATED
    credit_note = _make_invoice(
        total_amount=Decimal("-500.00"), total_amount_usd=Decimal("-500.00"), status="VALIDATED"
    )
    assert evaluate_invoice_ui_capabilities(credit_note, ["ap_clerk"]).show_approve_button is False

    # Confidence < 90% -> hidden for ap_clerk
    low_conf = _make_invoice(confidence=Decimal("89.99"))
    assert evaluate_invoice_ui_capabilities(low_conf, ["ap_clerk"]).show_approve_button is False

    # system_admin, unauthenticated, and spoofed role strings -> always hidden
    clean_inv = _make_invoice()
    for denied_roles in (
        ["system_admin"],
        [],
        None,
        ["AP_CLERK"],
        ["finance_manager;admin"],
        ["superadmin"],
    ):
        cap = evaluate_invoice_ui_capabilities(clean_inv, denied_roles)
        assert cap.show_approve_button is False


def test_thresholds_read_dynamically_from_settings_not_hardcoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLAUDE.md §16.8: HIGH_VALUE_THRESHOLD_USD & PO_VARIANCE_TOLERANCE_PERCENT come from get_settings()."""
    monkeypatch.setenv("HIGH_VALUE_THRESHOLD_USD", "5000.00")
    monkeypatch.setenv("PO_VARIANCE_TOLERANCE_PERCENT", "2.0")
    get_settings.cache_clear()
    try:
        inv_6k = _make_invoice(total_amount=Decimal("6000.00"), total_amount_usd=Decimal("6000.00"))
        cap = evaluate_invoice_ui_capabilities(inv_6k, ["ap_clerk"])
        assert cap.show_approve_button is False
        assert "5,000.00" in (cap.approve_hidden_reason or "")

        inv_3pct = _make_invoice(
            total_amount=Decimal("1030.00"), total_amount_usd=Decimal("1030.00")
        )
        cap_po = evaluate_invoice_ui_capabilities(
            inv_3pct, ["ap_clerk"], po_amount=Decimal("1000.00")
        )
        assert cap_po.show_approve_button is False
    finally:
        monkeypatch.delenv("HIGH_VALUE_THRESHOLD_USD", raising=False)
        monkeypatch.delenv("PO_VARIANCE_TOLERANCE_PERCENT", raising=False)
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Tests: Headless Workbench Verification — Approve Button HIDDEN for Clerk >$10k
# ---------------------------------------------------------------------------


def test_workbench_renderer_hides_approve_button_for_clerk_over_10k_and_shows_for_manager() -> None:
    """CLAUDE.md §12: Approve button must be hidden (not rendered) for ap_clerk when total > $10k."""
    high_val = _make_invoice(
        invoice_id="inv-high-15k",
        status="VALIDATED",
        total_amount=Decimal("15000.00"),
        total_amount_usd=Decimal("15000.00"),
        confidence=Decimal("96.50"),
    )

    # 1. AP Clerk -> Approve button is completely ABSENT from rendered buttons, escalation notice shown
    clerk_transport = _RBACWorkbenchTransport(high_val)
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=clerk_transport) as client:
        st_clerk = _FakeRBACStreamlit(
            button_clicks={"Approve (One-Click)", "Approve (Finance Manager)"}
        )
        render_review_workbench(
            client, invoice_id="inv-high-15k", st_module=st_clerk, user_roles=["ap_clerk"]
        )
        assert "Approve (One-Click)" not in st_clerk.rendered_buttons
        assert "Approve (Finance Manager)" not in st_clerk.rendered_buttons
        assert clerk_transport.approve_called is False
        assert any("Finance Manager" in msg for msg in st_clerk.infos + st_clerk.warnings)

    # 2. Finance Manager -> Approve button IS rendered and invokes POST /approve
    mgr_transport = _RBACWorkbenchTransport(high_val)
    with APInvoiceAPIClient(base_url="http://127.0.0.1:8000", transport=mgr_transport) as client:
        st_mgr = _FakeRBACStreamlit(button_clicks={"Approve (Finance Manager)"})
        render_review_workbench(
            client, invoice_id="inv-high-15k", st_module=st_mgr, user_roles=["finance_manager"]
        )
        assert "Approve (Finance Manager)" in st_mgr.rendered_buttons
        assert mgr_transport.approve_called is True


def test_ingestion_dashboard_table_includes_confidence_color_and_role_badges() -> None:
    """Unified confidence colour column in Ingestion Dashboard + clean sidebar role badges."""
    now = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    items = [
        BatchInvoiceItem(
            invoice_id="inv-1",
            filename="high.pdf",
            size_bytes=1024,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-001",
            status="VALIDATED",
            confidence_macro_avg=Decimal("94.00"),
        ),
        BatchInvoiceItem(
            invoice_id="inv-2",
            filename="med.pdf",
            size_bytes=1024,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-001",
            status="REQUIRES_REVIEW",
            confidence_macro_avg=Decimal("84.00"),
        ),
        BatchInvoiceItem(
            invoice_id="inv-3",
            filename="low.pdf",
            size_bytes=1024,
            uploaded_at=now,
            detected_mime="application/pdf",
            detection_mode="PDF Document",
            vendor_id="V-001",
            status="REQUIRES_APPROVAL",
            confidence_macro_avg=Decimal("71.00"),
        ),
    ]
    rows = build_status_table_rows(items)
    assert rows[0]["Confidence Color"] == "#22c55e"
    assert rows[1]["Confidence Color"] == "#fef08a"
    assert rows[2]["Confidence Color"] == "#ef4444"

    assert get_role_badge(["ap_clerk"]) == "AP Clerk (≤$10k Approval)"
    assert get_role_badge(["finance_manager"]) == "Finance Manager (Full Approval)"
    assert get_role_badge(["system_admin"]) == "System Admin (Audit & Ops)"
    assert get_role_badge([]) == "Read-Only (Unauthenticated)"
    assert get_role_badge(None) == "Read-Only (Unauthenticated)"


def test_all_ui_modules_obey_layering_and_zero_unsafe_html() -> None:
    """CLAUDE.md §4.2 & §12: Every file in src/ui/ obeys strict layering and zero unsafe_allow_html."""
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
    ui_files = sorted(Path("src/ui").glob("*.py"))
    assert (
        len(ui_files) >= 7
    )  # __init__, api_client, app, ingestion, workbench, exceptions, revision, audit, theme_rbac
    for ui_file in ui_files:
        source = ui_file.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"Forbidden import in {ui_file}: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_prefixes), (
                    f"Forbidden import in {ui_file}: {node.module}"
                )
            elif isinstance(node, ast.keyword) and node.arg == "unsafe_allow_html":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    raise AssertionError(f"unsafe_allow_html=True is forbidden in {ui_file}")
