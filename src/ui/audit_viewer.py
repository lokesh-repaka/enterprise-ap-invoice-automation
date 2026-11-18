"""
Audit Trail Viewer (/audit/{invoice_id}) — Chronological Timeline & Immutable Display (P11-6).

Implements PRD Screen 5, N3, N6, N8, BR-031, and CLAUDE.md §4.2, §12 & §16.9:
- Search & Filter Controls: Invoice ID lookup, multi-select Action Type filter (9 canonical
  AuditActionType values), Actor (User ID) filter, and bounded pagination.
- Immutable Chronological Timeline: Strictly read-only oldest-to-newest timeline displaying
  ingestion, extraction, validation, manual edits (Field, Old -> New, Reason Code, Comment),
  re-validations, approvals, and staging exports, with prominent WORM 7-year retention banner.
- Safe Read-Only Export: Formula-neutralized CSV and PII-redacted JSON downloads.

Security & Layering Invariants:
- Reaches backend exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
- Strictly immutable: zero edit/delete controls and zero ``st.data_editor`` calls.
- Never calls ``unsafe_allow_html=True``; masks sensitive audit fields (including dotted
  field names like ``invoice.iban``), redacts Bearer/JWT tokens, and neutralizes CSV
  formula injection (CWE-79, CWE-200, CWE-532, CWE-1236).
- Enforces fail-closed 3-role RBAC (``ap_clerk``, ``finance_manager``, ``system_admin``).
"""

import csv
import io
import json
import re
from collections.abc import Sequence
from datetime import UTC
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import AuditEventResponse, InvoiceAuditTrailResponse
from src.core.logging import get_logger
from src.ui.api_client import APIClientError, APInvoiceAPIClient
from src.ui.ingestion_dashboard import sanitize_display_text

logger = get_logger("ap.ui.audit_viewer")

AUDIT_VIEW_ALLOWED_ROLES: frozenset[str] = frozenset(
    {"ap_clerk", "finance_manager", "system_admin"}
)

CANONICAL_AUDIT_ACTION_TYPES: tuple[str, ...] = (
    "INGEST",
    "EXTRACTION",
    "VALIDATION",
    "EDIT",
    "REVALIDATE",
    "APPROVE",
    "REJECT",
    "STATUS_TRANSITION",
    "EXPORT",
)
_CANONICAL_ACTION_SET: frozenset[str] = frozenset(CANONICAL_AUDIT_ACTION_TYPES)

SENSITIVE_DISPLAY_FIELDS: frozenset[str] = frozenset(
    {
        "vendor_tax_id",
        "tax_id",
        "vat_id",
        "bank_account",
        "iban",
        "routing_number",
        "ssn",
        "swift_code",
        "password",
        "secret",
        "token",
    }
)

MAX_AUDIT_LIMIT: int = 200
MAX_AUDIT_OFFSET: int = 100_000
MAX_USER_ID_LENGTH: int = 128

_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_OR_BIDI_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_INLINE_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_INLINE_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


# ---------------------------------------------------------------------------
# Typed Filter & Summary Models
# ---------------------------------------------------------------------------


class AuditTrailFilter(BaseModel):
    """Typed filter & pagination contract for ``GET /api/v1/invoices/{id}/audit``."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    action_types: tuple[str, ...] = ()
    user_id: str | None = None
    limit: int = MAX_AUDIT_LIMIT
    offset: int = 0


class AuditTrailSummary(BaseModel):
    """Summary KPI counts for the Audit Trail Viewer header strip."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    invoice_number: str
    current_status: str
    immutable: bool
    total_events: int
    manual_edits: int
    revalidations: int
    approvals: int


# ---------------------------------------------------------------------------
# Validation, PII Redaction, Chronological Timeline & Safe Export Helpers
# ---------------------------------------------------------------------------


def can_view_audit_trail(user_roles: Sequence[str] | None) -> bool:
    """Allow audit trail inspection for all 3 authenticated platform roles; deny unauthenticated."""
    return bool(user_roles and AUDIT_VIEW_ALLOWED_ROLES.intersection(user_roles))


def validate_audit_filter(afilter: AuditTrailFilter) -> AuditTrailFilter:
    """Strictly validate invoice_id, action_types allowlist, user_id, and pagination bounds."""
    if not isinstance(afilter.invoice_id, str) or not _INVOICE_ID_RE.match(
        afilter.invoice_id.strip()
    ):
        raise ValueError("Invalid invoice_id format (allowed: A-Z, a-z, 0-9, _, -)")
    clean_id = afilter.invoice_id.strip()

    clean_actions: list[str] = []
    for raw_act in afilter.action_types:
        act = raw_act.strip().upper()
        if act not in _CANONICAL_ACTION_SET:
            raise ValueError(f"Unsupported action_type filter: {raw_act!r}")
        if act not in clean_actions:
            clean_actions.append(act)

    clean_user: str | None = None
    if afilter.user_id is not None:
        if _CONTROL_OR_BIDI_RE.search(afilter.user_id):
            raise ValueError("user_id filter contains disallowed control or bidi characters")
        stripped_user = afilter.user_id.strip()
        if stripped_user:
            if len(stripped_user) > MAX_USER_ID_LENGTH:
                raise ValueError(f"user_id filter exceeds maximum {MAX_USER_ID_LENGTH} characters")
            clean_user = stripped_user

    if isinstance(afilter.limit, bool) or not (1 <= afilter.limit <= MAX_AUDIT_LIMIT):
        raise ValueError(f"limit must be within [1, {MAX_AUDIT_LIMIT}]")
    if isinstance(afilter.offset, bool) or not (0 <= afilter.offset <= MAX_AUDIT_OFFSET):
        raise ValueError(f"offset must be within [0, {MAX_AUDIT_OFFSET}]")

    return AuditTrailFilter(
        invoice_id=clean_id,
        action_types=tuple(clean_actions),
        user_id=clean_user,
        limit=afilter.limit,
        offset=afilter.offset,
    )


def _is_sensitive_field(field_name: str | None) -> bool:
    """Match sensitive field names including dotted/nested paths like ``invoice.iban`` (CWE-200)."""
    if not field_name:
        return False
    normalized = field_name.strip().lower()
    if normalized in SENSITIVE_DISPLAY_FIELDS:
        return True
    leaf = normalized.rsplit(".", 1)[-1]
    if leaf in SENSITIVE_DISPLAY_FIELDS:
        return True
    return any(
        tok in normalized for tok in ("tax_id", "iban", "bank_account", "routing_number", "ssn")
    )


def _redact_inline_pii(value: str) -> str:
    """Defense-in-depth redaction of raw SSNs and IBANs in free-text audit values/comments (SEC-204)."""
    masked = _INLINE_SSN_RE.sub("[REDACTED_SSN]", value)
    return _INLINE_IBAN_RE.sub("[REDACTED_IBAN]", masked)


def _format_audit_value(field_name: str | None, value: str | None) -> str:
    if value is None or not str(value).strip():
        return "—"
    if _is_sensitive_field(field_name):
        return "[REDACTED_PII]"
    return sanitize_display_text(_redact_inline_pii(str(value)), max_length=160)


def build_chronological_timeline_rows(
    events: Sequence[AuditEventResponse],
) -> list[dict[str, Any]]:
    """
    Build strictly chronological (oldest -> newest), PII-masked, XSS/formula-safe timeline rows.
    """
    ordered = sorted(
        events,
        key=lambda ev: (
            ev.timestamp.astimezone(UTC)
            if ev.timestamp.tzinfo
            else ev.timestamp.replace(tzinfo=UTC),
            ev.audit_id,
        ),
    )
    rows: list[dict[str, Any]] = []
    for seq, ev in enumerate(ordered, start=1):
        ts_utc = (
            ev.timestamp.astimezone(UTC)
            if ev.timestamp.tzinfo
            else ev.timestamp.replace(tzinfo=UTC)
        )
        prev_str = _format_audit_value(ev.field_name, ev.previous_value)
        new_str = _format_audit_value(ev.field_name, ev.new_value)
        if prev_str == "—" and new_str == "—":
            change_str = "—"
        elif prev_str == "—":
            change_str = new_str
        else:
            change_str = f"{prev_str} -> {new_str}"

        rows.append(
            {
                "Seq #": seq,
                "Timestamp (UTC)": ts_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "Action": sanitize_display_text(ev.action_type, max_length=40),
                "Actor": sanitize_display_text(ev.user_id, max_length=128),
                "Field": sanitize_display_text(ev.field_name, max_length=80)
                if ev.field_name
                else "—",
                "Change": change_str,
                "Reason Code": sanitize_display_text(ev.reason_code, max_length=40)
                if ev.reason_code
                else "—",
                "Comment": sanitize_display_text(_redact_inline_pii(ev.comment), max_length=240)
                if ev.comment
                else "—",
                "Audit ID": sanitize_display_text(ev.audit_id, max_length=64),
            }
        )
    return rows


def summarize_audit_trail(trail: InvoiceAuditTrailResponse) -> AuditTrailSummary:
    """Compute Audit Trail Viewer header KPI counts."""
    manual_edits = sum(1 for ev in trail.events if ev.action_type == "EDIT")
    revalidations = sum(1 for ev in trail.events if ev.action_type == "REVALIDATE")
    approvals = sum(1 for ev in trail.events if ev.action_type == "APPROVE")
    return AuditTrailSummary(
        invoice_id=trail.invoice_id,
        invoice_number=trail.invoice_number,
        current_status=trail.current_status,
        immutable=trail.immutable,
        total_events=trail.total_events,
        manual_edits=manual_edits,
        revalidations=revalidations,
        approvals=approvals,
    )


def export_audit_trail_csv(trail: InvoiceAuditTrailResponse) -> str:
    """Export chronological, PII-redacted, CSV-formula-safe audit trail as UTF-8 CSV."""
    rows = build_chronological_timeline_rows(trail.events)
    fieldnames = [
        "Seq #",
        "Timestamp (UTC)",
        "Action",
        "Actor",
        "Field",
        "Change",
        "Reason Code",
        "Comment",
        "Audit ID",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def export_audit_trail_json(trail: InvoiceAuditTrailResponse) -> str:
    """Export chronological, PII-redacted audit trail as deterministic JSON with immutability header."""
    rows = build_chronological_timeline_rows(trail.events)
    envelope = {
        "invoice_id": sanitize_display_text(trail.invoice_id, max_length=64),
        "invoice_number": sanitize_display_text(trail.invoice_number, max_length=100),
        "current_status": sanitize_display_text(trail.current_status, max_length=40),
        "immutable": bool(trail.immutable),
        "retention_policy": "7-year WORM statutory retention (N6)",
        "total_events": trail.total_events,
        "timeline": rows,
    }
    return json.dumps(envelope, indent=2)


# ---------------------------------------------------------------------------
# Stateful Audit Trail Viewer Controller (Backend-Transport-Only)
# ---------------------------------------------------------------------------


class AuditTrailViewerController:
    """Fetches immutable chronological audit logs exclusively via ``APInvoiceAPIClient``."""

    def __init__(self, api_client: APInvoiceAPIClient) -> None:
        self._client = api_client

    def load_audit_trail(
        self,
        afilter: AuditTrailFilter,
        *,
        user_roles: Sequence[str] | None = None,
    ) -> InvoiceAuditTrailResponse:
        """Enforce 3-role RBAC + strict filter validation and query ``GET /invoices/{id}/audit``."""
        if not can_view_audit_trail(user_roles):
            raise PermissionError(
                "Audit trail access requires an authenticated 'ap_clerk', 'finance_manager', "
                "or 'system_admin' role"
            )
        clean = validate_audit_filter(afilter)
        return self._client.get_invoice_audit(
            clean.invoice_id,
            action_types=list(clean.action_types) if clean.action_types else None,
            user_id=clean.user_id,
            limit=clean.limit,
            offset=clean.offset,
        )


# ---------------------------------------------------------------------------
# Streamlit UI Renderer (Screen 5 — Immutable Audit Trail Viewer)
# ---------------------------------------------------------------------------


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def render_audit_trail_viewer(
    api_client: APInvoiceAPIClient,
    *,
    invoice_id: str | None = None,
    st_module: Any | None = None,
    user_roles: Sequence[str] | None = None,
) -> None:
    """Render PRD Screen 5 (Immutable Audit Trail Viewer `/audit/{invoice_id}`)."""
    st = _get_streamlit(st_module)
    controller = AuditTrailViewerController(api_client)

    st.title("Audit Trail Viewer")
    st.caption(
        "Immutable, append-only chronological audit timeline (7-year WORM statutory retention · "
        "read-only display — edits and deletions are structurally disabled)."
    )

    if not can_view_audit_trail(user_roles):
        st.info(
            "Sign in as an AP Clerk, Finance Manager, or System Admin to inspect invoice audit trails."
        )
        return

    # --- 1. Search & Filter Controls ---
    default_id = invoice_id or str(st.session_state.get("audit_invoice_id", ""))
    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
    with c1:
        entered_id = st.text_input("Invoice ID", value=default_id).strip()
    with c2:
        selected_actions = st.multiselect(
            "Action Type Filter",
            options=list(CANONICAL_AUDIT_ACTION_TYPES),
            default=[],
        )
    with c3:
        actor_filter = st.text_input("Filter by Actor (User ID)", value="").strip()
    with c4:
        load_clicked = st.button("Load Audit Trail")

    cached_trail: InvoiceAuditTrailResponse | None = st.session_state.get("audit_trail")
    should_load = bool(entered_id) and (
        load_clicked
        or cached_trail is None
        or cached_trail.invoice_id != entered_id
        or bool(selected_actions)
        or bool(actor_filter)
    )

    if should_load:
        try:
            trail = controller.load_audit_trail(
                AuditTrailFilter(
                    invoice_id=entered_id,
                    action_types=tuple(selected_actions),
                    user_id=actor_filter or None,
                ),
                user_roles=user_roles,
            )
            st.session_state["audit_invoice_id"] = trail.invoice_id
            st.session_state["audit_trail"] = trail
            cached_trail = trail
        except (PermissionError, ValueError, APIClientError) as exc:
            st.error(sanitize_display_text(str(exc), max_length=220))
            return

    if cached_trail is None:
        st.info("Enter an Invoice ID above and click Load Audit Trail to inspect its history.")
        return

    # --- 2. Immutable WORM Banner & Summary KPIs ---
    summary = summarize_audit_trail(cached_trail)
    st.info(
        f"IMMUTABLE AUDIT RECORD (Read-Only · 7-Year Retention) — "
        f"Invoice {sanitize_display_text(summary.invoice_number, max_length=80)} "
        f"({sanitize_display_text(summary.invoice_id, max_length=64)}) · "
        f"Status: {sanitize_display_text(summary.current_status, max_length=40)}"
    )

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        k1.metric("Total Events", summary.total_events)
    with k2:
        k2.metric("Manual Edits", summary.manual_edits)
    with k3:
        k3.metric("Re-Validations", summary.revalidations)
    with k4:
        k4.metric("Approvals", summary.approvals)

    st.divider()

    # --- 3. Chronological Immutable Timeline Table ---
    st.subheader("Chronological Timeline (Oldest -> Newest)")
    timeline_rows = build_chronological_timeline_rows(cached_trail.events)
    if timeline_rows:
        st.dataframe(timeline_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No audit events match the active filters.")

    # --- 4. Read-Only Safe Export Controls ---
    st.divider()
    safe_file_stem = (
        cached_trail.invoice_id if _INVOICE_ID_RE.match(cached_trail.invoice_id) else "audit_trail"
    )
    e1, e2 = st.columns(2)
    with e1:
        e1.download_button(
            "Download Immutable Audit CSV",
            data=export_audit_trail_csv(cached_trail),
            file_name=f"audit_{safe_file_stem}.csv",
            mime="text/csv",
        )
    with e2:
        e2.download_button(
            "Download Immutable Audit JSON",
            data=export_audit_trail_json(cached_trail),
            file_name=f"audit_{safe_file_stem}.json",
            mime="application/json",
        )


__all__ = [
    "AUDIT_VIEW_ALLOWED_ROLES",
    "AuditTrailFilter",
    "AuditTrailSummary",
    "AuditTrailViewerController",
    "CANONICAL_AUDIT_ACTION_TYPES",
    "MAX_AUDIT_LIMIT",
    "MAX_AUDIT_OFFSET",
    "MAX_USER_ID_LENGTH",
    "SENSITIVE_DISPLAY_FIELDS",
    "build_chronological_timeline_rows",
    "can_view_audit_trail",
    "export_audit_trail_csv",
    "export_audit_trail_json",
    "render_audit_trail_viewer",
    "summarize_audit_trail",
    "validate_audit_filter",
]
