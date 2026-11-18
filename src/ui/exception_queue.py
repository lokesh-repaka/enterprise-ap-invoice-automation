"""
Human Exception Queue (/exceptions) — Filtered Queue, Confidence Colour Coding & Bulk Actions (P11-4).

Implements PRD Screen 3, FR-04, FR-09, FR-10, FR-11, FR-13, and CLAUDE.md §4.2, §12 & §16.1:
- Filter & Search Controls: Exception type presets (Tax Mismatch, Low Confidence, Duplicate/Revision,
  Credit Note, High Value / Manager Escalation), vendor/invoice search, currency, date range, sort & pagination.
- Queue Grid: Urgency indicator, Invoice ID, Invoice Number, Vendor, Stated Total, Primary Exception Cause,
  tri-tier Confidence colour coding (#22c55e / #fef08a / #ef4444), Elapsed Time in Queue, Assigned Clerk,
  and deep-link Route (/revision/{id} vs /workbench/{id}).
- Bulk Actions: Bulk Assign to Clerk, Bulk Refresh Status (with HTTP 429 backoff), and role-aware
  Bulk Manager Approve (visible & authorized strictly for ``finance_manager`` on approvable statuses).

Security & Layering Invariants:
- Reaches backend exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
- Never calls ``unsafe_allow_html=True``; neutralizes XSS/HTML, bidi/control chars, JWT leaks,
  and CSV formula prefixes (CWE-79, CWE-1236).
- Enforces strict filter allowlists, 50-item bulk caps, RBAC fail-closed checks, and route traversal guards.
"""

import re
from collections.abc import Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import (
    ExceptionQueueItem,
    ExceptionQueueResponse,
    InvoiceApprovalRequest,
    InvoiceDetailResponse,
)
from src.core.logging import get_logger
from src.ui.api_client import APIClientError, APInvoiceAPIClient, APIRateLimitError
from src.ui.ingestion_dashboard import sanitize_display_text
from src.ui.review_workbench import (
    MANAGER_APPROVABLE_STATUSES,
    classify_confidence_cue,
)

logger = get_logger("ap.ui.exception_queue")

CANONICAL_EXCEPTION_STATUSES: frozenset[str] = frozenset(
    {
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "REQUIRES_MANAGER_APPROVAL",
    }
)

ALLOWED_SORT_COLUMNS: frozenset[str] = frozenset(
    {"created_at", "total_amount", "confidence_macro_avg", "invoice_date"}
)
ALLOWED_SORT_ORDERS: frozenset[str] = frozenset({"asc", "desc"})
ALLOWED_CURRENCIES: tuple[str, ...] = ("", "USD", "GBP", "EUR")

BULK_ASSIGN_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
BULK_REFRESH_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
BULK_APPROVE_ALLOWED_ROLES: frozenset[str] = frozenset({"finance_manager"})

MAX_BULK_SELECTION: int = 50
MAX_STORED_ASSIGNMENTS: int = 1000
MAX_PAGE_LIMIT: int = 100
MAX_PAGE_OFFSET: int = 100_000
MAX_FILTER_AMOUNT: Decimal = Decimal("999999999999.99")

_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_ASSIGNEE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{1,119}$")
_CONTROL_OR_BIDI_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")

EXCEPTION_CAUSE_LABELS: dict[str, str] = {
    "REJECTED_TAX_MISMATCH": "Tax Mismatch",
    "REQUIRES_REVIEW": "Low Confidence (80–89%)",
    "REQUIRES_APPROVAL": "Low Confidence (<80%) / Validation Fail",
    "DUPLICATE_INVOICE": "Duplicate Submission",
    "FLAGGED_POTENTIAL_REVISION": "Potential Revision (-REV / Amount Diff)",
    "CREDIT_NOTE": "Credit Note (Negative Balance)",
    "REQUIRES_MANAGER_APPROVAL": "High Value (>$10k) / PO Variance Escalation",
}

REVISION_ROUTE_STATUSES: frozenset[str] = frozenset(
    {"DUPLICATE_INVOICE", "FLAGGED_POTENTIAL_REVISION"}
)
CRITICAL_URGENCY_STATUSES: frozenset[str] = frozenset(
    {"REJECTED_TAX_MISMATCH", "DUPLICATE_INVOICE", "REQUIRES_MANAGER_APPROVAL", "REQUIRES_APPROVAL"}
)
HIGH_URGENCY_STATUSES: frozenset[str] = frozenset({"FLAGGED_POTENTIAL_REVISION", "CREDIT_NOTE"})


# ---------------------------------------------------------------------------
# Typed Filter, Summary & Bulk Operation Models
# ---------------------------------------------------------------------------


class ExceptionQueueFilter(BaseModel):
    """Typed filter & pagination specification for ``GET /api/v1/invoices/exceptions``."""

    model_config = ConfigDict(frozen=True)

    statuses: tuple[str, ...] = ()
    vendor_id: str | None = None
    vendor_name: str | None = None
    invoice_number: str | None = None
    currency: str | None = None
    min_amount: Decimal | None = None
    max_amount: Decimal | None = None
    date_from: date | None = None
    date_to: date | None = None
    max_confidence: Decimal | None = None
    sort_by: str = "created_at"
    sort_order: str = "desc"
    limit: int = 50
    offset: int = 0


EXCEPTION_TYPE_PRESETS: dict[str, ExceptionQueueFilter] = {
    "All Exceptions": ExceptionQueueFilter(),
    "Tax Mismatch": ExceptionQueueFilter(statuses=("REJECTED_TAX_MISMATCH",)),
    "Low Confidence": ExceptionQueueFilter(
        statuses=("REQUIRES_REVIEW", "REQUIRES_APPROVAL"),
        max_confidence=Decimal("89.99"),
    ),
    "Duplicate / Revision": ExceptionQueueFilter(
        statuses=("DUPLICATE_INVOICE", "FLAGGED_POTENTIAL_REVISION"),
    ),
    "Credit Note": ExceptionQueueFilter(statuses=("CREDIT_NOTE",)),
    "High Value / Manager Escalation": ExceptionQueueFilter(
        statuses=("REQUIRES_MANAGER_APPROVAL",),
    ),
}


class ExceptionQueueSummary(BaseModel):
    """Summary KPI counts for the Human Exception Queue header strip."""

    model_config = ConfigDict(frozen=True)

    total_in_queue: int
    critical: int
    tax_mismatches: int
    duplicates_and_revisions: int
    manager_escalations: int
    low_confidence: int


class BulkActionResult(BaseModel):
    """Outcome summary of a bounded bulk queue operation."""

    model_config = ConfigDict(frozen=True)

    action: str
    succeeded_ids: list[str]
    skipped_ids: list[str]
    errors: dict[str, str]
    rate_limited: bool = False


# ---------------------------------------------------------------------------
# Filter Validation, Urgency, Elapsed Time & Queue Grid Helpers
# ---------------------------------------------------------------------------


def resolve_exception_preset(preset_name: str) -> ExceptionQueueFilter:
    """Resolve a PRD Screen 3 exception type preset name into an ``ExceptionQueueFilter``."""
    if preset_name not in EXCEPTION_TYPE_PRESETS:
        raise ValueError(f"Unknown exception type preset: {preset_name!r}")
    return EXCEPTION_TYPE_PRESETS[preset_name]


def _clean_optional_search(value: str | None, *, field_name: str, max_length: int) -> str | None:
    if value is None:
        return None
    if _CONTROL_OR_BIDI_RE.search(value):
        raise ValueError(f"{field_name} contains disallowed control or bidi characters")
    stripped = value.strip()
    if not stripped:
        return None
    if len(stripped) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    return stripped


def validate_queue_filter(qfilter: ExceptionQueueFilter) -> ExceptionQueueFilter:
    """Validate and normalize an ``ExceptionQueueFilter`` before querying the backend."""
    clean_statuses: list[str] = []
    for raw_st in qfilter.statuses:
        st = raw_st.strip().upper()
        if st not in CANONICAL_EXCEPTION_STATUSES:
            raise ValueError(f"Unsupported exception status filter: {raw_st!r}")
        if st not in clean_statuses:
            clean_statuses.append(st)

    clean_vendor_id = _clean_optional_search(
        qfilter.vendor_id, field_name="vendor_id", max_length=64
    )
    if clean_vendor_id is not None and not _INVOICE_ID_RE.match(clean_vendor_id):
        raise ValueError("Invalid vendor_id filter format")

    clean_vendor_name = _clean_optional_search(
        qfilter.vendor_name, field_name="vendor_name", max_length=120
    )
    clean_invoice_number = _clean_optional_search(
        qfilter.invoice_number, field_name="invoice_number", max_length=100
    )

    clean_currency: str | None = None
    if qfilter.currency is not None and qfilter.currency.strip():
        cand = qfilter.currency.strip().upper()
        if not _CURRENCY_RE.match(cand):
            raise ValueError("currency must be a 3-letter ISO currency code (e.g., USD, GBP, EUR)")
        clean_currency = cand

    for label, amt in (("min_amount", qfilter.min_amount), ("max_amount", qfilter.max_amount)):
        if amt is not None:
            if not amt.is_finite() or amt < Decimal("0") or amt > MAX_FILTER_AMOUNT:
                raise ValueError(f"{label} must be finite and within [0, {MAX_FILTER_AMOUNT}]")
    if (
        qfilter.min_amount is not None
        and qfilter.max_amount is not None
        and qfilter.min_amount > qfilter.max_amount
    ):
        raise ValueError("min_amount cannot exceed max_amount")

    if (
        qfilter.date_from is not None
        and qfilter.date_to is not None
        and qfilter.date_from > qfilter.date_to
    ):
        raise ValueError("date_from cannot be after date_to")

    if qfilter.max_confidence is not None:
        if (
            not qfilter.max_confidence.is_finite()
            or qfilter.max_confidence < Decimal("0")
            or qfilter.max_confidence > Decimal("100")
        ):
            raise ValueError("max_confidence must be within [0, 100]")

    if qfilter.sort_by not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"Unsupported sort_by column: {qfilter.sort_by!r}")
    if qfilter.sort_order not in ALLOWED_SORT_ORDERS:
        raise ValueError(f"Unsupported sort_order: {qfilter.sort_order!r}")
    if isinstance(qfilter.limit, bool) or not (1 <= qfilter.limit <= MAX_PAGE_LIMIT):
        raise ValueError(f"limit must be within [1, {MAX_PAGE_LIMIT}]")
    if isinstance(qfilter.offset, bool) or not (0 <= qfilter.offset <= MAX_PAGE_OFFSET):
        raise ValueError(f"offset must be within [0, {MAX_PAGE_OFFSET}]")

    return ExceptionQueueFilter(
        statuses=tuple(clean_statuses),
        vendor_id=clean_vendor_id,
        vendor_name=clean_vendor_name,
        invoice_number=clean_invoice_number,
        currency=clean_currency,
        min_amount=qfilter.min_amount,
        max_amount=qfilter.max_amount,
        date_from=qfilter.date_from,
        date_to=qfilter.date_to,
        max_confidence=qfilter.max_confidence,
        sort_by=qfilter.sort_by,
        sort_order=qfilter.sort_order,
        limit=qfilter.limit,
        offset=qfilter.offset,
    )


def classify_exception_urgency(item: ExceptionQueueItem) -> str:
    """Compute urgency badge (`CRITICAL`, `HIGH`, `MEDIUM`) from exception status & confidence."""
    if item.status in CRITICAL_URGENCY_STATUSES or item.confidence_macro_avg < Decimal("80.00"):
        return "CRITICAL"
    if item.status in HIGH_URGENCY_STATUSES:
        return "HIGH"
    return "MEDIUM"


def format_elapsed_time(created_at: datetime, *, now: datetime | None = None) -> str:
    """Format elapsed time in queue as compact human-readable duration (`<1m`, `42m`, `3h 15m`, `2d 4h`)."""
    ref = now or datetime.now(UTC)
    created_utc = (
        created_at.astimezone(UTC) if created_at.tzinfo else created_at.replace(tzinfo=UTC)
    )
    delta_secs = max(0, int((ref - created_utc).total_seconds()))
    if delta_secs < 60:
        return "<1m"
    total_mins = delta_secs // 60
    if total_mins < 60:
        return f"{total_mins}m"
    total_hours, rem_mins = divmod(total_mins, 60)
    if total_hours < 24:
        return f"{total_hours}h {rem_mins}m"
    days, rem_hours = divmod(total_hours, 24)
    return f"{days}d {rem_hours}h"


def summarize_exception_queue(items: Sequence[ExceptionQueueItem]) -> ExceptionQueueSummary:
    """Compute KPI metrics for the Human Exception Queue summary strip."""
    critical = sum(1 for i in items if classify_exception_urgency(i) == "CRITICAL")
    tax_mismatches = sum(1 for i in items if i.status == "REJECTED_TAX_MISMATCH")
    dups_revs = sum(1 for i in items if i.status in REVISION_ROUTE_STATUSES)
    mgr_esc = sum(1 for i in items if i.status == "REQUIRES_MANAGER_APPROVAL")
    low_conf = sum(1 for i in items if i.confidence_macro_avg < Decimal("90.00"))
    return ExceptionQueueSummary(
        total_in_queue=len(items),
        critical=critical,
        tax_mismatches=tax_mismatches,
        duplicates_and_revisions=dups_revs,
        manager_escalations=mgr_esc,
        low_confidence=low_conf,
    )


def build_exception_queue_rows(
    items: Sequence[ExceptionQueueItem],
    *,
    assignments: dict[str, str] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Build sanitized, confidence-colour-coded rows for PRD Screen 3 Queue Grid."""
    assign_map = assignments or {}
    rows: list[dict[str, Any]] = []
    for item in items:
        cue = classify_confidence_cue(item.confidence_macro_avg)
        safe_id = item.invoice_id if _INVOICE_ID_RE.match(item.invoice_id) else None
        if safe_id is None:
            route = "—"
        elif item.status in REVISION_ROUTE_STATUSES:
            route = f"/revision/{safe_id}"
        else:
            route = f"/workbench/{safe_id}"

        cause = EXCEPTION_CAUSE_LABELS.get(item.status, item.status)
        usd_suffix = (
            f" (${item.total_amount_usd:,.2f} USD)"
            if item.total_amount_usd is not None and item.currency.upper() != "USD"
            else ""
        )
        assignee = assign_map.get(safe_id, "") if safe_id else ""

        rows.append(
            {
                "Urgency": classify_exception_urgency(item),
                "Invoice ID": safe_id if safe_id else "—",
                "Invoice Number": sanitize_display_text(item.invoice_number, max_length=100),
                "Vendor": sanitize_display_text(
                    item.vendor_name or item.vendor_id or "Unknown", max_length=120
                ),
                "Stated Total": f"{item.total_amount:,.2f} {sanitize_display_text(item.currency, max_length=8)}{usd_suffix}",
                "Primary Exception Cause": sanitize_display_text(cause, max_length=80),
                "Confidence": f"{cue.score:.1f}% ({cue.tier})",
                "Confidence Color": cue.hex_color,
                "Elapsed Time": format_elapsed_time(item.created_at, now=now),
                "Assigned Clerk": sanitize_display_text(assignee, max_length=120)
                if assignee
                else "Unassigned",
                "Route": route,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Role-Aware Bulk Action Permission Helpers
# ---------------------------------------------------------------------------


def can_bulk_assign_exceptions(user_roles: Sequence[str] | None) -> bool:
    """Allow bulk clerk assignment for ``ap_clerk`` and ``finance_manager``."""
    return bool(user_roles and BULK_ASSIGN_ALLOWED_ROLES.intersection(user_roles))


def can_bulk_approve_exceptions(user_roles: Sequence[str] | None) -> bool:
    """Allow bulk manager approval strictly for ``finance_manager`` (CLAUDE.md §12 & §16.1)."""
    return bool(user_roles and BULK_APPROVE_ALLOWED_ROLES.intersection(user_roles))


def _validate_bulk_invoice_ids(invoice_ids: Sequence[str]) -> list[str]:
    """Deduplicate and strictly validate selected invoice IDs with 50-item bulk DoS cap."""
    deduped: list[str] = []
    seen: set[str] = set()
    for raw_id in invoice_ids:
        if not isinstance(raw_id, str) or not _INVOICE_ID_RE.match(raw_id.strip()):
            raise ValueError(f"Invalid invoice_id in bulk selection: {raw_id!r}")
        clean = raw_id.strip()
        if clean not in seen:
            seen.add(clean)
            deduped.append(clean)
    if len(deduped) > MAX_BULK_SELECTION:
        raise ValueError(f"Bulk selection exceeds maximum limit of {MAX_BULK_SELECTION} invoices")
    return deduped


# ---------------------------------------------------------------------------
# Stateful Human Exception Queue Controller (Backend-Transport-Only)
# ---------------------------------------------------------------------------


class ExceptionQueueController:
    """Orchestrates exception queue queries and bulk actions via ``APInvoiceAPIClient``."""

    def __init__(self, api_client: APInvoiceAPIClient) -> None:
        self._client = api_client

    def fetch_queue(self, qfilter: ExceptionQueueFilter | None = None) -> ExceptionQueueResponse:
        """Validate filter parameters and query ``GET /api/v1/invoices/exceptions``."""
        clean = validate_queue_filter(qfilter or ExceptionQueueFilter())
        return self._client.list_exceptions(
            statuses=list(clean.statuses) if clean.statuses else None,
            vendor_id=clean.vendor_id,
            vendor_name=clean.vendor_name,
            invoice_number=clean.invoice_number,
            currency=clean.currency,
            min_amount=clean.min_amount,
            max_amount=clean.max_amount,
            date_from=clean.date_from,
            date_to=clean.date_to,
            max_confidence=clean.max_confidence,
            sort_by=clean.sort_by,
            sort_order=clean.sort_order,
            limit=clean.limit,
            offset=clean.offset,
        )

    def bulk_assign_to_clerk(
        self,
        invoice_ids: Sequence[str],
        *,
        assignee: str,
        existing_assignments: dict[str, str] | None = None,
        user_roles: Sequence[str] | None = None,
    ) -> tuple[dict[str, str], BulkActionResult]:
        """Assign up to 50 validated exception invoice IDs to a clerk handle in UI session state."""
        if user_roles is not None and not can_bulk_assign_exceptions(user_roles):
            raise PermissionError("Bulk assignment requires 'ap_clerk' or 'finance_manager' role")
        clean_ids = _validate_bulk_invoice_ids(invoice_ids)
        if not isinstance(assignee, str) or not _ASSIGNEE_RE.match(assignee.strip()):
            raise ValueError("Invalid assignee format (allowed: email or handle, 2-120 chars)")
        clean_assignee = assignee.strip()

        merged = dict(existing_assignments or {})
        for inv_id in clean_ids:
            merged[inv_id] = clean_assignee
        # Enforce session memory cap (CWE-400)
        if len(merged) > MAX_STORED_ASSIGNMENTS:
            keys_to_keep = list(merged.keys())[-MAX_STORED_ASSIGNMENTS:]
            merged = {k: merged[k] for k in keys_to_keep}

        return (
            merged,
            BulkActionResult(
                action="assign",
                succeeded_ids=clean_ids,
                skipped_ids=[],
                errors={},
            ),
        )

    def bulk_refresh_status(
        self,
        invoice_ids: Sequence[str],
        *,
        user_roles: Sequence[str] | None = None,
    ) -> tuple[dict[str, InvoiceDetailResponse], BulkActionResult]:
        """Re-fetch live details via ``GET /api/v1/invoices/{id}`` for selected invoices (429-safe)."""
        if user_roles is not None and not can_bulk_assign_exceptions(user_roles):
            raise PermissionError("Bulk refresh requires 'ap_clerk' or 'finance_manager' role")
        clean_ids = _validate_bulk_invoice_ids(invoice_ids)

        refreshed: dict[str, InvoiceDetailResponse] = {}
        succeeded: list[str] = []
        errors: dict[str, str] = {}
        rate_limited = False

        for inv_id in clean_ids:
            try:
                detail = self._client.get_invoice(inv_id)
                refreshed[inv_id] = detail
                succeeded.append(inv_id)
            except APIRateLimitError:
                rate_limited = True
                errors[inv_id] = "Rate limited (HTTP 429); bulk refresh paused"
                break
            except APIClientError as exc:
                errors[inv_id] = sanitize_display_text(str(exc), max_length=180)

        return (
            refreshed,
            BulkActionResult(
                action="refresh",
                succeeded_ids=succeeded,
                skipped_ids=[],
                errors=errors,
                rate_limited=rate_limited,
            ),
        )

    def bulk_manager_approve(
        self,
        invoice_ids: Sequence[str],
        *,
        queue_items: Sequence[ExceptionQueueItem],
        comment: str | None = None,
        user_roles: Sequence[str] | None = None,
    ) -> BulkActionResult:
        """
        Execute ``POST /api/v1/invoices/{id}/approve`` for selected approvable items.

        - Strictly restricted to ``finance_manager`` (``ap_clerk``, ``system_admin``, or omitted roles -> PermissionError).
        - Safely skips non-approvable exception statuses (duplicates, revisions, tax mismatches, credit notes).
        """
        if not can_bulk_approve_exceptions(user_roles):
            raise PermissionError("Bulk manager approval requires 'finance_manager' role")
        clean_ids = _validate_bulk_invoice_ids(invoice_ids)
        by_id = {item.invoice_id: item for item in queue_items}

        clean_comment = _clean_optional_search(comment, field_name="comment", max_length=1000)
        payload = InvoiceApprovalRequest(comment=clean_comment) if clean_comment else None

        succeeded: list[str] = []
        skipped: list[str] = []
        errors: dict[str, str] = {}
        rate_limited = False

        for inv_id in clean_ids:
            item = by_id.get(inv_id)
            if item is None or item.status not in MANAGER_APPROVABLE_STATUSES:
                skipped.append(inv_id)
                continue
            try:
                self._client.approve_invoice(inv_id, payload)
                succeeded.append(inv_id)
            except APIRateLimitError:
                rate_limited = True
                errors[inv_id] = "Rate limited (HTTP 429); bulk approval paused"
                break
            except APIClientError as exc:
                errors[inv_id] = sanitize_display_text(str(exc), max_length=180)

        return BulkActionResult(
            action="bulk_manager_approve",
            succeeded_ids=succeeded,
            skipped_ids=skipped,
            errors=errors,
            rate_limited=rate_limited,
        )


# ---------------------------------------------------------------------------
# Streamlit UI Renderer (Screen 3 — Human Exception Queue)
# ---------------------------------------------------------------------------


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def render_exception_queue(
    api_client: APInvoiceAPIClient,
    *,
    st_module: Any | None = None,
    user_roles: Sequence[str] | None = None,
) -> None:
    """Render PRD Screen 3 (Human Exception Queue `/exceptions`) using Streamlit."""
    st = _get_streamlit(st_module)
    controller = ExceptionQueueController(api_client)

    st.title("Human Exception Queue")
    st.caption(
        "Filter flagged invoices by exception type, inspect confidence colour cues "
        "(Green ≥90% · Yellow 80–89% · Red <80%), and execute role-authorized bulk actions."
    )

    # --- 1. Filter & Search Controls ---
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    preset_names = list(EXCEPTION_TYPE_PRESETS.keys())
    with f_col1:
        selected_preset = st.selectbox("Exception Type", options=preset_names, index=0)
    with f_col2:
        vendor_search = st.text_input("Vendor Name Search", value="")
    with f_col3:
        invoice_search = st.text_input("Invoice Number Search", value="")
    with f_col4:
        selected_currency = st.selectbox("Currency", options=list(ALLOWED_CURRENCIES), index=0)

    s_col1, s_col2 = st.columns(2)
    with s_col1:
        sort_by = st.selectbox("Sort By", options=sorted(ALLOWED_SORT_COLUMNS), index=0)
    with s_col2:
        sort_order = st.selectbox("Sort Order", options=["desc", "asc"], index=0)

    base_filter = resolve_exception_preset(selected_preset)
    try:
        active_filter = validate_queue_filter(
            base_filter.model_copy(
                update={
                    "vendor_name": vendor_search or None,
                    "invoice_number": invoice_search or None,
                    "currency": selected_currency or None,
                    "sort_by": sort_by,
                    "sort_order": sort_order,
                }
            )
        )
        queue_resp = controller.fetch_queue(active_filter)
    except (ValueError, APIClientError) as exc:
        st.error(sanitize_display_text(str(exc), max_length=220))
        return

    # --- 2. Summary KPI Strip ---
    summary = summarize_exception_queue(queue_resp.items)
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        k1.metric("Total in Queue", queue_resp.total)
    with k2:
        k2.metric("Critical", summary.critical)
    with k3:
        k3.metric("Tax Mismatches", summary.tax_mismatches)
    with k4:
        k4.metric("Manager Escalations", summary.manager_escalations)

    st.divider()

    # --- 3. Queue Grid with Confidence Colour Coding ---
    assignments: dict[str, str] = dict(st.session_state.get("exception_assignments", {}))
    if queue_resp.items:
        rows = build_exception_queue_rows(queue_resp.items, assignments=assignments)
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No exceptions match the active filters.")
        return

    # --- 4. Bulk Actions Panel ---
    st.divider()
    st.subheader("Bulk Actions")
    available_ids = [
        item.invoice_id for item in queue_resp.items if _INVOICE_ID_RE.match(item.invoice_id)
    ]
    selected_ids = st.multiselect(
        "Select Invoices for Bulk Action (max 50)",
        options=available_ids,
        default=[],
    )

    can_assign = can_bulk_assign_exceptions(user_roles)
    can_approve = can_bulk_approve_exceptions(user_roles)

    if not can_assign:
        st.info("Sign in as an AP Clerk or Finance Manager to perform bulk queue actions.")
        return

    b_col1, b_col2, b_col3 = st.columns(3)
    with b_col1:
        assignee_input = st.text_input("Assign To Clerk", value="sarah.clerk@company.com")
        if st.button("Assign Selected"):
            if not selected_ids:
                st.warning("Select at least one invoice to assign.")
            else:
                try:
                    updated_assign, res = controller.bulk_assign_to_clerk(
                        selected_ids,
                        assignee=assignee_input,
                        existing_assignments=assignments,
                        user_roles=user_roles,
                    )
                    st.session_state["exception_assignments"] = updated_assign
                    safe_assignee = sanitize_display_text(assignee_input, max_length=120)
                    st.success(f"Assigned {len(res.succeeded_ids)} invoice(s) to {safe_assignee}.")
                except (PermissionError, ValueError) as exc:
                    st.error(sanitize_display_text(str(exc), max_length=200))

    with b_col2:
        if st.button("Refresh Selected Status"):
            if not selected_ids:
                st.warning("Select at least one invoice to refresh.")
            else:
                try:
                    _, res = controller.bulk_refresh_status(selected_ids, user_roles=user_roles)
                    if res.rate_limited:
                        st.warning("Rate limited (HTTP 429); bulk refresh paused.")
                    elif res.errors:
                        st.warning(
                            f"Refreshed {len(res.succeeded_ids)} invoice(s) with {len(res.errors)} warning(s)."
                        )
                    else:
                        st.success(f"Refreshed {len(res.succeeded_ids)} invoice(s).")
                except (PermissionError, ValueError) as exc:
                    st.error(sanitize_display_text(str(exc), max_length=200))

    with b_col3:
        # CLAUDE.md §12: Hide Manager Bulk Approve completely for non-finance_manager roles
        if can_approve:
            mgr_comment = st.text_input("Manager Bulk Approval Comment", value="")
            if st.button("Bulk Manager Approve"):
                if not selected_ids:
                    st.warning("Select at least one approvable invoice.")
                else:
                    try:
                        res = controller.bulk_manager_approve(
                            selected_ids,
                            queue_items=queue_resp.items,
                            comment=mgr_comment or None,
                            user_roles=user_roles,
                        )
                        msg = f"Approved {len(res.succeeded_ids)} invoice(s)"
                        if res.skipped_ids:
                            msg += f"; skipped {len(res.skipped_ids)} non-approvable exception(s)"
                        st.success(msg + ".")
                        if res.errors:
                            st.warning(f"{len(res.errors)} approval error(s) occurred.")
                    except (PermissionError, ValueError) as exc:
                        st.error(sanitize_display_text(str(exc), max_length=200))


__all__ = [
    "ALLOWED_CURRENCIES",
    "ALLOWED_SORT_COLUMNS",
    "ALLOWED_SORT_ORDERS",
    "BULK_APPROVE_ALLOWED_ROLES",
    "BULK_ASSIGN_ALLOWED_ROLES",
    "BULK_REFRESH_ALLOWED_ROLES",
    "BulkActionResult",
    "CANONICAL_EXCEPTION_STATUSES",
    "CRITICAL_URGENCY_STATUSES",
    "EXCEPTION_CAUSE_LABELS",
    "EXCEPTION_TYPE_PRESETS",
    "ExceptionQueueController",
    "ExceptionQueueFilter",
    "ExceptionQueueSummary",
    "HIGH_URGENCY_STATUSES",
    "MAX_BULK_SELECTION",
    "MAX_FILTER_AMOUNT",
    "MAX_PAGE_LIMIT",
    "MAX_PAGE_OFFSET",
    "MAX_STORED_ASSIGNMENTS",
    "REVISION_ROUTE_STATUSES",
    "build_exception_queue_rows",
    "can_bulk_approve_exceptions",
    "can_bulk_assign_exceptions",
    "classify_exception_urgency",
    "format_elapsed_time",
    "render_exception_queue",
    "resolve_exception_preset",
    "summarize_exception_queue",
    "validate_queue_filter",
]
