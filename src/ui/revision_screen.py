"""
Revision Comparison Screen (/revision/{invoice_id}) — Side-by-Side Original vs. Revision (P11-5).

Implements PRD Screen 4, FR-10, and CLAUDE.md §4.2, §12 & §16.1:
- Left Column: Original Approved Invoice (PDF preview, extracted fields, masked Tax ID,
  approval timestamp & approving clerk fetched from immutable audit trail).
- Right Column: New Incoming Revision Invoice (PDF preview, extracted fields, confidence cue,
  modified fields highlighted in yellow #fef08a / red #ef4444).
- Diff Summary Tables: Direct comparison of Header Fields, Total/Tax Amount Deltas,
  Line-Item Deltas (ADDED / REMOVED / MODIFIED / UNCHANGED), and Revision Markers (-REV, v2, etc.).
- Decision Controls: "Confirm as Authorized Revision (Supersede Old)" (hands off to Review Workbench
  for auditable re-validation — never bypassing POST /approve) and "Reject as Unauthorized Duplicate".

Security & Layering Invariants:
- Reaches backend exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
- Never calls ``unsafe_allow_html=True``; masks Vendor Tax ID PII and neutralizes XSS/HTML,
  bidi/control chars, Bearer/JWT tokens, and CSV formula prefixes (CWE-79, CWE-1236).
- Enforces fail-closed RBAC, cross-vendor supersede blocking, self-comparison blocking,
  linear-time regexes (anti-ReDoS), and bounded decision history (CWE-400).
"""

import re
import unicodedata
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import (
    MAX_REVALIDATE_LINES,
    InvoiceDetailResponse,
    InvoiceLineResponse,
)
from src.core.logging import get_logger
from src.ui.api_client import APIClientError, APInvoiceAPIClient
from src.ui.ingestion_dashboard import sanitize_display_text
from src.ui.review_workbench import (
    classify_confidence_cue,
    extract_safe_document_url,
    mask_tax_id,
    render_document_preview,
)

logger = get_logger("ap.ui.revision_screen")

DECISION_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
DECIDABLE_REVISION_STATUSES: frozenset[str] = frozenset(
    {"FLAGGED_POTENTIAL_REVISION", "DUPLICATE_INVOICE"}
)

HIGHLIGHT_UNCHANGED_HEX: str = "#22c55e"
HIGHLIGHT_TEXT_HEX: str = "#fef08a"
HIGHLIGHT_FINANCIAL_HEX: str = "#ef4444"

MIN_DECISION_COMMENT_LENGTH: int = 5
MAX_DECISION_COMMENT_LENGTH: int = 1000
MAX_DECISION_HISTORY: int = 200

_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_OR_BIDI_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
# Linear non-backtracking revision suffix pattern (anti-ReDoS CWE-1333)
_REVISION_MARKER_RE = re.compile(
    r"(?i)(?:[-_\s](?:REV\d*|R\d+|V\d+|AMENDED|REVISED|CORRECTED))$",
)


class RevisionDecision(StrEnum):
    """Canonical PRD Screen 4 clerk/manager decision choices."""

    CONFIRM_AUTHORIZED_REVISION = "CONFIRM_AUTHORIZED_REVISION"
    REJECT_UNAUTHORIZED_DUPLICATE = "REJECT_UNAUTHORIZED_DUPLICATE"


# ---------------------------------------------------------------------------
# Typed Comparison & Decision Models
# ---------------------------------------------------------------------------


class RevisionMarkerAnalysis(BaseModel):
    """Revision suffix and base invoice number matching analysis (FR-10)."""

    model_config = ConfigDict(frozen=True)

    original_base_number: str
    incoming_base_number: str
    same_base_invoice_number: bool
    has_revision_marker: bool
    detected_markers: list[str]


class HeaderFieldDiff(BaseModel):
    """Single header-field comparison row between original and incoming invoice."""

    model_config = ConfigDict(frozen=True)

    field_name: str
    original_value: str
    incoming_value: str
    changed: bool
    is_financial: bool
    highlight_hex: str


class LineItemDiff(BaseModel):
    """Line-by-line diff row across original and incoming revision line items."""

    model_config = ConfigDict(frozen=True)

    line_number: int
    change_type: str  # UNCHANGED, MODIFIED, ADDED, REMOVED
    original_description: str
    incoming_description: str
    original_qty: str
    incoming_qty: str
    original_unit_price: str
    incoming_unit_price: str
    original_line_total: str
    incoming_line_total: str
    original_tax_rate: str
    incoming_tax_rate: str
    line_total_delta: Decimal
    highlight_hex: str


class RevisionDiffReport(BaseModel):
    """Complete side-by-side comparison summary between original and incoming invoices."""

    model_config = ConfigDict(frozen=True)

    same_vendor: bool
    currency_changed: bool
    is_exact_duplicate_candidate: bool
    markers: RevisionMarkerAnalysis
    total_amount_delta: Decimal
    tax_amount_delta: Decimal
    percentage_delta: Decimal | None
    modified_header_count: int
    modified_line_count: int
    header_diffs: list[HeaderFieldDiff]
    line_diffs: list[LineItemDiff]


class RevisionComparisonPair(BaseModel):
    """Loaded side-by-side pair with original approval audit provenance and computed diff."""

    model_config = ConfigDict(frozen=True)

    original: InvoiceDetailResponse
    revision: InvoiceDetailResponse
    original_approved_by: str | None = None
    original_approved_at: datetime | None = None
    diff: RevisionDiffReport


class RevisionDecisionRecord(BaseModel):
    """Structured decision outcome ready for audit handoff (never bypasses /approve)."""

    model_config = ConfigDict(frozen=True)

    original_invoice_id: str
    revision_invoice_id: str
    decision: RevisionDecision
    recommended_status: str
    handoff_route: str
    comment: str
    decided_at: datetime


# ---------------------------------------------------------------------------
# Pure Diff, Marker Detection & Table Formatting Helpers
# ---------------------------------------------------------------------------


def _normalize_base_invoice_number(raw: str) -> tuple[str, list[str]]:
    cleaned = unicodedata.normalize("NFC", raw.strip())[:256]
    markers: list[str] = []
    match = _REVISION_MARKER_RE.search(cleaned)
    if match:
        markers.append(match.group(0).strip().upper())
        base = cleaned[: match.start()].strip()
    else:
        base = cleaned
    return base.upper(), markers


def detect_revision_markers(
    original_invoice_number: str,
    incoming_invoice_number: str,
) -> RevisionMarkerAnalysis:
    """Detect revision markers (``-REV``, ``v2``, ``-R1``, ``AMENDED``) and compare base numbers."""
    orig_base, _ = _normalize_base_invoice_number(original_invoice_number)
    inc_base, markers = _normalize_base_invoice_number(incoming_invoice_number)
    return RevisionMarkerAnalysis(
        original_base_number=orig_base,
        incoming_base_number=inc_base,
        same_base_invoice_number=bool(orig_base and orig_base == inc_base),
        has_revision_marker=bool(markers),
        detected_markers=markers,
    )


def _fmt_dec(val: Decimal | None, *, places: int = 2) -> str:
    if val is None:
        return "—"
    return f"{val:.{places}f}"


def _fmt_date(val: Any) -> str:
    return val.isoformat() if val is not None else "—"


def _is_same_vendor(original: InvoiceDetailResponse, revision: InvoiceDetailResponse) -> bool:
    """Verify same vendor using authoritative Tax ID (blocking UNKNOWN placeholder spoofing: SEC-201)."""
    orig_tax = original.vendor_tax_id.strip().upper()
    rev_tax = revision.vendor_tax_id.strip().upper()
    if not orig_tax or not rev_tax or orig_tax == "UNKNOWN" or rev_tax == "UNKNOWN":
        return False
    if orig_tax != rev_tax:
        return False
    orig_vid = (original.vendor_id or "").strip().upper()
    rev_vid = (revision.vendor_id or "").strip().upper()
    if orig_vid and rev_vid and orig_vid != "UNKNOWN" and rev_vid != "UNKNOWN":
        return orig_vid == rev_vid
    return True


def compute_revision_diff(
    original: InvoiceDetailResponse,
    revision: InvoiceDetailResponse,
) -> RevisionDiffReport:
    """Compute deterministic field-by-field header, financial, and line-item comparison."""
    same_vendor = _is_same_vendor(original, revision)
    currency_changed = original.currency.upper() != revision.currency.upper()
    markers = detect_revision_markers(original.invoice_number, revision.invoice_number)

    header_specs: list[tuple[str, str, str, bool]] = [
        ("Invoice Number", original.invoice_number, revision.invoice_number, False),
        ("Invoice Date", _fmt_date(original.invoice_date), _fmt_date(revision.invoice_date), False),
        ("Due Date", _fmt_date(original.due_date), _fmt_date(revision.due_date), False),
        ("PO Number", original.po_number or "—", revision.po_number or "—", False),
        ("Subtotal", _fmt_dec(original.subtotal), _fmt_dec(revision.subtotal), True),
        (
            "Total Tax Amount",
            _fmt_dec(original.total_tax_amount),
            _fmt_dec(revision.total_tax_amount),
            True,
        ),
        ("Total Amount", _fmt_dec(original.total_amount), _fmt_dec(revision.total_amount), True),
        ("Currency", original.currency, revision.currency, True),
        ("Status", original.status, revision.status, False),
    ]

    header_diffs: list[HeaderFieldDiff] = []
    for field_name, orig_str, rev_str, is_fin in header_specs:
        changed = unicodedata.normalize("NFC", orig_str.strip()) != unicodedata.normalize(
            "NFC", rev_str.strip()
        )
        if not changed:
            color = HIGHLIGHT_UNCHANGED_HEX
        elif is_fin:
            color = HIGHLIGHT_FINANCIAL_HEX
        else:
            color = HIGHLIGHT_TEXT_HEX
        header_diffs.append(
            HeaderFieldDiff(
                field_name=field_name,
                original_value=orig_str,
                incoming_value=rev_str,
                changed=changed,
                is_financial=is_fin,
                highlight_hex=color,
            )
        )

    # Line-item alignment bounded to MAX_REVALIDATE_LINES
    orig_lines: dict[int, InvoiceLineResponse] = {
        ln.line_number: ln for ln in original.lines[:MAX_REVALIDATE_LINES]
    }
    rev_lines: dict[int, InvoiceLineResponse] = {
        ln.line_number: ln for ln in revision.lines[:MAX_REVALIDATE_LINES]
    }
    all_line_nums = sorted(set(orig_lines.keys()) | set(rev_lines.keys()))

    line_diffs: list[LineItemDiff] = []
    for num in all_line_nums:
        ol = orig_lines.get(num)
        rl = rev_lines.get(num)
        if ol is None and rl is not None:
            line_diffs.append(
                LineItemDiff(
                    line_number=num,
                    change_type="ADDED",
                    original_description="—",
                    incoming_description=rl.description,
                    original_qty="—",
                    incoming_qty=_fmt_dec(rl.quantity, places=4),
                    original_unit_price="—",
                    incoming_unit_price=_fmt_dec(rl.unit_price, places=4),
                    original_line_total="—",
                    incoming_line_total=_fmt_dec(rl.line_total),
                    original_tax_rate="—",
                    incoming_tax_rate=_fmt_dec(rl.line_tax_rate, places=4),
                    line_total_delta=rl.line_total,
                    highlight_hex=HIGHLIGHT_FINANCIAL_HEX,
                )
            )
        elif ol is not None and rl is None:
            line_diffs.append(
                LineItemDiff(
                    line_number=num,
                    change_type="REMOVED",
                    original_description=ol.description,
                    incoming_description="—",
                    original_qty=_fmt_dec(ol.quantity, places=4),
                    incoming_qty="—",
                    original_unit_price=_fmt_dec(ol.unit_price, places=4),
                    incoming_unit_price="—",
                    original_line_total=_fmt_dec(ol.line_total),
                    incoming_line_total="—",
                    original_tax_rate=_fmt_dec(ol.line_tax_rate, places=4),
                    incoming_tax_rate="—",
                    line_total_delta=-ol.line_total,
                    highlight_hex=HIGHLIGHT_FINANCIAL_HEX,
                )
            )
        elif ol is not None and rl is not None:
            fin_changed = (
                ol.quantity != rl.quantity
                or ol.unit_price != rl.unit_price
                or ol.line_total != rl.line_total
                or ol.line_tax_rate != rl.line_tax_rate
            )
            desc_changed = unicodedata.normalize("NFC", ol.description.strip()) != (
                unicodedata.normalize("NFC", rl.description.strip())
            )
            if fin_changed:
                change_type = "MODIFIED"
                color = HIGHLIGHT_FINANCIAL_HEX
            elif desc_changed:
                change_type = "MODIFIED"
                color = HIGHLIGHT_TEXT_HEX
            else:
                change_type = "UNCHANGED"
                color = HIGHLIGHT_UNCHANGED_HEX

            line_diffs.append(
                LineItemDiff(
                    line_number=num,
                    change_type=change_type,
                    original_description=ol.description,
                    incoming_description=rl.description,
                    original_qty=_fmt_dec(ol.quantity, places=4),
                    incoming_qty=_fmt_dec(rl.quantity, places=4),
                    original_unit_price=_fmt_dec(ol.unit_price, places=4),
                    incoming_unit_price=_fmt_dec(rl.unit_price, places=4),
                    original_line_total=_fmt_dec(ol.line_total),
                    incoming_line_total=_fmt_dec(rl.line_total),
                    original_tax_rate=_fmt_dec(ol.line_tax_rate, places=4),
                    incoming_tax_rate=_fmt_dec(rl.line_tax_rate, places=4),
                    line_total_delta=rl.line_total - ol.line_total,
                    highlight_hex=color,
                )
            )

    total_delta = revision.total_amount - original.total_amount
    orig_tax = original.total_tax_amount or Decimal("0.00")
    rev_tax = revision.total_tax_amount or Decimal("0.00")
    tax_delta = rev_tax - orig_tax

    pct_delta: Decimal | None = None
    if original.total_amount != Decimal("0"):
        pct_delta = ((total_delta / original.total_amount) * Decimal("100")).quantize(
            Decimal("0.01")
        )

    modified_header_count = sum(1 for h in header_diffs if h.changed)
    modified_line_count = sum(1 for ln in line_diffs if ln.change_type != "UNCHANGED")

    is_exact_dup = (
        same_vendor
        and not currency_changed
        and markers.same_base_invoice_number
        and not markers.has_revision_marker
        and total_delta == Decimal("0")
        and modified_line_count == 0
    )

    return RevisionDiffReport(
        same_vendor=same_vendor,
        currency_changed=currency_changed,
        is_exact_duplicate_candidate=is_exact_dup,
        markers=markers,
        total_amount_delta=total_delta,
        tax_amount_delta=tax_delta,
        percentage_delta=pct_delta,
        modified_header_count=modified_header_count,
        modified_line_count=modified_line_count,
        header_diffs=header_diffs,
        line_diffs=line_diffs,
    )


def build_header_diff_rows(header_diffs: Sequence[HeaderFieldDiff]) -> list[dict[str, Any]]:
    """Build sanitized, highlight-tagged rows for the Header Diff Summary Table."""
    return [
        {
            "Field": h.field_name,
            "Original Value": sanitize_display_text(h.original_value, max_length=140),
            "Incoming Revision": sanitize_display_text(h.incoming_value, max_length=140),
            "Delta Status": "CHANGED (Financial)"
            if (h.changed and h.is_financial)
            else ("CHANGED" if h.changed else "UNCHANGED"),
            "Highlight": h.highlight_hex,
        }
        for h in header_diffs
    ]


def build_line_diff_rows(line_diffs: Sequence[LineItemDiff]) -> list[dict[str, Any]]:
    """Build sanitized, highlight-tagged rows for the Line-Item Diff Summary Table."""
    return [
        {
            "Line #": ln.line_number,
            "Change": ln.change_type,
            "Original Description": sanitize_display_text(ln.original_description, max_length=160),
            "Revision Description": sanitize_display_text(ln.incoming_description, max_length=160),
            "Orig Qty -> Rev Qty": f"{ln.original_qty} -> {ln.incoming_qty}",
            "Orig Total -> Rev Total": f"{ln.original_line_total} -> {ln.incoming_line_total}",
            "Line Delta": f"{ln.line_total_delta:+.2f}",
            "Orig Tax -> Rev Tax": f"{ln.original_tax_rate} -> {ln.incoming_tax_rate}",
            "Highlight": ln.highlight_hex,
        }
        for ln in line_diffs
    ]


def can_decide_revision(
    revision: InvoiceDetailResponse,
    user_roles: Sequence[str] | None,
) -> bool:
    """Return True when the user may confirm/reject a flagged revision or duplicate."""
    if not user_roles or not DECISION_ALLOWED_ROLES.intersection(user_roles):
        return False
    return revision.status in DECIDABLE_REVISION_STATUSES


# ---------------------------------------------------------------------------
# Stateful Revision Comparison Controller (Backend-Transport-Only)
# ---------------------------------------------------------------------------


def _validate_id(raw: str, *, label: str) -> str:
    if not isinstance(raw, str) or not _INVOICE_ID_RE.match(raw.strip()):
        raise ValueError(f"Invalid {label} invoice_id format")
    return raw.strip()


class RevisionComparisonController:
    """Loads original vs. revision invoice pairs and records auditable clerk/manager decisions."""

    def __init__(self, api_client: APInvoiceAPIClient) -> None:
        self._client = api_client

    def load_comparison_pair(
        self,
        original_invoice_id: str,
        revision_invoice_id: str,
    ) -> RevisionComparisonPair:
        """Fetch both invoices + original approval audit record exclusively via ``APInvoiceAPIClient``."""
        orig_id = _validate_id(original_invoice_id, label="original")
        rev_id = _validate_id(revision_invoice_id, label="revision")
        if orig_id == rev_id:
            raise ValueError("Original and incoming revision must be different invoices")

        original = self._client.get_invoice(orig_id)
        revision = self._client.get_invoice(rev_id)

        approved_by: str | None = None
        approved_at: datetime | None = None
        try:
            audit = self._client.get_invoice_audit(orig_id, action_types=["APPROVE"], limit=10)
            if audit.events:
                latest_approval = audit.events[-1]
                approved_by = latest_approval.user_id
                approved_at = latest_approval.timestamp
        except APIClientError:
            logger.info(
                "original_approval_audit_unavailable",
                extra={"original_invoice_id": orig_id},
            )

        diff = compute_revision_diff(original, revision)
        return RevisionComparisonPair(
            original=original,
            revision=revision,
            original_approved_by=approved_by,
            original_approved_at=approved_at,
            diff=diff,
        )

    def record_decision(
        self,
        original: InvoiceDetailResponse,
        revision: InvoiceDetailResponse,
        *,
        decision: RevisionDecision,
        comment: str,
        existing_decisions: Sequence[RevisionDecisionRecord] | None = None,
        user_roles: Sequence[str] | None = None,
    ) -> tuple[list[RevisionDecisionRecord], RevisionDecisionRecord]:
        """
        Validate RBAC, vendor parity, and mandatory comment, and record revision decision.

        Never directly sets ``APPROVED_*`` (CLAUDE.md §16.1): confirming an authorized revision
        produces a workbench handoff to ``/workbench/{revision_id}`` for full rules re-validation.
        """
        if not can_decide_revision(revision, user_roles):
            raise PermissionError(
                "Revision decision requires 'ap_clerk' or 'finance_manager' role on a flagged revision/duplicate"
            )
        if original.invoice_id == revision.invoice_id:
            raise ValueError("Cannot record revision decision against the same invoice")
        if not isinstance(comment, str) or _CONTROL_OR_BIDI_RE.search(comment):
            raise ValueError("Decision comment contains disallowed control or bidi characters")
        cleaned_comment = unicodedata.normalize("NFC", comment.strip())
        if len(cleaned_comment) < MIN_DECISION_COMMENT_LENGTH:
            raise ValueError(
                f"Decision comment must be at least {MIN_DECISION_COMMENT_LENGTH} characters"
            )
        if len(cleaned_comment) > MAX_DECISION_COMMENT_LENGTH:
            raise ValueError(
                f"Decision comment exceeds maximum {MAX_DECISION_COMMENT_LENGTH} characters"
            )

        if decision is RevisionDecision.CONFIRM_AUTHORIZED_REVISION and not _is_same_vendor(
            original, revision
        ):
            raise ValueError(
                "Cross-vendor supersede blocked: original and incoming invoices belong to different vendors"
            )

        safe_rev_id = _validate_id(revision.invoice_id, label="revision")
        if decision is RevisionDecision.CONFIRM_AUTHORIZED_REVISION:
            rec_status = "REVALIDATING"
            route = f"/workbench/{safe_rev_id}"
        else:
            rec_status = "REJECTED_DUPLICATE"
            route = f"/audit/{safe_rev_id}"

        record = RevisionDecisionRecord(
            original_invoice_id=original.invoice_id,
            revision_invoice_id=revision.invoice_id,
            decision=decision,
            recommended_status=rec_status,
            handoff_route=route,
            comment=cleaned_comment,
            decided_at=datetime.now(UTC),
        )
        history = list(existing_decisions or [])
        history.append(record)
        if len(history) > MAX_DECISION_HISTORY:
            history = history[-MAX_DECISION_HISTORY:]
        return history, record


# ---------------------------------------------------------------------------
# Streamlit UI Renderer (Screen 4 — Side-by-Side Revision Comparison)
# ---------------------------------------------------------------------------


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def render_revision_comparison(
    api_client: APInvoiceAPIClient,
    *,
    original_invoice_id: str | None = None,
    revision_invoice_id: str | None = None,
    st_module: Any | None = None,
    user_roles: Sequence[str] | None = None,
    original_document_bytes: bytes | None = None,
    revision_document_bytes: bytes | None = None,
) -> None:
    """Render PRD Screen 4 (Revision Side-by-Side Comparison `/revision/{invoice_id}`)."""
    st = _get_streamlit(st_module)
    controller = RevisionComparisonController(api_client)

    st.title("Revision Comparison")
    st.caption(
        "Side-by-side comparison of the Original Approved Invoice against a Flagged Revision "
        "or Duplicate Submission (yellow = text change · red = financial/line change)."
    )

    # --- 1. Pair Selection Bar ---
    default_orig = original_invoice_id or str(st.session_state.get("revision_original_id", ""))
    default_rev = revision_invoice_id or str(st.session_state.get("revision_incoming_id", ""))

    s1, s2, s3 = st.columns([2, 2, 1])
    with s1:
        entered_orig = st.text_input("Original Approved Invoice ID", value=default_orig).strip()
    with s2:
        entered_rev = st.text_input("Incoming Revision Invoice ID", value=default_rev).strip()
    with s3:
        compare_clicked = st.button("Compare Invoices")

    pair: RevisionComparisonPair | None = st.session_state.get("revision_pair")
    should_load = bool(entered_orig and entered_rev) and (
        compare_clicked
        or pair is None
        or pair.original.invoice_id != entered_orig
        or pair.revision.invoice_id != entered_rev
    )

    if should_load:
        try:
            pair = controller.load_comparison_pair(entered_orig, entered_rev)
            st.session_state["revision_original_id"] = pair.original.invoice_id
            st.session_state["revision_incoming_id"] = pair.revision.invoice_id
            st.session_state["revision_pair"] = pair
        except (ValueError, APIClientError) as exc:
            st.error(sanitize_display_text(str(exc), max_length=220))
            return

    if pair is None:
        st.info(
            "Enter both the Original Approved Invoice ID and Incoming Revision Invoice ID above, "
            "then click Compare Invoices."
        )
        return

    diff = pair.diff

    # --- 2. Risk & Revision Marker Banners ---
    if not diff.same_vendor:
        st.error(
            "CROSS-VENDOR MISMATCH: These two invoices belong to different vendors. "
            "Confirming an authorized revision across vendors is blocked."
        )
    elif diff.currency_changed:
        st.warning(
            f"CURRENCY MISMATCH: Original invoice is in {pair.original.currency} while incoming "
            f"revision is in {pair.revision.currency}. Verify FX conversion before proceeding."
        )
    elif diff.is_exact_duplicate_candidate:
        st.warning(
            "EXACT DUPLICATE CANDIDATE: Same vendor, same base invoice number, zero financial "
            "delta, and identical line items."
        )
    elif diff.markers.has_revision_marker:
        markers_str = ", ".join(diff.markers.detected_markers)
        st.info(
            f"Revision marker detected ({sanitize_display_text(markers_str, max_length=60)}) "
            f"on base invoice {sanitize_display_text(diff.markers.incoming_base_number, max_length=60)}."
        )

    # --- 3. Financial Delta KPI Strip ---
    pct_text = f" ({diff.percentage_delta:+.2f}%)" if diff.percentage_delta is not None else ""
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        k1.metric(
            "Total Delta", f"{diff.total_amount_delta:+.2f} {pair.revision.currency}{pct_text}"
        )
    with k2:
        k2.metric("Tax Delta", f"{diff.tax_amount_delta:+.2f} {pair.revision.currency}")
    with k3:
        k3.metric("Modified Headers", diff.modified_header_count)
    with k4:
        k4.metric("Line Changes", diff.modified_line_count)

    st.divider()

    # --- 4. Side-by-Side Columns (Left: Original | Right: Incoming Revision) ---
    left_col, right_col = st.columns([1, 1])

    with left_col:
        left_col.subheader("Original Approved Invoice")
        left_col.caption(
            f"Invoice #: {sanitize_display_text(pair.original.invoice_number, max_length=80)} "
            f"| Status: {sanitize_display_text(pair.original.status, max_length=40)} "
            f"| Tax ID: {mask_tax_id(pair.original.vendor_tax_id)}"
        )
        if pair.original_approved_by:
            ts_str = (
                pair.original_approved_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
                if pair.original_approved_at
                else "Unknown time"
            )
            left_col.caption(
                f"Approved by: {sanitize_display_text(pair.original_approved_by, max_length=100)} "
                f"at {ts_str}"
            )
        safe_orig_url = extract_safe_document_url(pair.original.blob_raw_url)
        if safe_orig_url:
            left_col.caption(f"WORM Ref: {sanitize_display_text(safe_orig_url, max_length=120)}")
        if original_document_bytes:
            try:
                orig_page = render_document_preview(
                    original_document_bytes, filename="original.pdf"
                )
                left_col.image(orig_page.png_bytes, caption="Original Invoice Preview (Page 1)")
            except ValueError as exc:
                left_col.warning(sanitize_display_text(str(exc), max_length=180))

    with right_col:
        right_col.subheader("Incoming Revision Invoice")
        rev_cue = classify_confidence_cue(pair.revision.confidence_macro_avg)
        right_col.caption(
            f"Invoice #: {sanitize_display_text(pair.revision.invoice_number, max_length=80)} "
            f"| Status: {sanitize_display_text(pair.revision.status, max_length=40)} "
            f"| Confidence: {rev_cue.score:.1f}% ({rev_cue.tier})"
        )
        right_col.caption(
            f"Vendor: {sanitize_display_text(pair.revision.vendor_name or 'Unknown', max_length=100)} "
            f"| Tax ID: {mask_tax_id(pair.revision.vendor_tax_id)}"
        )
        safe_rev_url = extract_safe_document_url(pair.revision.blob_raw_url)
        if safe_rev_url:
            right_col.caption(f"WORM Ref: {sanitize_display_text(safe_rev_url, max_length=120)}")
        if revision_document_bytes:
            try:
                rev_page = render_document_preview(revision_document_bytes, filename="revision.pdf")
                right_col.image(rev_page.png_bytes, caption="Incoming Revision Preview (Page 1)")
            except ValueError as exc:
                right_col.warning(sanitize_display_text(str(exc), max_length=180))

    # --- 5. Diff Summary Tables ---
    st.divider()
    st.subheader("Header Diff Summary")
    st.dataframe(
        build_header_diff_rows(diff.header_diffs), use_container_width=True, hide_index=True
    )

    st.subheader("Line-Item Diff Summary")
    st.dataframe(build_line_diff_rows(diff.line_diffs), use_container_width=True, hide_index=True)

    # --- 6. Role-Aware Decision Controls ---
    st.divider()
    st.subheader("Revision Decision Controls")
    if not can_decide_revision(pair.revision, user_roles):
        st.info(
            "Decision controls are available only to AP Clerks and Finance Managers for invoices "
            "in FLAGGED_POTENTIAL_REVISION or DUPLICATE_INVOICE status."
        )
        return

    decision_comment = st.text_area("Decision Audit Comment (mandatory)", value="")
    decisions: list[RevisionDecisionRecord] = list(st.session_state.get("revision_decisions", []))

    d1, d2 = st.columns(2)
    with d1:
        if st.button("Confirm as Authorized Revision (Supersede Old)"):
            try:
                updated_hist, rec = controller.record_decision(
                    pair.original,
                    pair.revision,
                    decision=RevisionDecision.CONFIRM_AUTHORIZED_REVISION,
                    comment=decision_comment,
                    existing_decisions=decisions,
                    user_roles=user_roles,
                )
                st.session_state["revision_decisions"] = updated_hist
                st.session_state["selected_workbench_invoice_id"] = pair.revision.invoice_id
                st.success(
                    f"Confirmed as Authorized Revision — proceed to Review Workbench "
                    f"({rec.handoff_route}) to complete Re-Validation."
                )
            except (PermissionError, ValueError) as exc:
                st.error(sanitize_display_text(str(exc), max_length=220))

    with d2:
        if st.button("Reject as Unauthorized Duplicate"):
            try:
                updated_hist, rec = controller.record_decision(
                    pair.original,
                    pair.revision,
                    decision=RevisionDecision.REJECT_UNAUTHORIZED_DUPLICATE,
                    comment=decision_comment,
                    existing_decisions=decisions,
                    user_roles=user_roles,
                )
                st.session_state["revision_decisions"] = updated_hist
                st.success(
                    f"Recorded rejection as Unauthorized Duplicate ({rec.recommended_status}) "
                    f"for invoice {pair.revision.invoice_id}."
                )
            except (PermissionError, ValueError) as exc:
                st.error(sanitize_display_text(str(exc), max_length=220))


__all__ = [
    "DECIDABLE_REVISION_STATUSES",
    "DECISION_ALLOWED_ROLES",
    "HIGHLIGHT_FINANCIAL_HEX",
    "HIGHLIGHT_TEXT_HEX",
    "HIGHLIGHT_UNCHANGED_HEX",
    "HeaderFieldDiff",
    "LineItemDiff",
    "MAX_DECISION_COMMENT_LENGTH",
    "MAX_DECISION_HISTORY",
    "MIN_DECISION_COMMENT_LENGTH",
    "RevisionComparisonController",
    "RevisionComparisonPair",
    "RevisionDecision",
    "RevisionDecisionRecord",
    "RevisionDiffReport",
    "RevisionMarkerAnalysis",
    "build_header_diff_rows",
    "build_line_diff_rows",
    "can_decide_revision",
    "compute_revision_diff",
    "detect_revision_markers",
    "render_revision_comparison",
]
