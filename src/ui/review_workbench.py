"""
Review Workbench (/workbench/{invoice_id}) — Split-Screen PDF Viewer, Editable Fields & Re-Validate (P11-3).

Implements PRD Screen 2, FR-12, BR-004, BR-005, BR-016, BR-017, Journey 5, and CLAUDE.md §4.2 & §12:
- Left Pane (50%): Safe PyMuPDF PDF/image viewer with multi-page navigation and bounded zoom.
- Right Pane (50%):
  - Header Card (10 BR-004 fields: read-only vendor/currency/status + editable allowlisted fields)
  - Confidence color cues (Green >=90%, Light-Yellow 80–89%, Amber/Red <80%)
  - Editable Line-Item table (5 BR-005 fields per line)
  - Real-time Validation Alert Box (line arithmetic, invoice total, tax rate, date check)
  - Mandatory ReasonCode dropdown, tax-override flags, comment input, Re-Validate & role-aware Approve bar

Security & Layering Invariants:
- Reaches backend exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
- Never calls ``unsafe_allow_html=True``; masks Vendor Tax ID PII and sanitizes all rendered strings.
- Never fetches untrusted remote URLs from the UI (anti-SSRF); validates preview URLs strictly.
- Enforces strict field allowlists, client-side smart diff (no-op prevention), and role-aware
  RBAC + high-value approval button hiding (CLAUDE.md §12 & §16.1).
"""

import ipaddress
import math
import re
import unicodedata
from collections.abc import Sequence
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

import fitz
from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import (
    MAX_REVALIDATE_LINES,
    InvoiceApprovalRequest,
    InvoiceApprovalResponse,
    InvoiceDetailResponse,
    InvoiceHeaderEdits,
    InvoiceLineEdit,
    InvoiceLineResponse,
    InvoiceRevalidateRequest,
    InvoiceRevalidateResponse,
    ReasonCode,
)
from src.core.config import get_settings
from src.core.logging import get_logger
from src.ui.api_client import MAX_CLIENT_UPLOAD_BYTES, APIClientError, APInvoiceAPIClient
from src.ui.ingestion_dashboard import sanitize_display_text

logger = get_logger("ap.ui.review_workbench")

MAX_PREVIEW_BYTES: int = MAX_CLIENT_UPLOAD_BYTES
MAX_PREVIEW_PAGES: int = 200
MIN_PREVIEW_ZOOM: float = 0.5
MAX_PREVIEW_ZOOM: float = 3.0
DEFAULT_PREVIEW_ZOOM: float = 1.5
MAX_PREVIEW_PIXEL_DIM: int = 4096
ALLOWED_PREVIEW_EXTENSIONS: frozenset[str] = frozenset({"pdf", "png", "jpg", "jpeg"})

REVALIDATE_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
APPROVE_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})

EDITABLE_HEADER_FIELDS: frozenset[str] = frozenset(
    {
        "invoice_number",
        "invoice_date",
        "due_date",
        "po_number",
        "subtotal",
        "total_tax_amount",
        "total_amount",
    }
)
EDITABLE_LINE_FIELDS: frozenset[str] = frozenset(
    {
        "description",
        "quantity",
        "unit_price",
        "line_total",
        "line_tax_rate",
    }
)

NON_EDITABLE_STATUSES: frozenset[str] = frozenset(
    {
        "UPLOADED",
        "EXTRACTING",
        "REVALIDATING",
        "APPROVED_CLERK",
        "APPROVED_MANAGER",
        "REJECTED",
        "STAGED_FOR_EXPORT",
    }
)
MANAGER_APPROVABLE_STATUSES: frozenset[str] = frozenset(
    {
        "VALIDATED",
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REQUIRES_MANAGER_APPROVAL",
    }
)

CLERK_APPROVAL_CONFIDENCE_FLOOR: Decimal = Decimal("90.00")
REVIEW_CONFIDENCE_FLOOR: Decimal = Decimal("80.00")

_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
_LOCAL_PREVIEW_HTTP_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "azurite"})

REASON_CODE_LABELS: tuple[tuple[ReasonCode, str], ...] = (
    (ReasonCode.OCR_MISREAD, "OCR_MISREAD — OCR misread digit or text"),
    (ReasonCode.VENDOR_ROUNDING, "VENDOR_ROUNDING — Vendor invoice rounding difference"),
    (ReasonCode.TAX_CODE_OVERRIDE, "TAX_CODE_OVERRIDE — Reverse charge / tax exemption override"),
    (ReasonCode.VENDOR_DISCOUNT, "VENDOR_DISCOUNT — Uncaptured vendor discount"),
    (ReasonCode.OTHER, "OTHER — Other (comment mandatory)"),
)


# ---------------------------------------------------------------------------
# Typed Workbench Presentation & Draft Models
# ---------------------------------------------------------------------------


class ConfidenceCue(BaseModel):
    """Canonical tri-tier confidence color badge (CLAUDE.md §12, PRD Screen 2)."""

    model_config = ConfigDict(frozen=True)

    tier: str
    label: str
    hex_color: str
    score: Decimal


class DocumentPreviewPage(BaseModel):
    """Rendered single page of a PDF/image invoice for the Left Pane viewer."""

    model_config = ConfigDict(frozen=True)

    page_index: int
    page_count: int
    zoom: float
    png_bytes: bytes
    width: int
    height: int


class HeaderFormDraft(BaseModel):
    """Editable header form draft holding only allowlisted FR-12/BR-016 header fields."""

    model_config = ConfigDict(frozen=True)

    invoice_number: str
    invoice_date: str = ""
    due_date: str = ""
    po_number: str = ""
    subtotal: str = ""
    total_tax_amount: str = ""
    total_amount: str = ""

    @classmethod
    def from_invoice(cls, invoice: InvoiceDetailResponse) -> "HeaderFormDraft":
        return cls(
            invoice_number=invoice.invoice_number,
            invoice_date=invoice.invoice_date.isoformat() if invoice.invoice_date else "",
            due_date=invoice.due_date.isoformat() if invoice.due_date else "",
            po_number=invoice.po_number or "",
            subtotal=f"{invoice.subtotal:.2f}" if invoice.subtotal is not None else "",
            total_tax_amount=(
                f"{invoice.total_tax_amount:.2f}" if invoice.total_tax_amount is not None else ""
            ),
            total_amount=f"{invoice.total_amount:.2f}",
        )


class LineFormDraft(BaseModel):
    """Editable single line-item draft holding only allowlisted BR-005 fields."""

    model_config = ConfigDict(frozen=True)

    line_number: int
    description: str
    quantity: str
    unit_price: str
    line_total: str
    line_tax_rate: str

    @classmethod
    def from_line(cls, line: InvoiceLineResponse) -> "LineFormDraft":
        return cls(
            line_number=line.line_number,
            description=line.description,
            quantity=f"{line.quantity:.4f}",
            unit_price=f"{line.unit_price:.4f}",
            line_total=f"{line.line_total:.2f}",
            line_tax_rate=f"{line.line_tax_rate:.4f}",
        )


# ---------------------------------------------------------------------------
# Confidence Cues, PII Masking, Document Preview & URL Safety
# ---------------------------------------------------------------------------


def classify_confidence_cue(score: Decimal | float | int | None) -> ConfidenceCue:
    """Return CLAUDE.md §12 confidence tier color cue (Green / Light-Yellow / Red)."""
    val = Decimal("0.00") if score is None else Decimal(str(score))
    if val >= CLERK_APPROVAL_CONFIDENCE_FLOOR:
        return ConfidenceCue(
            tier="HIGH",
            label="High Confidence (≥90%)",
            hex_color="#22c55e",
            score=val,
        )
    if val >= REVIEW_CONFIDENCE_FLOOR:
        return ConfidenceCue(
            tier="REVIEW",
            label="Review Recommended (80–89%)",
            hex_color="#fef08a",
            score=val,
        )
    return ConfidenceCue(
        tier="LOW",
        label="Low Confidence (<80%)",
        hex_color="#ef4444",
        score=val,
    )


def mask_tax_id(raw_tax_id: str | None) -> str:
    """Mask Vendor Tax ID for UI display safety while preserving last 4 characters (N8)."""
    if not raw_tax_id:
        return "***"
    cleaned = sanitize_display_text(raw_tax_id, max_length=64)
    if len(cleaned) < 4:
        return "***"
    return f"***-**-{cleaned[-4:]}"


def extract_safe_document_url(raw_url: str | None) -> str | None:
    """
    Validate a document reference URL for safe display (never auto-fetched).

    Blocks ``javascript:``, ``data:``, ``file://``, embedded credentials, control chars,
    cloud metadata IPs (``169.254.0.0/16``), and non-local plain HTTP (CWE-79 / CWE-918).
    """
    if not raw_url or not isinstance(raw_url, str):
        return None
    if _CONTROL_CHAR_RE.search(raw_url):
        return None
    cleaned = raw_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("https", "http"):
        return None
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return None
    host = parsed.hostname.lower()
    if parsed.scheme == "http" and host not in _LOCAL_PREVIEW_HTTP_HOSTS:
        return None
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return None
        if ip.is_private and host != "127.0.0.1":
            return None
    except ValueError:
        pass
    return cleaned


def render_document_preview(
    document_bytes: bytes,
    *,
    filename: str = "invoice.pdf",
    page_index: int = 0,
    zoom: float = DEFAULT_PREVIEW_ZOOM,
) -> DocumentPreviewPage:
    """
    Render a single page of an in-memory PDF/PNG/JPEG document to PNG via PyMuPDF.

    Enforces 25 MB size bound, <=200 pages, non-encrypted PDFs, clamped zoom [0.5, 3.0],
    and a 4096px max output dimension guard against decompression bombs (CWE-400).
    """
    if not isinstance(document_bytes, (bytes, bytearray)) or len(document_bytes) == 0:
        raise ValueError("Document preview payload is empty")
    if len(document_bytes) > MAX_PREVIEW_BYTES:
        raise ValueError("Document preview exceeds maximum 25 MB limit")
    if isinstance(zoom, bool) or not isinstance(zoom, (int, float)) or not math.isfinite(zoom):
        raise ValueError("Document preview zoom must be a finite number")
    if isinstance(page_index, bool) or not isinstance(page_index, int):
        raise ValueError("Document preview page_index must be an integer")

    suffix = PurePosixPath(filename).suffix.lower().lstrip(".")
    if suffix in {"tif", "tiff"}:
        raise ValueError("TIFF preview is not supported (GAP-004)")
    if suffix not in ALLOWED_PREVIEW_EXTENSIONS:
        raise ValueError(
            f"Unsupported preview file extension '.{suffix}'; allowed: pdf, png, jpg, jpeg"
        )

    clamped_zoom = max(MIN_PREVIEW_ZOOM, min(float(zoom), MAX_PREVIEW_ZOOM))
    filetype_map = {"pdf": "pdf", "png": "png", "jpg": "jpeg", "jpeg": "jpeg"}
    filetype = filetype_map[suffix]

    try:
        doc = fitz.open(stream=bytes(document_bytes), filetype=filetype)
    except Exception:
        raise ValueError(
            "Unable to render document preview: unsupported or corrupted file"
        ) from None

    try:
        if doc.needs_pass:
            raise ValueError("Password-protected documents cannot be previewed")
        page_count = doc.page_count
        if page_count < 1:
            raise ValueError("Document contains zero pages")
        if page_count > MAX_PREVIEW_PAGES:
            raise ValueError(f"Document exceeds maximum preview limit of {MAX_PREVIEW_PAGES} pages")

        clamped_page = max(0, min(int(page_index), page_count - 1))
        page = doc.load_page(clamped_page)
        rect = page.rect
        max_dim = max(float(rect.width), float(rect.height), 1.0)
        effective_zoom = clamped_zoom
        if max_dim * effective_zoom > MAX_PREVIEW_PIXEL_DIM:
            effective_zoom = max(0.1, MAX_PREVIEW_PIXEL_DIM / max_dim)

        matrix = fitz.Matrix(effective_zoom, effective_zoom)
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        png_bytes = pix.tobytes("png")
        return DocumentPreviewPage(
            page_index=clamped_page,
            page_count=page_count,
            zoom=clamped_zoom,
            png_bytes=png_bytes,
            width=pix.width,
            height=pix.height,
        )
    finally:
        doc.close()


# ---------------------------------------------------------------------------
# Smart Diff Builder, Line Grid Formatter & RBAC Helpers
# ---------------------------------------------------------------------------


def _norm_text(val: str | None) -> str | None:
    if val is None:
        return None
    cleaned = unicodedata.normalize("NFC", val.strip())
    return cleaned if cleaned else None


def _parse_optional_decimal(raw: str, *, field_name: str) -> Decimal | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    try:
        parsed = Decimal(cleaned)
    except InvalidOperation:
        raise ValueError(f"{field_name} must be a valid decimal number") from None
    if not parsed.is_finite():
        raise ValueError(f"{field_name} must be finite")
    return Decimal("0") if parsed == 0 else parsed


def _parse_optional_date(raw: str, *, field_name: str) -> date | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        raise ValueError(f"{field_name} must be an ISO date (YYYY-MM-DD)") from None


def _decimals_equal(a: Decimal | None, b: Decimal | None) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return a == b


def build_editable_line_rows(lines: Sequence[InvoiceLineResponse]) -> list[dict[str, Any]]:
    """Build sanitized editable grid rows for the Right Pane line-item editor."""
    rows: list[dict[str, Any]] = []
    for line in sorted(lines, key=lambda item: item.line_number):
        cue = classify_confidence_cue(line.confidence_score)
        rows.append(
            {
                "Line #": line.line_number,
                "Description": sanitize_display_text(line.description, max_length=300),
                "Qty": f"{line.quantity:.4f}",
                "Unit Price": f"{line.unit_price:.4f}",
                "Line Total": f"{line.line_total:.2f}",
                "Tax Rate": f"{line.line_tax_rate:.4f}",
                "Confidence": f"{cue.score:.1f}% ({cue.tier})",
            }
        )
    return rows


def build_revalidate_request(
    original: InvoiceDetailResponse,
    *,
    header_draft: HeaderFormDraft,
    line_drafts: Sequence[LineFormDraft],
    reason_code: ReasonCode,
    comment: str | None = None,
    is_reverse_charge: bool = False,
    is_exempt: bool = False,
    po_amount: Decimal | None = None,
) -> InvoiceRevalidateRequest:
    """
    Construct a minimal, no-op-free ``InvoiceRevalidateRequest`` containing ONLY changed fields.

    Matches P9-1 / P9-4 backend contracts before sending HTTP requests:
    - Computes semantic diffs (Decimal scale & NFC text equivalence) so untouched fields are omitted.
    - Rejects client-side no-ops when zero fields changed and no tax override was toggled.
    - Enforces mandatory comment for ``ReasonCode.OTHER`` and valid reason codes for tax overrides.
    """
    if len(line_drafts) > MAX_REVALIDATE_LINES:
        raise ValueError(f"Line edits exceed maximum limit of {MAX_REVALIDATE_LINES} lines")

    # 1. Diff allowlisted header fields
    header_changes: dict[str, Any] = {}

    new_inv_num = _norm_text(header_draft.invoice_number)
    if new_inv_num is not None and new_inv_num != _norm_text(original.invoice_number):
        header_changes["invoice_number"] = new_inv_num

    new_inv_date = _parse_optional_date(header_draft.invoice_date, field_name="invoice_date")
    if new_inv_date is not None and new_inv_date != original.invoice_date:
        header_changes["invoice_date"] = new_inv_date

    new_due_date = _parse_optional_date(header_draft.due_date, field_name="due_date")
    if new_due_date is not None and new_due_date != original.due_date:
        header_changes["due_date"] = new_due_date

    new_po = _norm_text(header_draft.po_number)
    if new_po is not None and new_po != _norm_text(original.po_number):
        header_changes["po_number"] = new_po

    for field_name, orig_val in (
        ("subtotal", original.subtotal),
        ("total_tax_amount", original.total_tax_amount),
        ("total_amount", original.total_amount),
    ):
        raw_val = getattr(header_draft, field_name)
        parsed_val = _parse_optional_decimal(raw_val, field_name=field_name)
        if parsed_val is not None and not _decimals_equal(parsed_val, orig_val):
            header_changes[field_name] = parsed_val

    header_edits = InvoiceHeaderEdits(**header_changes) if header_changes else None

    # 2. Diff allowlisted line-item fields
    orig_lines_by_num = {line.line_number: line for line in original.lines}
    seen_draft_lines: set[int] = set()
    line_edits: list[InvoiceLineEdit] = []
    for draft in line_drafts:
        if draft.line_number in seen_draft_lines:
            raise ValueError(f"Duplicate line_number in line_drafts: {draft.line_number}")
        seen_draft_lines.add(draft.line_number)
        orig_line = orig_lines_by_num.get(draft.line_number)
        if orig_line is None:
            continue
        changes: dict[str, Any] = {}
        new_desc = _norm_text(draft.description)
        if new_desc is not None and new_desc != _norm_text(orig_line.description):
            changes["description"] = new_desc

        for field_name, orig_val in (
            ("quantity", orig_line.quantity),
            ("unit_price", orig_line.unit_price),
            ("line_total", orig_line.line_total),
            ("line_tax_rate", orig_line.line_tax_rate),
        ):
            parsed_val = _parse_optional_decimal(
                getattr(draft, field_name), field_name=f"line[{draft.line_number}].{field_name}"
            )
            if parsed_val is not None and not _decimals_equal(parsed_val, orig_val):
                changes[field_name] = parsed_val

        if changes:
            line_edits.append(InvoiceLineEdit(line_number=draft.line_number, **changes))

    if header_edits is None and not line_edits and not is_reverse_charge and not is_exempt:
        raise ValueError(
            "No changes detected: modify at least one field or enable a tax override before re-validating"
        )

    clean_comment = _norm_text(comment)
    return InvoiceRevalidateRequest(
        reason_code=reason_code,
        comment=clean_comment,
        is_reverse_charge=is_reverse_charge,
        is_exempt=is_exempt,
        po_amount=po_amount,
        header_edits=header_edits,
        line_edits=line_edits,
    )


def can_revalidate_in_workbench(
    invoice: InvoiceDetailResponse,
    user_roles: Sequence[str] | None,
) -> bool:
    """Return True when the active user may edit and re-validate this invoice."""
    if not user_roles or not REVALIDATE_ALLOWED_ROLES.intersection(user_roles):
        return False
    return invoice.status not in NON_EDITABLE_STATUSES


def can_approve_in_workbench(
    invoice: InvoiceDetailResponse,
    user_roles: Sequence[str] | None,
    high_value_threshold_usd: Decimal | None = None,
) -> bool:
    """
    Role-aware Approve button visibility guard (CLAUDE.md §12, FR-13, BR-014).

    - ``finance_manager``: allowed on approvable statuses including > HIGH_VALUE_THRESHOLD_USD.
    - ``ap_clerk``: allowed ONLY when ``status == VALIDATED``, confidence >= 90%, AND
      effective USD total <= ``HIGH_VALUE_THRESHOLD_USD`` (button is hidden otherwise!).
    - ``system_admin`` / unauthenticated: always False.
    """
    if not user_roles:
        return False
    role_set = set(user_roles)
    if not APPROVE_ALLOWED_ROLES.intersection(role_set):
        return False

    if "finance_manager" in role_set:
        return invoice.status in MANAGER_APPROVABLE_STATUSES

    # ap_clerk path
    if invoice.status != "VALIDATED":
        return False
    if invoice.confidence_macro_avg < CLERK_APPROVAL_CONFIDENCE_FLOOR:
        return False

    threshold = (
        high_value_threshold_usd
        if high_value_threshold_usd is not None
        else Decimal(str(get_settings().HIGH_VALUE_THRESHOLD_USD))
    )
    effective_usd = (
        invoice.total_amount_usd
        if invoice.total_amount_usd is not None
        else (invoice.total_amount if invoice.currency.upper() == "USD" else None)
    )
    if effective_usd is None:
        return False
    return effective_usd <= threshold


# ---------------------------------------------------------------------------
# Stateful Review Workbench Controller (Backend-Transport-Only)
# ---------------------------------------------------------------------------


class ReviewWorkbenchController:
    """Orchestrates invoice loading, re-validation, and approval exclusively via ``APInvoiceAPIClient``."""

    def __init__(self, api_client: APInvoiceAPIClient) -> None:
        self._client = api_client

    def load_invoice(self, invoice_id: str) -> InvoiceDetailResponse:
        """Validate ``invoice_id`` strictly and load full detail from ``GET /api/v1/invoices/{id}``."""
        if not isinstance(invoice_id, str) or not _INVOICE_ID_RE.match(invoice_id.strip()):
            raise ValueError("Invalid invoice_id format (allowed: A-Z, a-z, 0-9, _, -)")
        return self._client.get_invoice(invoice_id.strip())

    def submit_revalidation(
        self,
        original: InvoiceDetailResponse,
        *,
        header_draft: HeaderFormDraft,
        line_drafts: Sequence[LineFormDraft],
        reason_code: ReasonCode,
        comment: str | None = None,
        is_reverse_charge: bool = False,
        is_exempt: bool = False,
        po_amount: Decimal | None = None,
        user_roles: Sequence[str] | None = None,
    ) -> tuple[InvoiceRevalidateResponse, InvoiceDetailResponse]:
        """Validate RBAC + smart diff, submit ``POST /revalidate``, and refresh invoice detail."""
        if user_roles is not None and not can_revalidate_in_workbench(original, user_roles):
            raise PermissionError(
                "Re-validation requires 'ap_clerk' or 'finance_manager' role on an editable invoice"
            )
        req = build_revalidate_request(
            original,
            header_draft=header_draft,
            line_drafts=line_drafts,
            reason_code=reason_code,
            comment=comment,
            is_reverse_charge=is_reverse_charge,
            is_exempt=is_exempt,
            po_amount=po_amount,
        )
        reval_resp = self._client.revalidate_invoice(original.invoice_id, req)
        refreshed = self._client.get_invoice(original.invoice_id)
        return reval_resp, refreshed

    def submit_approval(
        self,
        invoice: InvoiceDetailResponse,
        *,
        comment: str | None = None,
        po_amount: Decimal | None = None,
        user_roles: Sequence[str] | None = None,
        high_value_threshold_usd: Decimal | None = None,
    ) -> tuple[InvoiceApprovalResponse, InvoiceDetailResponse]:
        """Enforce role-aware approval threshold, submit ``POST /approve``, and refresh detail."""
        if user_roles is not None and not can_approve_in_workbench(
            invoice, user_roles, high_value_threshold_usd
        ):
            raise PermissionError(
                "Approval denied: invoice requires Finance Manager approval or is not in an approvable state"
            )
        clean_comment = _norm_text(comment)
        req = (
            InvoiceApprovalRequest(comment=clean_comment, po_amount=po_amount)
            if (clean_comment is not None or po_amount is not None)
            else None
        )
        approve_resp = self._client.approve_invoice(invoice.invoice_id, req)
        refreshed = self._client.get_invoice(invoice.invoice_id)
        return approve_resp, refreshed


# ---------------------------------------------------------------------------
# Streamlit UI Renderer (Screen 2 — Split-Screen Review Workbench)
# ---------------------------------------------------------------------------


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def render_review_workbench(
    api_client: APInvoiceAPIClient,
    *,
    invoice_id: str | None = None,
    st_module: Any | None = None,
    user_roles: Sequence[str] | None = None,
    document_bytes: bytes | None = None,
    document_filename: str = "invoice.pdf",
) -> None:
    """Render PRD Screen 2 (Split-Screen Review Workbench `/workbench/{invoice_id}`)."""
    st = _get_streamlit(st_module)
    controller = ReviewWorkbenchController(api_client)

    st.title("Review Workbench")
    st.caption(
        "Split-screen document inspection, confidence-highlighted field editing, "
        "mandatory audit reason codes, and deterministic Re-Validation."
    )

    # --- Invoice Selection Bar ---
    default_id = invoice_id or str(st.session_state.get("selected_workbench_invoice_id", ""))
    sel_col1, sel_col2 = st.columns([3, 1])
    with sel_col1:
        entered_id = st.text_input("Invoice ID to Review", value=default_id).strip()
    with sel_col2:
        load_clicked = st.button("Load Invoice")

    active_invoice: InvoiceDetailResponse | None = st.session_state.get("workbench_invoice")
    should_load = bool(entered_id) and (
        load_clicked or active_invoice is None or active_invoice.invoice_id != entered_id
    )

    if should_load:
        try:
            active_invoice = controller.load_invoice(entered_id)
            st.session_state["selected_workbench_invoice_id"] = active_invoice.invoice_id
            st.session_state["workbench_invoice"] = active_invoice
            st.session_state.pop("workbench_last_revalidation", None)
        except (ValueError, APIClientError) as exc:
            st.error(sanitize_display_text(str(exc), max_length=220))
            return

    if active_invoice is None:
        st.info("Enter an Invoice ID above and click Load Invoice to open the Review Workbench.")
        return

    # --- Top Status & Confidence Strip ---
    cue = classify_confidence_cue(active_invoice.confidence_macro_avg)
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        m1.metric("Status", sanitize_display_text(active_invoice.status, max_length=40))
    with m2:
        m2.metric("Confidence", f"{cue.score:.1f}% ({cue.tier})")
    with m3:
        m3.metric(
            "Grand Total",
            f"{active_invoice.total_amount:.2f} {sanitize_display_text(active_invoice.currency, max_length=8)}",
        )
    with m4:
        m4.metric("Audit Events", active_invoice.audit_event_count)

    st.caption(f"Confidence Cue: {cue.label} [{cue.hex_color}]")
    st.divider()

    # --- 50 / 50 Split-Screen Layout (PRD Screen 2) ---
    left_pane, right_pane = st.columns([1, 1])

    # === LEFT PANE: Document Viewer ===
    with left_pane:
        left_pane.subheader("Document Viewer")
        safe_doc_url = extract_safe_document_url(active_invoice.blob_raw_url)
        if safe_doc_url:
            left_pane.caption(
                f"WORM Blob Reference: {sanitize_display_text(safe_doc_url, max_length=140)}"
            )

        preview_bytes = document_bytes
        preview_name = document_filename
        uploaded_preview = st.file_uploader(
            "Load local PDF/Image copy for visual side-by-side preview",
            type=["pdf", "png", "jpg", "jpeg"],
            accept_multiple_files=False,
        )
        if uploaded_preview is not None:
            preview_bytes = uploaded_preview.getvalue()
            preview_name = getattr(uploaded_preview, "name", "invoice.pdf")

        if preview_bytes:
            zoom_val = left_pane.slider(
                "Zoom",
                min_value=MIN_PREVIEW_ZOOM,
                max_value=MAX_PREVIEW_ZOOM,
                value=DEFAULT_PREVIEW_ZOOM,
            )
            page_num = int(
                left_pane.number_input("Page", value=1, min_value=1, max_value=MAX_PREVIEW_PAGES)
            )
            try:
                rendered = render_document_preview(
                    preview_bytes,
                    filename=preview_name,
                    page_index=page_num - 1,
                    zoom=zoom_val,
                )
                left_pane.image(
                    rendered.png_bytes,
                    caption=f"Page {rendered.page_index + 1} of {rendered.page_count} ({rendered.zoom:.1f}x)",
                )
            except ValueError as exc:
                left_pane.error(sanitize_display_text(str(exc), max_length=200))
        else:
            left_pane.info(
                "Attach a local PDF/PNG/JPG invoice copy above to inspect pages side-by-side "
                "(direct Azure Blob streaming from the UI is intentionally disabled per security architecture)."
            )

    # === RIGHT PANE: Editable Header, Line Items, Alerts & Action Bar ===
    with right_pane:
        right_pane.subheader("Extracted Header Fields")
        right_pane.caption(
            f"Vendor: {sanitize_display_text(active_invoice.vendor_name or 'Unknown', max_length=100)} "
            f"| Tax ID: {mask_tax_id(active_invoice.vendor_tax_id)} "
            f"| Currency: {sanitize_display_text(active_invoice.currency, max_length=8)}"
        )

        # Validation Alert Box (from latest revalidation if present)
        last_reval: InvoiceRevalidateResponse | None = st.session_state.get(
            "workbench_last_revalidation"
        )
        if last_reval is not None:
            vs = last_reval.validation_summary
            if vs.all_passed:
                right_pane.success(
                    f"Validation Passed — Line Math: OK | Total Math: OK | Tax: OK | Dates: OK "
                    f"(Status: {last_reval.status})"
                )
            else:
                flags = ", ".join(
                    sanitize_display_text(e, max_length=60) for e in vs.active_exceptions
                )
                right_pane.warning(f"Validation Alerts: {flags or last_reval.status}")

        base_header = HeaderFormDraft.from_invoice(active_invoice)
        hc1, hc2 = st.columns(2)
        with hc1:
            ed_inv_num = st.text_input("Invoice Number", value=base_header.invoice_number)
            ed_inv_date = st.text_input("Invoice Date (YYYY-MM-DD)", value=base_header.invoice_date)
            ed_due_date = st.text_input("Due Date (YYYY-MM-DD)", value=base_header.due_date)
            ed_po_num = st.text_input("PO Number", value=base_header.po_number)
        with hc2:
            ed_subtotal = st.text_input("Subtotal", value=base_header.subtotal)
            ed_tax = st.text_input("Total Tax Amount", value=base_header.total_tax_amount)
            ed_total = st.text_input("Total Amount", value=base_header.total_amount)

        header_draft = HeaderFormDraft(
            invoice_number=ed_inv_num,
            invoice_date=ed_inv_date,
            due_date=ed_due_date,
            po_number=ed_po_num,
            subtotal=ed_subtotal,
            total_tax_amount=ed_tax,
            total_amount=ed_total,
        )

        # Editable Line-Item Table
        right_pane.subheader("Line Items")
        line_rows = build_editable_line_rows(active_invoice.lines)
        edited_grid = st.data_editor(line_rows, use_container_width=True, hide_index=True)

        line_drafts: list[LineFormDraft] = []
        if isinstance(edited_grid, list):
            for row in edited_grid:
                if not isinstance(row, dict) or row.get("Line #") is None:
                    continue
                try:
                    line_num = int(row["Line #"])
                except (TypeError, ValueError):
                    continue
                if line_num < 1 or line_num > MAX_REVALIDATE_LINES:
                    continue
                line_drafts.append(
                    LineFormDraft(
                        line_number=line_num,
                        description=str(row.get("Description", "")),
                        quantity=str(row.get("Qty", "")),
                        unit_price=str(row.get("Unit Price", "")),
                        line_total=str(row.get("Line Total", "")),
                        line_tax_rate=str(row.get("Tax Rate", "")),
                    )
                )
        else:
            line_drafts = [LineFormDraft.from_line(line) for line in active_invoice.lines]

        # Tax Override & Mandatory Reason Code Controls
        right_pane.subheader("Re-Validation & Audit Controls")
        tc1, tc2 = st.columns(2)
        with tc1:
            is_reverse_charge = st.checkbox("EU Reverse Charge (0% VAT)", value=False)
        with tc2:
            is_exempt = st.checkbox("Tax Exempt", value=False)

        reason_options = [label for _, label in REASON_CODE_LABELS]
        reason_lookup = {label: code for code, label in REASON_CODE_LABELS}
        selected_reason_label = st.selectbox(
            "Mandatory Reason Code",
            options=reason_options,
            index=0,
        )
        selected_reason = reason_lookup.get(selected_reason_label, ReasonCode.OCR_MISREAD)
        audit_comment = st.text_area("Audit Comment (mandatory for OTHER)", value="")

        # Action Bar
        editable = can_revalidate_in_workbench(active_invoice, user_roles)
        approvable = can_approve_in_workbench(active_invoice, user_roles)

        act_col1, act_col2 = st.columns(2)
        with act_col1:
            if editable:
                if st.button("Re-Validate"):
                    try:
                        reval_resp, refreshed = controller.submit_revalidation(
                            active_invoice,
                            header_draft=header_draft,
                            line_drafts=line_drafts,
                            reason_code=selected_reason,
                            comment=audit_comment,
                            is_reverse_charge=is_reverse_charge,
                            is_exempt=is_exempt,
                            user_roles=user_roles,
                        )
                        st.session_state["workbench_invoice"] = refreshed
                        st.session_state["workbench_last_revalidation"] = reval_resp
                        active_invoice = refreshed
                        st.success(
                            f"Re-validated invoice {refreshed.invoice_id} -> {reval_resp.status} "
                            f"(Audit ID: {reval_resp.audit_event_id})"
                        )
                    except (PermissionError, ValueError, APIClientError) as exc:
                        st.error(sanitize_display_text(str(exc), max_length=220))
            else:
                st.info("Editing disabled for current role or terminal invoice status.")

        with act_col2:
            # CLAUDE.md §12: Hide Approve button completely (not just disable) when not authorized
            if approvable:
                if st.button("Approve (One-Click)"):
                    try:
                        app_resp, approved = controller.submit_approval(
                            active_invoice,
                            comment=audit_comment,
                            user_roles=user_roles,
                        )
                        st.session_state["workbench_invoice"] = approved
                        st.success(
                            f"Approved invoice {approved.invoice_id} -> {app_resp.status} "
                            f"(Audit ID: {app_resp.audit_event_id})"
                        )
                    except (PermissionError, ValueError, APIClientError) as exc:
                        st.error(sanitize_display_text(str(exc), max_length=220))


__all__ = [
    "ALLOWED_PREVIEW_EXTENSIONS",
    "APPROVE_ALLOWED_ROLES",
    "CLERK_APPROVAL_CONFIDENCE_FLOOR",
    "ConfidenceCue",
    "DEFAULT_PREVIEW_ZOOM",
    "DocumentPreviewPage",
    "EDITABLE_HEADER_FIELDS",
    "EDITABLE_LINE_FIELDS",
    "HeaderFormDraft",
    "LineFormDraft",
    "MANAGER_APPROVABLE_STATUSES",
    "MAX_PREVIEW_BYTES",
    "MAX_PREVIEW_PAGES",
    "MAX_PREVIEW_PIXEL_DIM",
    "MAX_PREVIEW_ZOOM",
    "MIN_PREVIEW_ZOOM",
    "NON_EDITABLE_STATUSES",
    "REASON_CODE_LABELS",
    "REVALIDATE_ALLOWED_ROLES",
    "REVIEW_CONFIDENCE_FLOOR",
    "ReviewWorkbenchController",
    "build_editable_line_rows",
    "build_revalidate_request",
    "can_approve_in_workbench",
    "can_revalidate_in_workbench",
    "classify_confidence_cue",
    "extract_safe_document_url",
    "mask_tax_id",
    "render_document_preview",
    "render_review_workbench",
]
