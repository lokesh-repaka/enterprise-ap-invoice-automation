"""
Ingestion Dashboard (/) — Drag-and-Drop Upload, Batch Status Table & Live Polling (P11-2).

Implements PRD Screen 1, FR-01, BR-001, GAP-004, and CLAUDE.md §4.2, §12 & §16:
- Drag-and-drop multi-file upload zone (PDF, JPG, JPEG, PNG, XLSX; max 25 MB; TIFF blocked)
- Vendor selection / auto-detection selector
- Active batch summary card (Total Uploaded, Processing, Passed, Needs Review)
- Live status table (Invoice ID, File Name, File Size, Upload Time, Detection Mode, Real-Time Status)
- Bounded live polling loop (`GET /api/v1/invoices/{id}`) with automatic stop on terminal status
  and graceful backoff on HTTP 429 rate limits

Security & Layering Invariants:
- Reaches the backend exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
- Never calls ``unsafe_allow_html=True``; neutralizes XSS/HTML tags, control/bidi spoofing,
  CSV formula prefixes (CWE-1236), and JWT token leaks before rendering.
- Enforces upload RBAC (``ap_clerk`` / ``finance_manager``), deterministic SHA-256 idempotency
  keys, and bounded batch/session/polling caps (CWE-400).
"""

import hashlib
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.core.logging import get_logger
from src.ui.api_client import (
    MAX_CLIENT_UPLOAD_BYTES,
    APIClientError,
    APInvoiceAPIClient,
    APIRateLimitError,
)
from src.ui.theme_rbac import classify_confidence_cue

logger = get_logger("ap.ui.ingestion_dashboard")

ALLOWED_UPLOAD_EXTENSIONS: tuple[str, ...] = ("pdf", "jpg", "jpeg", "png", "xlsx")
DISALLOWED_TIFF_EXTENSIONS: frozenset[str] = frozenset({"tif", "tiff"})
MAX_BATCH_FILES_PER_SUBMISSION: int = 50
MAX_BATCH_TOTAL_BYTES: int = 100 * 1024 * 1024
MAX_TRACKED_BATCH_ITEMS: int = 500
MAX_POLL_ITEMS_PER_CYCLE: int = 50
MIN_POLL_INTERVAL_SECONDS: float = 1.0
MAX_POLL_INTERVAL_SECONDS: float = 30.0
DEFAULT_POLL_INTERVAL_SECONDS: float = 3.0
MAX_AUTO_POLL_CYCLES: int = 60

UPLOAD_ALLOWED_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})

IN_PROGRESS_STATUSES: frozenset[str] = frozenset({"UPLOADED", "EXTRACTING", "REVALIDATING"})
PASSED_STATUSES: frozenset[str] = frozenset(
    {"VALIDATED", "APPROVED_CLERK", "APPROVED_MANAGER", "STAGED_FOR_EXPORT"}
)
NEEDS_REVIEW_STATUSES: frozenset[str] = frozenset(
    {
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "REQUIRES_MANAGER_APPROVAL",
        "REJECTED",
    }
)

AUTO_DETECT_VENDOR_LABEL: str = "Auto-Detect"
VENDOR_PRESET_OPTIONS: tuple[tuple[str, str], ...] = (
    (AUTO_DETECT_VENDOR_LABEL, ""),
    ("V-001 · Acme Technologies Inc. (US)", "V-001"),
    ("V-002 · GlobalTech LLC (US)", "V-002"),
    ("V-003 · Meridian Software Ltd. (UK)", "V-003"),
    ("V-004 · Thames Digital Services (UK)", "V-004"),
    ("V-005 · Berlin Systems GmbH (DE)", "V-005"),
    ("V-006 · Münster Analytics GmbH (DE)", "V-006"),
    ("V-007 · Madrid Consulting S.L. (ES)", "V-007"),
    ("V-008 · Barcelona Print S.A. (ES)", "V-008"),
)

_VENDOR_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_INVOICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_RESIDUAL_ANGLE_RE = re.compile(r"[<>]")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")
_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


# ---------------------------------------------------------------------------
# Typed Dashboard State & Transfer Models
# ---------------------------------------------------------------------------


class PendingUploadFile(BaseModel):
    """In-memory file selected via drag-and-drop prior to backend submission."""

    model_config = ConfigDict(frozen=True)

    filename: str
    content: bytes
    content_type: str | None = None


class BatchInvoiceItem(BaseModel):
    """Single row tracked in the Ingestion Dashboard live status table."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str | None = None
    filename: str
    size_bytes: int
    uploaded_at: datetime
    detected_mime: str | None = None
    detection_mode: str
    vendor_id: str = "UNKNOWN"
    status: str
    confidence_macro_avg: Decimal | None = None
    total_amount: Decimal | None = None
    currency: str | None = None
    deduplicated: bool = False
    idempotency_key: str | None = None
    last_polled_at: datetime | None = None
    error_message: str | None = None


class BatchSummary(BaseModel):
    """Active batch summary card metrics (PRD Screen 1)."""

    model_config = ConfigDict(frozen=True)

    total_uploaded: int
    processing: int
    passed: int
    needs_review: int
    failed: int
    deduplicated_count: int


class PollCycleResult(BaseModel):
    """Outcome of a single bounded live polling cycle."""

    model_config = ConfigDict(frozen=True)

    polled_count: int
    updated_count: int
    remaining_in_progress: int
    errors: dict[str, str]
    should_continue_polling: bool


# ---------------------------------------------------------------------------
# Validation, Formatting & Sanitization Helpers
# ---------------------------------------------------------------------------


def sanitize_display_text(value: str, *, max_length: int = 255) -> str:
    """
    Sanitize untrusted text for safe UI rendering and CSV export.

    Strips control characters, bidi/zero-width spoofing codepoints, and HTML tags,
    redacts embedded Bearer/JWT tokens, and neutralizes spreadsheet formula prefixes
    (CWE-79, CWE-117, CWE-451, CWE-532, CWE-1236).
    """
    text = _CONTROL_CHAR_RE.sub("", value)
    text = _BIDI_OR_ZERO_WIDTH_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    text = _RESIDUAL_ANGLE_RE.sub("", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED_TOKEN]", text)
    text = text.strip()
    if text and text.startswith(_FORMULA_PREFIXES):
        text = f"'{text}"
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


def validate_client_file(filename: str, content: bytes) -> str:
    """
    Validate an uploaded file client-side per FR-01, BR-001, GAP-004, and SEC-190.

    Returns the cleaned filename or raises ``ValueError``.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Filename must be a non-empty string")
    if _CONTROL_CHAR_RE.search(filename) or _BIDI_OR_ZERO_WIDTH_RE.search(filename):
        raise ValueError("Filename contains disallowed control or bidi characters")
    cleaned = filename.strip()
    if len(cleaned) > 255:
        raise ValueError("Filename exceeds maximum length of 255 characters")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError("Filename must not contain path separators or traversal segments")

    suffix = PurePosixPath(cleaned).suffix.lower().lstrip(".")
    if not suffix:
        raise ValueError("Filename must include a supported file extension (pdf, jpg, png, xlsx)")
    if suffix in DISALLOWED_TIFF_EXTENSIONS:
        raise ValueError("TIFF files are not supported (GAP-004); upload PDF, JPG, PNG, or XLSX")
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '.{suffix}'; allowed: {', '.join(ALLOWED_UPLOAD_EXTENSIONS)}"
        )

    if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
        raise ValueError("Uploaded file is empty")
    if len(content) > MAX_CLIENT_UPLOAD_BYTES:
        raise ValueError("Uploaded file exceeds the maximum limit of 25 MB (BR-001)")
    return cleaned


def validate_vendor_selection(vendor_id: str | None) -> str | None:
    """Validate optional vendor selector input; returns ``None`` for auto-detection."""
    if vendor_id is None:
        return None
    if not isinstance(vendor_id, str):
        raise ValueError("vendor_id must be a string")
    if _CONTROL_CHAR_RE.search(vendor_id) or _BIDI_OR_ZERO_WIDTH_RE.search(vendor_id):
        raise ValueError("vendor_id contains disallowed control characters")
    stripped = vendor_id.strip()
    if not stripped or stripped == AUTO_DETECT_VENDOR_LABEL:
        return None
    if not _VENDOR_ID_RE.match(stripped):
        raise ValueError(
            "vendor_id must match ^[A-Za-z0-9_-]{1,64}$ (letters, digits, hyphens, underscores)"
        )
    return stripped


def validate_poll_interval(interval_seconds: float) -> float:
    """Enforce bounded live polling interval ``[1.0, 30.0]`` seconds."""
    if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float)):
        raise ValueError("poll_interval must be a numeric value")
    val = float(interval_seconds)
    if val < MIN_POLL_INTERVAL_SECONDS or val > MAX_POLL_INTERVAL_SECONDS:
        raise ValueError(
            f"poll_interval must be between {MIN_POLL_INTERVAL_SECONDS} and "
            f"{MAX_POLL_INTERVAL_SECONDS} seconds"
        )
    return val


def compute_upload_idempotency_key(
    content: bytes,
    *,
    vendor_id: str | None = None,
) -> str:
    """Compute deterministic SHA-256 idempotency key per CLAUDE.md §16 rule 6."""
    normalized_vendor = validate_vendor_selection(vendor_id) or "AUTO"
    hasher = hashlib.sha256()
    hasher.update(f"ap-ui-upload:{normalized_vendor}:".encode())
    hasher.update(content)
    return f"ui-{hasher.hexdigest()[:48]}"


def format_file_size(size_bytes: int) -> str:
    """Render byte count in human-readable B / KB / MB units."""
    if size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.2f} MB"


def derive_detection_mode(detected_mime: str | None, filename: str = "") -> str:
    """Map detected MIME type (or extension fallback) to PRD Screen 1 Detection Mode."""
    mime = (detected_mime or "").lower().strip()
    if mime == "application/pdf":
        return "PDF Document"
    if mime in {"image/png", "image/jpeg", "image/jpg"}:
        return "Scanned Image"
    if mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        return "Excel Spreadsheet"

    suffix = PurePosixPath(filename).suffix.lower().lstrip(".")
    if suffix == "pdf":
        return "PDF Document"
    if suffix in {"png", "jpg", "jpeg"}:
        return "Scanned Image"
    if suffix == "xlsx":
        return "Excel Spreadsheet"
    return "Unsupported"


def is_in_progress_status(status: str) -> bool:
    """Return True when an invoice is actively queued/processing and should be polled."""
    return status in IN_PROGRESS_STATUSES


def can_upload_invoices(user_roles: Sequence[str] | None) -> bool:
    """Check whether the caller holds an upload-authorized role (``ap_clerk`` or ``finance_manager``)."""
    if not user_roles:
        return False
    return bool(UPLOAD_ALLOWED_ROLES.intersection(user_roles))


def summarize_batch(items: Sequence[BatchInvoiceItem]) -> BatchSummary:
    """Compute Active Batch Summary Card metrics (Total Uploaded, Processing, Passed, Needs Review)."""
    total_uploaded = 0
    processing = 0
    passed = 0
    needs_review = 0
    failed = 0
    deduplicated_count = 0

    for item in items:
        if item.status == "UPLOAD_FAILED" or item.invoice_id is None:
            failed += 1
            continue
        total_uploaded += 1
        if item.deduplicated:
            deduplicated_count += 1
        if item.status in IN_PROGRESS_STATUSES:
            processing += 1
        elif item.status in PASSED_STATUSES:
            passed += 1
        elif item.status in NEEDS_REVIEW_STATUSES:
            needs_review += 1
        else:
            needs_review += 1

    return BatchSummary(
        total_uploaded=total_uploaded,
        processing=processing,
        passed=passed,
        needs_review=needs_review,
        failed=failed,
        deduplicated_count=deduplicated_count,
    )


def build_status_table_rows(items: Sequence[BatchInvoiceItem]) -> list[dict[str, Any]]:
    """Build sanitized, formula-safe rows for the Ingestion Dashboard Live Status Table."""
    rows: list[dict[str, Any]] = []
    for item in items:
        notes_parts: list[str] = []
        if item.deduplicated:
            notes_parts.append("Replayed (Idempotent)")
        if item.error_message:
            notes_parts.append(sanitize_display_text(item.error_message, max_length=180))

        if item.confidence_macro_avg is not None:
            cue = classify_confidence_cue(item.confidence_macro_avg)
            confidence_str = f"{cue.score:.1f}%"
            confidence_color = cue.hex_color
        else:
            confidence_str = "—"
            confidence_color = "—"
        safe_invoice_id = (
            item.invoice_id if item.invoice_id and _INVOICE_ID_RE.match(item.invoice_id) else None
        )
        route = f"/workbench/{safe_invoice_id}" if safe_invoice_id else "—"
        rows.append(
            {
                "Invoice ID": safe_invoice_id if safe_invoice_id else "—",
                "File Name": sanitize_display_text(item.filename, max_length=160),
                "File Size": format_file_size(item.size_bytes),
                "Upload Time": item.uploaded_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "Detection Mode": sanitize_display_text(item.detection_mode, max_length=40),
                "Real-Time Status": sanitize_display_text(item.status, max_length=40),
                "Confidence": confidence_str,
                "Confidence Color": confidence_color,
                "Vendor": sanitize_display_text(item.vendor_id, max_length=64),
                "Notes": " · ".join(notes_parts) if notes_parts else "—",
                "Route": route,
            }
        )
    return rows


def _cap_tracked_items(items: list[BatchInvoiceItem]) -> list[BatchInvoiceItem]:
    """Enforce ``MAX_TRACKED_BATCH_ITEMS`` retaining most recent entries (anti-OOM CWE-400)."""
    if len(items) <= MAX_TRACKED_BATCH_ITEMS:
        return items
    return items[-MAX_TRACKED_BATCH_ITEMS:]


# ---------------------------------------------------------------------------
# Stateful Ingestion Dashboard Controller (Backend-Transport-Only)
# ---------------------------------------------------------------------------


class IngestionDashboardController:
    """Orchestrates drag-and-drop batch uploads and live status polling via ``APInvoiceAPIClient``."""

    def __init__(self, api_client: APInvoiceAPIClient) -> None:
        self._client = api_client

    def submit_batch(
        self,
        files: Sequence[PendingUploadFile],
        *,
        vendor_id: str | None = None,
        existing_items: Sequence[BatchInvoiceItem] | None = None,
        user_roles: Sequence[str] | None = None,
    ) -> list[BatchInvoiceItem]:
        """
        Validate and upload a batch of files through ``APInvoiceAPIClient.upload_invoice()``.

        - Enforces ``UPLOAD_ALLOWED_ROLES`` when ``user_roles`` is provided.
        - Rejects batches exceeding ``MAX_BATCH_FILES_PER_SUBMISSION``.
        - Isolates per-file validation and API failures so valid files still succeed.
        - Deduplicates rows by ``invoice_id`` when idempotent replays occur.
        """
        if user_roles is not None and not can_upload_invoices(user_roles):
            raise PermissionError(
                "Upload requires 'ap_clerk' or 'finance_manager' role; current role is read-only"
            )

        if not files:
            return list(existing_items) if existing_items else []

        if len(files) > MAX_BATCH_FILES_PER_SUBMISSION:
            raise ValueError(
                f"Batch exceeds maximum limit of {MAX_BATCH_FILES_PER_SUBMISSION} files per upload"
            )

        total_batch_bytes = sum(len(f.content) for f in files)
        if total_batch_bytes > MAX_BATCH_TOTAL_BYTES:
            raise ValueError(
                f"Batch total size exceeds maximum limit of {MAX_BATCH_TOTAL_BYTES // (1024 * 1024)} MB"
            )

        clean_vendor = validate_vendor_selection(vendor_id)
        tracked: list[BatchInvoiceItem] = list(existing_items) if existing_items else []
        index_by_invoice_id: dict[str, int] = {
            item.invoice_id: idx for idx, item in enumerate(tracked) if item.invoice_id is not None
        }

        for pending in files:
            now = datetime.now(UTC)
            try:
                clean_name = validate_client_file(pending.filename, pending.content)
                idem_key = compute_upload_idempotency_key(pending.content, vendor_id=clean_vendor)
                receipt = self._client.upload_invoice(
                    filename=clean_name,
                    content=pending.content,
                    content_type=pending.content_type,
                    vendor_id=clean_vendor,
                    idempotency_key=idem_key,
                )
                new_item = BatchInvoiceItem(
                    invoice_id=receipt.invoice_id,
                    filename=receipt.filename,
                    size_bytes=receipt.size_bytes,
                    uploaded_at=receipt.uploaded_at,
                    detected_mime=receipt.detected_mime,
                    detection_mode=derive_detection_mode(receipt.detected_mime, receipt.filename),
                    vendor_id=receipt.vendor_id,
                    status=receipt.status,
                    deduplicated=receipt.deduplicated,
                    idempotency_key=idem_key,
                    last_polled_at=now,
                    error_message=None,
                )
                if receipt.invoice_id in index_by_invoice_id:
                    tracked[index_by_invoice_id[receipt.invoice_id]] = new_item
                else:
                    index_by_invoice_id[receipt.invoice_id] = len(tracked)
                    tracked.append(new_item)
            except (ValueError, APIClientError) as exc:
                safe_error = sanitize_display_text(str(exc), max_length=200)
                logger.warning(
                    "ingestion_upload_item_failed",
                    extra={
                        "upload_filename": sanitize_display_text(pending.filename, max_length=120)
                    },
                )
                tracked.append(
                    BatchInvoiceItem(
                        invoice_id=None,
                        filename=sanitize_display_text(pending.filename, max_length=160),
                        size_bytes=len(pending.content),
                        uploaded_at=now,
                        detected_mime=pending.content_type,
                        detection_mode=derive_detection_mode(
                            pending.content_type, pending.filename
                        ),
                        vendor_id=clean_vendor or "UNKNOWN",
                        status="UPLOAD_FAILED",
                        deduplicated=False,
                        error_message=safe_error,
                    )
                )

        return _cap_tracked_items(tracked)

    def poll_batch_once(
        self,
        items: Sequence[BatchInvoiceItem],
        *,
        poll_cycle_count: int = 0,
        max_poll_cycles: int = MAX_AUTO_POLL_CYCLES,
    ) -> tuple[list[BatchInvoiceItem], PollCycleResult]:
        """
        Poll ``GET /api/v1/invoices/{id}`` for all non-terminal tracked invoices.

        - Skips already-terminal and failed rows to minimize backend load.
        - Backs off immediately (``should_continue_polling=False``) on HTTP 429 rate-limit.
        - Stops polling automatically once zero in-progress items remain or ``max_poll_cycles`` is reached.
        """
        bounded_max_cycles = max(1, min(int(max_poll_cycles), MAX_AUTO_POLL_CYCLES))
        bounded_cycle_count = max(0, int(poll_cycle_count))

        polled_count = 0
        updated_count = 0
        errors: dict[str, str] = {}
        rate_limited = False
        updated_items: list[BatchInvoiceItem] = []

        for idx, item in enumerate(items):
            if (
                item.invoice_id is None
                or not is_in_progress_status(item.status)
                or rate_limited
                or polled_count >= MAX_POLL_ITEMS_PER_CYCLE
            ):
                updated_items.append(item)
                continue

            polled_count += 1
            now = datetime.now(UTC)
            try:
                detail = self._client.get_invoice(item.invoice_id)
                changed = (
                    detail.status != item.status
                    or detail.confidence_macro_avg != item.confidence_macro_avg
                    or detail.total_amount != item.total_amount
                )
                if changed:
                    updated_count += 1
                updated_items.append(
                    item.model_copy(
                        update={
                            "status": detail.status,
                            "confidence_macro_avg": detail.confidence_macro_avg,
                            "total_amount": detail.total_amount,
                            "currency": detail.currency,
                            "vendor_id": detail.vendor_id or item.vendor_id,
                            "last_polled_at": now,
                            "error_message": None,
                        }
                    )
                )
            except APIRateLimitError as exc:
                rate_limited = True
                retry_after = getattr(exc, "retry_after", None)
                retry_hint = f" (retry after {retry_after:.0f}s)" if retry_after else ""
                safe_msg = sanitize_display_text(
                    f"Rate limited (HTTP 429){retry_hint}; auto-polling paused", max_length=180
                )
                errors[item.invoice_id] = safe_msg
                updated_items.append(
                    item.model_copy(update={"last_polled_at": now, "error_message": safe_msg})
                )
                # Append any remaining untouched items without hammering the rate-limited API
                updated_items.extend(items[idx + 1 :])
                break
            except APIClientError as exc:
                safe_msg = sanitize_display_text(str(exc), max_length=180)
                errors[item.invoice_id] = safe_msg
                updated_items.append(
                    item.model_copy(update={"last_polled_at": now, "error_message": safe_msg})
                )

        remaining_in_progress = sum(
            1
            for item in updated_items
            if item.invoice_id is not None and is_in_progress_status(item.status)
        )
        next_cycle = bounded_cycle_count + 1
        should_continue = (
            remaining_in_progress > 0 and not rate_limited and next_cycle < bounded_max_cycles
        )

        return (
            updated_items,
            PollCycleResult(
                polled_count=polled_count,
                updated_count=updated_count,
                remaining_in_progress=remaining_in_progress,
                errors=errors,
                should_continue_polling=should_continue,
            ),
        )


# ---------------------------------------------------------------------------
# Streamlit UI Renderer (Screen 1 — Ingestion Dashboard)
# ---------------------------------------------------------------------------


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def render_ingestion_dashboard(
    api_client: APInvoiceAPIClient,
    *,
    st_module: Any | None = None,
    user_roles: Sequence[str] | None = None,
) -> None:
    """Render PRD Screen 1 (Ingestion Dashboard `/`) using Streamlit."""
    st = _get_streamlit(st_module)
    controller = IngestionDashboardController(api_client)

    st.title("Ingestion Dashboard")
    st.caption(
        "Upload vendor invoices (PDF, JPG, PNG, XLSX — max 25 MB; TIFF unsupported) and "
        "monitor real-time extraction & validation status."
    )

    batch_items: list[BatchInvoiceItem] = list(st.session_state.get("batch_items", []))
    poll_cycles: int = int(st.session_state.get("poll_cycles", 0))

    # --- 1. Drag-and-Drop Upload Zone & Vendor Selector ---
    st.subheader("Upload Invoices")
    upload_permitted = user_roles is None or can_upload_invoices(user_roles)

    vendor_labels = [label for label, _ in VENDOR_PRESET_OPTIONS]
    vendor_lookup = dict(VENDOR_PRESET_OPTIONS)

    col_vendor, col_custom = st.columns(2)
    with col_vendor:
        selected_label = st.selectbox(
            "Vendor Selection / Auto-Detection",
            options=vendor_labels,
            index=0,
        )
    with col_custom:
        custom_vendor = st.text_input(
            "Optional Custom Vendor ID (overrides selector)",
            value="",
        )

    effective_vendor: str | None = (
        custom_vendor.strip() or vendor_lookup.get(selected_label) or None
    )

    uploaded_files = st.file_uploader(
        "Drag and drop invoice files here (multi-file supported)",
        type=list(ALLOWED_UPLOAD_EXTENSIONS),
        accept_multiple_files=True,
    )

    if not upload_permitted:
        st.info(
            "Your active role has read-only access on the Ingestion Dashboard. "
            "Sign in as an AP Clerk or Finance Manager to upload invoices."
        )
    elif st.button("Upload Selected Invoices"):
        if not uploaded_files:
            st.warning("Select at least one PDF, JPG, PNG, or XLSX invoice file before uploading.")
        else:
            pending = [
                PendingUploadFile(
                    filename=getattr(f, "name", "invoice.pdf"),
                    content=f.getvalue(),
                    content_type=getattr(f, "type", None),
                )
                for f in uploaded_files
            ]
            try:
                batch_items = controller.submit_batch(
                    pending,
                    vendor_id=effective_vendor,
                    existing_items=batch_items,
                    user_roles=user_roles,
                )
                st.session_state["batch_items"] = batch_items
                st.session_state["poll_cycles"] = 0
                poll_cycles = 0
                st.success(f"Processed {len(pending)} file(s) in current upload batch.")
            except (PermissionError, ValueError) as exc:
                st.error(sanitize_display_text(str(exc), max_length=220))

    # --- 2. Live Polling Controls ---
    st.divider()
    st.subheader("Active Batch & Live Status")
    p_col1, p_col2, p_col3, p_col4 = st.columns(4)
    with p_col1:
        auto_poll = st.checkbox("Auto-poll in-progress invoices", value=True)
    with p_col2:
        poll_interval = st.slider(
            "Poll interval (seconds)",
            min_value=MIN_POLL_INTERVAL_SECONDS,
            max_value=MAX_POLL_INTERVAL_SECONDS,
            value=DEFAULT_POLL_INTERVAL_SECONDS,
        )
    with p_col3:
        manual_refresh = st.button("Refresh Status Now")
    with p_col4:
        clear_completed = st.button("Clear Completed")

    if clear_completed:
        batch_items = [
            item
            for item in batch_items
            if item.invoice_id is not None and is_in_progress_status(item.status)
        ]
        st.session_state["batch_items"] = batch_items

    has_in_progress = any(
        item.invoice_id is not None and is_in_progress_status(item.status) for item in batch_items
    )

    if manual_refresh and has_in_progress:
        batch_items, poll_res = controller.poll_batch_once(
            batch_items, poll_cycle_count=poll_cycles
        )
        st.session_state["batch_items"] = batch_items
        st.session_state["poll_cycles"] = poll_cycles + 1
        if poll_res.errors:
            st.warning(f"Polling encountered {len(poll_res.errors)} warning(s); see Notes column.")

    # --- 3. Active Batch Summary Card (PRD Screen 1) ---
    summary = summarize_batch(batch_items)
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        m_col1.metric("Total Uploaded", summary.total_uploaded)
    with m_col2:
        m_col2.metric("Processing", summary.processing)
    with m_col3:
        m_col3.metric("Passed", summary.passed)
    with m_col4:
        m_col4.metric("Needs Review", summary.needs_review)

    if summary.failed > 0:
        st.warning(f"{summary.failed} file(s) failed upload validation; review Notes below.")

    # --- 4. Live Status Table ---
    if batch_items:
        rows = build_status_table_rows(batch_items)
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No invoices uploaded in this session yet. Drop files above to begin ingestion.")

    # --- 5. Bounded Live Polling Hook (Streamlit 1.37+ fragment or explicit status hint) ---
    if auto_poll and has_in_progress and poll_cycles < MAX_AUTO_POLL_CYCLES:
        safe_interval = validate_poll_interval(poll_interval)
        fragment_fn = getattr(st, "fragment", None)
        if callable(fragment_fn):

            @fragment_fn(run_every=safe_interval)
            def _auto_poll_fragment() -> None:
                current_items: list[BatchInvoiceItem] = list(
                    st.session_state.get("batch_items", [])
                )
                current_cycles: int = int(st.session_state.get("poll_cycles", 0))
                if not any(
                    i.invoice_id is not None and is_in_progress_status(i.status)
                    for i in current_items
                ):
                    return
                updated, res = controller.poll_batch_once(
                    current_items, poll_cycle_count=current_cycles
                )
                st.session_state["batch_items"] = updated
                st.session_state["poll_cycles"] = current_cycles + 1
                if res.updated_count > 0 or not res.should_continue_polling:
                    st.rerun()

            _auto_poll_fragment()
        else:
            st.caption(
                f"Live polling active (interval: {safe_interval:.0f}s, "
                f"cycle {poll_cycles}/{MAX_AUTO_POLL_CYCLES})."
            )


__all__ = [
    "ALLOWED_UPLOAD_EXTENSIONS",
    "AUTO_DETECT_VENDOR_LABEL",
    "BatchInvoiceItem",
    "BatchSummary",
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "DISALLOWED_TIFF_EXTENSIONS",
    "IN_PROGRESS_STATUSES",
    "IngestionDashboardController",
    "MAX_AUTO_POLL_CYCLES",
    "MAX_BATCH_FILES_PER_SUBMISSION",
    "MAX_BATCH_TOTAL_BYTES",
    "MAX_POLL_INTERVAL_SECONDS",
    "MAX_POLL_ITEMS_PER_CYCLE",
    "MAX_TRACKED_BATCH_ITEMS",
    "MIN_POLL_INTERVAL_SECONDS",
    "NEEDS_REVIEW_STATUSES",
    "PASSED_STATUSES",
    "PendingUploadFile",
    "PollCycleResult",
    "UPLOAD_ALLOWED_ROLES",
    "VENDOR_PRESET_OPTIONS",
    "build_status_table_rows",
    "can_upload_invoices",
    "compute_upload_idempotency_key",
    "derive_detection_mode",
    "format_file_size",
    "is_in_progress_status",
    "render_ingestion_dashboard",
    "sanitize_display_text",
    "summarize_batch",
    "validate_client_file",
    "validate_poll_interval",
    "validate_vendor_selection",
]
