"""
Confidence Colour Coding & Role-Aware UI Capability Policy (P11-7).

Single source of truth for visual confidence cues and role-based UI visibility across
all five Streamlit screens (CLAUDE.md §2, §4.2, §12, §16.1, §16.8, FR-04, FR-13):
- Confidence colour coding:
  - >= 90.00% -> Green (``#22c55e``) — High Confidence (eligible for one-click clerk approval)
  - 80.00% – 89.99% -> Light-Yellow (``#fef08a``) — Review Recommended
  - < 80.00% -> Amber/Red (``#f97316`` / ``#ef4444``) — Low Confidence / Exception Escalation
  - Corrupt / NaN / Infinity / bool / out-of-range scores fail closed to LOW (``#ef4444``).
- Role-aware UI visibility:
  - Approve button is **hidden** (never merely disabled) for ``ap_clerk`` when:
    - effective USD total > ``HIGH_VALUE_THRESHOLD_USD`` (from ``get_settings()``), OR
    - non-USD invoice lacks FX-converted ``total_amount_usd``, OR
    - PO variance > ``PO_VARIANCE_TOLERANCE_PERCENT`` (from ``get_settings()``), OR
    - invoice total < 0 (credit note), OR
    - confidence < 90%, OR
    - status != ``VALIDATED``.
  - ``finance_manager`` sees ``Approve (Finance Manager)`` across approvable statuses including
    > $10,000 USD and > 5% PO variance.
  - ``system_admin``, unauthenticated, and unrecognized/spoofed roles never see Approve controls.

Security & Layering Invariants:
- Zero imports from ``src/database``, ``src/storage``, ``src/extraction``, ``src/validation``,
  ``src/services``, ``sqlalchemy``, ``redis``, ``openai``, or ``azure.*`` (CLAUDE.md §4.2).
- Zero ``unsafe_allow_html=True``; UI hiding is defense-in-depth paired with FastAPI RBAC.
"""

from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.api.schemas.invoices import InvoiceDetailResponse
from src.core.config import get_settings

# Canonical CLAUDE.md §12 confidence palette
CONFIDENCE_GREEN_HEX: str = "#22c55e"
CONFIDENCE_YELLOW_HEX: str = "#fef08a"
CONFIDENCE_AMBER_HEX: str = "#f97316"
CONFIDENCE_RED_HEX: str = "#ef4444"

CLERK_APPROVAL_CONFIDENCE_FLOOR: Decimal = Decimal("90.00")
REVIEW_CONFIDENCE_FLOOR: Decimal = Decimal("80.00")

CANONICAL_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager", "system_admin"})
UPLOAD_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
EDIT_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
APPROVE_ROLES: frozenset[str] = frozenset({"ap_clerk", "finance_manager"})
BULK_MANAGER_APPROVE_ROLES: frozenset[str] = frozenset({"finance_manager"})

NON_EDITABLE_INVOICE_STATUSES: frozenset[str] = frozenset(
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
MANAGER_APPROVABLE_INVOICE_STATUSES: frozenset[str] = frozenset(
    {
        "VALIDATED",
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REQUIRES_MANAGER_APPROVAL",
    }
)
DECIDABLE_REVISION_STATUSES: frozenset[str] = frozenset(
    {"FLAGGED_POTENTIAL_REVISION", "DUPLICATE_INVOICE"}
)


class ConfidenceCue(BaseModel):
    """Canonical tri-tier confidence color cue (CLAUDE.md §12, FR-04)."""

    model_config = ConfigDict(frozen=True)

    tier: str
    label: str
    hex_color: str
    score: Decimal


class InvoiceUICapabilities(BaseModel):
    """Role-aware UI visibility & action capability flags for a single invoice."""

    model_config = ConfigDict(frozen=True)

    can_upload: bool
    can_edit_and_revalidate: bool
    show_approve_button: bool
    approve_button_label: str | None
    approve_hidden_reason: str | None
    show_bulk_manager_approve: bool
    can_decide_revision: bool
    can_view_audit: bool


# ---------------------------------------------------------------------------
# Confidence Colour Coding Helpers (Fail-Closed)
# ---------------------------------------------------------------------------


def _parse_safe_confidence(score: Any) -> Decimal | None:
    """Parse confidence score strictly within [0, 100]; return None on bool/NaN/Inf/out-of-range."""
    if score is None or isinstance(score, bool):
        return None
    try:
        val = score if isinstance(score, Decimal) else Decimal(str(score).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not val.is_finite():
        return None
    if val < Decimal("0") or val > Decimal("100"):
        return None
    return val


def classify_confidence_cue(score: Decimal | float | int | str | None) -> ConfidenceCue:
    """
    Classify an extraction confidence score into the canonical CLAUDE.md §12 colour tier.

    Fails closed to ``LOW`` (``#ef4444``) on ``None``, ``bool``, ``NaN``, ``Infinity``,
    negative, or ``>100`` values so corrupted data can never falsely display Green.
    """
    val = _parse_safe_confidence(score)
    if val is None:
        return ConfidenceCue(
            tier="LOW",
            label="Low Confidence (<80%)",
            hex_color=CONFIDENCE_RED_HEX,
            score=Decimal("0.00"),
        )
    if val >= CLERK_APPROVAL_CONFIDENCE_FLOOR:
        return ConfidenceCue(
            tier="HIGH",
            label="High Confidence (≥90%)",
            hex_color=CONFIDENCE_GREEN_HEX,
            score=val,
        )
    if val >= REVIEW_CONFIDENCE_FLOOR:
        return ConfidenceCue(
            tier="REVIEW",
            label="Review Recommended (80–89%)",
            hex_color=CONFIDENCE_YELLOW_HEX,
            score=val,
        )
    return ConfidenceCue(
        tier="LOW",
        label="Low Confidence (<80%)",
        hex_color=CONFIDENCE_RED_HEX,
        score=val,
    )


def build_confidence_color_map(scores: Sequence[Decimal | float | int | None]) -> dict[int, str]:
    """Return a row-index -> hex-color mapping for table rendering across Streamlit screens."""
    return {idx: classify_confidence_cue(score).hex_color for idx, score in enumerate(scores)}


# ---------------------------------------------------------------------------
# Role Normalization, Role Badges & Role-Aware UI Capability Evaluation
# ---------------------------------------------------------------------------


def normalize_canonical_roles(user_roles: Sequence[str] | None) -> frozenset[str]:
    """Extract only exact canonical role strings (rejects spoofed/mixed-case/injected roles)."""
    if not user_roles:
        return frozenset()
    return frozenset(r for r in user_roles if isinstance(r, str) and r in CANONICAL_ROLES)


def get_role_badge(user_roles: Sequence[str] | None) -> str:
    """Return a concise, human-readable sidebar role badge for the signed-in user."""
    roles = normalize_canonical_roles(user_roles)
    if "finance_manager" in roles:
        return "Finance Manager (Full Approval)"
    if "ap_clerk" in roles:
        return "AP Clerk (≤$10k Approval)"
    if "system_admin" in roles:
        return "System Admin (Audit & Ops)"
    return "Read-Only (Unauthenticated)"


def _exceeds_po_variance(
    total_amount: Decimal,
    po_amount: Decimal | None,
    tolerance_percent: Decimal,
) -> bool:
    if po_amount is None or not po_amount.is_finite() or po_amount <= Decimal("0"):
        return False
    variance_pct = (abs(total_amount - po_amount) / po_amount) * Decimal("100")
    return variance_pct > tolerance_percent


def evaluate_invoice_ui_capabilities(
    invoice: InvoiceDetailResponse,
    user_roles: Sequence[str] | None,
    *,
    po_amount: Decimal | None = None,
    high_value_threshold_usd: Decimal | None = None,
    po_variance_tolerance_percent: Decimal | None = None,
) -> InvoiceUICapabilities:
    """
    Compute complete role-aware UI capabilities for an invoice (CLAUDE.md §12, FR-13).

    Thresholds are dynamically read from ``get_settings()`` unless explicitly overridden.
    The Approve button is **hidden** (``show_approve_button=False``) for ``ap_clerk`` when:
    - ``effective_usd > HIGH_VALUE_THRESHOLD_USD``
    - ``currency != USD`` and ``total_amount_usd is None``
    - PO variance exceeds ``PO_VARIANCE_TOLERANCE_PERCENT``
    - ``total_amount < 0`` (credit note)
    - ``confidence_macro_avg < 90.00`` or ``status != VALIDATED``
    """
    roles = normalize_canonical_roles(user_roles)
    settings = get_settings()
    threshold_usd = (
        high_value_threshold_usd
        if high_value_threshold_usd is not None
        else Decimal(str(settings.HIGH_VALUE_THRESHOLD_USD))
    )
    po_tol_pct = (
        po_variance_tolerance_percent
        if po_variance_tolerance_percent is not None
        else Decimal(str(settings.PO_VARIANCE_TOLERANCE_PERCENT))
    )

    can_upload = bool(UPLOAD_ROLES.intersection(roles))
    can_edit = bool(EDIT_ROLES.intersection(roles)) and (
        invoice.status not in NON_EDITABLE_INVOICE_STATUSES
    )
    show_bulk_mgr = bool(BULK_MANAGER_APPROVE_ROLES.intersection(roles))
    can_decide_rev = bool(EDIT_ROLES.intersection(roles)) and (
        invoice.status in DECIDABLE_REVISION_STATUSES
    )
    can_view_audit = bool(roles)

    show_approve = False
    approve_label: str | None = None
    hidden_reason: str | None = None

    if "finance_manager" in roles:
        if invoice.status in MANAGER_APPROVABLE_INVOICE_STATUSES:
            show_approve = True
            approve_label = "Approve (Finance Manager)"
        else:
            hidden_reason = f"Invoice status '{invoice.status}' is not eligible for approval."
    elif "ap_clerk" in roles:
        if (
            not threshold_usd.is_finite()
            or threshold_usd < Decimal("0")
            or not po_tol_pct.is_finite()
            or po_tol_pct < Decimal("0")
        ):
            hidden_reason = "Invalid approval threshold configuration; clerk approval disabled."
        elif po_amount is not None and (not po_amount.is_finite() or po_amount < Decimal("0")):
            hidden_reason = "Invalid PO amount; Finance Manager verification required."
        else:
            # SEC-207: For USD invoices, use conservative max(total_amount, total_amount_usd)
            # so a stale lower total_amount_usd can never expose clerk approval on a >$10k invoice.
            if invoice.currency.upper() == "USD":
                effective_usd: Decimal | None = (
                    max(invoice.total_amount, invoice.total_amount_usd)
                    if invoice.total_amount_usd is not None
                    else invoice.total_amount
                )
            else:
                effective_usd = invoice.total_amount_usd

            if invoice.total_amount < Decimal("0"):
                hidden_reason = (
                    "Credit notes (negative balance) require Finance Manager / netting workflow."
                )
            elif invoice.status != "VALIDATED":
                hidden_reason = (
                    f"Requires Finance Manager approval or re-validation "
                    f"(current status: {invoice.status})."
                )
            elif invoice.confidence_macro_avg < CLERK_APPROVAL_CONFIDENCE_FLOOR:
                hidden_reason = "Confidence is below 90%; clerk one-click approval is disabled."
            elif effective_usd is None or not effective_usd.is_finite():
                hidden_reason = "Non-USD invoice lacks FX-converted USD total; Finance Manager approval required."
            elif effective_usd > threshold_usd:
                hidden_reason = (
                    f"Requires Finance Manager approval (total ${effective_usd:,.2f} USD exceeds "
                    f"${threshold_usd:,.2f} USD clerk threshold)."
                )
            elif _exceeds_po_variance(invoice.total_amount, po_amount, po_tol_pct):
                hidden_reason = (
                    f"Requires Finance Manager approval (PO variance exceeds "
                    f"{po_tol_pct:.1f}% tolerance)."
                )
            else:
                show_approve = True
                approve_label = "Approve (One-Click)"
    else:
        hidden_reason = "Approval requires an authenticated AP Clerk or Finance Manager role."

    return InvoiceUICapabilities(
        can_upload=can_upload,
        can_edit_and_revalidate=can_edit,
        show_approve_button=show_approve,
        approve_button_label=approve_label,
        approve_hidden_reason=hidden_reason,
        show_bulk_manager_approve=show_bulk_mgr,
        can_decide_revision=can_decide_rev,
        can_view_audit=can_view_audit,
    )


__all__ = [
    "APPROVE_ROLES",
    "BULK_MANAGER_APPROVE_ROLES",
    "CANONICAL_ROLES",
    "CLERK_APPROVAL_CONFIDENCE_FLOOR",
    "CONFIDENCE_AMBER_HEX",
    "CONFIDENCE_GREEN_HEX",
    "CONFIDENCE_RED_HEX",
    "CONFIDENCE_YELLOW_HEX",
    "ConfidenceCue",
    "DECIDABLE_REVISION_STATUSES",
    "EDIT_ROLES",
    "InvoiceUICapabilities",
    "MANAGER_APPROVABLE_INVOICE_STATUSES",
    "NON_EDITABLE_INVOICE_STATUSES",
    "REVIEW_CONFIDENCE_FLOOR",
    "UPLOAD_ROLES",
    "build_confidence_color_map",
    "classify_confidence_cue",
    "evaluate_invoice_ui_capabilities",
    "get_role_badge",
    "normalize_canonical_roles",
]
