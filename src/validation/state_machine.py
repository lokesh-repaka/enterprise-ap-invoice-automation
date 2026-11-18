"""
Deterministic Invoice Lifecycle Finite State Machine (P8-2).

Covers CLAUDE.md §2, §4.2, §5, §7.2, §7.4, §8, §16.1, LLD §3.1, §4, and PRD Journeys 1–7:
- Canonical ``InvoiceStatus`` enum spanning the 10 core processing/approval states
  (``CORE_WORKFLOW_STATES``) plus all exception and terminal resolution states
  (``DUPLICATE_INVOICE``, ``FLAGGED_POTENTIAL_REVISION``, ``CREDIT_NOTE``,
  ``REJECTED_TAX_MISMATCH``, ``REJECTED``, ``REJECTED_DUPLICATE``, ``VOID``).
- Deeply immutable ``LEGAL_TRANSITIONS`` transition graph (``MappingProxyType`` of
  ``frozenset``s) enforcing LLD §4 strictly: zero illegal shortcuts, zero self-transitions
  (no-op ban), and zero exits from terminal states.
- Role-based transition authorization (CLAUDE.md §2, §8, §16.1):
  - ``APPROVED_CLERK`` requires an authenticated human role (never ``system``/AI).
  - ``APPROVED_MANAGER`` and manager-queue rejection require ``finance_manager`` or
    ``system_admin`` (blocks ``ap_clerk`` privilege escalation and worker self-approval).
- Repository-backed ``InvoiceStateMachine`` persisting status transitions strictly through
  ``InvoiceStatusRepositoryProtocol`` (duck-typed for ``InvoiceRepository`` without importing
  SQLAlchemy) with atomic compare-and-swap (CAS) optimistic locking to prevent TOCTOU races
  (CWE-362).

Security & Layering Invariants:
- 100% deterministic Python — NEVER calls LLMs or imports OpenAI, the model gateway,
  extraction engine, or SQLAlchemy (CLAUDE.md §4.2, §7.2).
- Never logs raw vendor tax IDs, vendor names, or invoice financials (CWE-532).
- Validates bounded, control-char-free, bidi-free actor IDs and transition reasons
  (CWE-20 / CWE-117 / CWE-451).
"""

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from src.core.config import get_settings
from src.core.logging import get_logger

logger = get_logger("ap.validation.state_machine")

MAX_INVOICE_ID_CHARS: int = 64
MAX_ACTOR_ID_CHARS: int = 128
MAX_REASON_CHARS: int = 1000

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_OR_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


class InvoiceStatus(StrEnum):
    """
    Complete canonical Invoice lifecycle status enum (CLAUDE.md §5, LLD §3.1 & §4).
    """

    # Core 10 processing & approval workflow states
    UPLOADED = "UPLOADED"
    EXTRACTING = "EXTRACTING"
    VALIDATED = "VALIDATED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    REVALIDATING = "REVALIDATING"
    APPROVED_CLERK = "APPROVED_CLERK"
    REQUIRES_MANAGER_APPROVAL = "REQUIRES_MANAGER_APPROVAL"
    APPROVED_MANAGER = "APPROVED_MANAGER"
    STAGED_FOR_EXPORT = "STAGED_FOR_EXPORT"

    # Exception & resolution states (CLAUDE.md §5, LLD §3.1 & §4)
    REJECTED_TAX_MISMATCH = "REJECTED_TAX_MISMATCH"
    DUPLICATE_INVOICE = "DUPLICATE_INVOICE"
    FLAGGED_POTENTIAL_REVISION = "FLAGGED_POTENTIAL_REVISION"
    CREDIT_NOTE = "CREDIT_NOTE"
    REJECTED = "REJECTED"
    REJECTED_DUPLICATE = "REJECTED_DUPLICATE"
    VOID = "VOID"


class ActorRole(StrEnum):
    """Canonical RBAC roles plus automated background worker identity (CLAUDE.md §2)."""

    AP_CLERK = "ap_clerk"
    FINANCE_MANAGER = "finance_manager"
    SYSTEM_ADMIN = "system_admin"
    SYSTEM = "system"


# The 10 core lifecycle states referenced in TASKS.md P8-2
CORE_WORKFLOW_STATES: frozenset[InvoiceStatus] = frozenset(
    {
        InvoiceStatus.UPLOADED,
        InvoiceStatus.EXTRACTING,
        InvoiceStatus.VALIDATED,
        InvoiceStatus.REQUIRES_REVIEW,
        InvoiceStatus.REQUIRES_APPROVAL,
        InvoiceStatus.REVALIDATING,
        InvoiceStatus.APPROVED_CLERK,
        InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
        InvoiceStatus.APPROVED_MANAGER,
        InvoiceStatus.STAGED_FOR_EXPORT,
    }
)

# Terminal states: zero legal outgoing transitions
TERMINAL_STATES: frozenset[InvoiceStatus] = frozenset(
    {
        InvoiceStatus.STAGED_FOR_EXPORT,
        InvoiceStatus.REJECTED,
        InvoiceStatus.REJECTED_DUPLICATE,
        InvoiceStatus.VOID,
    }
)

# Human-approval states (CLAUDE.md §16.1: NEVER reachable by system/worker/AI actors)
APPROVAL_STATES: frozenset[InvoiceStatus] = frozenset(
    {
        InvoiceStatus.APPROVED_CLERK,
        InvoiceStatus.APPROVED_MANAGER,
    }
)

_HUMAN_ROLES: frozenset[ActorRole] = frozenset(
    {
        ActorRole.AP_CLERK,
        ActorRole.FINANCE_MANAGER,
        ActorRole.SYSTEM_ADMIN,
    }
)

_MANAGER_ROLES: frozenset[ActorRole] = frozenset(
    {
        ActorRole.FINANCE_MANAGER,
        ActorRole.SYSTEM_ADMIN,
    }
)

# Regular-invoice states forbidden for negative-balance credit notes (SEC-166, CLAUDE.md §16.1)
_REGULAR_INVOICE_ONLY_STATES: frozenset[InvoiceStatus] = frozenset(
    {
        InvoiceStatus.VALIDATED,
        InvoiceStatus.REQUIRES_REVIEW,
        InvoiceStatus.APPROVED_CLERK,
    }
)

# Strict automated-worker allowlist (SEC-167): ActorRole.SYSTEM may ONLY execute automated
# pipeline intake/extraction routing, threshold escalation, and post-approval export staging.
_SYSTEM_ALLOWED_TRANSITIONS: Mapping[InvoiceStatus, frozenset[InvoiceStatus]] = MappingProxyType(
    {
        InvoiceStatus.UPLOADED: frozenset(
            {
                InvoiceStatus.EXTRACTING,
                InvoiceStatus.DUPLICATE_INVOICE,
                InvoiceStatus.FLAGGED_POTENTIAL_REVISION,
                InvoiceStatus.CREDIT_NOTE,
            }
        ),
        InvoiceStatus.EXTRACTING: frozenset(
            {
                InvoiceStatus.VALIDATED,
                InvoiceStatus.REQUIRES_REVIEW,
                InvoiceStatus.REQUIRES_APPROVAL,
                InvoiceStatus.REJECTED_TAX_MISMATCH,
                InvoiceStatus.DUPLICATE_INVOICE,
                InvoiceStatus.FLAGGED_POTENTIAL_REVISION,
                InvoiceStatus.CREDIT_NOTE,
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
            }
        ),
        InvoiceStatus.VALIDATED: frozenset({InvoiceStatus.REQUIRES_MANAGER_APPROVAL}),
        InvoiceStatus.APPROVED_CLERK: frozenset({InvoiceStatus.STAGED_FOR_EXPORT}),
        InvoiceStatus.APPROVED_MANAGER: frozenset({InvoiceStatus.STAGED_FOR_EXPORT}),
    }
)

# Strictly legal directed transitions per LLD §4, CLAUDE.md §5/§7.4/§16.1, and PRD Journeys 1–7.
# Wrapped in MappingProxyType so the transition graph cannot be mutated at runtime.
LEGAL_TRANSITIONS: Mapping[InvoiceStatus, frozenset[InvoiceStatus]] = MappingProxyType(
    {
        InvoiceStatus.UPLOADED: frozenset(
            {
                InvoiceStatus.EXTRACTING,
                InvoiceStatus.DUPLICATE_INVOICE,
                InvoiceStatus.FLAGGED_POTENTIAL_REVISION,
                InvoiceStatus.CREDIT_NOTE,
            }
        ),
        InvoiceStatus.EXTRACTING: frozenset(
            {
                InvoiceStatus.VALIDATED,
                InvoiceStatus.REQUIRES_REVIEW,
                InvoiceStatus.REQUIRES_APPROVAL,
                InvoiceStatus.REJECTED_TAX_MISMATCH,
                InvoiceStatus.DUPLICATE_INVOICE,
                InvoiceStatus.FLAGGED_POTENTIAL_REVISION,
                InvoiceStatus.CREDIT_NOTE,
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
            }
        ),
        InvoiceStatus.REQUIRES_REVIEW: frozenset(
            {
                InvoiceStatus.VALIDATED,
                InvoiceStatus.REVALIDATING,
                InvoiceStatus.REQUIRES_APPROVAL,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.REQUIRES_APPROVAL: frozenset(
            {
                InvoiceStatus.REVALIDATING,
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.REJECTED_TAX_MISMATCH: frozenset(
            {
                InvoiceStatus.REVALIDATING,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.REVALIDATING: frozenset(
            {
                InvoiceStatus.VALIDATED,
                InvoiceStatus.REQUIRES_APPROVAL,
                InvoiceStatus.CREDIT_NOTE,
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
            }
        ),
        InvoiceStatus.DUPLICATE_INVOICE: frozenset(
            {
                InvoiceStatus.REJECTED_DUPLICATE,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.FLAGGED_POTENTIAL_REVISION: frozenset(
            {
                InvoiceStatus.REVALIDATING,
                InvoiceStatus.REJECTED_DUPLICATE,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.CREDIT_NOTE: frozenset(
            {
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                InvoiceStatus.REJECTED,
                InvoiceStatus.VOID,
            }
        ),
        InvoiceStatus.VALIDATED: frozenset(
            {
                InvoiceStatus.APPROVED_CLERK,
                InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                InvoiceStatus.REVALIDATING,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.REQUIRES_MANAGER_APPROVAL: frozenset(
            {
                InvoiceStatus.APPROVED_MANAGER,
                InvoiceStatus.REJECTED,
            }
        ),
        InvoiceStatus.APPROVED_CLERK: frozenset(
            {
                InvoiceStatus.STAGED_FOR_EXPORT,
                InvoiceStatus.VOID,
            }
        ),
        InvoiceStatus.APPROVED_MANAGER: frozenset(
            {
                InvoiceStatus.STAGED_FOR_EXPORT,
                InvoiceStatus.VOID,
            }
        ),
        # Terminal states
        InvoiceStatus.STAGED_FOR_EXPORT: frozenset(),
        InvoiceStatus.REJECTED: frozenset(),
        InvoiceStatus.REJECTED_DUPLICATE: frozenset(),
        InvoiceStatus.VOID: frozenset(),
    }
)


# ---------------------------------------------------------------------------
# Typed Domain Exceptions
# ---------------------------------------------------------------------------


class StateMachineError(Exception):
    """Base exception for invoice FSM violations."""


class InvalidInvoiceStatusError(StateMachineError, ValueError):
    """Raised when an unknown or malformed invoice status value is supplied."""


class IllegalStateTransitionError(StateMachineError, ValueError):
    """Raised when a requested status transition is not permitted by the FSM graph."""

    def __init__(
        self,
        current_status: InvoiceStatus,
        target_status: InvoiceStatus,
        allowed_targets: frozenset[InvoiceStatus],
    ) -> None:
        self.current_status = current_status
        self.target_status = target_status
        self.allowed_targets = allowed_targets
        allowed_list = sorted(s.value for s in allowed_targets)
        super().__init__(
            f"Illegal invoice state transition: '{current_status.value}' -> '{target_status.value}'. "
            f"Allowed targets: {allowed_list}"
        )


class UnauthorizedStateTransitionError(StateMachineError, PermissionError):
    """Raised when an actor role lacks authorization for a structurally legal transition (403)."""


class InvoiceNotFoundError(StateMachineError, LookupError):
    """Raised when the target invoice record does not exist in the repository (404)."""


class ConcurrentStateTransitionError(StateMachineError, RuntimeError):
    """Raised when optimistic-locking CAS detects a concurrent status change (409)."""


# ---------------------------------------------------------------------------
# Repository Protocol (Zero SQLAlchemy Import: CLAUDE.md §4.2)
# ---------------------------------------------------------------------------


@runtime_checkable
class InvoiceStatusRecordLike(Protocol):
    """Minimal duck-typed invoice object returned by the repository."""

    invoice_id: str
    status: str


@runtime_checkable
class InvoiceStatusRepositoryProtocol(Protocol):
    """Minimal async repository contract satisfied by ``InvoiceRepository``."""

    async def get_by_id(
        self,
        invoice_id: str,
        include_relations: bool = True,
    ) -> InvoiceStatusRecordLike | None: ...

    async def update_status(
        self,
        invoice_id: str,
        new_status: str,
    ) -> InvoiceStatusRecordLike | None: ...


class StateTransitionResult(BaseModel):
    """Immutable receipt returned after a verified, persisted FSM transition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    invoice_id: str
    previous_status: InvoiceStatus
    new_status: InvoiceStatus
    actor_id: str
    actor_role: ActorRole
    transitioned_at: datetime
    reason: str | None = None


# ---------------------------------------------------------------------------
# Pure Validation Helpers
# ---------------------------------------------------------------------------


def _validate_clean_text(
    raw: Any,
    *,
    field_name: str,
    max_length: int,
    allow_none: bool = False,
) -> str | None:
    """Validate bounded, control-char-free, bidi-free strings (CWE-20 / CWE-117 / CWE-451)."""
    if raw is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} cannot be None")
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    if _CONTROL_CHAR_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed control characters")
    if _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise ValueError(f"{field_name} contains disallowed invisible bidi/zero-width characters")
    cleaned = raw.strip()
    if not cleaned:
        if allow_none:
            return None
        raise ValueError(f"{field_name} cannot be empty")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length} characters")
    return cleaned


def parse_invoice_status(raw: InvoiceStatus | str) -> InvoiceStatus:
    """Strictly parse a canonical ``InvoiceStatus`` (exact uppercase match, fail closed)."""
    if isinstance(raw, InvoiceStatus):
        return raw
    if not isinstance(raw, str):
        raise InvalidInvoiceStatusError(
            f"Invoice status must be a string, got {type(raw).__name__}"
        )
    if _CONTROL_CHAR_RE.search(raw) or _BIDI_OR_ZERO_WIDTH_RE.search(raw):
        raise InvalidInvoiceStatusError(
            "Invoice status contains disallowed control/bidi characters"
        )
    try:
        return InvoiceStatus(raw)
    except ValueError:
        raise InvalidInvoiceStatusError(f"Unknown invoice status: {raw!r}") from None


def parse_actor_role(raw: ActorRole | str) -> ActorRole:
    """Strictly parse an ``ActorRole`` (fail closed on unknown roles)."""
    if isinstance(raw, ActorRole):
        return raw
    if not isinstance(raw, str):
        raise ValueError(f"actor_role must be an ActorRole or string, got {type(raw).__name__}")
    try:
        return ActorRole(raw.strip().lower())
    except ValueError:
        raise ValueError(f"Unknown actor_role: {raw!r}") from None


def get_allowed_transitions(current_status: InvoiceStatus | str) -> frozenset[InvoiceStatus]:
    """Return the immutable set of legal target statuses reachable from ``current_status``."""
    src = parse_invoice_status(current_status)
    return LEGAL_TRANSITIONS[src]


def is_legal_transition(
    current_status: InvoiceStatus | str,
    target_status: InvoiceStatus | str,
) -> bool:
    """Return True iff ``current_status -> target_status`` is a legal edge in the FSM graph."""
    src = parse_invoice_status(current_status)
    dst = parse_invoice_status(target_status)
    return dst in LEGAL_TRANSITIONS[src]


def _authorize_transition(
    src: InvoiceStatus,
    dst: InvoiceStatus,
    role: ActorRole,
) -> None:
    """Enforce CLAUDE.md §2, §8, §16.1 RBAC rules on sensitive workflow transitions."""
    # 0. Strict automated-system allowlist (SEC-167): system/worker/AI may never confirm
    #    human visual reviews, trigger re-validation, reject invoices, void approvals, or approve.
    if role == ActorRole.SYSTEM:
        allowed_for_system = _SYSTEM_ALLOWED_TRANSITIONS.get(src, frozenset())
        if dst not in allowed_for_system:
            raise UnauthorizedStateTransitionError(
                f"Automated role 'system' is not authorized to transition "
                f"'{src.value}' -> '{dst.value}'; authenticated human action is required."
            )
        return

    # 1. Human approval states can NEVER be triggered by non-human actors
    if dst == InvoiceStatus.APPROVED_CLERK and role not in _HUMAN_ROLES:
        raise UnauthorizedStateTransitionError(
            f"Role '{role.value}' is not authorized to transition invoice to APPROVED_CLERK; "
            "authenticated human approval is required (CLAUDE.md §16.1)."
        )

    # 2. Manager approval & manager-queue rejection require finance_manager or system_admin
    if dst == InvoiceStatus.APPROVED_MANAGER and role not in _MANAGER_ROLES:
        raise UnauthorizedStateTransitionError(
            f"Role '{role.value}' is not authorized to transition invoice to APPROVED_MANAGER; "
            "finance_manager or system_admin role is required (FR-13, CLAUDE.md §16.1)."
        )
    if (
        src == InvoiceStatus.REQUIRES_MANAGER_APPROVAL
        and dst == InvoiceStatus.REJECTED
        and role not in _MANAGER_ROLES
    ):
        raise UnauthorizedStateTransitionError(
            f"Role '{role.value}' is not authorized to reject an invoice in REQUIRES_MANAGER_APPROVAL; "
            "finance_manager or system_admin role is required."
        )

    # 3. Voiding an already-approved invoice (revision supersede) requires manager/admin
    if src in APPROVAL_STATES and dst == InvoiceStatus.VOID and role not in _MANAGER_ROLES:
        raise UnauthorizedStateTransitionError(
            f"Role '{role.value}' is not authorized to VOID an already-approved invoice; "
            "finance_manager or system_admin role is required."
        )


def _enforce_invoice_business_guards(
    invoice: InvoiceStatusRecordLike,
    *,
    src: InvoiceStatus,
    dst: InvoiceStatus,
    role: ActorRole,
) -> None:
    """
    Enforce domain invariants on persisted invoice amounts before status mutation
    (SEC-165 high-value clerk cap & SEC-166 negative-balance credit-note guard: CLAUDE.md §16.1).
    """
    raw_total = getattr(invoice, "total_amount", None)
    raw_subtotal = getattr(invoice, "subtotal", None)
    raw_total_usd = getattr(invoice, "total_amount_usd", None)
    raw_currency = getattr(invoice, "currency", None)

    total_dec = Decimal(str(raw_total)) if raw_total is not None else None
    subtotal_dec = Decimal(str(raw_subtotal)) if raw_subtotal is not None else None
    total_usd_dec = Decimal(str(raw_total_usd)) if raw_total_usd is not None else None

    # SEC-166: Negative-balance documents must NEVER transition into regular-invoice states
    if dst in _REGULAR_INVOICE_ONLY_STATES and (
        (total_dec is not None and total_dec < Decimal("0"))
        or (subtotal_dec is not None and subtotal_dec < Decimal("0"))
    ):
        raise IllegalStateTransitionError(src, dst, frozenset({InvoiceStatus.CREDIT_NOTE}))

    # SEC-165: ap_clerk cannot approve invoices > HIGH_VALUE_THRESHOLD_USD (or unconverted FX)
    if dst == InvoiceStatus.APPROVED_CLERK and role == ActorRole.AP_CLERK:
        threshold = Decimal(str(get_settings().HIGH_VALUE_THRESHOLD_USD))
        if total_usd_dec is not None:
            effective_usd = total_usd_dec
        elif total_dec is not None:
            currency_str = str(raw_currency).strip().upper() if raw_currency is not None else "USD"
            if currency_str != "USD":
                raise UnauthorizedStateTransitionError(
                    f"ap_clerk cannot approve non-USD ({currency_str}) invoice without "
                    "converted total_amount_usd (SEC-165, FR-13)."
                )
            effective_usd = total_dec
        else:
            effective_usd = None

        if effective_usd is not None and abs(effective_usd) > threshold:
            raise UnauthorizedStateTransitionError(
                f"ap_clerk cannot approve invoice exceeding HIGH_VALUE_THRESHOLD_USD "
                f"(${threshold}); finance_manager approval required (FR-13, CLAUDE.md §16.1)."
            )


def validate_transition(
    current_status: InvoiceStatus | str,
    target_status: InvoiceStatus | str,
    *,
    actor_role: ActorRole | str,
) -> tuple[InvoiceStatus, InvoiceStatus]:
    """
    Validate both FSM graph legality and actor RBAC authorization without performing I/O.

    Raises:
        InvalidInvoiceStatusError: Unknown/malformed status.
        IllegalStateTransitionError: Disallowed FSM edge or terminal exit.
        UnauthorizedStateTransitionError: Actor role forbidden for this transition.
    """
    src = parse_invoice_status(current_status)
    dst = parse_invoice_status(target_status)
    role = parse_actor_role(actor_role)

    allowed = LEGAL_TRANSITIONS[src]
    if dst not in allowed:
        raise IllegalStateTransitionError(src, dst, allowed)

    _authorize_transition(src, dst, role)
    return src, dst


# ---------------------------------------------------------------------------
# Repository-Backed Invoice State Machine (P8-2)
# ---------------------------------------------------------------------------


class InvoiceStateMachine:
    """
    Repository-backed deterministic Invoice State Machine (P8-2).

    Reads current invoice state via the injected repository, validates FSM transition legality
    and RBAC authorization, and writes the new status strictly through the repository using
    atomic compare-and-swap (``compare_and_update_status``) when supported.
    """

    def __init__(self, repository: InvoiceStatusRepositoryProtocol) -> None:
        if not isinstance(repository, InvoiceStatusRepositoryProtocol):
            raise ValueError(
                "repository must satisfy InvoiceStatusRepositoryProtocol (get_by_id + update_status)"
            )
        self._repository = repository

    async def transition(
        self,
        invoice_id: str,
        target_status: InvoiceStatus | str,
        *,
        actor_id: str,
        actor_role: ActorRole | str,
        reason: str | None = None,
        expected_status: InvoiceStatus | str | None = None,
    ) -> StateTransitionResult:
        """
        Validate and persist a legal invoice state transition through the repository.

        Args:
            invoice_id: Primary key of the target invoice.
            target_status: Desired next ``InvoiceStatus``.
            actor_id: Authenticated user ID or worker identifier.
            actor_role: Caller's verified ``ActorRole``.
            reason: Optional human-readable transition rationale (<= 1000 chars).
            expected_status: Optional optimistic-locking precondition; raises
                ``ConcurrentStateTransitionError`` if persisted status differs.
        """
        clean_invoice_id = _validate_clean_text(
            invoice_id, field_name="invoice_id", max_length=MAX_INVOICE_ID_CHARS
        )
        assert clean_invoice_id is not None
        clean_actor_id = _validate_clean_text(
            actor_id, field_name="actor_id", max_length=MAX_ACTOR_ID_CHARS
        )
        assert clean_actor_id is not None
        clean_reason = _validate_clean_text(
            reason, field_name="reason", max_length=MAX_REASON_CHARS, allow_none=True
        )
        dst = parse_invoice_status(target_status)
        role = parse_actor_role(actor_role)
        expected_enum = (
            parse_invoice_status(expected_status) if expected_status is not None else None
        )

        # 1. Load current persisted status via repository
        invoice = await self._repository.get_by_id(clean_invoice_id, include_relations=False)
        if invoice is None:
            raise InvoiceNotFoundError(f"Invoice not found: '{clean_invoice_id}'")

        current = parse_invoice_status(invoice.status)
        if expected_enum is not None and current != expected_enum:
            raise ConcurrentStateTransitionError(
                f"Concurrent status conflict for invoice '{clean_invoice_id}': "
                f"expected '{expected_enum.value}', found '{current.value}'"
            )

        # 2. Enforce FSM legality + RBAC authorization + domain invariants before writing
        src, validated_dst = validate_transition(current, dst, actor_role=role)
        _enforce_invoice_business_guards(invoice, src=src, dst=validated_dst, role=role)

        # 3. Persist new status strictly via repository (prefer atomic CAS when supported)
        cas_method = getattr(self._repository, "compare_and_update_status", None)
        if callable(cas_method):
            updated = await cas_method(
                clean_invoice_id,
                expected_status=src.value,
                new_status=validated_dst.value,
            )
            if updated is None:
                raise ConcurrentStateTransitionError(
                    f"Concurrent status conflict during CAS update for invoice '{clean_invoice_id}': "
                    f"status is no longer '{src.value}'"
                )
        else:
            updated = await self._repository.update_status(clean_invoice_id, validated_dst.value)
            if updated is None:
                raise InvoiceNotFoundError(f"Invoice not found during update: '{clean_invoice_id}'")

        result = StateTransitionResult(
            invoice_id=clean_invoice_id,
            previous_status=src,
            new_status=validated_dst,
            actor_id=clean_actor_id,
            actor_role=role,
            transitioned_at=datetime.now(UTC),
            reason=clean_reason,
        )

        logger.info(
            "Invoice state transition persisted",
            extra={
                "invoice_id": result.invoice_id,
                "previous_status": result.previous_status.value,
                "new_status": result.new_status.value,
                "actor_role": result.actor_role.value,
            },
        )
        return result


__all__ = [
    "APPROVAL_STATES",
    "CORE_WORKFLOW_STATES",
    "LEGAL_TRANSITIONS",
    "MAX_ACTOR_ID_CHARS",
    "MAX_INVOICE_ID_CHARS",
    "MAX_REASON_CHARS",
    "TERMINAL_STATES",
    "ActorRole",
    "ConcurrentStateTransitionError",
    "IllegalStateTransitionError",
    "InvalidInvoiceStatusError",
    "InvoiceNotFoundError",
    "InvoiceStateMachine",
    "InvoiceStatus",
    "InvoiceStatusRecordLike",
    "InvoiceStatusRepositoryProtocol",
    "StateMachineError",
    "StateTransitionResult",
    "UnauthorizedStateTransitionError",
    "get_allowed_transitions",
    "is_legal_transition",
    "parse_actor_role",
    "parse_invoice_status",
    "validate_transition",
]
