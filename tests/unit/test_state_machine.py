"""
Unit & SQLite Integration tests for P8-2 · Invoice State Machine (src/validation/state_machine.py).

Tests: FR-04, FR-09, FR-10, FR-11, FR-12, FR-13
Requirements: CLAUDE.md §2, §4.2, §5, §7.2, §7.4, §8, §16.1, LLD §4, PRD Journeys 1–7.
Strict offline isolation: zero external network or Azure calls (in-memory SQLite + pure FSM).
"""

import asyncio
import logging
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from src.database.models import Base, Invoice, Vendor
from src.database.repositories import InvoiceRepository, VendorRepository, compute_composite_hash
from src.database.session import create_db_engine, create_session_factory
from src.validation.state_machine import (
    APPROVAL_STATES,
    CORE_WORKFLOW_STATES,
    LEGAL_TRANSITIONS,
    TERMINAL_STATES,
    ActorRole,
    ConcurrentStateTransitionError,
    IllegalStateTransitionError,
    InvalidInvoiceStatusError,
    InvoiceNotFoundError,
    InvoiceStateMachine,
    InvoiceStatus,
    StateTransitionResult,
    UnauthorizedStateTransitionError,
    get_allowed_transitions,
    is_legal_transition,
    parse_invoice_status,
    validate_transition,
)


async def _setup_db_with_invoice(
    *,
    status: str = "UPLOADED",
    total_amount: Decimal = Decimal("1200.00"),
    invoice_number: str = "INV-FSM-001",
) -> tuple[Any, Any, str]:
    """Create isolated in-memory SQLite DB seeded with one vendor and one invoice."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)

    async with session_factory() as session:
        await VendorRepository(session).create(
            Vendor(
                vendor_tax_id="US-99-1234567",
                vendor_id="VEND-FSM-1",
                vendor_name="Acme FSM Test Inc.",
                country_code="US",
                date_format_locale="MM/DD/YYYY",
                default_currency="USD",
                standard_tax_rate=Decimal("0.0825"),
            )
        )
        inv = await InvoiceRepository(session).create(
            Invoice(
                vendor_tax_id="US-99-1234567",
                vendor_name="Acme FSM Test Inc.",
                invoice_number=invoice_number,
                subtotal=total_amount,
                total_tax_amount=Decimal("0.00"),
                total_amount=total_amount,
                currency="USD",
                status=status,
                composite_hash=compute_composite_hash(
                    "US-99-1234567", invoice_number, total_amount
                ),
            )
        )
        return engine, session_factory, inv.invoice_id


# ---------------------------------------------------------------------------
# 1. Complete Status Enum, Transition Graph Integrity & Terminal States
# ---------------------------------------------------------------------------


def test_fsm_status_registry_and_graph_structural_invariants() -> None:
    """Tests: LLD §4 & CLAUDE.md §5 — Complete status enum, immutable graph, zero self-loops."""
    # All CLAUDE.md §5 statuses + LLD §3.1 partial-index statuses exist
    expected_statuses = {
        "UPLOADED",
        "EXTRACTING",
        "VALIDATED",
        "REQUIRES_REVIEW",
        "REQUIRES_APPROVAL",
        "REJECTED_TAX_MISMATCH",
        "REVALIDATING",
        "DUPLICATE_INVOICE",
        "FLAGGED_POTENTIAL_REVISION",
        "CREDIT_NOTE",
        "APPROVED_CLERK",
        "REQUIRES_MANAGER_APPROVAL",
        "APPROVED_MANAGER",
        "REJECTED",
        "STAGED_FOR_EXPORT",
        "REJECTED_DUPLICATE",
        "VOID",
    }
    assert {s.value for s in InvoiceStatus} == expected_statuses
    assert set(LEGAL_TRANSITIONS.keys()) == set(InvoiceStatus)

    # Core 10 processing/approval states subset verified
    assert len(CORE_WORKFLOW_STATES) == 10
    assert CORE_WORKFLOW_STATES.issubset(set(InvoiceStatus))

    # Zero self-transitions anywhere (no-op ban: CLAUDE.md §16.1)
    for src_state, targets in LEGAL_TRANSITIONS.items():
        assert src_state not in targets, f"Disallowed self-transition on {src_state}"

    # Terminal states have zero outgoing transitions
    assert TERMINAL_STATES == frozenset(
        {
            InvoiceStatus.STAGED_FOR_EXPORT,
            InvoiceStatus.REJECTED,
            InvoiceStatus.REJECTED_DUPLICATE,
            InvoiceStatus.VOID,
        }
    )
    for term in TERMINAL_STATES:
        assert LEGAL_TRANSITIONS[term] == frozenset()
        assert get_allowed_transitions(term) == frozenset()

    # Approval states set matches CLAUDE.md §16.1
    assert APPROVAL_STATES == frozenset(
        {InvoiceStatus.APPROVED_CLERK, InvoiceStatus.APPROVED_MANAGER}
    )

    # LEGAL_TRANSITIONS mapping is read-only (MappingProxyType prevents runtime graph tampering)
    with pytest.raises(TypeError):
        LEGAL_TRANSITIONS[InvoiceStatus.UPLOADED] = frozenset({InvoiceStatus.STAGED_FOR_EXPORT})  # type: ignore[index]


# ---------------------------------------------------------------------------
# 2. All Legal Transitions (LLD §4, PRD Journeys 1–7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "target", "actor_role"),
    [
        # Intake & pre-extraction duplicate/revision/credit-note routing
        ("UPLOADED", "EXTRACTING", ActorRole.SYSTEM),
        ("UPLOADED", "DUPLICATE_INVOICE", ActorRole.SYSTEM),
        ("UPLOADED", "FLAGGED_POTENTIAL_REVISION", ActorRole.SYSTEM),
        ("UPLOADED", "CREDIT_NOTE", ActorRole.SYSTEM),
        # Extraction -> validation / confidence / exception outcomes
        ("EXTRACTING", "VALIDATED", ActorRole.SYSTEM),
        ("EXTRACTING", "REQUIRES_REVIEW", ActorRole.SYSTEM),
        ("EXTRACTING", "REQUIRES_APPROVAL", ActorRole.SYSTEM),
        ("EXTRACTING", "REJECTED_TAX_MISMATCH", ActorRole.SYSTEM),
        ("EXTRACTING", "DUPLICATE_INVOICE", ActorRole.SYSTEM),
        ("EXTRACTING", "FLAGGED_POTENTIAL_REVISION", ActorRole.SYSTEM),
        ("EXTRACTING", "CREDIT_NOTE", ActorRole.SYSTEM),
        ("EXTRACTING", "REQUIRES_MANAGER_APPROVAL", ActorRole.SYSTEM),
        # Medium-confidence review (PRD Journey 3)
        ("REQUIRES_REVIEW", "VALIDATED", ActorRole.AP_CLERK),
        ("REQUIRES_REVIEW", "REVALIDATING", ActorRole.AP_CLERK),
        ("REQUIRES_REVIEW", "REQUIRES_APPROVAL", ActorRole.AP_CLERK),
        ("REQUIRES_REVIEW", "REJECTED", ActorRole.AP_CLERK),
        # Exception re-validation entry (LLD §4, PRD Journeys 4–5)
        ("REQUIRES_APPROVAL", "REVALIDATING", ActorRole.AP_CLERK),
        ("REQUIRES_APPROVAL", "REQUIRES_MANAGER_APPROVAL", ActorRole.FINANCE_MANAGER),
        ("REQUIRES_APPROVAL", "REJECTED", ActorRole.AP_CLERK),
        ("REJECTED_TAX_MISMATCH", "REVALIDATING", ActorRole.AP_CLERK),
        ("REJECTED_TAX_MISMATCH", "REJECTED", ActorRole.AP_CLERK),
        # Re-validation outcomes (LLD §4, CLAUDE.md §7.4)
        ("REVALIDATING", "VALIDATED", ActorRole.AP_CLERK),
        ("REVALIDATING", "REQUIRES_APPROVAL", ActorRole.AP_CLERK),
        ("REVALIDATING", "CREDIT_NOTE", ActorRole.AP_CLERK),
        ("REVALIDATING", "REQUIRES_MANAGER_APPROVAL", ActorRole.AP_CLERK),
        # Duplicate, revision, and credit note resolution (PRD Journey 6)
        ("DUPLICATE_INVOICE", "REJECTED_DUPLICATE", ActorRole.AP_CLERK),
        ("DUPLICATE_INVOICE", "REJECTED", ActorRole.AP_CLERK),
        ("FLAGGED_POTENTIAL_REVISION", "REVALIDATING", ActorRole.AP_CLERK),
        ("FLAGGED_POTENTIAL_REVISION", "REJECTED_DUPLICATE", ActorRole.AP_CLERK),
        ("FLAGGED_POTENTIAL_REVISION", "REJECTED", ActorRole.AP_CLERK),
        ("CREDIT_NOTE", "REQUIRES_MANAGER_APPROVAL", ActorRole.AP_CLERK),
        ("CREDIT_NOTE", "REJECTED", ActorRole.FINANCE_MANAGER),
        ("CREDIT_NOTE", "VOID", ActorRole.FINANCE_MANAGER),
        # Approval & export staging (LLD §4, PRD Journeys 2 & 7)
        ("VALIDATED", "APPROVED_CLERK", ActorRole.AP_CLERK),
        ("VALIDATED", "APPROVED_CLERK", ActorRole.FINANCE_MANAGER),
        ("VALIDATED", "REQUIRES_MANAGER_APPROVAL", ActorRole.SYSTEM),
        ("VALIDATED", "REVALIDATING", ActorRole.AP_CLERK),
        ("VALIDATED", "REJECTED", ActorRole.AP_CLERK),
        ("REQUIRES_MANAGER_APPROVAL", "APPROVED_MANAGER", ActorRole.FINANCE_MANAGER),
        ("REQUIRES_MANAGER_APPROVAL", "APPROVED_MANAGER", ActorRole.SYSTEM_ADMIN),
        ("REQUIRES_MANAGER_APPROVAL", "REJECTED", ActorRole.FINANCE_MANAGER),
        ("APPROVED_CLERK", "STAGED_FOR_EXPORT", ActorRole.SYSTEM),
        ("APPROVED_CLERK", "VOID", ActorRole.FINANCE_MANAGER),
        ("APPROVED_MANAGER", "STAGED_FOR_EXPORT", ActorRole.SYSTEM),
        ("APPROVED_MANAGER", "VOID", ActorRole.FINANCE_MANAGER),
    ],
)
def test_all_legal_transitions_succeed(
    current: str,
    target: str,
    actor_role: ActorRole,
) -> None:
    """Tests: FR-04..FR-13 & LLD §4 — Every documented lifecycle edge is accepted with valid role."""
    assert is_legal_transition(current, target) is True
    src_enum, dst_enum = validate_transition(current, target, actor_role=actor_role)
    assert src_enum.value == current
    assert dst_enum.value == target


# ---------------------------------------------------------------------------
# 3. Illegal Transitions & Terminal State Protection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "target"),
    [
        # Skipping extraction / validation / approval
        ("UPLOADED", "VALIDATED"),
        ("UPLOADED", "APPROVED_CLERK"),
        ("UPLOADED", "APPROVED_MANAGER"),
        ("UPLOADED", "STAGED_FOR_EXPORT"),
        ("EXTRACTING", "APPROVED_CLERK"),
        ("EXTRACTING", "APPROVED_MANAGER"),
        ("EXTRACTING", "STAGED_FOR_EXPORT"),
        ("EXTRACTING", "UPLOADED"),
        ("VALIDATED", "STAGED_FOR_EXPORT"),
        ("VALIDATED", "APPROVED_MANAGER"),
        # Bypassing REVALIDATING from exception states
        ("REQUIRES_APPROVAL", "VALIDATED"),
        ("REQUIRES_APPROVAL", "APPROVED_CLERK"),
        ("REJECTED_TAX_MISMATCH", "VALIDATED"),
        ("REJECTED_TAX_MISMATCH", "APPROVED_CLERK"),
        # Duplicate & credit note export/approval bypasses
        ("DUPLICATE_INVOICE", "VALIDATED"),
        ("DUPLICATE_INVOICE", "APPROVED_CLERK"),
        ("DUPLICATE_INVOICE", "STAGED_FOR_EXPORT"),
        ("CREDIT_NOTE", "VALIDATED"),
        ("CREDIT_NOTE", "APPROVED_CLERK"),
        ("CREDIT_NOTE", "STAGED_FOR_EXPORT"),
        ("FLAGGED_POTENTIAL_REVISION", "APPROVED_CLERK"),
        ("FLAGGED_POTENTIAL_REVISION", "STAGED_FOR_EXPORT"),
        # Downgrading manager escalation back to clerk
        ("REQUIRES_MANAGER_APPROVAL", "VALIDATED"),
        ("REQUIRES_MANAGER_APPROVAL", "APPROVED_CLERK"),
        ("REQUIRES_MANAGER_APPROVAL", "STAGED_FOR_EXPORT"),
        # Self-transitions (no-op ban)
        ("UPLOADED", "UPLOADED"),
        ("EXTRACTING", "EXTRACTING"),
        ("VALIDATED", "VALIDATED"),
        ("APPROVED_CLERK", "APPROVED_CLERK"),
        # Terminal resurrection attacks
        ("STAGED_FOR_EXPORT", "UPLOADED"),
        ("STAGED_FOR_EXPORT", "VALIDATED"),
        ("STAGED_FOR_EXPORT", "VOID"),
        ("REJECTED", "VALIDATED"),
        ("REJECTED", "REVALIDATING"),
        ("REJECTED_DUPLICATE", "UPLOADED"),
        ("VOID", "VALIDATED"),
    ],
)
def test_illegal_transitions_raise_illegal_state_transition_error(
    current: str,
    target: str,
) -> None:
    """Tests: LLD §4 & CLAUDE.md §16.1 — Illegal shortcuts, downgrades, self-loops, and terminal exits fail closed."""
    assert is_legal_transition(current, target) is False
    with pytest.raises(IllegalStateTransitionError) as exc_info:
        validate_transition(current, target, actor_role=ActorRole.SYSTEM_ADMIN)
    assert exc_info.value.current_status == InvoiceStatus(current)
    assert exc_info.value.target_status == InvoiceStatus(target)


@pytest.mark.parametrize(
    "bad_status",
    [
        "",
        "   ",
        "validated",
        "UNKNOWN_STATE",
        "APPROVED",
        "VALIDATED; DROP TABLE invoices",
        123,
        None,
    ],
)
def test_invalid_status_strings_fail_closed(bad_status: Any) -> None:
    """Tests: CWE-20 — Unknown, lowercase, non-string, or SQLi status payloads raise InvalidInvoiceStatusError."""
    with pytest.raises(InvalidInvoiceStatusError):
        parse_invoice_status(bad_status)


# ---------------------------------------------------------------------------
# 4. RBAC & Actor Authorization Enforcement (CLAUDE.md §2, §8, §16.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "target", "forbidden_role"),
    [
        # System/worker/AI may NEVER self-approve (CLAUDE.md §16.1)
        ("VALIDATED", "APPROVED_CLERK", ActorRole.SYSTEM),
        ("REQUIRES_MANAGER_APPROVAL", "APPROVED_MANAGER", ActorRole.SYSTEM),
        ("REQUIRES_MANAGER_APPROVAL", "REJECTED", ActorRole.SYSTEM),
        # AP Clerk may NEVER approve or reject manager-escalated invoices (FR-13 / CLAUDE.md §16.1)
        ("REQUIRES_MANAGER_APPROVAL", "APPROVED_MANAGER", ActorRole.AP_CLERK),
        ("REQUIRES_MANAGER_APPROVAL", "REJECTED", ActorRole.AP_CLERK),
        # AP Clerk may not void an already-approved invoice (requires manager/admin)
        ("APPROVED_CLERK", "VOID", ActorRole.AP_CLERK),
        ("APPROVED_MANAGER", "VOID", ActorRole.AP_CLERK),
    ],
)
def test_unauthorized_actor_role_blocked_with_permission_error(
    current: str,
    target: str,
    forbidden_role: ActorRole,
) -> None:
    """Tests: FR-13 & CLAUDE.md §16.1 — RBAC guard blocks self-approval and clerk privilege escalation."""
    # Transition itself is structurally legal, yet actor role is unauthorized -> PermissionError
    assert is_legal_transition(current, target) is True
    with pytest.raises(UnauthorizedStateTransitionError):
        validate_transition(current, target, actor_role=forbidden_role)


# ---------------------------------------------------------------------------
# 5. Repository-Backed SQLite Persistence & End-to-End Lifecycle (P8-2 Core)
# ---------------------------------------------------------------------------


def test_state_machine_persists_full_stp_and_revalidation_lifecycles_via_repository() -> None:
    """Tests: P8-2 — Status written via InvoiceRepository across full SQLite lifecycles."""

    async def _run() -> None:
        engine, session_factory, inv_id = await _setup_db_with_invoice(status="UPLOADED")
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                fsm = InvoiceStateMachine(repository=repo)

                # 1. UPLOADED -> EXTRACTING -> REJECTED_TAX_MISMATCH -> REVALIDATING -> VALIDATED -> APPROVED_CLERK -> STAGED_FOR_EXPORT
                steps = [
                    (
                        InvoiceStatus.EXTRACTING,
                        "system-worker",
                        ActorRole.SYSTEM,
                        "Worker picked job",
                    ),
                    (
                        InvoiceStatus.REJECTED_TAX_MISMATCH,
                        "system-worker",
                        ActorRole.SYSTEM,
                        "Tax mismatch",
                    ),
                    (
                        InvoiceStatus.REVALIDATING,
                        "sarah.clerk@company.com",
                        ActorRole.AP_CLERK,
                        "Clerk edited tax",
                    ),
                    (
                        InvoiceStatus.VALIDATED,
                        "sarah.clerk@company.com",
                        ActorRole.AP_CLERK,
                        "All rules passed",
                    ),
                    (
                        InvoiceStatus.APPROVED_CLERK,
                        "sarah.clerk@company.com",
                        ActorRole.AP_CLERK,
                        "One-click approve",
                    ),
                    (
                        InvoiceStatus.STAGED_FOR_EXPORT,
                        "system-exporter",
                        ActorRole.SYSTEM,
                        "Staged to SQL",
                    ),
                ]
                prev = InvoiceStatus.UPLOADED
                for target, actor_id, role, reason in steps:
                    res = await fsm.transition(
                        inv_id,
                        target,
                        actor_id=actor_id,
                        actor_role=role,
                        reason=reason,
                    )
                    assert isinstance(res, StateTransitionResult)
                    assert res.invoice_id == inv_id
                    assert res.previous_status == prev
                    assert res.new_status == target
                    assert res.actor_id == actor_id
                    assert res.actor_role == role

                    persisted = await repo.get_by_id(inv_id, include_relations=False)
                    assert persisted is not None
                    assert persisted.status == target.value
                    prev = target

                # Terminal state rejects any further transition and leaves DB status untouched
                with pytest.raises(IllegalStateTransitionError):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.VOID,
                        actor_id="dave.admin@company.com",
                        actor_role=ActorRole.SYSTEM_ADMIN,
                    )
                final_inv = await repo.get_by_id(inv_id, include_relations=False)
                assert final_inv is not None
                assert final_inv.status == "STAGED_FOR_EXPORT"

                # Missing invoice raises InvoiceNotFoundError
                with pytest.raises(InvoiceNotFoundError):
                    await fsm.transition(
                        "00000000-0000-0000-0000-000000000000",
                        InvoiceStatus.EXTRACTING,
                        actor_id="system-worker",
                        actor_role=ActorRole.SYSTEM,
                    )
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_state_machine_atomic_cas_blocks_concurrent_toctou_race() -> None:
    """Tests: CWE-362 — Atomic compare-and-update blocks stale/concurrent state transitions."""

    async def _run() -> None:
        engine, session_factory, inv_id = await _setup_db_with_invoice(status="VALIDATED")
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                fsm = InvoiceStateMachine(repository=repo)

                # Explicit expected_status mismatch fails before/at CAS without mutating DB
                with pytest.raises(ConcurrentStateTransitionError):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.APPROVED_CLERK,
                        actor_id="sarah.clerk@company.com",
                        actor_role=ActorRole.AP_CLERK,
                        expected_status=InvoiceStatus.EXTRACTING,
                    )

                # Direct repository CAS returns None when DB status does not match expected_status
                missed = await repo.compare_and_update_status(
                    inv_id,
                    expected_status="EXTRACTING",
                    new_status="APPROVED_CLERK",
                )
                assert missed is None

                # Matching expected_status succeeds atomically
                updated = await repo.compare_and_update_status(
                    inv_id,
                    expected_status="VALIDATED",
                    new_status="APPROVED_CLERK",
                )
                assert updated is not None
                assert updated.status == "APPROVED_CLERK"

                # Second stale transition from VALIDATED now fails atomically
                second = await repo.compare_and_update_status(
                    inv_id,
                    expected_status="VALIDATED",
                    new_status="REQUIRES_MANAGER_APPROVAL",
                )
                assert second is None
        finally:
            await engine.dispose()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Immutability, Input Hygiene, Zero PII Logs & Layering Invariants
# ---------------------------------------------------------------------------


def test_state_machine_immutability_and_zero_pii_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tests: CWE-117, CWE-532, CWE-915 — Frozen results, control-char rejection, and clean logs."""

    async def _run() -> None:
        engine, session_factory, inv_id = await _setup_db_with_invoice(status="UPLOADED")
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                fsm = InvoiceStateMachine(repository=repo)

                # Disallowed control chars / empty actor_id / oversized reason rejected
                with pytest.raises(ValueError, match="actor_id"):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.EXTRACTING,
                        actor_id="bad\nactor",
                        actor_role=ActorRole.SYSTEM,
                    )
                with pytest.raises(ValueError, match="reason"):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.EXTRACTING,
                        actor_id="system-worker",
                        actor_role=ActorRole.SYSTEM,
                        reason="x" * 1001,
                    )

                with caplog.at_level(logging.INFO, logger="ap.validation.state_machine"):
                    res = await fsm.transition(
                        inv_id,
                        InvoiceStatus.EXTRACTING,
                        actor_id="system-worker",
                        actor_role=ActorRole.SYSTEM,
                        reason="Picked by worker",
                    )

                # Frozen result cannot be mutated
                with pytest.raises(ValidationError):
                    res.new_status = InvoiceStatus.APPROVED_CLERK  # type: ignore[misc]

                # Logs contain no vendor tax ID or vendor name
                log_text = " ".join(r.getMessage() for r in caplog.records)
                assert "US-99-1234567" not in log_text
                assert "Acme FSM Test Inc." not in log_text
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_state_machine_layering_invariant_zero_llm_or_sqlalchemy_imports() -> None:
    """Tests: CLAUDE.md §4.2 & §7.2 — src/validation/state_machine.py never imports LLMs or SQLAlchemy."""
    src = Path("src/validation/state_machine.py").read_text(encoding="utf-8")
    for forbidden in (
        "import openai",
        "from openai",
        "model_gateway",
        "extract_engine",
        "sqlalchemy",
        "AsyncSession",
    ):
        assert forbidden not in src, f"Layering violation: found forbidden token '{forbidden}'"


# ---------------------------------------------------------------------------
# 7. Penetration Tests for Security Audit Findings (SEC-165 .. SEC-168)
# ---------------------------------------------------------------------------


def test_pentest_sec165_high_value_and_unconverted_fx_clerk_approval_blocked() -> None:
    """Tests: SEC-165 (CWE-863, FR-13, CLAUDE.md §16.1) — Clerk cannot approve >$10k or unconverted FX invoices."""

    async def _run() -> None:
        # 1. USD invoice > $10,000 blocked for ap_clerk
        engine, session_factory, inv_id = await _setup_db_with_invoice(
            status="VALIDATED",
            total_amount=Decimal("15000.00"),
            invoice_number="INV-HIGH-001",
        )
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                fsm = InvoiceStateMachine(repository=repo)

                with pytest.raises(
                    UnauthorizedStateTransitionError, match="HIGH_VALUE_THRESHOLD_USD"
                ):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.APPROVED_CLERK,
                        actor_id="sarah.clerk@company.com",
                        actor_role=ActorRole.AP_CLERK,
                    )

                # DB status remains VALIDATED (untouched)
                unchanged = await repo.get_by_id(inv_id, include_relations=False)
                assert unchanged is not None and unchanged.status == "VALIDATED"

                # Must escalate to REQUIRES_MANAGER_APPROVAL -> APPROVED_MANAGER
                await fsm.transition(
                    inv_id,
                    InvoiceStatus.REQUIRES_MANAGER_APPROVAL,
                    actor_id="system-worker",
                    actor_role=ActorRole.SYSTEM,
                )
                mgr_res = await fsm.transition(
                    inv_id,
                    InvoiceStatus.APPROVED_MANAGER,
                    actor_id="michael.manager@company.com",
                    actor_role=ActorRole.FINANCE_MANAGER,
                )
                assert mgr_res.new_status == InvoiceStatus.APPROVED_MANAGER
        finally:
            await engine.dispose()

        # 2. Non-USD invoice (9,000 GBP ~ $11,400 USD) without total_amount_usd fails closed for ap_clerk
        engine2, session_factory2, inv_id2 = await _setup_db_with_invoice(
            status="VALIDATED",
            total_amount=Decimal("9000.00"),
            invoice_number="INV-FX-001",
        )
        try:
            async with session_factory2() as session:
                repo = InvoiceRepository(session)
                await repo.update_fields(inv_id2, currency="GBP", total_amount_usd=None)
                fsm = InvoiceStateMachine(repository=repo)

                with pytest.raises(UnauthorizedStateTransitionError, match="total_amount_usd"):
                    await fsm.transition(
                        inv_id2,
                        InvoiceStatus.APPROVED_CLERK,
                        actor_id="sarah.clerk@company.com",
                        actor_role=ActorRole.AP_CLERK,
                    )

                # Once FX converted to $11,400 USD -> still blocked for ap_clerk
                await repo.update_fields(inv_id2, total_amount_usd=Decimal("11400.00"))
                with pytest.raises(
                    UnauthorizedStateTransitionError, match="HIGH_VALUE_THRESHOLD_USD"
                ):
                    await fsm.transition(
                        inv_id2,
                        InvoiceStatus.APPROVED_CLERK,
                        actor_id="sarah.clerk@company.com",
                        actor_role=ActorRole.AP_CLERK,
                    )
        finally:
            await engine2.dispose()

    asyncio.run(_run())


def test_pentest_sec166_negative_balance_credit_note_blocked_from_regular_states() -> None:
    """Tests: SEC-166 (CWE-840, CLAUDE.md §16.1) — Negative-balance invoices cannot become VALIDATED or APPROVED_CLERK."""

    async def _run() -> None:
        engine, session_factory, inv_id = await _setup_db_with_invoice(
            status="EXTRACTING",
            total_amount=Decimal("-2450.00"),
            invoice_number="CN-2026-001",
        )
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)
                fsm = InvoiceStateMachine(repository=repo)

                with pytest.raises(IllegalStateTransitionError):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.VALIDATED,
                        actor_id="system-worker",
                        actor_role=ActorRole.SYSTEM,
                    )
                with pytest.raises(IllegalStateTransitionError):
                    await fsm.transition(
                        inv_id,
                        InvoiceStatus.REQUIRES_REVIEW,
                        actor_id="system-worker",
                        actor_role=ActorRole.SYSTEM,
                    )

                # Proper routing to CREDIT_NOTE succeeds
                res = await fsm.transition(
                    inv_id,
                    InvoiceStatus.CREDIT_NOTE,
                    actor_id="system-worker",
                    actor_role=ActorRole.SYSTEM,
                )
                assert res.new_status == InvoiceStatus.CREDIT_NOTE
        finally:
            await engine.dispose()

    asyncio.run(_run())


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("REQUIRES_REVIEW", "VALIDATED"),
        ("REQUIRES_APPROVAL", "REVALIDATING"),
        ("REJECTED_TAX_MISMATCH", "REVALIDATING"),
        ("DUPLICATE_INVOICE", "REJECTED_DUPLICATE"),
        ("FLAGGED_POTENTIAL_REVISION", "REVALIDATING"),
        ("VALIDATED", "REJECTED"),
        ("REQUIRES_REVIEW", "REJECTED"),
        ("REQUIRES_APPROVAL", "REJECTED"),
        ("APPROVED_CLERK", "VOID"),
    ],
)
def test_pentest_sec167_system_actor_blocked_from_human_only_transitions(
    current: str,
    target: str,
) -> None:
    """Tests: SEC-167 (CWE-863) — Automated system actor cannot bypass human review, revalidation, or rejection."""
    assert is_legal_transition(current, target) is True
    with pytest.raises(UnauthorizedStateTransitionError):
        validate_transition(current, target, actor_role=ActorRole.SYSTEM)


def test_pentest_sec168_repository_cas_rejects_unknown_and_noop_statuses() -> None:
    """Tests: SEC-168 (CWE-20) — InvoiceRepository.compare_and_update_status enforces canonical status allowlist."""

    async def _run() -> None:
        engine, session_factory, inv_id = await _setup_db_with_invoice(status="VALIDATED")
        try:
            async with session_factory() as session:
                repo = InvoiceRepository(session)

                with pytest.raises(ValueError, match="Unknown new_status"):
                    await repo.compare_and_update_status(
                        inv_id,
                        expected_status="VALIDATED",
                        new_status="HACKED_STATUS",
                    )
                with pytest.raises(ValueError, match="Unknown expected_status"):
                    await repo.compare_and_update_status(
                        inv_id,
                        expected_status="BOGUS",
                        new_status="APPROVED_CLERK",
                    )
                with pytest.raises(ValueError, match="self-transitions"):
                    await repo.compare_and_update_status(
                        inv_id,
                        expected_status="VALIDATED",
                        new_status="VALIDATED",
                    )
        finally:
            await engine.dispose()

    asyncio.run(_run())
