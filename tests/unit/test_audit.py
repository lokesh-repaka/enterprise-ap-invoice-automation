"""
Unit and Middleware Integration Tests for Immutable AuditLogger and AuditMiddleware (P3-4).

Tests: N3, N6, N8, FR-12, BR-017, BR-031, CLAUDE.md §5, §6, §7.1, §16
"""

import asyncio
import logging
from decimal import Decimal

import fakeredis.aioredis
import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from src.api.audit_middleware import AuditMiddleware, _sanitize_audit_path
from src.api.main import app as main_app
from src.api.middleware import RequestIDMiddleware
from src.api.rate_limit import RedisRateLimiterMiddleware
from src.core.audit import AuditActionType, AuditLogger, ReasonCode
from src.core.config import get_settings
from src.core.logging import audit_actor_ctx, request_id_ctx
from src.database.models import Base, Invoice, Vendor
from src.database.repositories import InvoiceRepository, VendorRepository, compute_composite_hash
from src.database.session import create_db_engine, create_session_factory


async def _setup_db_with_invoice():
    """Initialize isolated in-memory async SQLite DB with one vendor and one invoice."""
    engine = create_db_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = create_session_factory(engine)
    async with session_factory() as session:
        await VendorRepository(session).create(
            Vendor(
                vendor_tax_id="US-12-3456789",
                vendor_id="VEND-001",
                vendor_name="Acme Technologies Inc.",
                country_code="US",
                date_format_locale="MM/DD/YYYY",
                default_currency="USD",
            )
        )
        invoice = await InvoiceRepository(session).create(
            Invoice(
                vendor_tax_id="US-12-3456789",
                vendor_name="Acme Technologies Inc.",
                invoice_number="INV-AUDIT-001",
                subtotal=Decimal("1000.00"),
                total_tax_amount=Decimal("95.00"),
                total_amount=Decimal("1095.00"),
                currency="USD",
                status="REQUIRES_REVIEW",
                composite_hash=compute_composite_hash(
                    "US-12-3456789", "INV-AUDIT-001", Decimal("1095.00")
                ),
            )
        )
    return engine, session_factory, invoice.invoice_id


def test_audit_logger_appends_immutable_record_with_request_id_propagation() -> None:
    """Verify AuditLogger persists immutable AuditLog rows with active request_id correlation."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)
            # Non-negotiable append-only invariant (CLAUDE.md §6, §16)
            assert not hasattr(audit_logger, "update")
            assert not hasattr(audit_logger, "delete")

            token = request_id_ctx.set("req-trace-9001")
            try:
                entry = await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="demo-oid-sarah-clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="total_tax_amount",
                    previous_value="95.00",
                    new_value="0.00",
                    reason_code=ReasonCode.TAX_CODE_OVERRIDE,
                    comment="EU reverse charge verified",
                )
            finally:
                request_id_ctx.reset(token)

            assert entry.audit_id is not None
            assert entry.invoice_id == invoice_id
            assert entry.user_id == "demo-oid-sarah-clerk"
            assert entry.action_type == "EDIT"
            assert entry.field_name == "total_tax_amount"
            assert entry.previous_value == "95.00"
            assert entry.new_value == "0.00"
            assert entry.reason_code == "TAX_CODE_OVERRIDE"
            assert entry.comment == "[request_id=req-trace-9001] EU reverse charge verified"
            assert entry.timestamp is not None
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_logger_survives_caller_transaction_rollback() -> None:
    """Verify AuditLogger commits in an isolated transaction immune to caller rollbacks (CLAUDE.md §16)."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)

            # Simulate a failing caller business transaction that rolls back after writing an audit entry
            async with session_factory() as caller_session:
                inv_repo = InvoiceRepository(caller_session)
                invoice = await inv_repo.get_by_id(invoice_id, include_relations=False)
                assert invoice is not None
                invoice.status = "SHOULD_ROLL_BACK"

                # AuditLogger uses its own isolated session — must survive caller rollback!
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="demo-oid-michael-manager",
                    action_type=AuditActionType.APPROVE,
                    field_name="status",
                    previous_value="REQUIRES_REVIEW",
                    new_value="APPROVED_MANAGER",
                    comment="Audit recorded before downstream error",
                )

                await caller_session.rollback()

            # Verify business change rolled back, while immutable AuditLog row survived
            async with session_factory() as verify_session:
                reloaded = await InvoiceRepository(verify_session).get_by_id(
                    invoice_id, include_relations=False
                )
                assert reloaded is not None
                assert reloaded.status == "REQUIRES_REVIEW"

            trail = await audit_logger.get_invoice_audit_trail(invoice_id)
            assert len(trail) == 1
            assert trail[0].action_type == "APPROVE"
            assert trail[0].user_id == "demo-oid-michael-manager"
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_logger_rejects_noop_edits_and_invalid_reason_codes() -> None:
    """Verify no-op edits, invalid enums, missing financial reason codes, and OTHER without comment fail."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)

            # 1. No-op EDIT rejected (exact & whitespace-equivalent)
            with pytest.raises(ValueError, match="No-op"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="total_amount",
                    previous_value="1095.00",
                    new_value=" 1095.00 ",
                    reason_code=ReasonCode.OCR_MISREAD,
                )

            # 2. Unknown action_type rejected
            with pytest.raises(ValueError, match="action_type"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type="DELETE_EVERYTHING",
                )

            # 3. Unknown reason_code rejected
            with pytest.raises(ValueError, match="reason_code"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="total_amount",
                    previous_value="1095.00",
                    new_value="1090.00",
                    reason_code="FAKE_REASON",
                )

            # 4. ReasonCode.OTHER requires a non-blank comment (CLAUDE.md §5)
            with pytest.raises(ValueError, match="comment"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="po_number",
                    previous_value="PO-1",
                    new_value="PO-2",
                    reason_code=ReasonCode.OTHER,
                    comment="   ",
                )

            # 5. Financial/tax EDIT requires mandatory reason_code (CLAUDE.md §5)
            with pytest.raises(ValueError, match="reason_code"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="total_tax_amount",
                    previous_value="95.00",
                    new_value="90.00",
                )
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_logger_masks_sensitive_fields_and_truncates_oversized_comment(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify raw Tax IDs never leak in audit logs and comments stay within 1000-char schema bound."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)
            long_comment = "A" * 2500
            token = request_id_ctx.set("req-pii-safe-1")
            try:
                with caplog.at_level(logging.INFO, logger="ap.core.audit"):
                    entry = await audit_logger.record(
                        invoice_id=invoice_id,
                        user_id="sarah.clerk",
                        action_type=AuditActionType.EDIT,
                        field_name="vendor_tax_id",
                        previous_value="US-12-3456789",
                        new_value="US-98-7654321",
                        reason_code=ReasonCode.OCR_MISREAD,
                        comment=long_comment,
                    )
            finally:
                request_id_ctx.reset(token)

            assert entry.comment is not None
            assert entry.comment.startswith("[request_id=req-pii-safe-1]")
            assert len(entry.comment) <= 1000

            combined_logs = " ".join(record.getMessage() for record in caplog.records)
            assert "US-12-3456789" not in combined_logs
            assert "US-98-7654321" not in combined_logs
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_logger_get_invoice_audit_trail_chronological() -> None:
    """Verify get_invoice_audit_trail returns full chronological audit history."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)
            await audit_logger.record(
                invoice_id=invoice_id,
                user_id="system",
                action_type=AuditActionType.INGEST,
            )
            await audit_logger.record(
                invoice_id=invoice_id,
                user_id="gpt-4o-mini",
                action_type=AuditActionType.EXTRACTION,
            )
            await audit_logger.record(
                invoice_id=invoice_id,
                user_id="demo-oid-sarah-clerk",
                action_type=AuditActionType.APPROVE,
            )

            trail = await audit_logger.get_invoice_audit_trail(invoice_id)
            assert [e.action_type for e in trail] == ["INGEST", "EXTRACTION", "APPROVE"]
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_request_id_sanitization_blocks_crlf_and_oversized_header_injection() -> None:
    """Verify tainted or oversized X-Request-ID headers are replaced with safe server UUIDs (CWE-113/117)."""
    client = TestClient(main_app)

    # Valid custom X-Request-ID is preserved
    valid_id = "req-valid_123.abc"
    r_valid = client.get("/health", headers={"X-Request-ID": valid_id})
    assert r_valid.status_code == 200
    assert r_valid.headers["x-request-id"] == valid_id

    # Malicious CRLF, whitespace/special chars, and oversized IDs must be rejected & regenerated
    for bad_id in (
        "req-1\r\nX-Injected: evil",
        "req-1\nFAKE LOG ENTRY",
        "req with spaces;drop table",
        "x" * 200,
    ):
        r_bad = client.get("/health", headers={"X-Request-ID": bad_id})
        assert r_bad.status_code == 200
        returned_id = r_bad.headers["x-request-id"]
        assert returned_id != bad_id
        assert returned_id.startswith("req-")
        assert "\r" not in returned_id
        assert "\n" not in returned_id


def test_audit_middleware_propagates_request_id_verified_actor_and_never_leaks_jwt(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Verify AuditMiddleware logs verified actor, outcome, and request_id without leaking JWTs or context."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    get_settings.cache_clear()
    client = TestClient(main_app)

    dave_tok = client.post("/api/v1/auth/demo-token", json={"persona": "dave.admin"}).json()[
        "access_token"
    ]
    sarah_tok = client.post("/api/v1/auth/demo-token", json={"persona": "sarah.clerk"}).json()[
        "access_token"
    ]

    with caplog.at_level(logging.INFO, logger="ap.api.audit"):
        r_ok = client.get(
            "/health/ready",
            headers={"Authorization": f"Bearer {dave_tok}", "X-Request-ID": "req-audit-ok"},
        )
        r_403 = client.get(
            "/health/ready",
            headers={"Authorization": f"Bearer {sarah_tok}", "X-Request-ID": "req-audit-403"},
        )
        r_401 = client.get("/health/ready", headers={"X-Request-ID": "req-audit-401"})

    assert r_ok.status_code == 200
    assert r_403.status_code == 403
    assert r_401.status_code == 401

    # ContextVar must be reset after request completes (no cross-request actor bleed)
    assert audit_actor_ctx.get() == "anonymous"

    records_by_req = {getattr(rec, "audit_request_id", None): rec for rec in caplog.records}
    assert records_by_req["req-audit-ok"].actor_id == "demo-oid-dave-admin"
    assert records_by_req["req-audit-ok"].audit_outcome == "SUCCESS"
    assert records_by_req["req-audit-403"].actor_id == "demo-oid-sarah-clerk"
    assert records_by_req["req-audit-403"].audit_outcome == "AUTH_DENIED"
    assert records_by_req["req-audit-401"].actor_id == "anonymous"
    assert records_by_req["req-audit-401"].audit_outcome == "AUTH_DENIED"

    # Raw JWT tokens must NEVER appear in audit logs (CWE-532)
    combined_logs = " ".join(rec.getMessage() for rec in caplog.records)
    assert dave_tok not in combined_logs
    assert sarah_tok not in combined_logs


def test_middleware_stack_order_and_429_audit_capture(caplog: pytest.LogCaptureFixture) -> None:
    """Verify canonical middleware order on main_app and AuditMiddleware capture of 429 rate-limit blocks."""
    # Starlette stores user_middleware outermost-first (last added is index 0)
    middleware_classes = [m.cls for m in main_app.user_middleware]
    assert middleware_classes == [
        RequestIDMiddleware,
        CORSMiddleware,
        AuditMiddleware,
        RedisRateLimiterMiddleware,
    ]

    # Build isolated app with canonical middleware order and max_requests=1 to verify 429 audit capture
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    test_app = FastAPI()

    @test_app.get("/api/v1/resource")
    async def resource():
        return {"ok": True}

    test_app.add_middleware(
        RedisRateLimiterMiddleware, redis_client=fake_redis, max_requests=1, window_seconds=60
    )
    test_app.add_middleware(AuditMiddleware)
    test_app.add_middleware(RequestIDMiddleware)

    client = TestClient(test_app)
    with caplog.at_level(logging.INFO, logger="ap.api.audit"):
        assert (
            client.get("/api/v1/resource", headers={"X-Request-ID": "req-rl-1"}).status_code == 200
        )
        r429 = client.get("/api/v1/resource", headers={"X-Request-ID": "req-rl-2"})

    assert r429.status_code == 429
    assert r429.headers["x-request-id"] == "req-rl-2"

    records_by_req = {getattr(rec, "audit_request_id", None): rec for rec in caplog.records}
    assert records_by_req["req-rl-2"].audit_outcome == "RATE_LIMITED"
    assert records_by_req["req-rl-2"].http_status == 429


def test_audit_logger_rejects_oversized_values_and_ignores_tainted_request_id() -> None:
    """Verify AuditLogger rejects >4096-char field values and strips forged request_id tags (CWE-400/117)."""

    async def _run() -> None:
        engine, session_factory, invoice_id = await _setup_db_with_invoice()
        try:
            audit_logger = AuditLogger(session_factory)

            with pytest.raises(ValueError, match="new_value"):
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="sarah.clerk",
                    action_type=AuditActionType.EDIT,
                    field_name="po_number",
                    previous_value="PO-1",
                    new_value="X" * 5000,
                )

            # Tainted request_id with brackets/spaces must NOT be injected into comment tag
            entry = await audit_logger.record(
                invoice_id=invoice_id,
                user_id="sarah.clerk",
                action_type=AuditActionType.REVALIDATE,
                request_id="req-1] [actor=forged",
                comment="Revalidated cleanly",
            )
            assert entry.comment == "Revalidated cleanly"
        finally:
            await engine.dispose()

    asyncio.run(_run())


def test_audit_middleware_masks_pii_and_strips_crlf_in_url_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify AuditMiddleware masks Tax IDs and strips CRLF from URL paths before logging (CWE-117/532)."""
    # Direct sanitizer check against raw CRLF + Tax ID injection
    sanitized = _sanitize_audit_path("/api/v1/vendors/US-12-3456789\r\nFAKE_LOG")
    assert "US-12-3456789" not in sanitized
    assert "***-**-6789" in sanitized
    assert "\r" not in sanitized
    assert "\n" not in sanitized

    # Live HTTP middleware check with Tax ID in URL segment
    client = TestClient(main_app)
    with caplog.at_level(logging.INFO, logger="ap.api.audit"):
        resp = client.get(
            "/api/v1/vendors/US-12-3456789/details",
            headers={"X-Request-ID": "req-path-pii"},
        )

    assert resp.status_code == 404
    records_by_req = {getattr(rec, "audit_request_id", None): rec for rec in caplog.records}
    rec = records_by_req["req-path-pii"]
    assert "US-12-3456789" not in rec.http_path
    assert "US-12-3456789" not in rec.getMessage()
    assert "***-**-6789" in rec.http_path
