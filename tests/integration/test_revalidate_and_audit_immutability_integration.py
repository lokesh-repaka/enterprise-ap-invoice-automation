"""
End-to-End Offline Integration Tests: Re-Validate Workflow & Audit Log Append-Only Enforcement (P12-3).

Tests: FR-07, FR-12, FR-13, N3, N6
Requirements: CLAUDE.md §6, §7.4, §9, §13, §16 Rule 9, §16.1, BR-016, BR-017, PRD Journey 5.

Exercises strictly offline (FastAPI + SQLite + FakeRedis + WORM Blob + MockAOAI):
1. Full upload -> worker tax-mismatch detection -> clerk Re-Validate fix -> clerk Approve ->
   chronological immutable audit chain verification (preserving model confidence score unchanged).
2. Failed re-validation looping back to REQUIRES_APPROVAL, EU reverse-charge recovery -> VALIDATED,
   and >$10k edit escalation -> REQUIRES_MANAGER_APPROVAL.
3. No-op edit (422) & invalid reason_code rejection with zero AuditLogs pollution.
4. Defense-in-depth append-only enforcement across ALL 4 layers:
   - API (405 Method Not Allowed on PUT/PATCH/DELETE/POST)
   - Repository & AuditLogger (zero update/delete methods)
   - SQLAlchemy ORM listeners (AuditLogImmutabilityError on ORM UPDATE/DELETE & parent cascade: SEC-215)
   - SQLite database triggers (trg_audit_logs_no_update / trg_audit_logs_no_delete on raw SQL: SEC-216)
5. Isolated-transaction AuditLogger durability across caller business rollbacks.
"""

import asyncio
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

import fakeredis.aioredis
import fitz
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from src.api.invoices import (
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
)
from src.api.main import app
from src.core.audit import AuditActionType, AuditLogger, ReasonCode
from src.core.config import get_settings
from src.core.demo_auth import reset_demo_keypair_cache
from src.core.redis_client import RedisJobQueueClient
from src.database.models import AuditLogImmutabilityError, Base, Invoice, InvoiceLine
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
    InvoiceLineRepository,
    InvoiceRepository,
    compute_composite_hash,
)
from src.database.seed import seed_exchange_rates, seed_vendors
from src.database.session import create_db_engine, create_session_factory
from src.extraction.extract_engine import ExtractionEngine
from src.extraction.mock_aoai_client import MockAOAIClient
from src.extraction.model_gateway import ModelGateway
from src.services.pipeline import InvoiceProcessingPipeline
from src.services.worker import InvoiceBackgroundWorker
from src.storage.blob_client import InMemoryWORMBlobClient

SAMPLE_DATA_DIR = Path("./sample_data")


def _make_searchable_pdf(text_body: str) -> bytes:
    """Create a valid searchable PDF with sufficient text density for gpt-4o-mini routing."""
    full_text = (
        f"{text_body}\n"
        "Accounts Payable Commercial Invoice Document — Standard Searchable Text Layer.\n"
        "Payment Terms: Net 30 Days. Remit referencing invoice number."
    )
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), full_text)
    out = doc.tobytes()
    doc.close()
    return out


@dataclass
class _OfflineStack:
    client: TestClient
    clerk_headers: dict[str, str]
    manager_headers: dict[str, str]
    admin_headers: dict[str, str]
    session_factory: Any
    queue_client: RedisJobQueueClient
    blob_client: InMemoryWORMBlobClient

    def make_worker(self) -> InvoiceBackgroundWorker:
        gateway = ModelGateway(chat_client=MockAOAIClient())
        engine = ExtractionEngine(gateway=gateway)
        pipeline = InvoiceProcessingPipeline(
            extraction_engine=engine,
            session_factory=self.session_factory,
        )
        return InvoiceBackgroundWorker(
            queue_client=self.queue_client,
            blob_client=self.blob_client,
            session_factory=self.session_factory,
            pipeline=pipeline,
        )


@contextmanager
def _offline_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, db_name: str
) -> Generator[_OfflineStack, None, None]:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / db_name
    engine = create_db_engine(f"sqlite+aiosqlite:///{db_path}")
    session_factory = create_session_factory(engine)
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    queue_client = RedisJobQueueClient(fake_redis)
    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )

    async def _init_db() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with session_factory() as session:
            await seed_vendors(session, SAMPLE_DATA_DIR)
            await seed_exchange_rates(session, SAMPLE_DATA_DIR)
            fx_repo = ExchangeRateRepository(session)
            await fx_repo.upsert(
                rate_date=date(2026, 2, 1),
                from_currency="EUR",
                to_currency="USD",
                exchange_rate=Decimal("1.085000"),
            )
            await fx_repo.upsert(
                rate_date=date(2026, 2, 1),
                from_currency="GBP",
                to_currency="USD",
                exchange_rate=Decimal("1.272000"),
            )

    asyncio.run(_init_db())

    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client

    try:
        with TestClient(app) as tc:
            clerk_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "sarah.clerk@company.com"}
            ).json()["access_token"]
            mgr_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "michael.manager@company.com"}
            ).json()["access_token"]
            admin_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "dave.admin@company.com"}
            ).json()["access_token"]
            yield _OfflineStack(
                client=tc,
                clerk_headers={"Authorization": f"Bearer {clerk_tok}"},
                manager_headers={"Authorization": f"Bearer {mgr_tok}"},
                admin_headers={"Authorization": f"Bearer {admin_tok}"},
                session_factory=session_factory,
                queue_client=queue_client,
                blob_client=blob_client,
            )
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()


# ---------------------------------------------------------------------------
# 1. Full Upload -> Tax Mismatch -> Re-Validate -> Approve -> Audit Chain
# ---------------------------------------------------------------------------


def test_p12_3_full_upload_to_tax_mismatch_revalidate_and_approve_journey(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-07, FR-12, N3 — Upload tax mismatch -> clerk Re-Validate -> Approve -> full audit trail."""
    with _offline_stack(monkeypatch, tmp_path, db_name="p12_3_journey.db") as stack:
        # 1. Upload INV-2026-1010 (Spanish invoice with stated tax 1114.38 vs 21% of 5187.50 = 1089.38)
        r_up = stack.client.post(
            "/api/v1/invoices/upload",
            headers={**stack.clerk_headers, "X-Request-ID": "req-p12-3-up"},
            files={
                "file": (
                    "INV-2026-1010.pdf",
                    _make_searchable_pdf("Mediterraneo Quimica SA Invoice INV-2026-1010"),
                    "application/pdf",
                )
            },
        )
        assert r_up.status_code == 202
        invoice_id = r_up.json()["invoice_id"]

        outcome = asyncio.run(stack.make_worker().process_next_job())
        assert outcome.final_invoice_status == "REJECTED_TAX_MISMATCH"

        before_detail = stack.client.get(
            f"/api/v1/invoices/{invoice_id}", headers=stack.clerk_headers
        ).json()
        original_confidence = Decimal(before_detail["confidence_macro_avg"])
        assert original_confidence == Decimal("97.50")

        # 2. Clerk fixes OCR-misread tax & total and clicks Re-Validate (FR-12)
        r_reval = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/revalidate",
            headers={**stack.clerk_headers, "X-Request-ID": "req-p12-3-reval"},
            json={
                "reason_code": "OCR_MISREAD",
                "comment": "Corrected 21% IVA from 1114.38 to 1089.38 per PDF scan",
                "header_edits": {
                    "total_tax_amount": "1089.38",
                    "total_amount": "6276.88",
                },
            },
        )
        assert r_reval.status_code == 200
        reval_body = r_reval.json()
        assert reval_body["status"] == "VALIDATED"
        assert reval_body["validation_summary"]["all_passed"] is True
        assert reval_body["validation_summary"]["tax_valid"] is True

        # Edits MUST NOT alter immutable model confidence_macro_avg (CLAUDE.md §7.4)
        after_reval = stack.client.get(
            f"/api/v1/invoices/{invoice_id}", headers=stack.clerk_headers
        ).json()
        assert Decimal(after_reval["confidence_macro_avg"]) == original_confidence

        # 3. Clerk one-click approves (6276.88 EUR * 1.085 = $6,810.41 <= $10k)
        r_app = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/approve",
            headers={**stack.clerk_headers, "X-Request-ID": "req-p12-3-app"},
            json={"comment": "Verified corrected VAT and totals"},
        )
        assert r_app.status_code == 200
        assert r_app.json()["status"] == "APPROVED_CLERK"

        # 4. Verify complete chronological Audit Trail (N3)
        audit_resp = stack.client.get(
            f"/api/v1/invoices/{invoice_id}/audit", headers=stack.admin_headers
        )
        assert audit_resp.status_code == 200
        events = audit_resp.json()["events"]
        actions = [e["action_type"] for e in events]
        assert actions == [
            "INGEST",
            "STATUS_TRANSITION",
            "EXTRACTION",
            "EDIT",
            "EDIT",
            "REVALIDATE",
            "APPROVE",
        ]
        edit_events = [e for e in events if e["action_type"] == "EDIT"]
        edited_fields = {
            e["field_name"]: (e["previous_value"], e["new_value"], e["reason_code"])
            for e in edit_events
        }
        assert edited_fields["total_tax_amount"] == ("1114.38", "1089.38", "OCR_MISREAD")
        assert edited_fields["total_amount"] == ("6301.88", "6276.88", "OCR_MISREAD")


# ---------------------------------------------------------------------------
# 2. Failed Re-Validation Loop, EU Reverse Charge Recovery & >$10k Escalation
# ---------------------------------------------------------------------------


def test_p12_3_failed_revalidation_eu_reverse_charge_and_high_value_escalation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-07, FR-12, FR-13 — Failed reval -> REQUIRES_APPROVAL; reverse-charge -> VALIDATED; >$10k -> manager."""
    with _offline_stack(monkeypatch, tmp_path, db_name="p12_3_flows.db") as stack:

        async def _seed_german_invoice() -> str:
            async with stack.session_factory() as session:
                inv = await InvoiceRepository(session).create(
                    Invoice(
                        vendor_tax_id="DE123456789",
                        vendor_name="Bavaria Werkzeuge GmbH",
                        invoice_number="INV-DE-REVAL-01",
                        invoice_date=date(2026, 2, 10),
                        due_date=date(2026, 3, 12),
                        po_number="PO-DE-100",
                        subtotal=Decimal("2000.00"),
                        total_tax_amount=Decimal("100.00"),
                        total_amount=Decimal("2100.00"),
                        currency="EUR",
                        confidence_macro_avg=Decimal("95.00"),
                        status="REJECTED_TAX_MISMATCH",
                        composite_hash=compute_composite_hash(
                            "DE123456789", "INV-DE-REVAL-01", Decimal("2100.00")
                        ),
                    )
                )
                await InvoiceLineRepository(session).create_many(
                    [
                        InvoiceLine(
                            invoice_id=inv.invoice_id,
                            line_number=1,
                            description="Precision Bearings",
                            quantity=Decimal("20.0000"),
                            unit_price=Decimal("100.0000"),
                            line_total=Decimal("2000.00"),
                            line_tax_rate=Decimal("0.0000"),
                            confidence_score=Decimal("95.00"),
                        )
                    ]
                )
                return inv.invoice_id

        invoice_id = asyncio.run(_seed_german_invoice())

        # A. Arithmetically inconsistent edit -> loops back to REQUIRES_APPROVAL (CLAUDE.md §7.4)
        r_bad = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/revalidate",
            headers=stack.clerk_headers,
            json={
                "reason_code": "OCR_MISREAD",
                "header_edits": {"total_amount": "2500.00"},
            },
        )
        assert r_bad.status_code == 200
        assert r_bad.json()["status"] == "REQUIRES_APPROVAL"
        assert r_bad.json()["validation_summary"]["invoice_total_valid"] is False

        # B. EU Reverse Charge fix (0% VAT + TAX_CODE_OVERRIDE) -> VALIDATED (PRD Journey 5)
        r_rc = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/revalidate",
            headers=stack.clerk_headers,
            json={
                "reason_code": "TAX_CODE_OVERRIDE",
                "comment": "EU Reverse Charge Article 196 confirmed",
                "is_reverse_charge": True,
                "header_edits": {
                    "total_tax_amount": "0.00",
                    "total_amount": "2000.00",
                },
            },
        )
        assert r_rc.status_code == 200
        assert r_rc.json()["status"] == "VALIDATED"
        assert r_rc.json()["validation_summary"]["all_passed"] is True

        # C. High-value edit (> $10,000 USD) escalates to REQUIRES_MANAGER_APPROVAL (FR-13)
        r_hv = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/revalidate",
            headers=stack.clerk_headers,
            json={
                "reason_code": "OCR_MISREAD",
                "is_reverse_charge": False,
                "header_edits": {
                    "subtotal": "12000.00",
                    "total_tax_amount": "2280.00",
                    "total_amount": "14280.00",
                },
                "line_edits": [
                    {
                        "line_number": 1,
                        "quantity": "120",
                        "line_total": "12000.00",
                        "line_tax_rate": "0.19",
                    }
                ],
            },
        )
        assert r_hv.status_code == 200
        assert r_hv.json()["status"] == "REQUIRES_MANAGER_APPROVAL"


# ---------------------------------------------------------------------------
# 3. No-Op Edits & Invalid Reason Codes Rejected with Zero Audit Pollution
# ---------------------------------------------------------------------------


def test_p12_3_noop_edits_and_invalid_reason_codes_zero_audit_pollution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-12, CLAUDE.md §16.1 — No-op edits & invalid reason codes return 422 and write 0 audit rows."""
    with _offline_stack(monkeypatch, tmp_path, db_name="p12_3_noop.db") as stack:

        async def _seed_us_invoice() -> str:
            async with stack.session_factory() as session:
                inv = await InvoiceRepository(session).create(
                    Invoice(
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Apex Global Logistics Inc",
                        invoice_number="INV-US-NOOP-01",
                        invoice_date=date(2026, 2, 10),
                        due_date=date(2026, 3, 12),
                        po_number="PO-US-500",
                        subtotal=Decimal("1000.00"),
                        total_tax_amount=Decimal("80.00"),
                        total_amount=Decimal("1080.00"),
                        currency="USD",
                        confidence_macro_avg=Decimal("85.00"),
                        status="REQUIRES_REVIEW",
                        composite_hash=compute_composite_hash(
                            "US-12-3456789", "INV-US-NOOP-01", Decimal("1080.00")
                        ),
                    )
                )
                return inv.invoice_id

        invoice_id = asyncio.run(_seed_us_invoice())

        bad_payloads = [
            # Exact no-op (decimal scale equivalent "1000" == Decimal("1000.00"))
            {"reason_code": "OCR_MISREAD", "header_edits": {"subtotal": "1000"}},
            # Empty edit payload
            {"reason_code": "OCR_MISREAD"},
            # Unknown reason code
            {"reason_code": "FAKE_CODE", "header_edits": {"subtotal": "950.00"}},
            # OTHER without visible comment
            {
                "reason_code": "OTHER",
                "comment": "   ",
                "header_edits": {"subtotal": "950.00"},
            },
        ]
        for payload in bad_payloads:
            resp = stack.client.post(
                f"/api/v1/invoices/{invoice_id}/revalidate",
                headers=stack.clerk_headers,
                json=payload,
            )
            assert resp.status_code == 422

        # Zero audit rows written for rejected no-op / invalid attempts
        audit_resp = stack.client.get(
            f"/api/v1/invoices/{invoice_id}/audit", headers=stack.admin_headers
        )
        assert audit_resp.status_code == 200
        assert audit_resp.json()["total_events"] == 0
        assert audit_resp.json()["events"] == []


# ---------------------------------------------------------------------------
# 4. 4-Layer Append-Only Audit Log Immutability Enforcement (SEC-215, SEC-216)
# ---------------------------------------------------------------------------


def test_p12_3_audit_log_append_only_enforced_across_api_repo_orm_and_sql(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: N3, N6, CLAUDE.md §6, §16 Rule 9, SEC-215, SEC-216 — 4-layer audit immutability."""
    with _offline_stack(monkeypatch, tmp_path, db_name="p12_3_immut.db") as stack:

        async def _seed_audited_invoice() -> tuple[str, str]:
            async with stack.session_factory() as session:
                inv = await InvoiceRepository(session).create(
                    Invoice(
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Apex Global Logistics Inc",
                        invoice_number="INV-US-IMMUT-01",
                        invoice_date=date(2026, 2, 10),
                        subtotal=Decimal("500.00"),
                        total_tax_amount=Decimal("40.00"),
                        total_amount=Decimal("540.00"),
                        currency="USD",
                        confidence_macro_avg=Decimal("96.00"),
                        status="VALIDATED",
                        composite_hash=compute_composite_hash(
                            "US-12-3456789", "INV-US-IMMUT-01", Decimal("540.00")
                        ),
                    )
                )
            audit_logger = AuditLogger(stack.session_factory)
            entry = await audit_logger.record(
                invoice_id=inv.invoice_id,
                user_id="demo-oid-sarah-clerk",
                action_type=AuditActionType.EDIT,
                field_name="total_tax_amount",
                previous_value="35.00",
                new_value="40.00",
                reason_code=ReasonCode.OCR_MISREAD,
                comment="Immutable audit proof row",
            )
            return inv.invoice_id, entry.audit_id

        invoice_id, audit_id = asyncio.run(_seed_audited_invoice())

        # Layer 1 — API routes reject all mutating HTTP verbs with 405 Method Not Allowed
        for verb in ("put", "patch", "delete", "post"):
            resp = getattr(stack.client, verb)(
                f"/api/v1/invoices/{invoice_id}/audit",
                headers=stack.admin_headers,
            )
            assert resp.status_code == 405

        # Layer 2 — Repository & AuditLogger expose zero update/delete APIs
        assert not hasattr(AuditLogRepository, "update")
        assert not hasattr(AuditLogRepository, "delete")
        assert not hasattr(AuditLogger, "update")
        assert not hasattr(AuditLogger, "delete")

        async def _attempt_orm_and_raw_sql_tampering() -> None:
            # Layer 3a — ORM attribute mutation -> AuditLogImmutabilityError (SEC-215)
            async with stack.session_factory() as session:
                row = await AuditLogRepository(session).get_by_id(audit_id)
                assert row is not None
                row.new_value = "9999.99"
                with pytest.raises(AuditLogImmutabilityError):
                    await session.commit()
                await session.rollback()

            # Layer 3b — ORM session.delete(audit_row) -> AuditLogImmutabilityError (SEC-215)
            async with stack.session_factory() as session:
                row = await AuditLogRepository(session).get_by_id(audit_id)
                assert row is not None
                await session.delete(row)
                with pytest.raises(AuditLogImmutabilityError):
                    await session.commit()
                await session.rollback()

            # Layer 3c — Deleting parent Invoice cannot cascade-delete immutable AuditLog rows (SEC-215/216)
            async with stack.session_factory() as session:
                with pytest.raises((AuditLogImmutabilityError, IntegrityError)):
                    await InvoiceRepository(session).delete(invoice_id)
                await session.rollback()

            # Layer 4a — Raw SQL UPDATE on audit_logs blocked by DB trigger (SEC-216)
            async with stack.session_factory() as session:
                with pytest.raises(IntegrityError):
                    await session.execute(
                        text("UPDATE audit_logs SET new_value = '0.00' WHERE audit_id = :aid"),
                        {"aid": audit_id},
                    )
                    await session.commit()
                await session.rollback()

            # Layer 4b — Raw SQL DELETE on audit_logs blocked by DB trigger (SEC-216)
            async with stack.session_factory() as session:
                with pytest.raises(IntegrityError):
                    await session.execute(
                        text("DELETE FROM audit_logs WHERE audit_id = :aid"),
                        {"aid": audit_id},
                    )
                    await session.commit()
                await session.rollback()

            # Verify original immutable audit row survived every tampering attempt completely unaltered
            async with stack.session_factory() as session:
                preserved = await AuditLogRepository(session).get_by_id(audit_id)
                assert preserved is not None
                assert preserved.previous_value == "35.00"
                assert preserved.new_value == "40.00"
                assert preserved.reason_code == "OCR_MISREAD"

        asyncio.run(_attempt_orm_and_raw_sql_tampering())


# ---------------------------------------------------------------------------
# 5. Isolated Audit Transaction Durability Across Business Rollback
# ---------------------------------------------------------------------------


def test_p12_3_audit_logger_isolated_transaction_survives_caller_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: N3, CLAUDE.md §16 Rule 9 — AuditLog commits independently of rolled-back business transactions."""
    with _offline_stack(monkeypatch, tmp_path, db_name="p12_3_tx.db") as stack:

        async def _verify_isolation() -> None:
            async with stack.session_factory() as session:
                inv = await InvoiceRepository(session).create(
                    Invoice(
                        vendor_tax_id="US-12-3456789",
                        vendor_name="Apex Global Logistics Inc",
                        invoice_number="INV-US-TX-01",
                        invoice_date=date(2026, 2, 10),
                        subtotal=Decimal("300.00"),
                        total_tax_amount=Decimal("24.00"),
                        total_amount=Decimal("324.00"),
                        currency="USD",
                        confidence_macro_avg=Decimal("92.00"),
                        status="REQUIRES_REVIEW",
                        composite_hash=compute_composite_hash(
                            "US-12-3456789", "INV-US-TX-01", Decimal("324.00")
                        ),
                    )
                )
                invoice_id = inv.invoice_id

            audit_logger = AuditLogger(stack.session_factory)
            async with stack.session_factory() as business_session:
                loaded = await InvoiceRepository(business_session).get_by_id(
                    invoice_id, include_relations=False
                )
                assert loaded is not None
                loaded.status = "ABORTED_TRANSITION"
                await audit_logger.record(
                    invoice_id=invoice_id,
                    user_id="demo-oid-sarah-clerk",
                    action_type=AuditActionType.REVALIDATE,
                    field_name="status",
                    previous_value="REQUIRES_REVIEW",
                    new_value="VALIDATED",
                    comment="Recorded prior to downstream business rollback",
                )
                await business_session.rollback()

            # Business mutation rolled back; immutable AuditLog row survived!
            async with stack.session_factory() as verify_session:
                reloaded = await InvoiceRepository(verify_session).get_by_id(
                    invoice_id, include_relations=False
                )
                assert reloaded is not None
                assert reloaded.status == "REQUIRES_REVIEW"
                trail = await AuditLogRepository(verify_session).get_by_invoice_id(invoice_id)
                assert len(trail) == 1
                assert trail[0].action_type == "REVALIDATE"

        asyncio.run(_verify_isolation())
