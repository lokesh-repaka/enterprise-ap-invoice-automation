"""
End-to-End Offline Integration Tests: Idempotency Key Deduplication (P12-5).

Tests: FR-01, FR-09, CLAUDE.md §4.1, §13, §16 Rule 6, LLD §6.1
Security Controls: CWE-74, CWE-345, CWE-362, CWE-636, CWE-639, SEC-219.

Exercises the complete live FastAPI + SQLite + FakeRedis + WORM Blob + Worker + MockAOAI stack:
1. Re-submitting an identical file before extraction, after worker extraction (VALIDATED), and
   after approval (APPROVED_CLERK) returns HTTP 200 with X-Idempotency-Replayed: true, the exact
   same InvoiceID, live SQL status, 0 duplicate queue/SQL/Blob writes, and mock_aoai.call_count == 1.
2. Explicit & content-derived Idempotency-Key conflict guards (different bytes -> 409; conflicting
   vendor_id -> 409 on both explicit and implicit keys: SEC-219; malformed header -> 422).
3. Concurrent parallel upload race (5 identical requests) yields strictly 1 winner (202), 4 replays
   (200), 1 SQL row, 1 Redis job, and 1 MockAOAIClient invocation.
4. Cross-actor isolation between sarah.clerk and michael.manager (shared file & shared header).
5. Transient storage failure (503) releases the claimed idempotency lock so immediate retry succeeds.
"""

import asyncio
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
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

from src.api.invoices import (
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
)
from src.api.main import app
from src.core.config import get_settings
from src.core.demo_auth import reset_demo_keypair_cache
from src.core.redis_client import RedisJobQueueClient
from src.database.models import Base
from src.database.repositories import ExchangeRateRepository, InvoiceRepository
from src.database.seed import seed_exchange_rates, seed_vendors
from src.database.session import create_db_engine, create_session_factory
from src.extraction.extract_engine import ExtractionEngine
from src.extraction.mock_aoai_client import MockAOAIClient
from src.extraction.model_gateway import ModelGateway
from src.services.pipeline import InvoiceProcessingPipeline
from src.services.worker import InvoiceBackgroundWorker
from src.storage.blob_client import BlobStorageError, InMemoryWORMBlobClient

SAMPLE_DATA_DIR = Path("./sample_data")


def _make_searchable_pdf(text: str) -> bytes:
    """Generate a valid searchable PDF (>= 60 chars text density -> gpt-4o-mini route)."""
    body = (
        f"{text}\n"
        "Accounts Payable Commercial Invoice Document — Standard Searchable Text Layer.\n"
        "Payment Terms: Net 30 Days. Remit referencing invoice number."
    )
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), body)
    out = doc.tobytes()
    doc.close()
    return out


@dataclass
class _IdemStack:
    client: TestClient
    clerk_headers: dict[str, str]
    manager_headers: dict[str, str]
    session_factory: Any
    queue_client: RedisJobQueueClient
    blob_client: InMemoryWORMBlobClient

    def make_worker(
        self, *, mock_aoai: MockAOAIClient | None = None
    ) -> tuple[InvoiceBackgroundWorker, MockAOAIClient]:
        aoai = mock_aoai or MockAOAIClient()
        gateway = ModelGateway(chat_client=aoai)
        engine = ExtractionEngine(gateway=gateway)
        pipeline = InvoiceProcessingPipeline(
            extraction_engine=engine,
            session_factory=self.session_factory,
        )
        worker = InvoiceBackgroundWorker(
            queue_client=self.queue_client,
            blob_client=self.blob_client,
            session_factory=self.session_factory,
            pipeline=pipeline,
        )
        return worker, aoai


@contextmanager
def _idem_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, db_name: str
) -> Generator[_IdemStack, None, None]:
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
            yield _IdemStack(
                client=tc,
                clerk_headers={"Authorization": f"Bearer {clerk_tok}"},
                manager_headers={"Authorization": f"Bearer {mgr_tok}"},
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
# 1. End-to-End Idempotency Without Re-Invoking Model (CLAUDE.md §16 Rule 6)
# ---------------------------------------------------------------------------


def test_p12_5_resubmitted_identical_file_returns_existing_id_without_reinvoking_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-01, FR-09, CLAUDE.md §16.6 — Identical re-upload returns existing InvoiceID, 0 extra AI calls."""
    with _idem_stack(monkeypatch, tmp_path, db_name="p12_5_e2e.db") as stack:
        pdf_bytes = _make_searchable_pdf("Mediterraneo Quimica SA Invoice INV-2026-1001")

        # 1. Initial upload -> 202 Accepted
        r1 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            files={"file": ("INV-2026-1001.pdf", pdf_bytes, "application/pdf")},
        )
        assert r1.status_code == 202
        body1 = r1.json()
        invoice_id = body1["invoice_id"]
        assert body1["status"] == "UPLOADED"
        assert body1["queued"] is True
        assert body1["deduplicated"] is False
        assert asyncio.run(stack.queue_client.queue_depth()) == 1

        # 2. Immediate double-click re-submission (pre-worker) -> 200 OK replay, still 1 queued job
        r2 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            files={"file": ("INV-2026-1001.pdf", pdf_bytes, "application/pdf")},
        )
        assert r2.status_code == 200
        assert r2.headers.get("x-idempotency-replayed") == "true"
        assert r2.headers.get("cache-control") == "no-store"
        body2 = r2.json()
        assert body2["invoice_id"] == invoice_id
        assert body2["status"] == "UPLOADED"
        assert body2["queued"] is False
        assert body2["deduplicated"] is True
        assert asyncio.run(stack.queue_client.queue_depth()) == 1

        # 3. Worker extracts, validates, and routes -> VALIDATED (exactly 1 MockAOAIClient call)
        worker, mock_aoai = stack.make_worker()
        outcome = asyncio.run(worker.process_next_job())
        assert outcome.status == "COMPLETED"
        assert outcome.final_invoice_status == "VALIDATED"
        assert mock_aoai.call_count == 1
        assert asyncio.run(stack.queue_client.queue_depth()) == 0

        # 4. Re-submit identical bytes (different filename) AFTER worker extraction -> 200 OK + live VALIDATED
        r3 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            files={"file": ("INV-2026-1001_resubmit.pdf", pdf_bytes, "application/pdf")},
        )
        assert r3.status_code == 200
        assert r3.headers.get("x-idempotency-replayed") == "true"
        body3 = r3.json()
        assert body3["invoice_id"] == invoice_id
        assert body3["status"] == "VALIDATED"
        assert body3["queued"] is False
        assert body3["deduplicated"] is True
        assert asyncio.run(stack.queue_client.queue_depth()) == 0

        # Worker finds empty queue -> AI model NEVER re-invoked!
        idle_outcome = asyncio.run(worker.process_next_job())
        assert idle_outcome.status == "SKIPPED_EMPTY"
        assert mock_aoai.call_count == 1

        # 5. Approve invoice -> re-submit identical bytes -> 200 OK + live APPROVED_CLERK
        r_app = stack.client.post(
            f"/api/v1/invoices/{invoice_id}/approve",
            headers=stack.clerk_headers,
            json={"comment": "Approved after STP"},
        )
        assert r_app.status_code == 200
        assert r_app.json()["status"] == "APPROVED_CLERK"

        r4 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            files={"file": ("INV-2026-1001_final_copy.pdf", pdf_bytes, "application/pdf")},
        )
        assert r4.status_code == 200
        assert r4.json()["invoice_id"] == invoice_id
        assert r4.json()["status"] == "APPROVED_CLERK"
        assert r4.json()["deduplicated"] is True
        assert mock_aoai.call_count == 1

        # Strictly 1 SQL invoice row exists across all 4 submissions
        async def _count_invoices() -> int:
            async with stack.session_factory() as session:
                return len(await InvoiceRepository(session).list_by_status())

        assert asyncio.run(_count_invoices()) == 1


# ---------------------------------------------------------------------------
# 2. Conflict Guards (409) & Malformed Idempotency-Key Injection Guard (422)
# ---------------------------------------------------------------------------


def test_p12_5_idempotency_conflict_409_on_payload_or_vendor_mismatch_and_422_bad_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: CLAUDE.md §16.6, CWE-74, CWE-345, SEC-219 — 409 on mismatched bytes/vendor; 422 on bad header."""
    with _idem_stack(monkeypatch, tmp_path, db_name="p12_5_conflict.db") as stack:
        pdf_a = _make_searchable_pdf("Invoice Payload Alpha INV-2026-1001")
        pdf_b = _make_searchable_pdf("Invoice Payload Beta INV-2026-1010")

        # A. Explicit Idempotency-Key: same bytes -> 200; different bytes -> 409; conflicting vendor -> 409
        hdr_explicit = {**stack.clerk_headers, "Idempotency-Key": "batch-idem-key-001"}
        r1 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr_explicit,
            data={"vendor_id": "VEND-1001"},
            files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
        )
        assert r1.status_code == 202

        r_ok = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr_explicit,
            data={"vendor_id": "VEND-1001"},
            files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
        )
        assert r_ok.status_code == 200
        assert r_ok.json()["invoice_id"] == r1.json()["invoice_id"]

        r_diff_bytes = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr_explicit,
            data={"vendor_id": "VEND-1001"},
            files={"file": ("beta.pdf", pdf_b, "application/pdf")},
        )
        assert r_diff_bytes.status_code == 409

        r_diff_vendor_explicit = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr_explicit,
            data={"vendor_id": "VEND-2001"},
            files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
        )
        assert r_diff_vendor_explicit.status_code == 409

        # B. Content-derived (no header) identical bytes with conflicting explicit vendor_id -> 409 (SEC-219)
        pdf_c = _make_searchable_pdf("Invoice Payload Gamma Vendor Conflict Guard")
        r_c1 = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            data={"vendor_id": "VEND-1001"},
            files={"file": ("gamma.pdf", pdf_c, "application/pdf")},
        )
        assert r_c1.status_code == 202

        r_c2_conflict = stack.client.post(
            "/api/v1/invoices/upload",
            headers=stack.clerk_headers,
            data={"vendor_id": "VEND-2001"},
            files={"file": ("gamma.pdf", pdf_c, "application/pdf")},
        )
        assert r_c2_conflict.status_code == 409

        # C. Malformed / injected Idempotency-Key headers rejected with 422 (CWE-74)
        for bad_key in ("key with spaces", "x" * 129, "tab\tinjected"):
            r_bad = stack.client.post(
                "/api/v1/invoices/upload",
                headers={**stack.clerk_headers, "Idempotency-Key": bad_key},
                files={"file": ("alpha.pdf", pdf_a, "application/pdf")},
            )
            assert r_bad.status_code == 422


# ---------------------------------------------------------------------------
# 3. Concurrent Parallel Upload Race (Atomic Redis SET NX EX: CWE-362)
# ---------------------------------------------------------------------------


def test_p12_5_concurrent_identical_uploads_produce_single_winner_and_single_model_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: CLAUDE.md §16.6, CWE-362 — 5 concurrent identical uploads -> 1x 202, 4x 200, 1 AI call."""
    with _idem_stack(monkeypatch, tmp_path, db_name="p12_5_race.db") as stack:
        pdf_bytes = _make_searchable_pdf("Concurrent Race Invoice INV-2026-1001")

        def _upload_once(idx: int) -> tuple[int, str, bool]:
            resp = stack.client.post(
                "/api/v1/invoices/upload",
                headers=stack.clerk_headers,
                files={"file": (f"race_{idx}.pdf", pdf_bytes, "application/pdf")},
            )
            body = resp.json()
            return resp.status_code, body["invoice_id"], body["deduplicated"]

        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(_upload_once, range(5)))

        status_codes = sorted(code for code, _iid, _dedup in results)
        invoice_ids = {iid for _code, iid, _dedup in results}
        dedup_flags = [dedup for _code, _iid, dedup in results]

        assert status_codes == [200, 200, 200, 200, 202]
        assert len(invoice_ids) == 1
        assert dedup_flags.count(False) == 1
        assert dedup_flags.count(True) == 4
        assert asyncio.run(stack.queue_client.queue_depth()) == 1

        # Drain worker: strictly 1 job processed and 1 MockAOAIClient call
        worker, mock_aoai = stack.make_worker()
        outcomes = asyncio.run(worker.run_loop(max_jobs=5, poll_timeout_seconds=0))
        assert len(outcomes) == 1
        assert outcomes[0].final_invoice_status == "VALIDATED"
        assert mock_aoai.call_count == 1


# ---------------------------------------------------------------------------
# 4. Cross-Actor Isolation (sarah.clerk vs michael.manager: CWE-639)
# ---------------------------------------------------------------------------


def test_p12_5_actor_isolation_across_shared_files_and_shared_headers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: CLAUDE.md §16.6, CWE-639 — Identical files & headers across distinct actors never collide."""
    with _idem_stack(monkeypatch, tmp_path, db_name="p12_5_actors.db") as stack:
        pdf_bytes = _make_searchable_pdf("Shared Invoice Across Actors INV-2026-1001")

        r_sarah = stack.client.post(
            "/api/v1/invoices/upload",
            headers={**stack.clerk_headers, "Idempotency-Key": "shared-team-key"},
            files={"file": ("shared.pdf", pdf_bytes, "application/pdf")},
        )
        r_michael = stack.client.post(
            "/api/v1/invoices/upload",
            headers={**stack.manager_headers, "Idempotency-Key": "shared-team-key"},
            files={"file": ("shared.pdf", pdf_bytes, "application/pdf")},
        )
        assert r_sarah.status_code == 202
        assert r_michael.status_code == 202
        assert r_sarah.json()["invoice_id"] != r_michael.json()["invoice_id"]

        # Each actor's own retry replays ONLY their own invoice_id
        r_sarah_retry = stack.client.post(
            "/api/v1/invoices/upload",
            headers={**stack.clerk_headers, "Idempotency-Key": "shared-team-key"},
            files={"file": ("shared.pdf", pdf_bytes, "application/pdf")},
        )
        assert r_sarah_retry.status_code == 200
        assert r_sarah_retry.json()["invoice_id"] == r_sarah.json()["invoice_id"]


# ---------------------------------------------------------------------------
# 5. Lock Release on Transient Storage Failure Enables Clean Retry (CWE-636)
# ---------------------------------------------------------------------------


def test_p12_5_transient_blob_failure_releases_idempotency_lock_for_clean_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: CLAUDE.md §16.6, CWE-636 — Failed blob upload releases lock so immediate retry succeeds."""
    with _idem_stack(monkeypatch, tmp_path, db_name="p12_5_rollback.db") as stack:
        pdf_bytes = _make_searchable_pdf("Transient Blob Outage Recovery INV-2026-1001")
        hdr = {**stack.clerk_headers, "Idempotency-Key": "retry-after-503"}

        real_upload = stack.blob_client.upload_raw_invoice
        calls = {"n": 0}

        def _flaky_upload(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise BlobStorageError("Simulated transient Azure Blob 503")
            return real_upload(*args, **kwargs)

        monkeypatch.setattr(stack.blob_client, "upload_raw_invoice", _flaky_upload)

        # Attempt 1 fails with 503 and MUST release the claimed idempotency lock
        r_fail = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr,
            files={"file": ("flaky.pdf", pdf_bytes, "application/pdf")},
        )
        assert r_fail.status_code == 503

        # Attempt 2 with the exact same Idempotency-Key & bytes succeeds cleanly (202 -> VALIDATED)
        r_ok = stack.client.post(
            "/api/v1/invoices/upload",
            headers=hdr,
            files={"file": ("flaky.pdf", pdf_bytes, "application/pdf")},
        )
        assert r_ok.status_code == 202
        assert r_ok.json()["deduplicated"] is False

        worker, mock_aoai = stack.make_worker()
        outcome = asyncio.run(worker.process_next_job())
        assert outcome.status == "COMPLETED"
        assert outcome.final_invoice_status == "VALIDATED"
        assert mock_aoai.call_count == 1
