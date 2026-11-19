# Phase 12: Comprehensive Interview Questions & Answers — Integration Testing & Security Controls

> **Document Scope:** Deep-dive technical, distributed systems integration, race conditions, atomic locks, 4-layer audit immutability, RBAC spending limits, and security threat modeling covering **Phase 12 (Integration Tests — P12-1 through P12-5)**.  
> **Audience:** Candidates interviewing for Lead Backend Engineer, FinTech Security Architect, or Distributed Systems Principal Engineer roles.

---

## 1. End-to-End Pipeline & Offline Test Architecture

### Q1.1: How do you test a distributed AI ingestion pipeline (FastAPI + Redis + Celery/Worker + Azure OpenAI + Azure SQL) completely offline in CI?

**Answer:**
We designed a tripartite virtualization pattern:
1. **Network Transport:** Tests execute in-process using `httpx.ASGITransport(app=app)`. No real TCP sockets are opened.
2. **Storage & Queue Virtualization:** Azure SQL is replaced with async SQLite (`aiosqlite`), Azure Cache for Redis is replaced with in-memory `fakeredis.aioredis`, and Azure Blob WORM is replaced with a local tempfile/dict client.
3. **Model Gateway Mocking:** `MockAOAIClient` intercepts chat completion calls, matches document hashes against `sample_data/ground_truth/`, and returns structured JSON responses within 5ms.
This architecture allows our full integration suite to execute in **under 10 seconds** on standard GitHub Actions runners with 0 cloud cost.

---

## 2. 4-Layer Audit Immutability Defense

### Q2.1: Why did you implement a 4-layer immutability defense for AuditLogs instead of simply relying on database permissions?

**Answer:**
In enterprise FinTech systems subject to SOX, SEC, and IRS compliance, a single line of defense is insufficient:
1. **Layer 1 (API Layer):** FastAPI routes explicitly disallow `PUT`, `PATCH`, and `DELETE` on `/api/v1/invoices/{id}/audit`, returning `405 Method Not Allowed`.
2. **Layer 2 (Repository Layer):** `AuditLogRepository` defines only `insert()` and `get_by_invoice_id()`. Update and delete methods are completely absent from the class.
3. **Layer 3 (ORM Event Layer):** SQLAlchemy `before_update` and `before_delete` event hooks raise `AuditLogImmutabilityError` if any ORM query attempts to mutate an `AuditLog` instance.
4. **Layer 4 (Database Trigger Layer):** SQLite/SQL triggers (`BEFORE UPDATE` / `BEFORE DELETE`) raise hard database exceptions.
Even if a developer introduces an accidental `DELETE` query or a compromised backend service attempts an update, the database engine itself aborts the statement (`SEC-215`, `SEC-216`).

### Q2.2: Why must the AuditLogger write in an isolated database transaction?

**Answer:**
If an invoice processing step fails and triggers a database `ROLLBACK`, any audit entry written within that same transaction would also be rolled back—erasing the record of the failure! By executing audit writes in an independent session/connection, the audit record of the error remains permanently recorded even when the invoice transaction aborts.

---

## 3. Idempotency & Concurrency Defenses

### Q3.1: How did you prevent race conditions when two identical invoices are uploaded at the exact same millisecond?

**Answer:**
In P12-5, we tested concurrent race conditions where 5 identical upload requests were submitted simultaneously via `asyncio.gather()`:
1. The endpoint computes the SHA-256 payload hash and executes an atomic Redis `SET idempotency:<hash> <invoice_id> NX EX 86400` lock.
2. Exactly **one** request successfully acquires the lock (`SET NX` returns `True`), commits the `Invoice(status='UPLOADED')` record, queues the job to Redis, and returns **`202 Accepted`**.
3. The other 4 concurrent requests find the lock already exists, await the original invoice status, and return **`200 OK`** with `X-Idempotency-Replayed: true`.
4. As verified in `test_idempotency_concurrent_upload_race`, `mock_aoai.call_count` is exactly **1**, completely eliminating duplicate billing and redundant LLM extraction costs.

