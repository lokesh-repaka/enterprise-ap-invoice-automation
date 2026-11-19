# Phase 5: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 5 (Invoice Upload API and Job Queue — P5-1 through P5-5)**.  
> **Target Audience:** Solution Architects, Backend Leads, Distributed Systems Engineers, and System Design Interviewers.

---

## 1. Phase 5 Mission & Architectural Baseline

Entering Phase 5, the platform had all four foundational infrastructure layers verified with **150 passing tests** and **76 mitigated security findings**:
- **Phase 1:** FastAPI runtime skeleton, JSON PII-masked logging, offline test harness, CI pipeline.
- **Phase 2:** Dual-dialect async SQLAlchemy 2.0 persistence tier (5 tables, repositories, composite-hash uniqueness).
- **Phase 3:** Entra ID RS256 RBAC, ephemeral demo tokens, Redis sliding-window rate limiter, isolated-tx `AuditLogger`, keyless Key Vault stub.
- **Phase 4:** Keyless Azure Blob WORM client, hardened local Azurite emulator, deep magic-byte file validator, and canonical `VendorID`/`UploadTimestamp`/`FileHash` metadata tagging.

The mission of **Phase 5** was to orchestrate those layers into a **decoupled, idempotent, asynchronous invoice ingestion, queueing, background processing, and read/filter API tier** enforcing six invariants:

1. **Non-Blocking Async Ingestion (`P5-1`, `CWE-400`):** Bounded 64 KB multipart streaming (`<= 25 MB`), pre-parse `Content-Length` DoS guard, and `asyncio.to_thread` offloading for CPU-bound validation and synchronous storage I/O.
2. **Fail-Closed Distributed Reliability (`P5-1`, `P5-2`, `CWE-636`):** Never return a false `202 Accepted` when Blob, SQL, Audit, or Redis fails; enforce TLS `rediss://` in production and hard-block `USE_FAKE_REDIS` outside local dev/SQLite.
3. **Poison-Pill Resilience & Backpressure (`P5-2`, `CWE-400`):** Quarantine malformed queue payloads into a `LTRIM`-bounded Dead-Letter Queue (`10,000` max) and enforce `64 KB` job / `100,000` depth limits to protect Azure Cache for Redis Basic B0 (`250 MB`).
4. **Zero-Trust Background Execution (`P5-3`, `CLAUDE.md §8`, `CWE-863` / `CWE-639` / `CWE-354`):** Pluggable `InvoicePipelineProtocol` wrapped by a strict non-approval status allowlist (hard-blocking `APPROVED_*`), cross-invoice blob-swap guard, constant-time `FileHash` verification, per-job timeout, and bounded retry -> DLQ escalation.
5. **Data-Minimized, Injection-Proof Read & Exception Queries (`P5-4`, `CWE-89` / `CWE-200`):** Parameterized SQLAlchemy filters with escaped `LIKE` wildcards, explicit sort-column allowlist, `COUNT(*)` audit counts (no unbounded ORM hydration), and omitted `vendor_tax_id` on bulk exception lists.
6. **Atomic Race-Safe Idempotency Deduplication (`P5-5`, `LLD §6.1`, `CWE-362` / `CWE-345`):** Atomic Redis `SET NX EX` claims (`SHA256(file_bytes + clerk_id)` or actor-scoped `Idempotency-Key` header), `200 OK` live-status replays, `409 Conflict` on payload/`vendor_id` mismatch, and `WATCH/MULTI/EXEC` lock rollback on downstream failure.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 4 Baseline (Unconnected Building Blocks)

At the end of Phase 4, the storage validator, WORM client, SQL repositories, and RBAC guards existed independently—with no invoice HTTP routes, no Redis job queue client, and no background worker.

```mermaid
flowchart LR
    API["src/api/ (Only /health & /auth/*)"]
    DB["src/database/ (5 Async Tables & Repos)"]
    ST["src/storage/ (Validator + WORM + Metadata)"]
    SVC["src/services/ (Empty Placeholder)"]

    API -.->|"No Invoice Routes"| DB
    API -.->|"No Upload Intake"| ST
    SVC -.->|"No Worker"| DB

    style SVC fill:#ffebee,stroke:#c62828,stroke-width:2px;
```

---

### 2.2 Stage 1 (P5-1): Multipart Invoice Upload API (`src/api/invoices.py`, PR #15)

In **P5-1 (`feature/api-invoice-upload`)**, we built `POST /api/v1/invoices/upload` and created the typed schema package `src/api/schemas/invoices.py`.

```mermaid
flowchart TD
    REQ["POST /api/v1/invoices/upload (Multipart + Bearer JWT)"] --> CL["guard_upload_content_length (<= 26 MB, Reject Negative/Malformed)"]
    CL --> RBAC["require_role(AP_CLERK, FINANCE_MANAGER) (Unauth -> 401, Admin -> 403)"]
    RBAC --> STREAM["_read_upload_bounded (64 KB Chunks, Abort > 25 MB -> 413)"]
    STREAM --> VAL["asyncio.to_thread(validate_invoice_file) (413 / 415 / 422)"]
    VAL --> VEND["Resolve Active Vendor OR Idempotent Inactive 'UNKNOWN' Sentinel"]
    VEND --> BLOB["asyncio.to_thread(blob_client.upload_raw_invoice) (WORM + Metadata)"]
    BLOB --> SQL["InvoiceRepository.create(status='UPLOADED')"]
    SQL --> AUD["AuditLogger.record(INGEST, Isolated Tx + request_id)"]
    AUD --> REDIS["Enqueue JSON Job onto ap:queue:invoices (Fail-Closed -> 503)"]
    REDIS --> RESP["202 Accepted + Location + Cache-Control: no-store"]

    style RBAC fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style VAL fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style RESP fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

### 2.3 Stage 2 (P5-2): Redis Job Queue & Atomic Idempotency Client (`src/core/redis_client.py`, PR #16)

In **P5-2 (`feature/core-redis-job-queue`)**, we extracted a dedicated, production-hardened async Redis client in `src/core/redis_client.py` supporting FIFO job operations, DLQ poison-pill quarantine, and atomic idempotency primitives.

```mermaid
flowchart TD
    CFG["get_redis_queue_client(settings)"] --> GATE{"Production Safety Gate"}
    GATE -->|"USE_FAKE_REDIS=true outside dev OR SQLite=false"| BLOCK["RedisQueueConfigurationError"]
    GATE -->|"Non-dev AND scheme != rediss://"| BLOCK
    GATE -->|"Valid"| CLIENT["RedisJobQueueClient"]

    CLIENT --> ENQ["enqueue(InvoiceQueueJob): Validate ID/Path/URL/SHA256, <=64 KB, Depth < 100k -> RPUSH"]
    CLIENT --> DEQ["dequeue(timeout 0..30s): LPOP / BLPOP"]
    DEQ -->|"Valid JSON"| JOB["InvoiceQueueJob"]
    DEQ -->|"Corrupted / Poison Pill"| DLQ["Quarantine to ap:queue:invoices:dlq (LTRIM 10,000) + Raise RedisJobPayloadError"]

    CLIENT --> IDEM["Idempotency Primitives (ap:idempotency:<sha256>)"]
    IDEM --> CLAIM["claim_idempotency_key(): Atomic SET NX EX (Zero TOCTOU)"]
    IDEM --> UPD["update_idempotency_status(): WATCH/MULTI/EXEC + XX KEEPTTL"]
    IDEM --> REL["release_idempotency_key(): Owner-Verified WATCH/MULTI/EXEC DEL"]

    style GATE fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style DLQ fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style IDEM fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
```

---

### 2.4 Stage 3 (P5-3): Background Worker Skeleton (`src/services/worker.py`, PR #17)

In **P5-3 (`feature/worker-pipeline-skeleton`)**, we built `InvoiceBackgroundWorker` in `src/services/` (strictly zero direct HTTP imports per `CLAUDE.md §4.2`) with a pluggable `InvoicePipelineProtocol` ready for Phases 6–8.

```mermaid
flowchart TD
    POLL["process_next_job() -> RedisJobQueueClient.dequeue()"] -->|"None"| EMPTY["SKIPPED_EMPTY (Sleep 50ms if poll=0)"]
    POLL -->|"Poison Pill"| PILL["POISON_PILL_DLQ (Already Quarantined)"]
    POLL -->|"InvoiceQueueJob"| CTX["Set request_id_ctx (Guaranteed Reset in finally)"]

    CTX --> STATE{"SQL Entry State in {UPLOADED, EXTRACTING}?"}
    STATE -->|"Missing SQL Row"| MISS["DLQ + SKIPPED_MISSING_INVOICE"]
    STATE -->|"Already VALIDATED / APPROVED_*"| SKIP["SKIPPED_INVALID_STATE (Zero Mutation)"]
    STATE -->|"Eligible"| TRANS["SQL -> EXTRACTING + Isolated AuditLog(STATUS_TRANSITION)"]

    TRANS --> SWAP{"blob_name Matches raw-invoices/{id}/ & SQL blob_raw_url?"}
    SWAP -->|"No (CWE-639)"| ESC["Escalate -> REQUIRES_APPROVAL + Audit + DLQ"]
    SWAP -->|"Yes"| HASH{"Download Blob + verify_blob_metadata_integrity() == job.file_hash?"}
    HASH -->|"Mismatch / Missing (CWE-354)"| ESC
    HASH -->|"Verified"| PIPE["asyncio.wait_for(pipeline.execute(ctx), timeout)"]

    PIPE -->|"Status in APPROVED_* (CWE-863)"| ESC
    PIPE -->|"Timeout / Transient Error"| RETRY{"attempt < max_retries?"}
    RETRY -->|"Yes"| REENQ["Re-Enqueue (attempt + 1) -> RETRIED"]
    RETRY -->|"No"| ESC
    PIPE -->|"Valid Non-Approval Status"| SAVE["Optional extraction.json WORM Write + SQL Update + AuditLog(EXTRACTION) -> COMPLETED"]

    style SWAP fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style HASH fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style SAVE fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

### 2.5 Stage 4 (P5-4): Invoice Detail & Exception Queue Read Routes (`src/api/invoices.py` & `repositories.py`, PR #18)

In **P5-4 (`feature/api-invoice-read-routes`)**, we added `GET /api/v1/invoices/exceptions` (registered strictly *before* `/{invoice_id}`!) and `GET /api/v1/invoices/{invoice_id}`.

```mermaid
flowchart LR
    USER["AP Clerk / Finance Manager (Bearer JWT)"] --> EXC["GET /api/v1/invoices/exceptions (Registered 1st)"]
    USER --> DET["GET /api/v1/invoices/{invoice_id} (Registered 2nd)"]

    EXC --> F_VAL["Filter Guards: <=7 Exception Statuses, Escaped LIKE (%, _), Finite Decimals, Allowlisted Sort, limit<=100"]
    F_VAL --> REPO_E["InvoiceRepository.list_exceptions() (Parameterized + Exact COUNT)"]
    REPO_E --> MIN["ExceptionQueueResponse (Omit raw vendor_tax_id & composite_hash + no-store)"]

    DET --> ID_VAL["Regex Guard: ^[A-Za-z0-9_-]{1,64}$ (Block SQLi/Traversal -> 422)"]
    ID_VAL --> REPO_D["get_by_id(include_audit_logs=False) + AuditLogRepository.count_by_invoice_id()"]
    REPO_D --> FULL["InvoiceDetailResponse (Header + Ordered Lines + audit_event_count + no-store)"]

    style F_VAL fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style MIN fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

### 2.6 Stage 5 (P5-5): Atomic Upload Idempotency Key Deduplication (`src/api/invoices.py`, PR #19)

In **P5-5 (`feature/api-idempotency-dedup`)**, we closed the loop by wiring atomic `SET NX EX` idempotency claims, live SQL status replays, `409 Conflict` payload/`vendor_id` guards, and owner-verified rollback release directly into `POST /api/v1/invoices/upload`—and unified upload enqueueing through `RedisJobQueueClient.enqueue()`.

```mermaid
flowchart TD
    UP["Validated Upload (raw_bytes, validated, resolved_vendor_id)"] --> KEY{"Idempotency-Key Header Present?"}
    KEY -->|"Yes"| HK["hash_client_idempotency_key(hdr, clerk_id) (Null-Byte Scoped SHA-256)"]
    KEY -->|"No"| CK["compute_idempotency_key(raw_bytes, clerk_id) (LLD §6.1)"]

    HK & CK --> CLAIM["Atomic SET NX EX: claim_idempotency_key(key, new_id, file_hash)"]
    CLAIM -->|"acquired=False (Replay!)"| CHECK{"file_hash & explicit vendor_id Match?"}
    CHECK -->|"Mismatch (CWE-345)"| C409["409 Conflict (Reject Key Reuse)"]
    CHECK -->|"Match"| LIVE["Refresh Live SQL Invoice (Fallback to Redis if In-Flight)"]
    LIVE --> R200["200 OK (deduplicated=True, queued=False, X-Idempotency-Replayed: true)"]

    CLAIM -->|"acquired=True (New!)"| WRITE["WORM Blob -> SQL Invoice -> AuditLog(INGEST)"]
    WRITE -->|"Blob / SQL / Audit Fails"| ROLL["Best-Effort WATCH/MULTI/EXEC release_idempotency_key() -> 503"]
    WRITE -->|"Success"| ENQ["RedisJobQueueClient.enqueue(InvoiceQueueJob) -> 202 Accepted"]

    style CLAIM fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style C409 fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style R200 fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style ENQ fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

## 3. Key Architectural Trade-Offs Made in Phase 5

| Design Decision | Alternative Considered | Why We Chose Our Approach |
|---|---|---|
| **Inactive `UNKNOWN` sentinel vendor in `vendors` table for pre-OCR uploads** | Dropping the `NOT NULL` / FK constraint on `invoices.vendor_tax_id` | Preserves Phase 2 DDL & foreign-key integrity on both SQLite and Azure SQL with zero schema breakage, while `is_active=False` keeps `VendorRepository.list_all(active_only=True)` strictly limited to the 15 real vendors. |
| **Redis `RPUSH` + `LPOP`/`BLPOP` + `WATCH/MULTI/EXEC` inside `RedisJobQueueClient`** | Introducing Celery + RabbitMQ right away | Keeps Phase 5 100% pure-Python async, zero extra broker containers, `fakeredis` offline parity in 0.04s, and fits Azure Cache for Redis Basic B0 (\$16/mo per HLD §256) with explicit `64 KB` / `100k` / `10k DLQ` memory ceilings. |
| **Pluggable `InvoicePipelineProtocol` with conservative `DefaultSkeletonPipeline`** | Hardcoding mock extraction directly inside the worker | Cleanly decouples queue orchestration & security invariants (`P5-3`) from Azure OpenAI extraction (`Phase 6`) and deterministic rules (`Phase 7`), while ensuring unextracted invoices default to `REQUIRES_REVIEW` rather than false `VALIDATED`. |
| **SQL `COUNT(*)` for `audit_event_count` instead of eager-loading `Invoice.audit_logs`** | `len(invoice.audit_logs)` with `selectinload(Invoice.audit_logs)` | Prevents hydrating hundreds of historical audit rows on every Streamlit detail poll (`SEC-098`, `CWE-400`), leaving full audit timeline fetching cleanly to `GET /api/v1/invoices/{id}/audit` (P9-3). |
| **Returning `409 Conflict` when an explicit `Idempotency-Key` is reused with different bytes or `vendor_id`** | Silently returning the cached first invoice | Follows IETF `Idempotency-Key` draft spec and blocks subtle client bugs where a clerk's retry sends Invoice B under Invoice A's key (`SEC-101`, `CWE-345`). |

---

## 4. Verification & Security Evolution Across Phase 5

| Subtask | PR | New Tests | Cumulative Offline Tests | Security Findings Mitigated |
|---|---|---|---|---|
| Phase 4 Baseline | #11–#14 | — | 150 | 76 (`SEC-001`–`SEC-076`) |
| **P5-1** `POST /api/v1/invoices/upload` | #15 | +11 | 161 | +6 (`SEC-077`–`SEC-082`: 4 High, 2 Medium) |
| **P5-2** `src/core/redis_client.py` | #16 | +9 | 170 | +6 (`SEC-083`–`SEC-088`: 4 High, 2 Medium) |
| **P5-3** `src/services/worker.py` | #17 | +9 | 179 | +6 (`SEC-089`–`SEC-094`: 1 Critical, 4 High, 1 Medium) |
| **P5-4** `GET /invoices/{id}` & `/exceptions` | #18 | +7 | 186 | +6 (`SEC-095`–`SEC-100`: 3 High, 3 Medium) |
| **P5-5** Idempotency Key Deduplication | #19 | +7 | **193** | +5 (`SEC-101`–`SEC-105`: 3 High, 2 Medium) |
| **Phase 5 Total** | **#15–#19** | **+43 tests** | **193 passing (5.34s)** | **+29 findings (105 total, 0 open)** |

