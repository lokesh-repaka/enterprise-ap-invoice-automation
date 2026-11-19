# Phase 5: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, distributed systems, FastAPI async concurrency, Redis atomicity, SQL query security, and debugging interview preparation covering **Phase 5 (Invoice Upload API and Job Queue — P5-1 through P5-5)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, Distributed Systems Engineer, Cloud/AI Solution Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [Multipart Invoice Upload API & Async Event-Loop Hygiene (P5-1)](#1-multipart-invoice-upload-api--async-event-loop-hygiene-p5-1)
2. [Redis Job Queue, DLQ Poison-Pill Quarantine & Atomic Primitives (P5-2)](#2-redis-job-queue-dlq-poison-pill-quarantine--atomic-primitives-p5-2)
3. [Background Worker Skeleton & Zero-Trust Pipeline Isolation (P5-3)](#3-background-worker-skeleton--zero-trust-pipeline-isolation-p5-3)
4. [Invoice Detail & Exception Queue Query Security (P5-4)](#4-invoice-detail--exception-queue-query-security-p5-4)
5. [Idempotency Key Deduplication, Conflict Handling & Rollback Safety (P5-5)](#5-idempotency-key-deduplication-conflict-handling--rollback-safety-p5-5)
6. [Real-World Debugging Stories & Security Threat Model Summary](#6-real-world-debugging-stories--security-threat-model-summary)

---

## 1. Multipart Invoice Upload API & Async Event-Loop Hygiene (P5-1)

### Q1.1: Why does `POST /api/v1/invoices/upload` return `202 Accepted` instead of `200 OK` or `201 Created`, and why did you offload file validation and Blob upload via `asyncio.to_thread()`?

**Answer:**
1. **HTTP `202 Accepted` Semantics (RFC 7231 §6.3.3):** Invoice extraction (GPT-4o Vision + deterministic validation rules) takes 3–15 seconds per document. Returning `202 Accepted` with a `Location: /api/v1/invoices/{invoice_id}` header signals truthfully that the raw document has been validated, durably stored in WORM Blob Storage, recorded in SQL (`UPLOADED`), and queued in Redis for asynchronous processing—keeping UI response latency under ~100 ms even during 100-invoice month-end batch uploads.
2. **Preventing Async Event-Loop Starvation (`SEC-078`, `CWE-400`):** FastAPI runs all `async def` handlers on a single `asyncio` event loop. Both `validate_invoice_file()` (CPU-intensive PyMuPDF parsing, ZIP decompression, SHA-256 hashing of up to 25 MB) and `blob_client.upload_raw_invoice()` (synchronous `azure-storage-blob` HTTP network I/O) are **blocking**. Calling them directly inside `async def upload_invoice()` would freeze every concurrent request on that worker (including `/health` probes, rate limiter checks, and clerk reads). Offloading both via `await asyncio.to_thread(...)` keeps the event loop responsive under load.

---

### Q1.2: How do you prevent a malicious client from OOM-crashing FastAPI with a 1 GB upload to `/api/v1/invoices/upload`?

**Answer:**
We enforce a **two-layer memory defense (`SEC-077`, `CWE-400`)**:
1. **Pre-Parse `Content-Length` Guard (`guard_upload_content_length` dependency):** Runs before file reading and immediately rejects requests declaring `Content-Length > 26 MB` (`25 MB + 1 MB` multipart framing overhead) with `413`, and rejects negative or non-numeric `Content-Length` headers with `400`.
2. **Bounded 64 KB Streaming Reader (`_read_upload_bounded`):** Never calls unbounded `await file.read()` (which handles chunked transfer-encoding requests lacking `Content-Length`). Instead, reads `64 KB` chunks in a loop, aborting immediately with `HTTP 413` the moment cumulative bytes exceed `25 MB` (`MAX_UPLOAD_SIZE_BYTES`), and always calls `await file.close()` in a `finally` block so temp file descriptors never leak.

---

### Q1.3: How do you handle inserting an `Invoice` row in SQL at upload time when OCR hasn't extracted the vendor yet and `invoices.vendor_tax_id` is a `NOT NULL` Foreign Key?

**Answer:**
In Phase 2, `invoices.vendor_tax_id` was intentionally modeled as a strict `NOT NULL` Foreign Key referencing `vendors.vendor_tax_id` so every invoice in SQL maintains referential integrity.
At upload time (`P5-1`):
- If the caller supplies an optional `vendor_id` form parameter, we look up that vendor in SQL and verify `vendor.is_active == True` (rejecting unknown or deactivated vendors with `422` *before* writing any orphan WORM blob).
- If the caller omits `vendor_id` (standard drag-and-drop invoice intake), `_ensure_unknown_sentinel_vendor()` idempotently provisions a system placeholder vendor (`vendor_tax_id="UNKNOWN"`, `vendor_id="UNKNOWN"`, `is_active=False`) with concurrent `IntegrityError` rollback handling. Because `is_active=False`, `VendorRepository.list_all(active_only=True)` continues to return strictly the 15 real active vendors without polluting UI dropdowns!

---

## 2. Redis Job Queue, DLQ Poison-Pill Quarantine & Atomic Primitives (P5-2)

### Q2.1: How does `RedisJobQueueClient` handle poison-pill messages and protect Azure Cache for Redis Basic B0 (250 MB RAM)?

**Answer:**
1. **Automatic Poison-Pill DLQ Quarantine (`SEC-086`):** If a corrupted JSON string, oversized payload (`> 64 KB`), or schema-invalid job (e.g., traversal `blob_name`) is popped by `dequeue()`, a naive worker would crash and leave the queue wedged or lose the message silently. Instead, `dequeue()` catches the validation failure, wraps a bounded `2 KB` preview + sanitized failure reason + UTC timestamp into `ap:queue:invoices:dlq`, and raises `RedisJobPayloadError` so the worker logs the event and immediately moves on to the next healthy job.
2. **250 MB RAM Memory Ceilings:** Azure Cache for Redis Basic B0 (`HLD §256`) has 250 MB RAM. We bound memory across all three surfaces:
   - Individual job payloads capped at **`64 KB`** (`MAX_JOB_PAYLOAD_BYTES`).
   - Main queue capped at **`100,000` jobs** (`MAX_QUEUE_DEPTH`)—failing closed with `RedisQueueError` backpressure rather than triggering Redis OOM eviction of active idempotency keys.
   - Dead-Letter Queue capped via **`LTRIM dlq -10000 -1`** (`MAX_DLQ_LENGTH = 10,000`).

---

### Q2.2: Why did you use Redis `WATCH / MULTI / EXEC` optimistic locking for `update_idempotency_status()` and `release_idempotency_key()` instead of simple `GET` then `SET`/`DEL`?

**Answer:**
A naive check-then-act sequence (`GET` -> verify `invoice_id` -> `DEL`) suffers from a classic **TOCTOU race condition (`SEC-083`, `CWE-362`)**:
1. Request A (failing upload `inv-1`) calls `GET` and confirms it owns key `K`.
2. Key `K` expires (or is deleted) right before Request A calls `DEL`.
3. Request B (`inv-2`) immediately acquires key `K` via `SET NX EX`.
4. Request A executes `DEL K` — **accidentally deleting Request B's active lock!**

By wrapping both `update_idempotency_status()` (with `XX KEEPTTL` so TTL never resets!) and `release_idempotency_key()` in `WATCH key` → `GET` → owner check → `MULTI` → `SET`/`DEL` → `EXEC` and catching `WatchError`, Redis atomically aborts the transaction if any other client modified key `K` after `WATCH`, guaranteeing zero foreign-lock deletions or lost updates.

---

### Q2.3: Why did you switch from `f"{clerk_id}:{raw_key}"` to null-byte delimited hashing in `hash_client_idempotency_key()`?

**Answer:**
Simple delimiter concatenation (`f"{clerk_id}:{raw_key}"`) is vulnerable to **tuple-boundary collisions (`CWE-327`)**: `clerk_id="a:b", raw_key="c"` produces the exact same pre-image (`"a:b:c"`) as `clerk_id="a", raw_key="b:c"`.
Since both `clerk_id` and `raw_key` strictly forbid ASCII control characters (including `\x00`), hashing `b"client-idem\x00" + clerk_id + b"\x00" + raw_key` guarantees mathematical injectivity (zero boundary collisions) **and** strict domain separation from content-derived keys (`SHA256(file_bytes + clerk_id)`).

---

## 3. Background Worker Skeleton & Zero-Trust Pipeline Isolation (P5-3)

### Q3.1: How does `InvoiceBackgroundWorker` enforce the `CLAUDE.md §8` invariant that no AI model or pipeline can ever self-approve an invoice?

**Answer:**
This is a **Critical security boundary (`SEC-089`, `CWE-863`)**. If a prompt-injected invoice or buggy validation module returned `PipelineResult(target_status="APPROVED_CLERK")` or `"APPROVED_MANAGER"`, blindly persisting that status would bypass human RBAC and high-value >\$10,000 manager sign-off!
In `src/services/worker.py`:
- `_validate_pipeline_result()` checks `result.target_status` against an explicit non-approval allowlist (`ALLOWED_PIPELINE_TARGET_STATUSES`), which strictly **excludes** `APPROVED_CLERK`, `APPROVED_MANAGER`, and `STAGED_FOR_EXPORT`.
- Any violation raises `PipelineStatusViolationError`—immediately escalating the invoice to `REQUIRES_APPROVAL` (Human Exception Queue), recording an isolated-tx `AuditLog`, and quarantining the job to the DLQ.

---

### Q3.2: What defenses prevent a tampered Redis job from making the worker process the wrong invoice's PDF or overwrite an already-approved invoice?

**Answer:**
We enforce **three independent pre-pipeline security checks** in `InvoiceBackgroundWorker.process_job()`:
1. **Entry-State Guard (`SEC-093`, `CWE-841`):** Only invoices currently in `{"UPLOADED", "EXTRACTING"}` are eligible. Replaying an old queue message for an `APPROVED_CLERK`, `APPROVED_MANAGER`, or `VALIDATED` invoice returns `SKIPPED_INVALID_STATE` with zero SQL mutation and zero pipeline calls.
2. **Cross-Invoice Blob-Swap Guard (`SEC-090`, `CWE-639`):** Verifies `job.blob_name` starts with `raw-invoices/{job.invoice_id}/` **AND** matches the `Invoice.blob_raw_url` recorded in SQL at upload time—blocking an attacker from pairing Invoice A's ID with Invoice B's PDF path.
3. **End-to-End Cryptographic `FileHash` Parity (`SEC-091`, `CWE-354`):** Downloads raw bytes from WORM Blob Storage, runs `verify_blob_metadata_integrity(raw_bytes, stored_meta)`, and checks constant-time `hmac.compare_digest(verified_meta.file_hash, job.file_hash)` before calling the pipeline.

---

## 4. Invoice Detail & Exception Queue Query Security (P5-4)

### Q4.1: Why MUST `GET /api/v1/invoices/exceptions` be registered before `GET /api/v1/invoices/{invoice_id}`, and how do you protect the filter parameters against SQL injection and DoS?

**Answer:**
1. **Route Precedence:** FastAPI evaluates routes in registration order. If `/{invoice_id}` were registered first, `GET /api/v1/invoices/exceptions` would match `invoice_id="exceptions"` and return `404 Not Found`! Registering `/exceptions` first guarantees deterministic static routing.
2. **SQL Injection & LIKE Wildcard DoS Defense (`SEC-095`, `CWE-89` / `CWE-400`):**
   - All filters use strictly parameterized SQLAlchemy ORM expressions (zero f-string SQL).
   - Free-text search parameters (`vendor_name`, `invoice_number`) pass through `_escape_like()` escaping `\`, `%`, and `_` with `escape="\\"`—preventing attackers from sending `?vendor_name=%` to force full-table wildcard scans.
   - `sort_by` maps through an explicit `ALLOWED_SORT_COLUMNS` dictionary (`created_at`, `total_amount`, `confidence_macro_avg`, `invoice_date`)—never `getattr(Invoice, user_input)`.
   - Query bounds cap `status` list length (`<= 7`), `limit <= 100`, `offset <= 100,000`, finite `Decimal` magnitude, and non-inverted date/amount ranges.
3. **Data Minimization & Zero-Hydration Audit Count (`SEC-096`, `SEC-098`):**
   - `ExceptionQueueItem` intentionally omits `vendor_tax_id` and `composite_hash` from bulk listings (`CWE-200`).
   - `get_invoice_detail()` passes `include_audit_logs=False` and runs `AuditLogRepository.count_by_invoice_id()` (`SELECT COUNT(*)`) instead of hydrating potentially hundreds of `AuditLog` ORM rows into RAM on every poll!

---

## 5. Idempotency Key Deduplication, Conflict Handling & Rollback Safety (P5-5)

### Q5.1: Walk through what happens when a clerk accidentally submits the exact same invoice twice—and what happens if an upload fails halfway through?

**Answer:**
1. **Identical Re-Submission (`LLD §6.1`):**
   - Without an explicit header, we compute `SHA256(raw_bytes + clerk_id)` (`compute_idempotency_key`). With an `Idempotency-Key` header, we compute null-byte-delimited `SHA256("client-idem\x00" + clerk_id + "\x00" + header)` (`hash_client_idempotency_key`).
   - `claim_idempotency_key()` runs atomic `SET ap:idempotency:<hash> <json> NX EX 86400`.
   - On the second submission, `SET NX` returns `False`. We verify `file_hash` (constant-time `hmac.compare_digest`) and `vendor_id` match (returning **`409 Conflict`** if a client reused an explicit `Idempotency-Key` for a different file or vendor — `SEC-101`).
   - We query SQL for the live `Invoice` row (falling back cleanly to the Redis record if Request 1 is still mid-flight — `SEC-103`) and return **`HTTP 200 OK`** with the existing `invoice_id`, live `status` (e.g., `VALIDATED`), `deduplicated=True`, `queued=False`, `Location`, `Cache-Control: no-store`, and `X-Idempotency-Replayed: true`—zero duplicate Blob writes, SQL rows, or Redis jobs!
2. **Mid-Flight Failure Rollback (`SEC-103`):**
   - If WORM Blob upload, SQL insert, or `AuditLog` write fails *after* claiming the Redis idempotency slot, `_try_release_idempotency_key()` runs our owner-verified `WATCH/MULTI/EXEC` release so the clerk can retry immediately instead of being locked out for 24 hours by a ghost key!

---

## 6. Real-World Debugging Stories & Security Threat Model Summary

### Story 1: Eliminating Starlette 0.48+ Deprecation Warnings Without Breaking Older CI Starlette
During P5-1 testing on Python 3.13, `status.HTTP_422_UNPROCESSABLE_ENTITY` and `status.HTTP_413_REQUEST_ENTITY_TOO_LARGE` emitted `StarletteDeprecationWarning` recommending `HTTP_422_UNPROCESSABLE_CONTENT` / `HTTP_413_CONTENT_TOO_LARGE`. However, blindly switching to the new constant names could break older Starlette versions resolved by `fastapi>=0.110.0` in CI. Using canonical integer codes `422` and `413` eliminated all deprecation warnings locally while guaranteeing 100% cross-version compatibility in GitHub Actions!

### Story 2: Catching Reflected Error Injection & Audit Hydration Bloat in P5-4 Code Review
During our P5-4 security review, we spotted two subtle issues before merge:
1. Our initial `422` error for invalid `status` echoed `f"Unsupported exception status filter '{st}'"`—meaning `?status=<script>alert(1)</script>` reflected raw HTML into the JSON error body (`SEC-099`, `CWE-116`). Replacing it with a static message eliminated error reflection completely.
2. `get_invoice_detail()` was calling `get_by_id(include_relations=True)` (which `selectinload`ed all `AuditLog` rows) just to take `len(invoice.audit_logs)`. Adding `include_audit_logs=False` and `AuditLogRepository.count_by_invoice_id()` turned an O(N) ORM hydration into a single O(1) SQL `COUNT(*)` query (`SEC-098`).

### Story 3: Unifying Upload Enqueueing Through `RedisJobQueueClient` in P5-5
In P5-1 (built before P5-2 existed), `upload_invoice()` called `await redis_client.rpush(...)` directly. During P5-5's security audit, we noticed that bypassed `RedisJobQueueClient.enqueue()`'s `64 KB` payload cap, `blob_url` scheme guard, and `100,000`-job queue backpressure cap (`SEC-105`). Routing upload enqueueing through `queue_client.enqueue(InvoiceQueueJob(...))` unified the entire API-to-Worker contract under one validated client.

---

### Phase 5 Security Threat Model Summary (29 Findings — All Mitigated ✅)

| Severity | Count | Findings (`SEC-077`–`SEC-105`) |
|---|---:|---|
| **Critical** | 1 | `SEC-089` (unauthorized pipeline self-approval `APPROVED_*`) |
| **High** | 18 | `SEC-077` (multipart OOM / `Content-Length`), `SEC-078` (event-loop blocking), `SEC-079` (`FakeRedis` in prod), `SEC-080` (upload RBAC), `SEC-083` (idempotency TOCTOU), `SEC-084` (plaintext Redis / prod gate), `SEC-085` (Redis key injection / cross-clerk collision), `SEC-086` (poison pill / B0 RAM exhaustion), `SEC-090` (cross-invoice blob swap), `SEC-091` (`FileHash` tampering), `SEC-092` (hung job timeout / busy-spin), `SEC-093` (terminal invoice replay), `SEC-095` (SQLi / LIKE wildcard DoS), `SEC-096` (bulk `vendor_tax_id` PII exposure), `SEC-097` (read route RBAC), `SEC-101` (`Idempotency-Key` payload/`vendor_id` conflict), `SEC-102` (cross-clerk idempotency IDOR), `SEC-103` (concurrent race & ghost lock) |
| **Medium** | 10 | `SEC-081` (false 202 / error leak), `SEC-082` (upload cache/PII logs), `SEC-087` (unsafe URL/status), `SEC-088` (Redis error cred leak), `SEC-094` (JSON upload/confidence/ctx leak), `SEC-098` (query flood & audit hydration DoS), `SEC-099` (reflected XSS in status error), `SEC-100` (read cache/DB error leak), `SEC-104` (`Idempotency-Key` header injection), `SEC-105` (raw `rpush` guard bypass) |
| **Total** | **29** | **100% Mitigated ✅ · 105 Cumulative Findings Audited (0 Open) · 193 Offline Tests Passing** |
