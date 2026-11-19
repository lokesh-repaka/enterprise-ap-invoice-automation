# Phase 9: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 9 (Re-Validation and Approval API — P9-1 through P9-4)**.  
> **Target Audience:** Solution Architects, Backend Leads, Staff Engineers, Financial Systems Engineers, and System Design Interviewers.

---

## 1. Phase 9 Mission & Architectural Baseline

Entering Phase 9, Phases 1–8 and Phase 10 were complete (**43 / 68 tasks · 63%**, **538 passing offline tests**, **172 mitigated security findings**):
- **Phase 5 (`src/api/invoices.py`):** Exposed `POST /api/v1/invoices/upload`, `GET /api/v1/invoices/exceptions`, and `GET /api/v1/invoices/{id}`.
- **Phase 7 (`src/validation/`):** Built the 5 deterministic accounting validators chained inside `RulesEngine` (`validate_extraction` + `validate_revalidation`).
- **Phase 8 (`src/validation/`):** Built `ConfidenceRouter` (tri-tier routing + re-validation promotion), `InvoiceStateMachine` (17-status immutable FSM + SQL atomic CAS), and `EscalationEvaluator` (`>\$10k` USD via ECB FX + `>5%` PO variance).

What remained unbuilt at the end of Phase 8 was the **human-in-the-loop REST API & Service Orchestration Layer** connecting Phase 3 Entra ID RBAC, Phase 2 async SQL repositories, Phase 7/8 deterministic validation engines, and Phase 3 isolated-transaction audit logging—while strictly honoring `CLAUDE.md §4.2` layering rules (**zero validation logic inside `src/api/`, zero HTTP/FastAPI imports inside `src/services/`**).

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 8 Baseline (Engines Built, Human Action Endpoints Missing)

At the end of Phase 8, invoices could be uploaded, queued, extracted, validated, and read—but AP Clerks, Finance Managers, and Auditors had no HTTP routes to re-validate exceptions, execute role-gated approvals, or retrieve full audit trails.

```mermaid
flowchart LR
    UI["Streamlit UI (Phase 11)"] -.->|"Missing P9-1/P9-4"| Rev["POST /revalidate"]
    UI -.->|"Missing P9-2"| App["POST /approve"]
    UI -.->|"Missing P9-3"| Aud["GET /audit"]

    subgraph Existing ["Existing Phases 2–8 Core"]
        API["src/api/invoices.py (upload, exceptions, detail)"]
        Val["src/validation/ (RulesEngine, ConfidenceRouter, FSM, Escalation)"]
        DB["src/database/ (5 Async Repositories)"]
        Log["src/core/audit.py (Isolated AuditLogger)"]
    end

    API --> DB
    API --> Log
```

---

### 2.2 Stage 1 — P9-1: Re-Validation Endpoint & Orchestration Service (`POST /api/v1/invoices/{id}/revalidate`)

We introduced a strict two-tier separation:
- **Thin API Controller (`src/api/invoices.py` + `src/api/schemas/invoices.py`):** Enforces `require_role(Role.AP_CLERK)`, 1 MB `Content-Length` fail-fast cap (`SEC-175`), `invoice_id` regex validation, anti-impersonation `clerk_id` JWT verification, and strict `extra="forbid"` Pydantic request schemas (`InvoiceRevalidateRequest`, `InvoiceHeaderEdits`, `InvoiceLineEdit`).
- **Orchestration Service (`src/services/revalidation.py`):** Owns the complete transactional workflow without importing FastAPI or HTTP libraries.
- **Atomic Persistence (`src/database/repositories.py::apply_revalidation_edits` — `SEC-173`):** Commits header + line edits in ONE SQL transaction verifying `expected_status == "REVALIDATING"`, field allowlists, and line ownership (`line.invoice_id == invoice_id`).

```mermaid
flowchart TD
    Req["POST /api/v1/invoices/{id}/revalidate (ap_clerk JWT)"] --> Size["Content-Length <= 1 MB (SEC-175)"]
    Size --> Schema["Pydantic v2 extra='forbid' + ReasonCode + OTHER Comment + Tax Override Governance (SEC-174)"]
    Schema --> Actor["Verify Optional clerk_id == JWT Principal (403 on Spoof)"]
    Actor --> Svc["RevalidationService.revalidate() (src/services/revalidation.py)"]

    Svc --> Load["Load Invoice + Active Vendor (SEC-176) + Lines"]
    Load --> FSMCheck["Pre-check FSM Entry Legality (-> REVALIDATING; 409 if Disallowed)"]
    FSMCheck --> Lock["Atomic CAS Lock: previous_status -> REVALIDATING (CWE-362)"]

    Lock --> DupHash["Check Recomputed composite_hash Collision (409 + Rollback Lock)"]
    DupHash --> Rules["RulesEngine.validate_revalidation() (FR-05/06/07/08/11)"]
    Rules --> Conf["ConfidenceRouter.route_revalidation() (Preserve Original Model Confidence)"]
    Conf --> Esc["EscalationEvaluator + ExchangeRateRepository (Live Invoice-Date ECB FX)"]
    Esc --> AtomicDB["InvoiceRepository.apply_revalidation_edits() (Single SQL Tx: SEC-173)"]
    AtomicDB --> FinalFSM["InvoiceStateMachine.transition(): REVALIDATING -> VALIDATED | REQUIRES_MANAGER_APPROVAL | REQUIRES_APPROVAL | CREDIT_NOTE"]
    FinalFSM --> Audit["AuditLogger (Isolated Tx): EDIT rows (changed fields only) + REVALIDATE row"]
    Audit --> Resp["200 OK InvoiceRevalidateResponse (Cache-Control: no-store)"]
```

**Key Architectural Decisions in P9-1:**
- **Non-Wedging Lock Recovery:** Any failure while holding the transient `REVALIDATING` lock (such as a `composite_hash` collision or missing ECB FX rate) triggers `_restore_status_best_effort()` via atomic CAS (`expected_status="REVALIDATING" -> previous_status`), ensuring no invoice is ever left permanently stuck in `REVALIDATING`.
- **Immutable AI Confidence:** `confidence_macro_avg` and every line's `confidence_score` are snapshotted read-only and structurally excluded from `ALLOWED_REVALIDATION_HEADER_FIELDS` and `ALLOWED_REVALIDATION_LINE_FIELDS` (`CLAUDE.md §7.4`).

---

### 2.3 Stage 2 — P9-2: Dual-Key Approval Route & Service (`POST /api/v1/invoices/{id}/approve`)

We created dedicated approval modules matching `CLAUDE.md §3 (FR-13)` and `§4.3`: **`src/api/approvals.py`** (registered in `src/api/main.py`) and **`src/services/approval.py`** (`ApprovalService`).

```mermaid
flowchart TD
    Req["POST /api/v1/invoices/{id}/approve (ap_clerk | finance_manager JWT)"] --> BodyCap["Async 64 KB Cap: Content-Length + Chunked Stream (SEC-180)"]
    BodyCap --> Schema["Optional InvoiceApprovalRequest (extra='forbid', One-Click Empty Body OK)"]
    Schema --> Actor["Verify Optional approver_id == JWT + Fail-Closed Role Resolution (SEC-179)"]
    Actor --> Svc["ApprovalService.approve() (src/services/approval.py)"]

    Svc --> Entry{"Persisted Status in {VALIDATED, REQUIRES_MANAGER_APPROVAL}?"}
    Entry -->|"No (15 Other States / Replay)"| C409["409 Conflict"]
    Entry -->|"Yes"| Guards["Active Vendor + No PENDING-/UNKNOWN Placeholder (SEC-178) + No Credit Note"]

    Guards --> Sub90{"ap_clerk on VALIDATED with min_conf < CONFIDENCE_HIGH_THRESHOLD?"}
    Sub90 -->|"Yes & No Prior REVALIDATE Audit (SEC-177)"| C409
    Sub90 -->|"No or Previously Re-Validated"| LiveFX["EscalationEvaluator + ExchangeRateRepository (Live ECB FX vs get_settings())"]

    LiveFX --> MgrCheck{"REQUIRES_MANAGER_APPROVAL or USD > Threshold or PO > Tolerance?"}
    MgrCheck -->|"Yes & role != finance_manager"| F403["403 Forbidden (Zero DB/Audit Mutation)"]
    MgrCheck -->|"Yes & role == finance_manager"| TwoStep["Sync USD + FSM: (VALIDATED -> REQUIRES_MANAGER_APPROVAL ->) APPROVED_MANAGER"]
    MgrCheck -->|"No (Within Clerk Cap)"| ClerkStep["Sync USD + FSM: VALIDATED -> APPROVED_CLERK"]

    TwoStep --> AudMgr["AuditLogger (Isolated Tx): Optional STATUS_TRANSITION (SEC-177) + APPROVE"]
    ClerkStep --> AudClk["AuditLogger (Isolated Tx): APPROVE"]
    AudMgr & AudClk --> Resp["200 OK InvoiceApprovalResponse (Cache-Control: no-store)"]
```

**Key Architectural Decisions in P9-2:**
- **Live Authoritative FX Verification:** `ApprovalService` never trusts a potentially stale SQL `total_amount_usd` column; it recomputes exact USD totals via `EscalationEvaluator.evaluate_with_fx()` against `ExchangeRateRepository` on `invoice.invoice_date` and atomically syncs `total_amount_usd` if drifted.
- **BR-015 + PRD Journey 5 Reconciliation (`SEC-177`):** `ap_clerk` cannot one-click approve an unreviewed `< 90%` confidence invoice (`409`), yet *can* approve a `< 90%` invoice once a prior `REVALIDATE` audit event proves human review!
- **Isomorphic Two-Step Audit Trail (`SEC-177`):** When a `finance_manager` approves a high-value `VALIDATED` invoice directly, both `STATUS_TRANSITION` (`VALIDATED → REQUIRES_MANAGER_APPROVAL`) and `APPROVE` (`REQUIRES_MANAGER_APPROVAL → APPROVED_MANAGER`) are recorded in chronological order.

---

### 2.4 Stage 3 — P9-3: Immutable Audit Trail Route (`GET /api/v1/invoices/{id}/audit`)

We created **`src/api/audit.py`** (registered in `src/api/main.py`) and added **`AuditLogRepository.list_for_invoice()`** in `src/database/repositories.py`.

```mermaid
flowchart LR
    Req["GET /api/v1/invoices/{id}/audit (ap_clerk | finance_manager | system_admin)"] --> ReadOnly["GET Only (POST/PUT/PATCH/DELETE -> 405)"]
    ReadOnly --> Filters["Allowlisted action_type (<=50 chars, SEC-182) + Non-Blank user_id (SEC-183) + Bounded limit (1..500)"]
    Filters --> Exists["InvoiceRepository.get_by_id() (404 if Missing)"]
    Exists --> Query["AuditLogRepository.list_for_invoice() (VALID_AUDIT_ACTION_TYPES + ORDER BY timestamp ASC, audit_id ASC)"]
    Query --> Mask["PII Redaction (SEC-181): Leaf SENSITIVE_AUDIT_FIELDS + Digit-Bearing Comment Regex (***-**-XXXX)"]
    Mask --> Resp["200 OK InvoiceAuditTrailResponse (Cache-Control: no-store + X-Content-Type-Options: nosniff)"]
```

**Key Architectural Decisions in P9-3:**
- **Deterministic Ordering:** `ORDER BY AuditLog.timestamp ASC, AuditLog.audit_id ASC` guarantees stable chronological timelines even when multiple `EDIT` + `REVALIDATE` records share identical timestamps.
- **Precision PII Redaction (`SEC-181`):** Leaf-segment field matching (`header.vendor_tax_id` → `vendor_tax_id`) plus digit-bearing comment regex masks SSNs, US EINs, EU VAT IDs, and IBANs without ever corrupting uppercase status keywords (`VALIDATED`, `REVALIDATING`) or `[request_id=...]` correlation tags.

---

### 2.5 Stage 4 — P9-4: API & Service No-Op Edit Guard (`previous_value == new_value`)

We hardened the entire re-validation intake pipeline so no-op edits are blocked cleanly at **three defense-in-depth layers**—strictly preserving FSM-first error ordering (`409` before `422` to prevent approved-invoice value-guessing oracles: `SEC-186`):

```mermaid
flowchart TD
    In["POST /api/v1/invoices/{id}/revalidate"] --> L1["Layer 1: Pydantic Schema Guard (src/api/schemas/invoices.py)"]
    L1 -->|"Empty payload / header_edits={} / fieldless line_edit / explicit JSON null / NBSP homoglyph (SEC-184)"| R422A["422 Unprocessable Entity (0 DB I/O)"]
    L1 -->|"Normalized NFC + Valid Structure"| L2["Layer 2: Service Fast-Fail & FSM Ordering (src/services/revalidation.py)"]
    L2 -->|"Empty Service DTO (SEC-185)"| R422B["422 RevalidationNoOpError (0 DB I/O)"]
    L2 --> Exists["Load Invoice (404) -> Active Vendor (422) -> FSM Legality (409 FIRST: SEC-186)"]
    Exists --> L3["Layer 3: Canonical Persisted-Value Diff Guard"]
    L3 -->|"Any header_edits field unchanged (scale/-0.00/NFC) OR any line_edits entry unchanged OR replayed tax flag"| R422C["422 RevalidationNoOpError (Allowlisted Field Names Only, 0 Lock/DB/Audit Writes)"]
    L3 -->|"All Submitted Edits Strictly Produce previous_value != new_value"| Run["Proceed to CAS Lock -> Rules -> Persist -> Audit"]
```

---

## 3. End-of-Phase 9 Complete System Architecture

With all four Phase 9 subtasks merged (`47 / 68 tasks · 69%`), the complete FastAPI backend API surface (Phases 1–9) is now live and ready for Phase 11 Streamlit UI integration:

```mermaid
flowchart TB
    subgraph Client ["Authenticated Callers (Phase 11 Streamlit UI / API Clients)"]
        Clerk["AP Clerk (ap_clerk)"]
        Mgr["Finance Manager (finance_manager)"]
        Admin["System Admin / Auditor (system_admin)"]
    end

    subgraph API ["FastAPI API Layer (src/api/) — Zero Validation Logic (CLAUDE.md §4.2)"]
        MW["Middleware Stack: RequestID -> CORS -> AuditMiddleware -> RedisRateLimiter"]
        InvR["src/api/invoices.py: POST /upload, GET /exceptions, GET /{id}, POST /{id}/revalidate"]
        AppR["src/api/approvals.py: POST /{id}/approve"]
        AudR["src/api/audit.py: GET /{id}/audit (Read-Only)"]
    end

    subgraph Svc ["Service Orchestration Layer (src/services/) — Zero HTTP Imports"]
        RevalSvc["RevalidationService (P9-1, P9-4)"]
        AppSvc["ApprovalService (P9-2)"]
        Worker["InvoiceBackgroundWorker (P5-3)"]
    end

    subgraph Val ["Deterministic Validation Layer (src/validation/) — Zero LLM / Zero SQLAlchemy"]
        RE["RulesEngine (P7-6)"]
        CR["ConfidenceRouter (P8-1)"]
        FSM["InvoiceStateMachine (P8-2)"]
        ESC["EscalationEvaluator (P8-3)"]
    end

    subgraph Data ["Data & Audit Stores (src/database/ & src/core/)"]
        Repos["Async SQL Repositories (Atomic CAS + Single-Tx Revalidation Edits)"]
        AuditLog["AuditLogger (Isolated Tx Append-Only Writer)"]
    end

    Clerk & Mgr & Admin --> MW --> InvR & AppR & AudR
    InvR --> RevalSvc
    AppR --> AppSvc
    AudR --> Repos
    RevalSvc & AppSvc & Worker --> RE & CR & FSM & ESC
    RevalSvc & AppSvc & Worker --> Repos & AuditLog
```

---

## 4. Evolution Metrics Summary (Phase 8 → Phase 9)

| Metric | End of Phase 8 | End of Phase 9 | Delta |
|---|---:|---:|---:|
| Completed Platform Tasks | 43 / 68 (63%) | **47 / 68 (69%)** | **+4 tasks (Phase 9 100% ✅)** |
| FastAPI Invoice Endpoints | 3 (`/upload`, `/exceptions`, `/{id}`) | **6** (`+/revalidate`, `+/approve`, `+/audit`) | **+3 production endpoints** |
| Service Orchestrators (`src/services/`) | 1 (`worker.py`) | **3** (`+revalidation.py`, `+approval.py`) | **+2 decoupled services** |
| Offline Passing Tests | 538 | **589** | **+51 Phase 9 tests** |
| Audited & Mitigated Security Findings | 172 (`SEC-001`–`SEC-172`) | **186 (`SEC-001`–`SEC-186`)** | **+14 findings closed** |
| Ruff Formatted Files | 96 (0 errors) | **104 (0 errors)** | **+8 files** |

