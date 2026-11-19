# Phase 8: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 8 (Confidence Routing and State Machine — P8-1 through P8-3)**.  
> **Target Audience:** Solution Architects, Backend Leads, Staff Engineers, Financial Systems Engineers, and System Design Interviewers.

---

## 1. Phase 8 Mission & Architectural Baseline

Entering Phase 8, Phases 1–7 and Phase 10 were complete (**40 / 68 tasks · 59%**, **360 passing offline tests**, **160 mitigated security findings**):
- **Phase 6 (`src/extraction/`):** Produces strictly validated `InvoiceExtractionSchema` payloads with 10 header fields, 5 line-item fields per line, and `[0.00, 100.00]` per-field confidence scores.
- **Phase 7 (`src/validation/`):** Chains all 5 deterministic validators (`duplicate_detector.py`, `line_arithmetic.py`, `invoice_total.py`, `tax_validator.py`, `date_normalizer.py`) inside `RulesEngine`, returning an immutable `RulesEngineResult` with `all_passed`, `failed_rules`, `errors`, and `recommended_status`.

However, three critical orchestration and governance layers remained unbuilt at the end of Phase 7:
1. **Confidence Triage (`FR-04`, `BR-007`):** Translating per-field AI confidence scores + `RulesEngineResult` into tri-tier workflow routing (`VALIDATED` / `REQUIRES_REVIEW` / `REQUIRES_APPROVAL`) with UI colour metadata and re-validation promotion semantics.
2. **Lifecycle Integrity (`LLD §4`, `CLAUDE.md §5 & §16.1`):** Enforcing legal state transitions exclusively, preventing RBAC privilege escalation or worker self-approval, and persisting transitions atomically through `InvoiceRepository` without TOCTOU races (`CWE-362`).
3. **Financial Escalation (`FR-13`, `BR-012a`, `BR-014`):** Normalizing multi-currency totals to USD via invoice-date ECB daily exchange rates and enforcing configurable `HIGH_VALUE_THRESHOLD_USD` (`>\$10,000`) and `PO_VARIANCE_TOLERANCE_PERCENT` (`>5%`) Finance Manager escalation.

The mission of **Phase 8** was to close all three gaps while maintaining **100% deterministic Python**, **zero LLM or SQLAlchemy imports inside `src/validation/`**, and **all thresholds loaded dynamically from `get_settings()`**.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 7 Baseline (Rules Pass/Fail Ready, No Routing / FSM / Escalation)

At the end of Phase 7, `RulesEngine` emitted pass/fail outcomes, and `InvoiceRepository` exposed raw `update_status()` without FSM legality checks or optimistic locking.

```mermaid
flowchart LR
    Ext["ExtractionEngine (P6-4)"] --> RE["RulesEngine (P7-6)"]
    RE -->|"RulesEngineResult"| Gap1["Missing: Confidence Router (P8-1)"]
    Gap1 -.-> Gap2["Missing: Escalation Rules + ECB FX (P8-3)"]
    Gap2 -.-> Gap3["Missing: Legal-Only FSM + CAS Lock (P8-2)"]
    Gap3 -.-> Repo["InvoiceRepository.update_status() (Unchecked Write)"]
```

---

### 2.2 Stage 1 — P8-1: Tri-Tier Confidence Router (`src/validation/confidence_router.py`)

We designed `ConfidenceRouter`, `route_confidence_scores()`, and `route_extraction_confidence()` to combine worst-field-wins per-field confidence triage with Rules-First precedence and clerk re-validation semantics.

```mermaid
flowchart TD
    In["InvoiceExtractionSchema / field_scores + Optional RulesEngineResult"] --> Parse["Strict ASCII Decimal Parser (No 0-1 Rescaling, No Sub-Cent Round-Up)"]
    Parse --> Canon["Canonical Field-Key Dedup (SEC-163: Blocks Bare+Header Aliases)"]
    Canon --> Min["Worst-Field-Wins: min_confidence = min(all 10 header + all line fields)"]
    Min --> Tier{"Compare Unrounded Decimal vs get_settings() Thresholds"}

    Tier -->|">= 90.00% (HIGH)"| StHigh["VALIDATED (#22c55e green)"]
    Tier -->|"80.00%..89.999% (MEDIUM)"| StMed["REQUIRES_REVIEW (#fef08a light_yellow)"]
    Tier -->|"< 80.00% (LOW)"| StLow["REQUIRES_APPROVAL (#ef4444 amber_red)"]

    StHigh & StMed & StLow --> Mode{"is_revalidation?"}
    Mode -->|"Yes (CLAUDE.md §7.4)"| Reval{"Verify RulesEngineResult Integrity (SEC-164)"}
    Reval -->|"all_passed=True"| RevalPass["Promote to VALIDATED (Keep Immutable Model Confidence)"]
    Reval -->|"CREDIT_NOTE"| RevalCN["CREDIT_NOTE"]
    Reval -->|"Other Failure"| RevalFail["REQUIRES_APPROVAL"]

    Mode -->|"No (Initial Extraction)"| Precedence["Strictest Priority Wins: DUPLICATE > CREDIT_NOTE > REVISION > TAX > APPROVAL > REVIEW > VALIDATED"]
    Precedence --> CNCheck["Unconditional detect_credit_note() Guard (SEC-161)"]
    CNCheck --> Out["Frozen ConfidenceRoutingResult (Non-Approval Allowlist)"]
```

**Key Architectural Decisions in P8-1:**
- **Worst-Field-Wins vs. Macro Average:** `min_confidence` drives routing per `BR-007` and `PRD Journeys 2–4` (preventing a `97%` macro-average from masking a `74%` `total_amount`), while `macro_avg_confidence` and `header_macro_avg_confidence` are computed alongside for SQL persistence (`dbo.Invoices.confidence_macro_avg`).
- **Percentage-Scale Safety Floors (`SEC-162`):** `CONFIDENCE_HIGH_THRESHOLD` (`ge=60.0, le=100.0`) and `CONFIDENCE_MEDIUM_THRESHOLD` (`ge=50.0, lt=100.0`) live in `src/core/config.py` + `.env.example` and are double-checked inside `_resolve_thresholds()`, preventing `0.90`/`0.80` fraction-scale typos from auto-validating low-confidence OCR.
- **Re-Validation Promotion Without Altering Model Scores:** Honors `CLAUDE.md §7.4`—clerk edits do not mutate immutable AI confidence scores, yet passing deterministic rules promote the invoice from `REVALIDATING → VALIDATED` instead of trapping it in an infinite `REQUIRES_APPROVAL` loop.

---

### 2.3 Stage 2 — P8-2: Invoice Lifecycle Finite State Machine (`src/validation/state_machine.py` + Atomic Repository CAS)

We built the full 10-core / 17-status `InvoiceStateMachine` enforcing `LLD §4` through a deeply immutable `MappingProxyType` graph, strict RBAC transition guards, and atomic SQL compare-and-swap (`InvoiceRepository.compare_and_update_status()`).

```mermaid
stateDiagram-v2
    [*] --> UPLOADED
    UPLOADED --> EXTRACTING : SYSTEM
    UPLOADED --> DUPLICATE_INVOICE : SYSTEM
    UPLOADED --> FLAGGED_POTENTIAL_REVISION : SYSTEM
    UPLOADED --> CREDIT_NOTE : SYSTEM

    EXTRACTING --> VALIDATED : SYSTEM (Conf >= 90% & Rules Pass)
    EXTRACTING --> REQUIRES_REVIEW : SYSTEM (Conf 80-89% / Ambiguous Date)
    EXTRACTING --> REQUIRES_APPROVAL : SYSTEM (Conf < 80% / Math Error)
    EXTRACTING --> REJECTED_TAX_MISMATCH : SYSTEM (Tax Mismatch)
    EXTRACTING --> REQUIRES_MANAGER_APPROVAL : SYSTEM (>$10k / >5% PO)
    EXTRACTING --> DUPLICATE_INVOICE : SYSTEM
    EXTRACTING --> FLAGGED_POTENTIAL_REVISION : SYSTEM
    EXTRACTING --> CREDIT_NOTE : SYSTEM

    REQUIRES_REVIEW --> VALIDATED : Clerk Visual Confirm
    REQUIRES_REVIEW --> REVALIDATING : Clerk Edit
    REQUIRES_REVIEW --> REQUIRES_APPROVAL : Escalate
    REQUIRES_REVIEW --> REJECTED : Human Reject

    REQUIRES_APPROVAL --> REVALIDATING : Clerk Edit
    REQUIRES_APPROVAL --> REQUIRES_MANAGER_APPROVAL : Manager Override
    REQUIRES_APPROVAL --> REJECTED : Human Reject

    REJECTED_TAX_MISMATCH --> REVALIDATING : Clerk Tax Edit
    REJECTED_TAX_MISMATCH --> REJECTED : Human Reject

    FLAGGED_POTENTIAL_REVISION --> REVALIDATING : Accept Revision
    FLAGGED_POTENTIAL_REVISION --> REJECTED_DUPLICATE : Reject Duplicate
    DUPLICATE_INVOICE --> REJECTED_DUPLICATE : Confirm Duplicate

    REVALIDATING --> VALIDATED : Rules Pass
    REVALIDATING --> REQUIRES_APPROVAL : Rules Fail
    REVALIDATING --> CREDIT_NOTE : Negative Edit
    REVALIDATING --> REQUIRES_MANAGER_APPROVAL : Rules Pass + >$10k/>5% PO

    VALIDATED --> APPROVED_CLERK : Human Clerk (<= $10k USD)
    VALIDATED --> REQUIRES_MANAGER_APPROVAL : SYSTEM / Escalation
    VALIDATED --> REVALIDATING : Clerk Edit
    VALIDATED --> REJECTED : Human Reject

    CREDIT_NOTE --> REQUIRES_MANAGER_APPROVAL : Netting Approval
    CREDIT_NOTE --> VOID : Manager Void

    REQUIRES_MANAGER_APPROVAL --> APPROVED_MANAGER : Finance Manager / Admin
    REQUIRES_MANAGER_APPROVAL --> REJECTED : Finance Manager / Admin

    APPROVED_CLERK --> STAGED_FOR_EXPORT : SYSTEM Export
    APPROVED_CLERK --> VOID : Manager Supersede
    APPROVED_MANAGER --> STAGED_FOR_EXPORT : SYSTEM Export
    APPROVED_MANAGER --> VOID : Manager Supersede

    STAGED_FOR_EXPORT --> [*]
    REJECTED --> [*]
    REJECTED_DUPLICATE --> [*]
    VOID --> [*]
```

**Key Architectural Decisions in P8-2:**
- **Zero SQLAlchemy Imports via Protocol (`CLAUDE.md §4.2`):** `InvoiceStateMachine` depends solely on `InvoiceStatusRepositoryProtocol` (satisfied directly by `InvoiceRepository`).
- **Optimistic-Locking CAS (`CWE-362`):** `InvoiceRepository.compare_and_update_status()` executes a single atomic conditional `UPDATE invoices SET status = :new WHERE invoice_id = :id AND status = :expected`, eliminating read-modify-write races and raising `ConcurrentStateTransitionError` (`HTTP 409`) if another worker/user changed the row concurrently.
- **Defense-in-Depth Business & RBAC Guards (`SEC-165`–`SEC-167`):** Even if an upstream API route forgets to enforce authorization, `InvoiceStateMachine` itself blocks `ap_clerk` approval on invoices `> HIGH_VALUE_THRESHOLD_USD` or unconverted non-USD invoices, blocks negative-balance promotion to regular states, and confines `ActorRole.SYSTEM` to an explicit `_SYSTEM_ALLOWED_TRANSITIONS` allowlist.

---

### 2.4 Stage 3 — P8-3: High-Value & PO-Variance Escalation Engine (`src/validation/escalation_rules.py`)

We built `EscalationEvaluator`, `evaluate_escalation()`, and `evaluate_extraction_escalation()` to execute `FR-13` / `BR-014` / `BR-012a` using dynamic `get_settings()` thresholds and invoice-date ECB daily exchange rates.

```mermaid
flowchart TD
    In["Invoice Total, Currency, Invoice Date, Optional PO Amount / Variance, Optional ConfidenceRoutingResult"] --> FX{"Currency == USD?"}
    FX -->|"Yes"| USDUnity["Verify rate == 1.0 & USD Consistency (SEC-169)"]
    FX -->|"No (EUR / GBP)"| Repo["ExchangeRateLookupProtocol.get_latest_rate_on_or_before(invoice_date, ccy, USD)"]
    Repo --> FXChk["Validate Pure Date, rate_date <= invoice_date, rate > 0 (SEC-171)"]
    FXChk --> Conv["usd_exact = total_amount * exchange_rate (Unrounded Decimal)"]

    USDUnity & Conv --> HV{"abs(usd_exact) > get_settings().HIGH_VALUE_THRESHOLD_USD?"}
    HV -->|"Yes"| FlagHV["Add EscalationReason.HIGH_VALUE"]
    HV -->|"No"| NoHV["Within $10k USD Cap"]

    FlagHV & NoHV --> PO{"po_amount or po_variance_percent Supplied?"}
    PO -->|"po_amount == 0 & total != 0"| FlagPO["Add EscalationReason.PO_VARIANCE (Zero-PO Overrun)"]
    PO -->|"Yes"| CalcPO["exact_pct = abs(total - po) / po * 100 > PO_VARIANCE_TOLERANCE_PERCENT?"]
    CalcPO -->|"Yes"| FlagPO
    CalcPO -->|"No"| NoPO["Within 5% PO Tolerance"]
    PO -->|"None"| NoPO

    FlagPO & NoPO --> Status{"Negative Total or Blocking Exception Status?"}
    Status -->|"total < 0"| OutCN["CREDIT_NOTE (eligible_for_clerk_approval=False)"]
    Status -->|"Blocking Exception (DUPLICATE/TAX/REVIEW/APPROVAL)"| OutKeep["Preserve Exception Status (Never Mask Exceptions)"]
    Status -->|"VALIDATED + Escalation Triggered"| OutMgr["REQUIRES_MANAGER_APPROVAL (eligible_for_clerk_approval=False)"]
    Status -->|"VALIDATED + Clean"| OutVal["VALIDATED (eligible_for_clerk_approval=True)"]
```

---

## 3. End-of-Phase 8 Complete Deterministic Validation & Governance Architecture

By the end of Phase 8, Phases 6, 7, and 8 connect into a seamless, zero-LLM-decision deterministic pipeline tested end-to-end across all **300 pilot ground-truth invoices** with zero crashes:

```mermaid
flowchart LR
    subgraph P6["Phase 6: Extraction (AI Restricted to Parsing)"]
        Ext["ExtractionEngine -> InvoiceExtractionSchema"]
    end

    subgraph P7["Phase 7: Deterministic Rules Engine"]
        RE["RulesEngine (Dup + Line Math + Total Math + 4-Country Tax + Locale Dates)"]
    end

    subgraph P8["Phase 8: Governance, Routing & Lifecycle Control"]
        CR["P8-1 ConfidenceRouter (Tri-Tier + Rules-First + Re-Validation)"]
        ESC["P8-3 EscalationEvaluator (>$10k USD via ECB FX + >5% PO Variance)"]
        FSM["P8-2 InvoiceStateMachine (10-Core / 17-Status Legal FSM + RBAC)"]
    end

    subgraph P2["Phase 2: Persistence Layer"]
        InvRepo["InvoiceRepository (compare_and_update_status CAS)"]
        FXRepo["ExchangeRateRepository (ECB Daily Rates on Invoice Date)"]
    end

    Ext --> RE
    RE -->|"RulesEngineResult"| CR
    CR -->|"ConfidenceRoutingResult"| ESC
    FXRepo -.->|"ExchangeRateLookupProtocol"| ESC
    ESC -->|"EscalationResult (target_status)"| FSM
    FSM -->|"Atomic CAS Write"| InvRepo
```

---

## 4. Evolution Metrics & Security Ledger Delta (Phase 7 → Phase 8)

| Dimension | End of Phase 7 | End of Phase 8 | Delta |
|---|---|---|---|
| **Completed Tasks** | 40 / 68 (59%) | **43 / 68 (63%)** | **+3 tasks (Phase 8 100% ✅)** |
| **Offline Passing Tests** | 360 tests (7.10s) | **538 tests (7.90s)** | **+178 new deterministic & pentest cases** |
| **Audited & Mitigated Findings** | 160 (`SEC-001`–`SEC-160`) | **172 (`SEC-001`–`SEC-172`)** | **+12 governance & CAS security controls** |
| **Formatted Python Files (Ruff)** | 90 files (0 errors) | **96 files (0 errors)** | **+6 files (`confidence_router`, `state_machine`, `escalation_rules` + 3 test suites)** |
| **External Dependencies Added** | 0 | **0** | Pure Python stdlib + Pydantic v2 + existing protocols |

