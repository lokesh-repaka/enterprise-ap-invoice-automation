# Phase 7: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 7 (Validation Rules Engine — P7-1 through P7-6)**.  
> **Target Audience:** Solution Architects, Backend Leads, Staff Engineers, Financial Systems Engineers, and System Design Interviewers.

---

## 1. Phase 7 Mission & Architectural Baseline

Entering Phase 7, Phases 1–6 and Phase 10 were complete (**34 / 68 tasks · 50%**, **242 passing offline tests**, **136 mitigated security findings**):
- **Phases 1–5:** FastAPI runtime, 5-table async SQLAlchemy persistence (`InvoiceRepository`, `compute_composite_hash`, `UX_invoices_composite_hash`), Entra ID RS256 RBAC, Redis rate limiting & FIFO job queue, immutable `AuditLogger`, keyless Key Vault stub, WORM Blob storage, and `InvoiceBackgroundWorker`.
- **Phase 6:** Complete `src/extraction/` pipeline (`classify_document`, `ModelGateway`, `InvoiceExtractionSchema`, `ExtractionEngine`, `MockAOAIClient`) producing strictly typed 10-header + 5-line extraction outputs with per-field `[0.00, 100.00]` confidence scores and zero business-rule coupling.

The mission of **Phase 7** was to build the entire **Deterministic Validation Rules Engine (`src/validation/`)** honoring **ADR-002 (Rules-First, Model-Second)** and six non-negotiable architectural invariants:

1. **100% Deterministic Python (`CLAUDE.md §4.2, §7.2`):** Zero LLM calls, zero `openai` imports, and zero direct `sqlalchemy` imports anywhere in `src/validation/`—database reads occur strictly through the read-only `InvoiceLookupProtocol` (satisfied directly by `InvoiceRepository`).
2. **Exact Financial `Decimal` Precision (`BR-009`, `BR-010`, `BR-011`):** Every arithmetic, tax, and hash calculation uses bounded finite `Decimal` with explicit `ROUND_HALF_UP` quantization, preserving unrounded stated totals for boundary comparisons so `+0.021 > 0.02` and `+0.051 > 0.05` never round into false passes.
3. **Zero Hardcoded Thresholds (`CLAUDE.md §16 Rule 8`):** All rounding tolerances (`LINE_ROUNDING_TOLERANCE`, `INVOICE_ROUNDING_TOLERANCE`) are resolved dynamically from `get_settings()` and fail-closed bounded to `[0.00, 100.00]`.
4. **Non-Negotiable Credit-Note & Non-Approval Invariants (`CLAUDE.md §16.1`):** Negative-balance documents (negative total, subtotal, or any negative line item) are **always** classified as `CREDIT_NOTE` (unless an identical duplicate credit note already exists → `DUPLICATE_INVOICE`), and no validation module can ever emit `APPROVED_CLERK`, `APPROVED_MANAGER`, or `STAGED_FOR_EXPORT`.
5. **Fail-Closed Financial Fraud Defense:** Blocks Unicode soft-hyphen/NFKC hash bypasses, SQLite mixed-case duplicate bypasses, opposite-sign negative-tax `\$10,000` threshold evasion, partial-line VAT subtotal evasion, unsupported/homograph country fallbacks, partial line-tax omissions, and chronological locale inversions.
6. **Zero-Crash 300-Invoice Batch Stability (`AC-005`, `CLAUDE.md §10`):** Full 5-rule orchestration handles malformed OCR dates gracefully and routes all 300 pilot ground-truth invoices deterministically with zero unhandled exceptions.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 6 Baseline (Extraction Ready, Validation Package Empty)

At the end of Phase 6, `ExtractionEngine` emitted validated `InvoiceExtractionSchema` payloads, and `InvoiceRepository` provided async DB lookups, while `src/validation/` contained only a placeholder `__init__.py`.

```mermaid
flowchart LR
    Ext["ExtractionEngine (src/extraction/extract_engine.py)"]
    Schema["InvoiceExtractionSchema (10 Header + 5 Line Fields)"]
    Val["src/validation/ (Empty Placeholder)"]
    Repo["InvoiceRepository (src/database/repositories.py)"]

    Ext --> Schema
    Schema -.->|"No Rules Engine Yet"| Val
    Repo -.->|"Unwired Lookup"| Val
```

---

### 2.2 Stage 1 — P7-1: Duplicate, Revision & Credit-Note Detector (`src/validation/duplicate_detector.py`)

We built a protocol-decoupled `DuplicateDetector` enforcing a strict 4-tier decision precedence (`FR-09`, `FR-10`, `FR-11`, `ADR-006`) with 100% SHA-256 parity across all 300 ground-truth files and `InvoiceRepository`.

```mermaid
flowchart TD
    In["DuplicateCheckInput / InvoiceExtractionSchema"] --> San["Identifier & Decimal Sanitizer (Blocks Cc/Cf/NBSP/NFKC, NaN/Inf/Bombs)"]
    San --> Hash["compute_composite_hash: SHA256(tax_id + inv_num + total:.2f)"]
    Hash --> Lookup["InvoiceLookupProtocol (Exact + Base + Uppercase Fallback, Self & VOID Excluded)"]

    Lookup --> P1{"Priority 1: Exact Hash or Vendor+Number+Total Match?"}
    P1 -->|"Yes"| Dup["DUPLICATE_INVOICE (matched_invoice_id)"]
    P1 -->|"No"| P2{"Priority 2: Negative Total, Subtotal, or Any Line < 0?"}
    P2 -->|"Yes"| CN["CREDIT_NOTE (+ Related Invoice ID for Netting)"]
    P2 -->|"No"| P3{"Priority 3: -REV/Rev/v2 Suffix (Number/File) or Differing Total?"}
    P3 -->|"Yes"| Rev["FLAGGED_POTENTIAL_REVISION (+ Base Link & amount_difference)"]
    P3 -->|"No"| Ok["PROCEED (Unique Regular Invoice)"]
```

**Key Design Decisions:**
- **Exact Duplicate Beats Credit Note:** Prevents double-crediting when the identical negative-balance credit note is uploaded twice.
- **Credit Note Beats Revision:** Ensures negative adjustments referencing an earlier positive invoice number (like `INV-2026-500` → `-\$1,000`) always route to `CREDIT_NOTE` (with `matched_invoice_id` attached for netting).
- **Decoupled Protocol:** `InvoiceLookupProtocol` matches `InvoiceRepository` directly without importing SQLAlchemy inside `src/validation/`.

---

### 2.3 Stage 2 — P7-2: Line-Item Arithmetic Validator (`src/validation/line_arithmetic.py`)

We implemented `validate_line_items()` (LLD §5.1 signature) and `evaluate_line_items()` (`FR-05`, `BR-009`), supporting `LineItemArithmeticInput`, P6-3 `InvoiceLineItemExtraction`, duck-typed SQLAlchemy `InvoiceLine`, and `/revalidate` dicts.

```mermaid
flowchart LR
    Lines["Invoice Lines (<= 500, Unique line_number)"] --> Coerce["Polymorphic Coercer + Strict ASCII [0-9] Decimal Parser"]
    Coerce --> Calc["expected = (qty * unit_price).quantize(0.01, ROUND_HALF_UP)"]
    Calc --> Overflow{"abs(product) <= DECIMAL(18,2)?"}
    Overflow -->|"No"| ErrOv["Fail Closed: Overflow ValueError"]
    Overflow -->|"Yes"| Diff["diff = abs(expected - unrounded line_total)"]
    Diff --> Tol{"diff <= get_settings().LINE_ROUNDING_TOLERANCE?"}
    Tol -->|"Yes"| Pass["Line Valid + Accumulate Subtotals"]
    Tol -->|"No"| Fail["Line Error (LLD §5.1 Message)"]
    Pass --> Drift["Expose computed_subtotal, expected_subtotal, cumulative_rounding_drift"]
```

**Key Design Decisions:**
- **Unrounded `line_total` Diff:** Compares `abs(expected_total - line.line_total)` without pre-rounding `line_total`, preventing `+0.021` from rounding down to `0.02`.
- **Salami-Slicing Visibility (`SEC-145`):** Exposes `cumulative_rounding_drift = abs(computed_subtotal - expected_subtotal)` so 100 lines each inflated by `+0.02` (`\$2.00` total drift) are visible to downstream auditors.

---

### 2.4 Stage 3 — P7-3: Invoice Total Arithmetic Validator (`src/validation/invoice_total.py`)

We implemented `validate_invoice_total()` (LLD §5.2 signature), `evaluate_invoice_total()`, `validate_extraction_invoice_total()`, and `evaluate_invoice_record()` (`FR-06`, `BR-010`).

```mermaid
flowchart TD
    Hdr["Header: Subtotal, Tax, Grand Total (+ Optional lines_subtotal)"] --> Sign{"Same Sign or Zero Tax? (Blocks +$10k + -$100 = $9.9k)"}
    Sign -->|"Opposite Sign"| FailSign["Fail: sign_consistent=False (SEC-146)"]
    Sign -->|"Consistent"| Sum["expected = (subtotal + tax).quantize(0.01, ROUND_HALF_UP)"]
    Sum --> Tol{"abs(expected - unrounded total) <= INVOICE_ROUNDING_TOLERANCE?"}
    Tol -->|"No"| FailTot["Fail: LLD §5.2 Total Mismatch Error"]
    Tol -->|"Yes"| LineChk{"lines_subtotal Provided?"}
    LineChk -->|"Yes & Diff > Tol"| FailSub["Fail: Header Subtotal vs Line Sum Mismatch"]
    LineChk -->|"Pass / Omitted"| Ok["Valid (+ rounding_within_tolerance Telemetry Flag)"]
```

---

### 2.5 Stage 4 — P7-4: Multi-Country Tax Validator (`src/validation/tax_validator.py`)

We built `validate_tax_rate()` (LLD §5.3 signature), `evaluate_tax_rate()`, and `validate_extraction_tax()` (`FR-07`, `BR-011`, `PRD Journey 5`) covering US, UK (`GB`/`UK`), DE, and ES.

```mermaid
flowchart TD
    Req["Country, Subtotal, Stated Tax, Flags, Vendor Rate, Optional Lines"] --> CC["normalize_country_code() Allowlist: {US, GB, DE, ES} (UK->GB; Fail-Closed)"]
    CC --> Ex{"is_reverse_charge or is_exempt? (Strict Bool)"}
    Ex -->|"Yes & abs(tax) < 0.01"| PassEx["Valid Exemption / Reverse Charge"]
    Ex -->|"Yes & abs(tax) >= 0.01"| FailEx["REJECTED_TAX_MISMATCH (Must Be Zero)"]
    Ex -->|"No"| Sign["Opposite-Sign & Zero-Subtotal Guards"]
    Sign --> Split{"Jurisdiction"}
    Split -->|"US"| US["Match vendor_tax_rate (<=15%) OR Bounded 0%-15% Ceiling"]
    Split -->|"GB / DE / ES + Lines"| Mixed["Verify All Line Rates Statutory + Reconcile Line Subtotal == Header Subtotal + Match Tax Sum"]
    Split -->|"GB / DE / ES Header"| Stat["Match Statutory Table: GB 20/5/0%, DE 19/7/0%, ES 21/10/4/0%"]
    US --> Out["TaxValidationResult (None or REJECTED_TAX_MISMATCH)"]
    Mixed --> Out
    Stat --> Out
```

---

### 2.6 Stage 5 — P7-5: Date Normaliser & Locale Disambiguator (`src/validation/date_normalizer.py`)

We built `resolve_date_locale()`, `parse_invoice_date()` (LLD §5.4 signature), `normalize_invoice_date()`, and `normalize_invoice_dates()` (`FR-08`, `BR-012`).

```mermaid
flowchart TD
    In["invoice_date (+ Optional due_date) + Vendor Master Locale"] --> Loc["resolve_date_locale(): US (MM/DD/YYYY) | EU (DD/MM/YYYY) | None (Unlisted)"]
    Loc --> Regex["Strict ASCII [0-9] Uniform-Separator Parser + Year [1990..2100]"]
    Regex -->|"ISO YYYY-MM-DD"| ISO["Unambiguous ISO 8601 Date"]
    Regex -->|"Regional AA/BB/YYYY"| Known{"Locale Known?"}
    Known -->|"None (Unlisted)"| Amb["is_ambiguous=True -> REQUIRES_REVIEW (+ US/EU Candidates)"]
    Known -->|"US or EU"| Parse["Parse Primary + Alternate Candidate"]
    Parse -->|"Invalid in Primary Locale"| Inv["Cross-Locale Inversion -> REQUIRES_REVIEW (+ Alt Hint)"]
    Parse -->|"Valid"| Chrono{"due_date < invoice_date? (e.g. INV-2026-1005)"}
    Chrono -->|"Yes"| Conf["chronological_conflict=True -> REQUIRES_REVIEW (+ Alt Locale Range)"]
    Chrono -->|"No"| Ok["Normalized ISO Dates (is_valid=True)"]
```

---

### 2.7 Stage 6 — P7-6: Rules Engine Orchestrator (`src/validation/rules_engine.py`) — Final Phase 7 Architecture

Finally, `RulesEngine` chained all 5 validators into two deterministic pipelines—`validate_extraction()` (async, full 5-rule intake) and `validate_revalidation()` (sync, clerk edit loop)—and directly re-exported `validate_line_items`, `validate_invoice_total`, `validate_tax_rate`, and `parse_invoice_date` per `CLAUDE.md §3 & §7.4`.

```mermaid
flowchart TD
    subgraph "Phase 7 Validation Rules Engine (src/validation/rules_engine.py)"
        In["InvoiceExtractionSchema + VendorRuleContext"] --> R1["1. P7-1 DuplicateDetector (FR-09/10/11 + Unconditional Credit-Note Guard)"]
        R1 --> R2["2. P7-2 Line Arithmetic (FR-05: Qty * Price = Total +/- LINE_ROUNDING_TOLERANCE)"]
        R2 --> R3["3. P7-3 Invoice Total (FR-06: Subtotal + Tax = Total +/- INVOICE_ROUNDING_TOLERANCE + Line Sum)"]
        R3 --> R4["4. P7-4 Multi-Country Tax (FR-07: US/GB/DE/ES + Mixed + Reverse-Charge/Exempt)"]
        R4 --> R5["5. P7-5 Date Normaliser (FR-08: Vendor Locale + Chronological Conflict + Crash-Safe OCR)"]
        R5 --> Agg["Deterministic Precedence Aggregator (Never Self-Approves)"]
    end

    Agg -->|"Priority 1"| S1["DUPLICATE_INVOICE"]
    Agg -->|"Priority 2"| S2["CREDIT_NOTE"]
    Agg -->|"Priority 3"| S3["FLAGGED_POTENTIAL_REVISION"]
    Agg -->|"Priority 4"| S4["REJECTED_TAX_MISMATCH"]
    Agg -->|"Priority 5"| S5["REQUIRES_APPROVAL (Math Errors)"]
    Agg -->|"Priority 6"| S6["REQUIRES_REVIEW (Date Ambiguity)"]
    Agg -->|"All 5 Passed"| S7["None -> Forward to Phase 8 Confidence Router"]
```

---

## 3. Architecture Evolution Summary Table (P7-1 → P7-6)

| Subtask | PR | New Module | Functional Req | Key Architectural Upgrade | Security Findings Closed |
|---|---|---|---|---|---|
| **P7-1** | #25 | `src/validation/duplicate_detector.py` | FR-09, FR-10, FR-11 | SHA-256 composite key (300/300 GT parity), `-REV`/`v2` base-invoice linking, negative total/line `CREDIT_NOTE`, protocol-decoupled DB lookup | `SEC-137`–`SEC-141` |
| **P7-2** | #26 | `src/validation/line_arithmetic.py` | FR-05 | Exact `Decimal` `ROUND_HALF_UP`, settings-driven `±0.02`, polymorphic ORM/Schema/Dict inputs, `cumulative_rounding_drift` | `SEC-142`–`SEC-145` |
| **P7-3** | #27 | `src/validation/invoice_total.py` | FR-06 | Settings-driven `±0.05`, `rounding_within_tolerance` telemetry (`INV-2026-1030`), optional `lines_subtotal` cross-check, sign-consistency check | `SEC-146`–`SEC-149` |
| **P7-4** | #28 | `src/validation/tax_validator.py` | FR-07 | US Vendor Master / bounded 15% cap, UK/DE/ES statutory rate tables, mixed-rate line reconciliation, reverse-charge/exemption zero-tax enforcement | `SEC-150`–`SEC-153` |
| **P7-5** | #29 | `src/validation/date_normalizer.py` | FR-08 | Vendor Master US/EU locale resolution, unlisted ambiguity flagging, chronological conflict detection (`INV-2026-1005`) | `SEC-154`–`SEC-156` |
| **P7-6** | #30 | `src/validation/rules_engine.py` | FR-05–FR-11, FR-12 | Unified 5-rule orchestrator (`validate_extraction` + `validate_revalidation`), deterministic precedence, LLD §2.2 summary, 300-invoice zero-crash stability | `SEC-157`–`SEC-160` |

**Phase 7 Exit State:** **40 / 68 tasks (59%)** · **360 / 360 offline tests passing (7.10s)** · **160 cumulative security findings mitigated** · **Ready for Phase 8 (Confidence Routing & 10-State FSM)**.

