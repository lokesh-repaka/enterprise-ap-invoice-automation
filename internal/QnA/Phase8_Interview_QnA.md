# Phase 8: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, workflow orchestration, finite state machine, concurrency/CAS locking, multi-currency FX normalization, RBAC governance, and penetration-testing interview preparation covering **Phase 8 (Confidence Routing and State Machine — P8-1 through P8-3)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, FinTech / AP Automation Engineer, AI Systems Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [Tri-Tier Confidence Routing & Re-Validation Semantics (P8-1)](#1-tri-tier-confidence-routing--re-validation-semantics-p8-1)
2. [Invoice Finite State Machine, RBAC & Atomic CAS Concurrency (P8-2)](#2-invoice-finite-state-machine-rbac--atomic-cas-concurrency-p8-2)
3. [High-Value, PO-Variance & ECB FX Escalation Rules (P8-3)](#3-high-value-po-variance--ecb-fx-escalation-rules-p8-3)
4. [Cross-Phase Integration, Layering & Clean Architecture](#4-cross-phase-integration-layering--clean-architecture)
5. [Real-World Pentest Stories & Security Threat Model Summary (`SEC-161`–`SEC-172`)](#5-real-world-pentest-stories--security-threat-model-summary-sec-161sec-172)

---

## 1. Tri-Tier Confidence Routing & Re-Validation Semantics (P8-1)

### Q1.1: Why does `ConfidenceRouter` use minimum per-field confidence ("worst-field-wins") instead of the macro-average confidence across all fields?

**Answer:**
Because macro-averaging hides dangerous single-field extraction failures!
- Suppose an invoice has 10 header fields and 5 line-item fields (15 fields total). If 14 fields extract at `99%` confidence and `total_amount` extracts at `74%` confidence due to a coffee stain or smudge, the macro-average is **`97.33%`**.
- Routing on the macro-average would falsely mark a `74%`-confident grand total as Green / `VALIDATED` and let a clerk one-click approve the wrong dollar amount!
- Per `BR-007` and `PRD Journeys 2–4`, our `ConfidenceRouter` computes **`min_confidence`** across *every* header and line-item field so:
  - Any field `< 80.00%` → `LOW` → `REQUIRES_APPROVAL` (`#ef4444` Amber/Red, Human Exception Queue).
  - Else any field in `[80.00%, 90.00%)` → `MEDIUM` → `REQUIRES_REVIEW` (`#fef08a` Light-Yellow, visual check).
  - Else (all fields `≥ 90.00%`) → `HIGH` → `VALIDATED` (`#22c55e` Green).
- We still compute and return `macro_avg_confidence`, `header_macro_avg_confidence`, and `min_critical_confidence` (for the 4 `BR-006` critical fields) so the worker can store `dbo.Invoices.confidence_macro_avg` and populate UI dashboards cleanly.

---

### Q1.2: How do you avoid an infinite exception loop when a clerk edits and re-validates a low-confidence invoice (`68%` OCR)?

**Answer:**
Per `CLAUDE.md §7.4` and `LLD §4`, **manual clerk edits never overwrite immutable AI extraction confidence scores** (preserving audit honesty about what the model originally saw), *yet* they must still allow the invoice to progress once verified by a human!
- When `ConfidenceRouter.route_revalidation(extraction_or_scores, rules_result=...)` is called (`is_revalidation=True`):
  1. It requires a verified `RulesEngineResult` (failing closed with `ValueError` if `rules_result is None` or internally contradictory — `SEC-164`).
  2. It preserves the original `min_confidence`, `confidence_tier`, and `field_assessments` untouched on the returned `ConfidenceRoutingResult`.
  3. If `rules_result.all_passed` is `True` (and the payload is not a negative-balance credit note — `SEC-161`), it promotes `target_status` to **`VALIDATED`** (`rules_override_applied=True`).
  4. If rules still fail, it returns `CREDIT_NOTE` (for negative-balance edits) or **`REQUIRES_APPROVAL`** (matching `LLD §4`: `REVALIDATING --> REQUIRES_APPROVAL : Checks Fail`).

---

### Q1.3: What edge cases did you handle around the `80%` and `90%` confidence boundaries?

**Answer:**
Three subtle production bugs that trip up naive implementations:
1. **No Gap Between `89%` and `90%`:** Business docs often write "80–89%", which naively coded as `80 <= score <= 89` leaves `89.50%` unmapped! We use contiguous half-open intervals: `score >= 90.00` (HIGH), `80.00 <= score < 90.00` (MEDIUM), `score < 80.00` (LOW).
2. **Sub-Cent Round-Up Escalation (`SEC-164`):** We compare the **exact unrounded `Decimal`** against thresholds *before* any display quantization so `89.999%` stays `MEDIUM` (`REQUIRES_REVIEW`) and `79.999%` stays `LOW` (`REQUIRES_APPROVAL`)—never rounding up into a higher trust tier!
3. **Zero Silent `0–1` Rescaling & Scale-Typo Floor (`SEC-162`):** Passing `0.95` is treated strictly as `0.95%` (`LOW`), never silently rescaled to `95%`. Likewise, configuring `CONFIDENCE_HIGH_THRESHOLD=0.90` and `CONFIDENCE_MEDIUM_THRESHOLD=0.80` in `.env` fails loudly because we enforce percentage-scale safety floors (`≥ 60%` high, `≥ 50%` medium) in both `Settings` and `_resolve_thresholds()`.

---

## 2. Invoice Finite State Machine, RBAC & Atomic CAS Concurrency (P8-2)

### Q2.1: Why did you make `LEGAL_TRANSITIONS` a `MappingProxyType` of `frozenset`s, and why ban self-transitions (`X → X`)?

**Answer:**
1. **Runtime Graph Immutability:** A plain Python `dict[InvoiceStatus, set[InvoiceStatus]]` can be mutated accidentally (or by a buggy test/plugin) at runtime. Wrapping the graph in `MappingProxyType` with `frozenset` values guarantees `TypeError` on any mutation attempt.
2. **No-Op Self-Transition Ban (`CLAUDE.md §16.1`):** Allowing `VALIDATED → VALIDATED` or `APPROVED_CLERK → APPROVED_CLERK` creates meaningless audit noise and violates our no-op guard (`previous_value != new_value`). Both `LEGAL_TRANSITIONS` and `InvoiceRepository.compare_and_update_status()` reject self-transitions explicitly.
3. **Terminal State Finality:** `STAGED_FOR_EXPORT`, `REJECTED`, `REJECTED_DUPLICATE`, and `VOID` map to `frozenset()`—once an invoice is staged for ERP export or voided/rejected, it can never be resurrected by a replay or bug.

---

### Q2.2: How do you prevent two concurrent API requests (e.g., two clerks or a clerk + retry worker) from corrupting an invoice's status?

**Answer:**
We eliminated classic **read-modify-write TOCTOU race conditions (`CWE-362`)** using **optimistic locking (Compare-And-Swap)** directly inside `InvoiceRepository.compare_and_update_status()`:
```sql
UPDATE invoices
SET status = :new_status, updated_at = :now_utc
WHERE invoice_id = :invoice_id AND status = :expected_status;
```
- Because the `WHERE status = :expected_status` predicate is evaluated atomically by Azure SQL (and SQLite) under row/table write locking, if two FastAPI replicas both read `VALIDATED` at `t=0` and submit `UPDATE` at `t=1`, **exactly one receives `rowcount == 1`** and commits.
- The losing replica receives `rowcount == 0`, rolls back cleanly, and `InvoiceStateMachine` raises **`ConcurrentStateTransitionError`** (which Phase 9 maps to HTTP **`409 Conflict`**).
- This gives us multi-replica horizontal scalability without slow `SELECT ... FOR UPDATE` deadlocks or extra Redis lock infrastructure.

---

### Q2.3: How does `InvoiceStateMachine` enforce defense-in-depth RBAC even if an API route forgets a permission check?

**Answer:**
`InvoiceStateMachine.transition()` enforces three layers of authorization before persisting any status change:
1. **Role-Scoped Transition Guard (`_authorize_transition`):**
   - `APPROVED_CLERK` requires an authenticated human role (`ap_clerk`, `finance_manager`, `system_admin`)—never `ActorRole.SYSTEM` (`CLAUDE.md §16.1`).
   - `APPROVED_MANAGER`, `REQUIRES_MANAGER_APPROVAL → REJECTED`, and `APPROVED_* → VOID` require `finance_manager` or `system_admin`—`ap_clerk` gets `UnauthorizedStateTransitionError` (`PermissionError` → HTTP `403`).
   - `ActorRole.SYSTEM` is strictly restricted by `_SYSTEM_ALLOWED_TRANSITIONS` (`SEC-167`) so background workers can *only* perform intake, extraction routing, high-value escalation, and post-approval export staging—never human visual confirmation, re-validation, rejection, or approval.
2. **High-Value & Unconverted FX Clerk Cap (`SEC-165`):** Before persisting `APPROVED_CLERK` for `ap_clerk`, `_enforce_invoice_business_guards()` checks `total_amount_usd` against `get_settings().HIGH_VALUE_THRESHOLD_USD`—and **fails closed** if a non-USD invoice has `total_amount_usd=None` so a `£9,000` (`~\$11,400 USD`) invoice can never sneak past the `\$10,000` cap!
3. **Unconditional Negative-Balance Credit-Note Guard (`SEC-166`):** Any invoice with `total_amount < 0` or `subtotal < 0` is blocked from transitioning to `VALIDATED`, `REQUIRES_REVIEW`, or `APPROVED_CLERK`.

---

## 3. High-Value, PO-Variance & ECB FX Escalation Rules (P8-3)

### Q3.1: Why does currency conversion use the invoice date instead of the upload date, and how do you handle weekend or holiday invoice dates?

**Answer:**
Per `CLAUDE.md §6` and `BR-012a`, financial accounting standards (GAAP/IFRS) value foreign-currency payables at the **transaction (invoice) date**—not when an AP clerk happened to upload the PDF days or weeks later.
- `EscalationEvaluator.evaluate_with_fx()` queries `ExchangeRateRepository.get_latest_rate_on_or_before(invoice_date, currency, "USD")`, which performs an indexed lookup (`IX_exchange_rates_lookup`) returning the most recent ECB published rate on or before `invoice_date`.
- If an invoice is dated on a Sunday or European bank holiday, it deterministically resolves Friday's closing ECB rate.
- If **no** rate exists on or before `invoice_date` (or a compromised repo returns `rate_date > invoice_date` or `rate <= 0` — `SEC-171`), it fails closed with `MissingExchangeRateError` / `ValueError` instead of falling back to `1.0`!

---

### Q3.2: How do you handle exact boundaries and zero-PO edge cases for `HIGH_VALUE_THRESHOLD_USD` and `PO_VARIANCE_TOLERANCE_PERCENT`?

**Answer:**
- **Strict `>` Boundaries (`BR-014`, `BR-015`, `LLD §4`):**
  - `total_amount_usd == \$10,000.00` → stays `VALIDATED` (clerk-eligible).
  - `total_amount_usd == \$10,000.001` or `\$10,000.01` → `REQUIRES_MANAGER_APPROVAL` (`EscalationReason.HIGH_VALUE`). We compare the **exact unrounded `Decimal`** so sub-cent overruns never round down!
  - `po_variance == +5.00%` or `-5.00%` → within tolerance.
  - `po_variance == +5.001%` or `-5.01%` → `REQUIRES_MANAGER_APPROVAL` (`EscalationReason.PO_VARIANCE`). Both upward *and* downward deviations beyond `5%` trigger escalation per `BR-014`.
- **Zero-PO Overrun Protection:** If `po_amount == 0` and `invoice_total == 0`, variance is `0.00%` (valid). If `po_amount == 0` and `invoice_total > 0`, dividing by zero would crash a naive implementation—instead we treat it as a `100.00%` overrun (`po_variance_exceeded = True`) and escalate to `REQUIRES_MANAGER_APPROVAL` fail-closed!
- **Exception Preservation (`BR-018`):** If an invoice is already in a blocking exception state (`DUPLICATE_INVOICE`, `CREDIT_NOTE`, `FLAGGED_POTENTIAL_REVISION`, `REJECTED_TAX_MISMATCH`, `REQUIRES_APPROVAL`, `REQUIRES_REVIEW`), `EscalationEvaluator` preserves that exception status while still recording `high_value_exceeded=True` and `eligible_for_clerk_approval=False`.

---

## 4. Cross-Phase Integration, Layering & Clean Architecture

### Q4.1: How does `src/validation/` interact with `InvoiceRepository` and `ExchangeRateRepository` without violating `CLAUDE.md §4.2` layering rules?

**Answer:**
Via **Dependency Inversion using Python `@runtime_checkable` `Protocol`s** (PEP 544):
- `src/validation/duplicate_detector.py` defines `InvoiceLookupProtocol` (read-only duplicate queries).
- `src/validation/state_machine.py` defines `InvoiceStatusRepositoryProtocol` (`get_by_id` + `update_status` + optional atomic `compare_and_update_status`).
- `src/validation/escalation_rules.py` defines `ExchangeRateLookupProtocol` (`get_latest_rate_on_or_before`).

Our SQLAlchemy repositories in `src/database/repositories.py` satisfy these protocols structurally without `src/validation/` ever importing `sqlalchemy` or `AsyncSession`—verified automatically by layering unit tests on every PR! This also makes unit testing trivial (we test both pure in-memory protocol fakes and real async SQLite repositories in milliseconds).

---

## 5. Real-World Pentest Stories & Security Threat Model Summary (`SEC-161`–`SEC-172`)

### Q5.1: Tell me about the best security vulnerabilities you caught while pentesting your own Phase 8 code.

**Answer:**
Here are four concrete, high-impact findings we discovered and remediated during our Phase 8 security audit:

1. **Fraction-Scale Config Typo Auto-Validating Garbage OCR (`SEC-162`, High, `CWE-1188`):**
   - *Attack/Failure:* Setting `CONFIDENCE_HIGH_THRESHOLD=0.90` and `CONFIDENCE_MEDIUM_THRESHOLD=0.80` (a classic `0–1` vs `0–100` DevOps typo) passed naive `0 < med < high <= 100` checks, causing every `5%`-confidence scan to route straight to Green `VALIDATED`!
   - *Fix:* Enforced percentage-scale safety floors (`≥ 60%` high / `≥ 50%` medium) in both `Settings` and `_resolve_thresholds()`.
2. **Spoofed `total_amount_usd` & Non-Unity USD FX Rate (`SEC-169`, High, `CWE-840` / `CWE-345`):**
   - *Attack:* Calling `evaluate_escalation(total_amount=25000, currency="USD", total_amount_usd=5000)` or passing `exchange_rate_to_usd=0.20` on a USD invoice let a `\$25,000` bill masquerade as `\$5,000` and evade manager escalation!
   - *Fix:* Enforced `exchange_rate_to_usd == 1.0` and `≤ \$0.01` consistency on USD invoices, `≤ \$0.05` conversion consistency on non-USD invoices when both `rate` and `total_amount_usd` are passed, and mutual exclusivity between `po_amount` and `po_variance_percent`.
3. **Conflicting `current_status="VALIDATED"` Masking a Failing `ConfidenceRoutingResult` (`SEC-170`, High, `CWE-840` / `CWE-863`):**
   - *Attack:* Passing `current_status="VALIDATED"` alongside a low-confidence `ConfidenceRoutingResult(target_status="REQUIRES_APPROVAL")` silently overwrote the failure and returned `eligible_for_clerk_approval=True`!
   - *Fix:* Added an explicit fail-closed contradiction check rejecting mismatched `current_status` and `confidence_result.target_status` with `ValueError`.
4. **Unconverted Foreign-Currency Clerk Approval Bypass in FSM (`SEC-165`, High, `CWE-863`):**
   - *Attack:* Attempting `InvoiceStateMachine.transition(VALIDATED → APPROVED_CLERK, role=ap_clerk)` on a `£9,000 GBP` (`~\$11,400 USD`) invoice whose `total_amount_usd` column was `None` would have skipped the `\$10,000` cap if only `total_amount` was compared numerically.
   - *Fix:* `_enforce_invoice_business_guards()` fails closed with `UnauthorizedStateTransitionError` whenever `ap_clerk` tries to approve a non-USD invoice lacking a populated `total_amount_usd`, AND enforces `abs(total_amount_usd) <= HIGH_VALUE_THRESHOLD_USD`.

### Phase 8 Complete Security Ledger (`SEC-161` – `SEC-172`)

| Vuln ID | Subtask | Severity | CWE | Mitigated Control |
|---|---|---|---|---|
| `SEC-161` | P8-1 | High | CWE-840 / CWE-20 | Unconditional `detect_credit_note()` guard in `route_extraction_confidence()` |
| `SEC-162` | P8-1 | High | CWE-1188 / CWE-636 | Percentage-scale floors (`≥60%` high / `≥50%` med) blocking `0.90`/`0.80` config typos |
| `SEC-163` | P8-1 | Medium | CWE-840 / CWE-20 | Canonical case-insensitive & bare/header field-key alias deduplication |
| `SEC-164` | P8-1 | Medium | CWE-345 / CWE-863 | `_verify_rules_result_integrity()` contradiction check + unrounded Decimal + frozen non-approval allowlist |
| `SEC-165` | P8-2 | High | CWE-863 / CWE-840 | High-value `>$10k` & unconverted non-USD `ap_clerk` approval block inside FSM |
| `SEC-166` | P8-2 | High | CWE-840 | Negative-balance credit-note block from regular states (`VALIDATED`/`REQUIRES_REVIEW`/`APPROVED_CLERK`) |
| `SEC-167` | P8-2 | Medium | CWE-863 | Strict read-only `_SYSTEM_ALLOWED_TRANSITIONS` allowlist for `ActorRole.SYSTEM` |
| `SEC-168` | P8-2 | Medium | CWE-20 / CWE-840 | `VALID_INVOICE_STATUSES` allowlist & self-transition ban in `InvoiceRepository.compare_and_update_status()` |
| `SEC-169` | P8-3 | High | CWE-840 / CWE-345 | Unity USD FX rate, `total_amount_usd` cross-check, and `po_amount`/`po_variance_percent` mutual exclusivity |
| `SEC-170` | P8-3 | High | CWE-840 / CWE-863 | Fail-closed rejection when `current_status` contradicts `confidence_result.target_status` |
| `SEC-171` | P8-3 | Medium | CWE-20 / CWE-704 | Strict pure `date` validation (no `datetime`) & repo FX row checks (`rate_date <= invoice_date`, `rate > 0`) |
| `SEC-172` | P8-3 | Medium | CWE-1188 / CWE-636 | Strict Pydantic `Field` bounds on `HIGH_VALUE_THRESHOLD_USD` & `PO_VARIANCE_TOLERANCE_PERCENT` in `Settings` |

