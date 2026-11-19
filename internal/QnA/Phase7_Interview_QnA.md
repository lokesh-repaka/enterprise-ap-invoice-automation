# Phase 7: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, financial domain modeling, precision arithmetic, multi-country tax compliance, date disambiguation, security pentesting, and architecture interview preparation covering **Phase 7 (Validation Rules Engine — P7-1 through P7-6)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, FinTech / AP Automation Engineer, AI Systems Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [Duplicate, Revision & Credit-Note Detection (P7-1)](#1-duplicate-revision--credit-note-detection-p7-1)
2. [Line-Item & Invoice Total Financial Arithmetic (P7-2 & P7-3)](#2-line-item--invoice-total-financial-arithmetic-p7-2--p7-3)
3. [Multi-Country Tax Validation & Fraud Prevention (P7-4)](#3-multi-country-tax-validation--fraud-prevention-p7-4)
4. [Date Locale Disambiguation & Chronological Conflict Detection (P7-5)](#4-date-locale-disambiguation--chronological-conflict-detection-p7-5)
5. [Rules Engine Orchestration & Re-Validation Architecture (P7-6)](#5-rules-engine-orchestration--re-validation-architecture-p7-6)
6. [Real-World Pentest Stories & Security Threat Model Summary](#6-real-world-pentest-stories--security-threat-model-summary)

---

## 1. Duplicate, Revision & Credit-Note Detection (P7-1)

### Q1.1: Why do you use a SHA-256 composite business key (`Vendor Tax ID + Invoice Number + Total Amount`) instead of hashing the raw PDF bytes?

**Answer:**
We actually use **both** at different layers for two completely different problems:
1. **File-byte SHA-256 (`Idempotency-Key` in Phase 5):** Catches accidental double-clicks or network retries uploading the *exact same binary file*, returning HTTP `200 OK` with the existing `InvoiceID`.
2. **Composite business-key SHA-256 (`DuplicateDetector` in P7-1, `FR-09`):** Catches **re-scanned duplicates**! If a vendor emails a PDF today and someone scans a printed copy of the exact same invoice tomorrow, the raw file bytes are completely different—yet `SHA256(f"{vendor_tax_id}_{invoice_number}_{total_amount:.2f}")` is **100% identical** and stops duplicate payment!

Crucially, our `composite_hash` also allows legitimate revisions: if the vendor sends the same `invoice_number` with a *changed* `total_amount` (or a `-REV` / `v2` suffix), the hash differs, and `DuplicateDetector` routes it to `FLAGGED_POTENTIAL_REVISION` with `matched_invoice_id` linked to the original invoice for side-by-side clerk comparison (`FR-10`, `ADR-006`).

---

### Q1.2: Walk me through your decision precedence when an invoice triggers multiple signals—for example, a duplicate credit note or a negative-balance document referencing an existing invoice number.

**Answer:**
Our pure `evaluate_duplicate_rules()` enforces a strict 4-tier financial precedence:
1. **Priority 1 — `DUPLICATE_INVOICE`:** If an active non-self, non-`VOID`, non-`REJECTED_DUPLICATE` record already matches the exact SHA-256 composite hash (or normalized `(vendor_tax_id, invoice_number, total_amount)`), it MUST be flagged `DUPLICATE_INVOICE`—even if it is a credit note or a `-REV` invoice! Otherwise re-submitting the same credit note would double-credit the ledger and violate `UX_invoices_composite_hash`.
2. **Priority 2 — `CREDIT_NOTE` (`FR-11`, `CLAUDE.md §16.1`):** If non-duplicate AND `total_amount < 0`, `subtotal < 0`, OR *any* `line_total < 0` (matching our pilot dataset's `INV-2026-1025`, which has a positive grand total of `€5,228.86` with a `-€171.00` credit line!), it routes to `CREDIT_NOTE`—attaching `matched_invoice_id` if an earlier invoice with that number exists for netting context.
3. **Priority 3 — `FLAGGED_POTENTIAL_REVISION` (`FR-10`):** Triggered by a revision suffix (`-REV`, `Rev2`, `-REVISION`, `-v2`, `_ver2`) in the invoice number or filename stem, OR an existing active invoice for the same vendor & base invoice number with a differing total.
4. **Priority 4 — `PROCEED`:** Clean unique invoice continues to math, tax, and date validation.

---

### Q1.3: What subtle duplicate-detection bypasses did your security audit uncover and fix in P7-1?

**Answer:**
Three high-impact real bypasses:
1. **Invisible Unicode Soft-Hyphen & NFKC Fullwidth Spoofing (`SEC-137`, `CWE-172` / `CWE-451`):** Blocking only `\u200b–\u200f` and `\u202a–\u202e` missed **soft hyphen (`\u00ad`)**, **non-breaking space (`\u00a0`)**, and **fullwidth digits (`１` = `\uff11`)**. An attacker submitting `"INV-2026\u00ad-1001"` produced a completely different SHA-256 hash while looking identical to an AP clerk! We fixed `_sanitize_identifier()` to reject all Unicode `Cc/Cf/Cs/Co/Cn` categories, non-ASCII whitespace, and `NFC != NFKC` compatibility homographs.
2. **SQLite Case-Sensitivity Bypass (`SEC-138`, `CWE-178`):** Azure SQL's default collation (`CI_AS`) is case-insensitive, whereas SQLite equality is case-sensitive. Submitting lowercase `"inv-2026-1001"` against `"INV-2026-1001"` slipped past SQLite lookups! Adding uppercase-normalized hash and vendor-number fallback lookups in `DuplicateDetector.detect()` closed the gap while keeping 100% parity with all 300 ground-truth hashes.
3. **Cross-Vendor Hash Disclosure (`SEC-139`, `CWE-284`):** Enforced explicit `vendor_tax_id` parity on both hash and vendor-number matches so a misconfigured repository or underscore delimiter collision can never disclose another vendor's `matched_invoice_id`.

---

## 2. Line-Item & Invoice Total Financial Arithmetic (P7-2 & P7-3)

### Q2.1: Why did you avoid Python `float` and preserve unrounded `line_total` / `grand_total` precision when checking `±0.02` and `±0.05` tolerances?

**Answer:**
Two classic financial precision bugs:
1. **Binary Floating-Point Artifacts:** In IEEE 754 `float`, `10.02 - 10.00` evaluates to `0.019999999999999574` or `100.02 - 100.00` evaluates to `0.020000000000003126 > 0.02`—causing valid boundary invoices to fail randomly! Using exact `Decimal` with explicit `ROUND_HALF_UP` eliminates float drift completely.
2. **Sub-Cent Rounding Bypass (`SEC-145`, `SEC-148`):** If you naively quantize `stated_total = Decimal("100.021")` to 2 decimal places *before* subtracting `expected_total = Decimal("100.00")`, `100.021` rounds down to `100.02`, making `diff = 0.02 <= 0.02` and falsely passing an out-of-tolerance invoice! We quantize `expected_total` to `0.01` (`ROUND_HALF_UP`) and subtract the **unrounded** `stated_total` so `+0.021 > 0.02` and `+0.051 > 0.05` fail deterministically.

---

### Q2.2: How do you prevent an attacker from exploiting `Subtotal + Tax = Total` to evade the `\$10,000` Finance Manager approval threshold?

**Answer:**
During our P7-3 penetration test, we discovered an **Opposite-Sign Tax Injection attack (`SEC-146`, `CWE-840`)**:
- Suppose an invoice has `subtotal = \$10,000.00`, `tax_amount = -\$100.00`, and `total_amount = \$9,900.00`.
- Pure addition `10000 + (-100) = 9900` balances with `diff = 0.00`—yet the negative tax artificially drops the grand total *below* `HIGH_VALUE_THRESHOLD_USD = \$10,000` (`FR-13`) so an `ap_clerk` could approve it without Finance Manager sign-off!
- We closed this in both `evaluate_invoice_total()` and `evaluate_tax_rate()` by enforcing **sign consistency**: whenever `(subtotal > 0 and tax < 0)` or `(subtotal < 0 and tax > 0)`, validation immediately fails (`sign_consistent=False`, `is_valid=False`), while still permitting `tax == 0` (exempt/reverse-charge) and all-negative credit notes.

---

### Q2.3: Tell me about a subtle Python `Decimal` / regex bug your own penetration tests caught in P7-2.

**Answer:**
While pentesting `line_arithmetic.py` (`SEC-143`, `CWE-20` / `CWE-436`), we noticed Python's `Decimal()` silently accepts **underscore literals** (`Decimal("1_000.00") == Decimal("1000.00")`) and **Arabic-Indic Unicode digits** (`Decimal("١٠.٠٠") == Decimal("10.00")`). Even more subtly, when we first added a regex guard using `\d`, our own pentest caught that Python 3's `\d` matches Unicode digits by default unless `re.ASCII` or `[0-9]` is used! Switching to strict `[0-9]` (`^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?$`) plus `_CONTROL_CHAR_RE` blocked underscores, non-ASCII digits, and CRLF completely across P7-2, P7-3, and P7-4.

---

## 3. Multi-Country Tax Validation & Fraud Prevention (P7-4)

### Q3.1: How does `tax_validator.py` handle US sales tax vs. European VAT/MwSt/IVA, mixed-rate invoices, and reverse-charge exemptions?

**Answer:**
`src/validation/tax_validator.py` implements `FR-07` / `BR-011` cleanly across all four jurisdictions:
- **Reverse Charge / Exemption (`is_reverse_charge` / `is_exempt`):** Strictly requires Python `bool` (rejecting `"false"` / `1` so truthy strings can never bypass tax checks — `SEC-152`) and enforces `abs(stated_tax) < 0.01`; any non-zero tax fails with `REJECTED_TAX_MISMATCH`.
- **US Sales Tax:** When `vendor_tax_rate` from Vendor Master is supplied (e.g., CA `9.5%`, TX `8.25%`, OR `0.0%`), validates `abs((subtotal * vendor_tax_rate).quantize(0.01) - stated_tax) <= tolerance`. When called via the 5-argument `LLD §5.3` signature without Vendor Master, enforces a fail-closed `0%–15%` combined US statutory sales tax ceiling rather than blindly accepting any number.
- **UK VAT (`GB` / alias `UK`: `20/5/0%`), DE MwSt (`19/7/0%`), ES IVA (`21/10/4/0%`):**
  - Header-only mode matches against the country's statutory rate tuple within `get_settings().INVOICE_ROUNDING_TOLERANCE`.
  - Mixed-rate multi-line mode (for vendors like UK V-004 mixing `20%` and `5%` lines) verifies **three things**: (1) every line rate is an approved statutory rate for that country, (2) `sum(line_total)` reconciles with the header `subtotal` within tolerance (`SEC-150`), and (3) `sum(line_total * line.tax_rate)` matches `stated_tax` within tolerance!

---

### Q3.2: What two critical VAT-bypass vulnerabilities did you discover in the naive LLD §5.3 design and fix in P7-4?

**Answer:**
1. **Partial Line-Item Subtotal VAT Evasion (`SEC-150`, `CWE-840`):** If an attacker submitted a `£10,000` UK invoice with `£200` tax (`2%`) and supplied a single `£1,000 @ 20%` line item (`= £200`), a line-only tax sum check would pass `£200 == £200` while ignoring `£9,000` of untaxed subtotal! Adding mandatory `abs(sum(line_total) - subtotal) <= tolerance` reconciliation closed this completely.
2. **Unsupported / Homograph Country Code Fallback-to-US Bypass (`SEC-151`, `CWE-20` / `CWE-172`):** Naive `if country_code not in COUNTRY_TAX_RATES: return (True, "US accepted...")` meant any typo (`"DE "`), unsupported country (`"FR"`, `"XX"`), or soft-hyphen homograph (`"DE\u00ad"`) would silently bypass European VAT validation! Our `normalize_country_code()` enforces a strict fail-closed `{US, GB, DE, ES}` allowlist (mapping `UK -> GB`) with Unicode `Cc/Cf/Cs/Co/Cn` and `NFC == NFKC` rejection.

---

## 4. Date Locale Disambiguation & Chronological Conflict Detection (P7-5)

### Q4.1: How do you disambiguate `05/06/2026` (May 6 vs. June 5), and how did your normaliser catch `INV-2026-1005` in the 300-invoice pilot dataset?

**Answer:**
1. **Vendor Master Resolution (`BR-012`):** `resolve_date_locale()` maps Vendor Master preferences (`US` / `MM/DD/YYYY` → US `%m/%d/%Y`; `GB`/`UK`/`DE`/`ES`/`EU`/`DD/MM/YYYY` → EU `%d/%m/%Y`) and always accepts unambiguous ISO 8601 (`YYYY-MM-DD`).
2. **Unlisted Vendor Ambiguity:** When `locale` is `None` or `"UNKNOWN"`, non-ISO regional dates flag `is_ambiguous=True`, `recommended_status="REQUIRES_REVIEW"` (and `parse_invoice_date()` raises `AmbiguousDateError`, a subclass of `ValueError`), returning both `candidate_us_date` and `candidate_eu_date` for one-click clerk confirmation.
3. **Chronological Locale Conflict (`INV-2026-1005` — `SEC-154`):** In our 300-invoice pilot dataset, `INV-2026-1005` is a **US vendor** whose invoice has `invoice_date = "05/06/2026"` and `due_date = "03/09/2026"`. Under US (`MM/DD/YYYY`), that parses as **May 6 → March 9** (`due_date < invoice_date`—58 days backwards!), whereas under EU (`DD/MM/YYYY`) it is **June 5 → September 3** (valid 90-day terms!). Because `CLAUDE.md §6` uses `invoice_date` to fetch the ECB FX rate, silently accepting the inverted month would corrupt currency conversion! `normalize_invoice_dates()` detects `due_date < invoice_date`, flags `chronological_conflict=True` → `REQUIRES_REVIEW`, and attaches the alternate EU range hint—catching **exactly `INV-2026-1005`** while passing all 299 other pilot invoices cleanly.

---

## 5. Rules Engine Orchestration & Re-Validation Architecture (P7-6)

### Q5.1: Why does `RulesEngine` evaluate all 5 validators instead of short-circuiting on the first failure, and how does it choose `recommended_status`?

**Answer:**
Short-circuiting creates a frustrating "whack-a-mole" UX for AP clerks: if an invoice has both a line-item math error AND a tax mismatch, stopping at line math forces the clerk to edit, click Re-Validate, and only then discover the tax mismatch! Instead, `RulesEngine` runs all 5 deterministic checks in one pass (~1.3 ms total), collects every `RuleCheckOutcome` into `rule_outcomes` + `errors` (and serializes `to_validation_summary()` matching `LLD §2.2`), and selects `recommended_status` via an explicit deterministic priority table:
1. `DUPLICATE_INVOICE`
2. `CREDIT_NOTE`
3. `FLAGGED_POTENTIAL_REVISION`
4. `REJECTED_TAX_MISMATCH`
5. `REQUIRES_APPROVAL` (line/total arithmetic errors)
6. `REQUIRES_REVIEW` (date ambiguity / chronological conflict)
7. `None` (all rules passed → forward to Phase 8 Confidence Router)

Notice also that `AllowedRuleStatus` is a strict `Literal` excluding `APPROVED_CLERK`, `APPROVED_MANAGER`, and `STAGED_FOR_EXPORT` (`CWE-863`), guaranteeing the validation layer can **never** self-approve an invoice.

---

### Q5.2: How does `RulesEngine` enforce `CLAUDE.md §16.1` during clerk re-validation (`validate_revalidation()`) or when `run_duplicate_check=False`?

**Answer:**
During our P7-6 pentest (`SEC-157`), we verified that skipping the database duplicate lookup (e.g., on `POST /api/v1/invoices/{id}/revalidate` where the invoice already exists in SQL, or when calling `validate_extraction(..., run_duplicate_check=False)`) must **never** disable credit-note detection! Both code paths unconditionally execute `detect_credit_note(total_amount, subtotal=subtotal, line_totals=...)`, guaranteeing that even if a clerk edits a regular invoice into a negative balance, it routes to `CREDIT_NOTE` rather than passing as a regular payable invoice. We also closed **partial per-line `tax_rate` omission (`SEC-158`)** so omitting `tax_rate` on one line of a multi-line edit fails closed rather than silently falling back to header-only VAT validation.

---

## 6. Real-World Pentest Stories & Security Threat Model Summary

### Q6.1: Summarize the Phase 7 security posture if a Staff Security Engineer asks how you hardened the validation layer.

**Answer:**
Across Phase 7 (PRs #25–#30), we audited and mitigated **24 concrete vulnerabilities (`SEC-137`–`SEC-160`)**, verified by dedicated penetration tests across **360 passing offline tests (0.0 network calls, 7.10s)**:
- **Hash & Identifier Integrity (`SEC-137`, `SEC-138`, `SEC-139`):** Unicode `Cc/Cf/Cs/Co/Cn` + NBSP + `NFC == NFKC` rejection, SQLite mixed-case fallback, and cross-vendor hash isolation.
- **Financial Fraud & Threshold Evasion (`SEC-145`, `SEC-146`, `SEC-150`, `SEC-154`, `SEC-157`, `SEC-158`):** Sub-cent unrounded diff checks, salami-slicing drift visibility, opposite-sign negative-tax `\$10k` evasion blocking, partial-line VAT subtotal reconciliation, chronological date-swap detection, unconditional credit-note guard, and partial line-tax omission rejection.
- **Parser Differentials & DoS (`SEC-141`, `SEC-142`, `SEC-143`, `SEC-147`, `SEC-155`, `SEC-159`):** Strict ASCII `[0-9]` regexes (no underscores or Arabic-Indic digits), duplicate `line_number` rejection, `MAX_LINE_ITEMS=500`, `MAX_EXISTING_LOOKUP_RECORDS=1,000`, linear-time anchored regexes, SQL `DECIMAL(18, 2)` overflow caps, and `[1990, 2100]` financial year bounds.
- **Governance & Layer Isolation (`SEC-140`, `SEC-144`, `SEC-152`, `SEC-156`, `SEC-160`):** `***-**-XXXX` Tax ID masking, CRLF log-injection stripping, `[0.00, 100.00]` fail-closed env tolerance bounds, strict Python `bool` enforcement, `frozen=True` + `extra="forbid"` models, zero approval statuses, and pytest-verified zero imports of `openai` or `sqlalchemy` anywhere in `src/validation/`.

