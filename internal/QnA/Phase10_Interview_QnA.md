# Phase 10: Comprehensive Interview Questions & Answers — Synthetic Benchmark Data

> **Document Scope:** Deep-dive technical, data engineering, synthetic dataset design, multi-jurisdiction tax modeling, date disambiguation, exchange rate governance, and ground-truth verification interview preparation covering **Phase 10 (Synthetic Sample Data — P10-1 through P10-4)**.  
> **Audience:** Candidates interviewing for Senior AI Engineer, Data Architect, FinTech Platform Lead, or Machine Learning QA Architect roles.

---

## 1. Synthetic Data Architecture & Compliance

### Q1.1: Why did you build a synthetic 300-invoice dataset rather than using sanitized real client invoices?

**Answer:**
1. **Privacy & Regulatory Compliance (GDPR / NDA):** Even "sanitized" real invoices often leak proprietary pricing agreements, supplier discount tiers, bank account numbers, or personal contact details. Synthetic generation completely eliminates GDPR Article 17 erasure requests and NDA breaches.
2. **Controlled Edge-Case Distribution:** In real invoice sets, edge cases (reverse-charge, ambiguous dates, negative credit notes, handwritten markup) may only appear in 0.5% of documents. Synthetic generation allowed us to deliberately inject exactly **10% problem cases (30 of 300)** to thoroughly test the limits of our rules engine and Model Gateway.
3. **Deterministic Ground-Truth Baseline:** Real production invoices frequently contain arithmetic errors made by suppliers. With synthetic data, we have an mathematically verified answer key, ensuring our evaluation suite measures AI extraction precision rather than supplier typos.

---

## 2. Multi-Jurisdiction Financial Modeling

### Q2.1: How does the Vendor Master resolve ambiguous dates like `05/06/2026` across different jurisdictions?

**Answer:**
Per `FR-08` and `CLAUDE.md §5`, date interpretation cannot rely on LLM guessing. `sample_data/vendor_master.json` explicitly defines `date_locale` for each registered vendor:
- For US vendors (`date_locale="US"`), `05/06/2026` is deterministically resolved as **May 6, 2026** (`MM/DD/YYYY`).
- For UK, German, and Spanish vendors (`date_locale="EU"`), it is resolved as **June 5, 2026** (`DD/MM/YYYY`).
- If an unregistered vendor submits a date where both day and month are $\le12$ and no vendor locale is available, `src/validation/date_normalizer.py` marks `is_ambiguous = True`, routing the invoice to `REQUIRES_REVIEW` for human confirmation.

### Q2.2: Why does currency conversion use the invoice date rather than the upload date?

**Answer:**
Under GAAP/IFRS commercial accounting standards and `CLAUDE.md §6`, transactions must be recognized at the spot exchange rate on the date the goods or services were delivered (the **invoice date**). Using the upload date would introduce financial distortion and allow vendors or clerks to delay uploading bills to take advantage of favorable currency fluctuations. `sample_data/exchange_rates.json` provides daily historical ECB rates matched to `invoice.invoice_date`.

---

## 3. Ground-Truth Data Structure & Precision Scoring

### Q3.1: How is the ground-truth JSON structured to enable automated field-by-field scoring without floating-point errors?

**Answer:**
In `sample_data/ground_truth/`:
- Monetary values (`subtotal_amount`, `tax_amount`, `total_amount`, `unit_price`, `line_total`) are stored as fixed-scale string representations of decimals (e.g., `"1250.50"`), which parse directly into Python `Decimal` instances.
- Dates are stored strictly in ISO 8601 (`YYYY-MM-DD`).
- This prevents IEEE 754 binary floating-point drift (e.g. `0.1 + 0.2 = 0.30000000000000004`) from falsely failing mathematical comparisons in `src/evaluation/evaluator.py`.
- Line items are structured as an ordered array, allowing the evaluator to test both 1-to-1 row alignment and set-based matching with hallucination penalties.

