# Phase 10 Codebase Explained: The Master Flight Simulator, Synthetic Benchmark Corpus & Ground-Truth Test Matrix

> **Audience:** Recruiters, hiring managers, non-technical stakeholders, and interview board members.  
> **Purpose:** Plain-English walkthrough of everything built in **Phase 10 (Synthetic Sample Data — P10-1 through P10-4)**—how we built an enterprise-grade benchmark corpus of 300 synthetic international invoices across 15 vendors, daily ECB exchange rates, and human-verified ground-truth JSONs to safely stress-test our AI extraction engine, accounting rules, and approval workflows without risking real client financial data.

---

## 1. Executive Summary: Why Phase 10 Matters

Imagine training pilots for an international airline. You would never put a trainee pilot into a Boeing 777 filled with passengers on day one and fly into a hurricane. Instead, you put them inside a **high-fidelity flight simulator** that recreates clear blue skies, crosswinds, engine failures, heavy turbulence, and icy runways.

In an enterprise AI platform processing financial invoices:
- We **cannot use real client production invoices** during early testing because real bills contain proprietary supplier prices, employee home addresses, and confidential bank accounts (violating GDPR and client NDA).
- We **cannot test with just 5 or 10 clean toy PDFs** because clean invoices don't test dirty OCR, international VAT, European reverse-charge rules, duplicate submissions, currency conversions, or sneaky arithmetic errors.

**Phase 10: Synthetic Sample Data** built the platform's **complete 300-invoice flight simulator** across four core pillars:

1. **The International Vendor Directory (`sample_data/vendor_master.json` — P10-1):** 15 synthetic vendors spanning 4 major jurisdictions—United States (US sales tax in California & Texas), United Kingdom (UK VAT 20% & 5%), Germany (German MwSt 19% & reverse-charge), and Spain (Spanish IVA 21% & reduced 10%).
2. **The Daily Currency Exchange Matrix (`sample_data/exchange_rates.json` — P10-2):** Authoritative daily European Central Bank (ECB) exchange rates converting British Pounds (GBP) and Euros (EUR) to US Dollars (USD) based on invoice date, preventing currency fraud and ensuring accurate spending threshold enforcement.
3. **The 300 Multi-Format Invoice Corpus (`sample_data/invoices/` — P10-3):** 300 realistic digital PDFs, scanned PDFs, JPG/PNG mobile snapshots, and Excel XLSX files with authentic layouts, letterheads, and line items—including **30 deliberate "problem cases"** (the hurricanes, fog, and turbulence).
4. **The Gold-Standard Ground-Truth Answer Key (`sample_data/ground_truth/` — P10-4):** 300 human-verified JSON files capturing the exact 10 header fields and all line items for every invoice, against which our automated AI evaluation engine scores precision, recall, and straight-through processing.

---

## 2. Real-World Analogy: Building the Standardized Exam & Answer Key

| Phase 10 Component | Real-World Exam Analogy | What It Provides to the System |
|---|---|---|
| **P10-1 · Vendor Master** (`vendor_master.json`) | The Official Student Roster & Rules Guide | Defines each vendor's home country, tax scheme (US sales tax, UK VAT, German MwSt, Spanish IVA), and date reading rules (US `MM/DD/YYYY` vs EU `DD/MM/YYYY`). |
| **P10-2 · Exchange Rates** (`exchange_rates.json`) | The Currency Conversion Table | Daily ECB conversion rates for EUR/GBP to USD by invoice date so multi-currency bills are accurately compared against the `$10,000` manager approval threshold. |
| **P10-3 · 300 Invoices** (`sample_data/invoices/`) | The 300-Question Exam Booklet | A rigorous mix of 270 clean digital invoices and 30 deliberate "trap" questions (handwritten notes, messy scans, currency mix-ups, duplicates, credit notes). |
| **P10-4 · Ground Truth** (`sample_data/ground_truth/`) | The Professor's Sealed Answer Key | The 100% human-verified correct answers for every field on all 300 invoices, enabling automated grading with zero human guesswork. |

---

## 3. The 7 "Turbulence" Cases: Stress-Testing the Accounting Engine

Of the 300 synthetic pilot invoices, 30 represent intentional edge cases designed to test whether our safety filters catch real-world accounting hazards:

1. **Scanned & Handwritten Invoices:** Low-resolution mobile photos and noisy scans where quantities were crossed out or modified by hand—verifying the Model Gateway routes them to **GPT-4o Vision** instead of failing on text extraction.
2. **EU Reverse-Charge Invoices:** German and UK B2B invoices marked *"Reverse Charge — 0% VAT"*—verifying the tax engine recognizes valid cross-border tax exemptions without falsely failing math rules.
3. **Identical Duplicate Submissions:** The exact same invoice re-submitted under a different filename or scanned twice—verifying the SHA-256 composite business key (`Vendor Tax ID + Invoice # + Total`) halts duplicate processing immediately (`DUPLICATE_INVOICE`).
4. **Amended Revisions (`-REV`):** A vendor resending an invoice with updated line items or a changed total bearing a `-REV` suffix—verifying the system flags it as `FLAGGED_POTENTIAL_REVISION` for side-by-side comparison.
5. **Credit Notes (Negative Totals):** Returns and vendor rebates containing negative line items or a negative total—verifying the system routes them to `CREDIT_NOTE` and netting workflows instead of regular payment approval.
6. **Ambiguous Dates (`05/06/2026`):** Dates that could mean May 6th in the US or June 5th in Europe—verifying the date normalizer disambiguates using the Vendor Master's registered locale (US vs EU).
7. **Sub-Cent Rounding Differences (±$0.02 to ±$0.05):** Invoices where multiplying quantity by unit price produces minor fractional cent rounding discrepancies—verifying the rules engine accepts valid commercial rounding within configured tolerances (`LINE_ROUNDING_TOLERANCE = 0.02`, `INVOICE_ROUNDING_TOLERANCE = 0.05`).

---

## 4. Built-In Data Privacy & Security Hygiene

- **Zero Real PII or Client Secrets:** Every vendor name, tax ID, bank routing number, employee name, and address was synthetically generated. No real corporate data exists in the repository.
- **Strict File-System Isolation:** Sample data is kept strictly inside `sample_data/`, completely separated from application production logic in `src/`.
- **Deterministic Generation Scripts:** Generation scripts in `scratch/generate_mock_data.py` use fixed random seeds, ensuring that whenever test datasets are regenerated, invoice numbers, dollar amounts, and ground-truth JSONs remain 100% reproducible.

---

## 5. Phase 10 Proof by Numbers

- **Phase 10 Completion:** **4 / 4 subtasks completed (100% ✅)** — PRs `#27` through `#30` merged cleanly into `development`.
- **Corpus Volume:** **300 synthetic invoices** (PDF, PNG, JPG, XLSX) across 15 vendors and 4 jurisdictions.
- **Ground-Truth Coverage:** **300 ground-truth JSONs (100%)** covering **3,000 header fields** and **over 1,000 line items**.
- **Exchange Rates:** Daily historical exchange rate records covering USD, GBP, and EUR for the entire pilot operating period.
- **Enables CI/CD Gates:** Provided the mandatory benchmark corpus required for **Phase 13 (Automated Evaluation Suite)** and **Milestone 3 Pilot Sign-Off**.

