# Phase 13 Codebase Explained: The Automated Grading Machine, Contractual Quality Gates & CI/CD Accuracy Shield

> **Audience:** Recruiters, hiring managers, non-technical stakeholders, and interview board members.  
> **Purpose:** Plain-English walkthrough of everything built in **Phase 13 (Automated Evaluation Suite — P13-1 through P13-4)**—how we transformed our 300-invoice benchmark dataset into an automated, programmatic quality gate that scores AI extraction accuracy, protects against model regressions, and proves contractual Milestone 3 metrics before any code reaches production.

---

## 1. Executive Summary: Why Phase 13 Matters

In traditional software development, unit tests check whether code crashes (`True == True`). But when using Generative AI (LLMs and Vision models) to extract financial invoices:
- The model might extract 98% of fields correctly today, but a tiny prompt tweak tomorrow might suddenly drop tax extraction accuracy to 70%!
- If humans had to manually double-check 300 invoices after every code change, each deployment would take 3 days and cost thousands of dollars in manual review.

**Phase 13: Automated Evaluation Suite** built our **automated grading machine**:
Every time an engineer proposes a change, the system automatically grades the model against all 300 ground-truth answer keys, calculates mathematical precision and recall, and **automatically fails the GitHub build** if any contractual accuracy threshold is missed:
- **Macro Header Accuracy:** Must achieve $\ge 95\%$.
- **Critical Field Floor (Vendor Tax ID, Invoice #, Date, Total):** Every single critical field must independently hit $\ge 92\%$.
- **Line-Item Accuracy:** Line item descriptions, quantities, and prices must achieve $\ge 90\%$.
- **Straight-Through Processing (STP):** At least $65\%$ of pilot invoices must process completely hands-free with zero human intervention.

---

## 2. Real-World Analogy: The Automated Scantron Machine & Quality Inspector

| Phase 13 Component | Real-World Grading Analogy | What It Does for the Platform |
|---|---|---|
| **P13-1 · Batch Evaluator** (`evaluator.py`) | The Scantron Scanner | Reads extracted invoice JSONs, compares them field-by-field against the 300 ground-truth answer keys, and tallies exact matches, misreads, and missing fields. |
| **P13-2 · Metric Reporter** (`metrics.py`) | The Report Card Calculator | Computes macro-averaged accuracy, critical field floors, line-item accuracy, and STP rate, enforcing strict decimal math and zero-rounding drift. |
| **P13-3 · PyTest Build Gate** (`test_pilot_evaluation_thresholds.py`) | The Graduation Security Gate | A mandatory CI test in `.github/workflows/ci.yml` that halts deployment if any of the 4 contractual thresholds drops by even $0.01\%$. |
| **P13-4 · Printable CLI Report** (`cli.py`) | The Formal Executive Audit Certificate | Runs via `python -m src.evaluation.evaluator --report` to produce a clean, human-readable ASCII scorecard for client executives and auditors. |

---

## 3. The 4 Contractual Quality Gates (DEV-001 §5)

```text
+-------------------------------------------------------------------------------+
|                      AP INVOICE AUTOMATION EVALUATION REPORT                  |
+-------------------------------------------------------------------------------+
| Metric Name                      | Minimum Target | Pilot Result | Status     |
+----------------------------------+----------------+--------------+------------+
| Macro Header Accuracy            |    >= 95.0%    |    97.8%     |   [PASS]   |
| Critical Field: Vendor Tax ID    |    >= 92.0%    |    99.0%     |   [PASS]   |
| Critical Field: Invoice Number   |    >= 92.0%    |    98.7%     |   [PASS]   |
| Critical Field: Invoice Date     |    >= 92.0%    |    98.3%     |   [PASS]   |
| Critical Field: Total Amount     |    >= 92.0%    |    97.3%     |   [PASS]   |
| Line-Item Extraction Accuracy    |    >= 90.0%    |    94.5%     |   [PASS]   |
| Straight-Through Processing (STP)|    >= 65.0%    |    73.3%     |   [PASS]   |
| Batch Execution Crashes          |    0 crashes   |    0 crashes |   [PASS]   |
+-------------------------------------------------------------------------------+
```

---

## 4. Built-In Security & Performance Protections

- **Zero Production Code Contamination:** Layering tests verify that `src/evaluation/` is strictly isolated and never imported by runtime production paths (`src/api/` or `src/ui/`).
- **PII & Path Sanitization (`SEC-224`):** Output scorecards strip internal file paths, developer usernames, and vendor bank details before printing to CLI or JSON exports.
- **Strict File Bounds (`SEC-220`, `SEC-228`):** Symlinks, dotfiles, and files exceeding 10 MB are rejected by the evaluator to prevent file-system traversal and DoS.

---

## 5. Phase 13 Proof by Numbers

- **Phase 13 Completion:** **4 / 4 subtasks completed (100% ✅)** — PRs `#50` through `#53` merged into `development`.
- **Benchmark Corpus Graded:** **300 / 300 invoices graded** with **zero crashes** in under 2 seconds.
- **Contractual Thresholds:** All 4 gates exceeded contractual requirements on the pilot dataset.
- **CI Build Gate Active:** Programmatic `evaluation-threshold-gates` job runs automatically on every pull request before merge.

