# Phase 13: Comprehensive Interview Questions & Answers — Automated AI Evaluation & Accuracy Gates

> **Document Scope:** Deep-dive technical, AI evaluation methodology, macro vs micro accuracy metrics, critical field floors, line-item alignment algorithms, and CI build-gate architecture covering **Phase 13 (Automated Evaluation Suite — P13-1 through P13-4)**.  
> **Audience:** Candidates interviewing for Senior ML Engineer, AI Quality Architect, FinTech Platform Lead, or System Design Interviewers.

---

## 1. AI Evaluation Methodology & Regression Gates

### Q1.1: Why are automated evaluations necessary for Generative AI applications when unit tests already exist?

**Answer:**
Traditional unit tests verify deterministic code logic (`if x > 10: ...`), but LLMs and multimodal vision models are **probabilistic and non-deterministic**.
1. **Silent Regressions:** Modifying a prompt, tweaking temperature, changing system prompt formatting, or updating the base model (e.g. GPT-4o update) can improve one invoice layout while silently degrading extraction accuracy on another.
2. **Contractual SLAs:** Enterprise clients do not contract on whether the code runs; they contract on **accuracy metrics** ($\ge95\%$ header, $\ge90\%$ line, $\ge65\%$ STP).
3. **Automated Gatekeeping:** By executing `tests/evaluation/test_pilot_evaluation_thresholds.py` as a blocking CI job (`evaluation-threshold-gates`), any pull request that causes model performance to drop below contractual minimums fails the build automatically before code reaches staging or production.

---

## 2. Metric Formulations & Financial Thresholds

### Q2.1: Why does the platform enforce BOTH a "Macro Header Accuracy $\ge 95\%$" AND a "Critical Field Floor $\ge 92\%$"?

**Answer:**
Because an aggregate macro average can hide catastrophic failures on critical business fields!
- If an evaluation averages 10 header fields, a model could achieve **`96%` overall accuracy** by getting low-stakes fields right (e.g. `currency`, `due_date`, `po_number`) while failing on `vendor_tax_id` 30% of the time!
- In an Accounts Payable system, missing `vendor_tax_id` or `total_amount` leads to tax penalties, duplicate payments, or accounting fraud.
- By enforcing an independent **$\ge 92\%$ hard floor** on the 4 critical fields (`vendor_tax_id`, `invoice_number`, `invoice_date`, `total_amount`), the system guarantees that high aggregate scores cannot mask critical financial vulnerabilities.

### Q2.2: How does the evaluation engine evaluate line items when a model hallucinates extra rows or omits valid lines?

**Answer:**
In `src/evaluation/evaluator.py`, line-item comparison evaluates slot-level precision and recall:
1. Ground-truth line items are matched against extracted line items based on description similarity and unit price alignment.
2. **Hallucinated Rows:** Extra extracted lines that have no counterpart in ground truth are counted as false positives, reducing line-item precision.
3. **Omitted Rows:** Ground-truth lines missed by the model are counted as false negatives, reducing line-item recall.
4. Total Line Accuracy is calculated strictly as:
   $$\text{Line Accuracy} = \frac{\text{Correct Field Slots}}{\text{Total Ground-Truth Slots + Hallucinated Slots}} \ge 90\%$$

---

## 3. Architecture & CLI Security

### Q3.1: Why is `src/evaluation/` strictly barred from being imported by `src/api/` or `src/ui/`?

**Answer:**
Per `CLAUDE.md §4.2`:
1. **Attack Surface Minimization:** The evaluation suite contains dataset readers, ground-truth matchers, and batch runners that have no business running inside the public-facing API or Streamlit container.
2. **Memory & Cold-Start Latency:** Loading evaluation datasets or comparison schemas inside production containers increases RAM consumption and slows cold-start scaling.
3. **AST Enforcement:** CI unit tests parse the Abstract Syntax Tree (AST) of all production files to verify that zero production modules import `src.evaluation`.

