# GEMINI.md — AP Invoice Automation Platform
# Antigravity Workspace Rules · Keep under 150 lines / 24 KB

> **Full domain specification:** Read [CLAUDE.md](CLAUDE.md) first.
> This file governs Antigravity agent behaviour. CLAUDE.md governs the
> platform architecture, domain model, and coding rules. When they conflict,
> CLAUDE.md wins — update CLAUDE.md first, then this file.

---

## 1. What We Are Building

An AI-powered **Accounts Payable Invoice Automation Platform** (portfolio project,
synthetic data, Azure East US 2). Pipeline:
```
Ingest → Classify → Extract → Validate → Route → Review → Approve → Export
```
Stack: Python 3.11 · FastAPI · Pydantic v2 · SQLAlchemy 2 async · Streamlit 1.35+
· Azure OpenAI (GPT-4o + GPT-4o-mini) · Azure Blob WORM · Azure SQL · Redis

---

## 2. Layer Rules (Enforced — Do Not Cross)

```
src/ui/          → REST calls via src/ui/api_client.py only. No Azure, no rules.
src/api/         → Routes, schemas, RBAC. No validation logic.
src/services/    → Orchestrates repositories + extraction + rules.
src/database/    → SQLAlchemy async. No LLM calls.
src/extraction/  → Model Gateway, prompts, confidence. No business rules.
src/validation/  → Deterministic Python only. Never calls LLMs.
src/storage/     → Blob WORM client. No business logic.
src/core/        → Config, security, logging. Never imports extraction/ or validation/.
src/evaluation/  → Offline eval only. Never imported by production paths.
```

---

## 3. The Three Rules That Cannot Be Broken

1. **Rules first, model second.** Python decides approval, tax, status.
   Model extracts text. Never ask the model whether an invoice should be approved.

2. **Prompt injection defence always on.** All invoice content goes inside
   `<invoice_text>...</invoice_text>` before passing to any model call.

3. **Zero static secrets.** All Azure auth via Entra ID Managed Identity.
   No connection strings, API keys, or `.env` values in code.

---

## 4. Skill Quick-Reference

| Goal | Use |
|------|-----|
| Plan a new feature before coding | `/plan` |
| Implement an approved plan | `/implement` |
| Write or run tests | `/test` |
| Review git diff for security/arch | `/review` |
| Ask extraction/routing question | `/consult-rag` |
| Audit agent cost and blocked calls | `/cost-report` |

---

## 5. Subagent Tier Policy

| Tier | Model | Allowed Roles |
|------|-------|---------------|
| `pro` | Gemini Pro | `architect`, `planner`, `rag-consultant` only |
| `flash` | Gemini Flash | `implementer`, `test-engineer`, `code-reviewer` |
| `flash_lite` | Gemini Flash Lite | `log-triage`, `explorer` |

The `agent_guard.py` hook denies `pro` tier for any role not in the allowed list.

---

## 6. Key Business Rules (Hardcoded in Python — See CLAUDE.md §7)

- Line tolerance: ±0.02 · Invoice total tolerance: ±0.05
- High-value threshold: \$10,000 → `REQUIRES_MANAGER_APPROVAL`
- PO variance threshold: 5% → `REQUIRES_MANAGER_APPROVAL`
- Confidence: ≥90% → VALIDATED · 80–89% → REQUIRES_REVIEW · <80% → REQUIRES_APPROVAL
- Tax: US sales tax (vendor master) · UK VAT 20/5/0% · DE MwSt 19/7/0% · ES IVA 21/10/4/0%
- Date locale: US = MM/DD/YYYY · EU (UK/DE/ES) = DD/MM/YYYY via Vendor Master
- All thresholds from `get_settings()` — never hardcoded

---

## 7. Never Do These

- Approve an invoice without `POST /api/v1/invoices/{id}/approve` with an Entra ID token.
- Let the model decide an approval, tax rate, or status transition.
- Let a clerk approve an invoice where `total > HIGH_VALUE_THRESHOLD_USD`.
- Classify a negative-balance document as a regular invoice (must be `CREDIT_NOTE`).
- Write an audit log row where `previous_value == new_value`.
- Commit `.env`, `*.db`, real credentials, or real vendor invoice data.
- Make any Azure service call with a static connection string or API key.

---

## 8. Delivery Milestones

| Milestone | Week | Payment |
|-----------|------|--------:|
| M1 — Environment & CI | 1 | \$7,200 |
| M2 — 50-invoice Prototype | 4 | \$10,800 |
| M3 — 300-invoice Pilot (STP ≥ 65%) | 8 | \$10,800 |
| M4 — Hypercare Complete | 12 | \$7,200 |

Track progress in [TASKS.md](TASKS.md).

