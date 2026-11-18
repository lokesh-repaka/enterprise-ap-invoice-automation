# AP Invoice Automation — Task Tracker

> Concise checklist for GitHub-visible progress.
> Architecture & Spec: [CLAUDE.md](CLAUDE.md) · HLD: [docs/HLD_High_Level_Design.md](docs/HLD_High_Level_Design.md) · LLD: [docs/LLD_Low_Level_Design.md](docs/LLD_Low_Level_Design.md) · Implementation Plan: [docs/Implementation_Planning_and_Development.md](docs/Implementation_Planning_and_Development.md)

**Branch convention:** `feature/<repo-name>` (one feature branch per sub-task; open the PR against `development`)
**Status:** `Pending ❌` · `Completed ✅`

Sub-tasks in the same phase that do not share files can be open at the same time. Do not stack a branch on another feature branch. Merge the listed predecessor first when a row names one.

---

## Phase 1 — Runtime Skeleton

> Depends on: nothing. Unblocks: every later phase.
> Merge order: P1-1 first. P1-2 and P1-3 in parallel after it. P1-4 after P1-2.

| Task | Branch | Status |
|------|--------|--------|
| P1-1 · Project structure, `pyproject.toml`, and `.env.example` | `feature/project-bootstrap` | Completed ✅ |
| P1-2 · Centralised settings (`src/core/config.py`) and JSON logging | `feature/core-config-logging` | Completed ✅ |
| P1-3 · Makefile with `run-api`, `run-ui`, `test`, `lint` targets | `feature/makefile-dev-commands` | Completed ✅ |
| P1-4 · FastAPI app skeleton — health routes and `request_id` middleware | `feature/api-health-middleware` | Completed ✅ |
| P1-5 · Offline pytest harness (`conftest.py`, SQLite fixture, fake Redis, mock AOAI) | `feature/test-harness-offline` | Completed ✅ |
| P1-6 · GitHub Actions CI pipeline — lint → unit test → build | `feature/ci-pipeline-github-actions` | Completed ✅ |

---

## Phase 2 — Persistence and Vendor Master

> Depends on: P1-2. Unblocks: Phases 3, 4, 5, 6, and 8.
> Merge order: P2-1 first. P2-2 and P2-3 in parallel after it. P2-4 after P2-3.

| Task | Branch | Status |
|------|--------|--------|
| P2-1 · SQLAlchemy 2 async models — `Vendors`, `Invoices`, `InvoiceLines`, `AuditLogs`, `ExchangeRates` | `feature/sqlalchemy-models` | Completed ✅ |
| P2-2 · Database schema DDL (`schema.sql`) and Alembic migration baseline | `feature/database-schema-migrations` | Completed ✅ |
| P2-3 · Repository layer — async CRUD for all five tables | `feature/repository-layer` | Completed ✅ |
| P2-4 · Seed scripts — Vendor Master (15 vendors, 4 jurisdictions) and exchange rates | `feature/seed-vendor-master` | Completed ✅ |
| P2-5 · `composite_hash` unique index and duplicate-safe upsert logic | `feature/database-composite-hash` | Completed ✅ |

---

## Phase 3 — Identity and Security

> Depends on: P1-4 and P2-1. Unblocks: protected routes in Phase 4 and Phase 7.
> Merge order: P3-1 and P3-3 in parallel. P3-2 after P3-1. P3-4 last (owns middleware order).

| Task | Branch | Status |
|------|--------|--------|
| P3-1 · Entra ID JWT validation and `require_role()` guard | `feature/entra-id-jwt-rbac` | Completed ✅ |
| P3-2 · Demo auth tokens for `sarah.clerk`, `michael.manager`, `dave.admin` | `feature/auth-demo-tokens` | Completed ✅ |
| P3-3 · Redis rate limiter middleware | `feature/rate-limit-redis` | Completed ✅ |
| P3-4 · Audit middleware — `request_id` propagation and immutable `AuditLog` writer | `feature/audit-middleware` | Completed ✅ |
| P3-5 · Azure Key Vault stub (`src/core/secrets.py`) — zero static secrets in code | `feature/core-keyvault-stub` | Completed ✅ |

---

## Phase 4 — Azure Storage Layer

> Depends on: P1-2 and P2-1. Parallel with: Phase 3. Unblocks: Phase 5.
> Merge order: P4-1 first. P4-2 and P4-3 in parallel after it.

| Task | Branch | Status |
|------|--------|--------|
| P4-1 · Azure Blob WORM client (`src/storage/blob_client.py`) with Managed Identity auth | `feature/storage-blob-worm-client` | Completed ✅ |
| P4-2 · Azurite local emulator setup and integration smoke test | `feature/storage-azurite-local` | Completed ✅ |
| P4-3 · File validator — MIME type guard, 25 MB limit, password-protected PDF rejection | `feature/storage-file-validator` | Completed ✅ |
| P4-4 · Blob metadata tagging — `VendorID`, `UploadTimestamp`, `FileHash` | `feature/storage-blob-metadata` | Completed ✅ |

---

## Phase 5 — Invoice Upload API and Job Queue

> Depends on: P2-3, P3-1, and P4-1. Unblocks: Phase 6.
> Merge order: P5-1 first. P5-2 and P5-3 in parallel after it. P5-4 last.

| Task | Branch | Status |
|------|--------|--------|
| P5-1 · `POST /api/v1/invoices/upload` — multipart upload, Blob write, Redis enqueue, 202 Accepted | `feature/api-invoice-upload` | Completed ✅ |
| P5-2 · Redis job queue client (`src/core/redis_client.py`) — enqueue, dequeue, idempotency key | `feature/core-redis-job-queue` | Completed ✅ |
| P5-3 · Background worker skeleton — picks jobs from Redis, calls pipeline, updates status | `feature/worker-pipeline-skeleton` | Completed ✅ |
| P5-4 · `GET /api/v1/invoices/{id}` and `GET /api/v1/invoices/exceptions` — query and filter routes | `feature/api-invoice-read-routes` | Completed ✅ |
| P5-5 · Idempotency key deduplication — re-submitted identical files return existing InvoiceID | `feature/api-idempotency-dedup` | Completed ✅ |

---

## Phase 6 — Extraction Engine and Model Gateway

> Depends on: P5-3. Parallel with: nothing inside the phase after P6-1.
> Merge order: P6-1 first. P6-2 and P6-3 in parallel after it. P6-4 after P6-2.

| Task | Branch | Status |
|------|--------|--------|
| P6-1 · Document classifier — PyMuPDF text-layer density check → `searchable_pdf`, `scanned_image`, `xlsx` | `feature/extraction-document-classifier` | Completed ✅ |
| P6-2 · Model Gateway (`src/extraction/model_gateway.py`) — route to GPT-4o-mini or GPT-4o Vision | `feature/extraction-model-gateway` | Completed ✅ |
| P6-3 · Pydantic extraction schema — 10 header fields + line-item fields with per-field confidence scores | `feature/extraction-pydantic-schema` | Completed ✅ |
| P6-4 · Extraction engine (`src/extraction/extract_engine.py`) — prompt assembly, `<invoice_text>` delimiters, schema enforcement | `feature/extraction-engine-prompts` | Completed ✅ |
| P6-5 · Mock AOAI client for offline testing — returns fixture JSON matching Pydantic schema | `feature/extraction-mock-aoai-client` | Completed ✅ |

---

## Phase 7 — Validation Rules Engine

> Depends on: P2-3 and P6-3. Parallel with: nothing inside the phase after P7-1.
> Merge order: P7-1 first. P7-2, P7-3, and P7-4 in parallel after it. P7-5 after all four.

| Task | Branch | Status |
|------|--------|--------|
| P7-1 · Duplicate detector (`src/validation/duplicate_detector.py`) — SHA-256 composite key, `-REV` suffix, credit note (negative total) detection | `feature/validation-duplicate-detector` | Completed ✅ |
| P7-2 · Line-item arithmetic validator — Qty × Unit Price = Total ± 0.02 (FR-05) | `feature/validation-line-arithmetic` | Completed ✅ |
| P7-3 · Invoice total arithmetic validator — Subtotal + Tax = Total ± 0.05 (FR-06) | `feature/validation-invoice-total` | Completed ✅ |
| P7-4 · Multi-country tax validator (FR-07) — US sales tax, UK VAT 20/5/0%, DE MwSt 19/7/0%, ES IVA 21/10/4/0%, reverse-charge and exemption flags | `feature/validation-tax-validator` | Completed ✅ |
| P7-5 · Date normaliser (FR-08) — Vendor Master locale resolution (US: MM/DD/YYYY; EU: DD/MM/YYYY), ambiguous flag | `feature/validation-date-normaliser` | Completed ✅ |
| P7-6 · Rules Engine orchestrator (`src/validation/rules_engine.py`) — chains all validators, returns pass/fail list | `feature/validation-rules-engine` | Completed ✅ |

---

## Phase 8 — Confidence Routing and State Machine

> Depends on: P7-6. Unblocks: Phase 9.
> Merge order: P8-1 first. P8-2 and P8-3 in parallel after it.

| Task | Branch | Status |
|------|--------|--------|
| P8-1 · Confidence router (`src/validation/confidence_router.py`) — ≥90% → VALIDATED, 80–89% → REQUIRES_REVIEW, <80% → REQUIRES_APPROVAL | `feature/validation-confidence-router` | Completed ✅ |
| P8-2 · Invoice state machine — 10-state FSM, legal transitions only, status written via repository | `feature/validation-state-machine` | Completed ✅ |
| P8-3 · High-value and PO-variance escalation rules — >$10,000 or >5% PO variance → REQUIRES_MANAGER_APPROVAL (all thresholds from `get_settings()`) | `feature/validation-escalation-rules` | Completed ✅ |

---

## Phase 9 — Re-Validation and Approval API

> Depends on: P3-1, P7-6, and P8-2. Unblocks: Phase 11 (UI).
> Merge order: P9-1 first. P9-2 and P9-3 in parallel after it.

| Task | Branch | Status |
|------|--------|--------|
| P9-1 · `POST /api/v1/invoices/{id}/revalidate` — reason code validation, re-runs rules engine, re-evaluates confidence, writes audit log | `feature/api-revalidate-route` | Pending ❌ |
| P9-2 · `POST /api/v1/invoices/{id}/approve` — RBAC check (clerk ≤$10k / manager >$10k), status transition, audit log | `feature/api-approve-route` | Pending ❌ |
| P9-3 · `GET /api/v1/invoices/{id}/audit` — full immutable audit trail for an invoice | `feature/api-audit-trail-route` | Pending ❌ |
| P9-4 · No-op edit guard — reject revalidate request where `previous_value == new_value` at the API layer | `feature/api-noop-edit-guard` | Pending ❌ |

---

## Phase 10 — Synthetic Sample Data

> Depends on: P2-4. Parallel with: Phases 6–9. Does not block any code phase.
> Merge order: P10-1 first. P10-2 and P10-3 in parallel after it. P10-4 last.

| Task | Branch | Status |
|------|--------|--------|
| P10-1 · Vendor Master JSON (`sample_data/vendor_master.json`) — 15 vendors, country, tax scheme, date locale | `feature/sample-data-vendor-master` | Completed ✅ |
| P10-2 · Exchange rates seed file (`sample_data/exchange_rates.json`) — USD/GBP/EUR daily rates | `feature/sample-data-exchange-rates` | Completed ✅ |
| P10-3 · Synthetic invoice files (`sample_data/invoices/`) — 300 files for 15 vendors, including 7 problem-case types | `feature/sample-data-invoices` | Completed ✅ |
| P10-4 · Ground-truth JSON (`sample_data/ground_truth/`) — human-verified extraction JSON for all 300 pilot invoices | `feature/sample-data-ground-truth` | Completed ✅ |

---

## Phase 11 — Streamlit UI

> Depends on: P5-4 and P9-2. Parallel with: nothing inside the phase after P11-1.
> Merge order: P11-1 first (API client must exist before pages). P11-2 through P11-5 in parallel after it.

| Task | Branch | Status |
|------|--------|--------|
| P11-1 · Typed HTTP API client (`src/ui/api_client.py`) wrapping `httpx` — all backend routes | `feature/ui-api-client` | Pending ❌ |
| P11-2 · Ingestion Dashboard (`/`) — drag-and-drop upload, batch status table, live polling | `feature/ui-ingestion-dashboard` | Pending ❌ |
| P11-3 · Review Workbench (`/workbench/{invoice_id}`) — split-screen PDF viewer + editable fields table, reason code dropdown, Re-Validate button | `feature/ui-review-workbench` | Pending ❌ |
| P11-4 · Human Exception Queue (`/exceptions`) — filtered queue by exception type, confidence colour coding, bulk actions | `feature/ui-exception-queue` | Pending ❌ |
| P11-5 · Revision Comparison screen (`/revision/{invoice_id}`) — side-by-side original vs. revision | `feature/ui-revision-comparison` | Pending ❌ |
| P11-6 · Audit Trail Viewer (`/audit/{invoice_id}`) — chronological timeline, immutable display | `feature/ui-audit-trail-viewer` | Pending ❌ |
| P11-7 · Confidence colour coding and role-aware UI — hide Approve button for `ap_clerk` when total > $10,000 | `feature/ui-confidence-colours-rbac` | Pending ❌ |

---

## Phase 12 — Integration Tests

> Depends on: Phase 9 (all API routes done). Parallel with: Phase 11.
> Merge order: P12-1 first. P12-2 through P12-5 in parallel after it.

| Task | Branch | Status |
|------|--------|--------|
| P12-1 · Unit tests — line arithmetic, invoice total, tax (all countries + reverse-charge), date locale, duplicate hash, confidence router, reason code enum | `feature/tests-unit-validation` | Pending ❌ |
| P12-2 · Integration test — full upload → extract → validate → route flow with mocked AOAI | `feature/tests-integration-upload-flow` | Pending ❌ |
| P12-3 · Integration test — re-validate workflow and audit log append-only enforcement | `feature/tests-integration-revalidate` | Pending ❌ |
| P12-4 · Integration test — RBAC 403 scenarios (clerk approving >$10k, unauthenticated access) | `feature/tests-integration-rbac` | Pending ❌ |
| P12-5 · Integration test — idempotency key deduplication (re-submitted identical file) | `feature/tests-integration-idempotency` | Pending ❌ |

---

## Phase 13 — Automated Evaluation Suite

> Depends on: Phase 10 (sample data) and Phase 9 (all API routes done).
> Merge order: P13-1 first. P13-2 and P13-3 in parallel after it. P13-4 last.

| Task | Branch | Status |
|------|--------|--------|
| P13-1 · Evaluator script (`src/evaluation/evaluator.py`) — batch inference, field-by-field comparison against ground-truth JSON | `feature/eval-evaluator-script` | Pending ❌ |
| P13-2 · Metric reporting — Header Accuracy ≥95%, Critical Field Floor ≥92%, Line-Item Accuracy ≥90%, STP ≥65% | `feature/eval-metric-reporting` | Pending ❌ |
| P13-3 · Evaluation pytest suite — threshold assertions that fail the CI build if missed | `feature/eval-pytest-thresholds` | Pending ❌ |
| P13-4 · `python -m src.evaluation.evaluator --report` CLI — printable evaluation summary | `feature/eval-cli-report` | Pending ❌ |

---

## Phase 14 — Infrastructure and Delivery

> Depends on: Phase 12 and Phase 13 pass. Image and Bicep files do not import the application graph.
> Merge order: P14-1 and P14-2 in parallel. P14-3 after both. P14-4 and P14-5 in parallel after P14-3.

| Task | Branch | Status |
|------|--------|--------|
| P14-1 · `Dockerfile.api` — FastAPI image (Python 3.11-slim, non-root user) | `feature/docker-api-image` | Pending ❌ |
| P14-2 · `Dockerfile.ui` — Streamlit image | `feature/docker-ui-image` | Pending ❌ |
| P14-3 · `docker-compose.yml` — FastAPI + Streamlit + Redis + Azurite + SQLite local stack | `feature/docker-compose-local-stack` | Pending ❌ |
| P14-4 · Azure Bicep template (`infrastructure/main.bicep`) — East US 2: Container Apps, Azure SQL, Redis Cache, Blob WORM, OpenAI, Key Vault, VNet, NSG | `feature/infra-bicep-east-us2` | Pending ❌ |
| P14-5 · Deployment hygiene tests — no `.env` committed, no static secrets, NSG East US 2 egress-deny verified | `feature/tests-deployment-hygiene` | Pending ❌ |

---

## Dependency Overview

```text
P1  Runtime skeleton
  └─► P2  Persistence & Vendor Master
        ├─► P3  Identity & Security  ─────────────────────────────────┐
        ├─► P4  Azure Storage Layer  ─────────────────────────────────┤
        │         └─► P5  Upload API & Job Queue ──────────────────── ┤
        │                   └─► P6  Extraction & Model Gateway        │
        │                              └─► P7  Validation Rules       │
        │                                       └─► P8  Confidence    │
        │                                              Routing & FSM  │
        │                   ┌──────────────────────────────────────── ┘
        │                   └─► P9  Re-Validate & Approval API
        │                              └─► P11  Streamlit UI ◄──────── ┐
        ├─► P10  Synthetic Sample Data ────────────────────────────── ─┤
        │                              └─► P13  Evaluation Suite      │
        └────────────────────────────► P12  Integration Tests ◄────── ┘
                                             └─► P14  Infra & Delivery
```

Phases 3 and 4 start together once Phase 2 merges. Phase 5 waits on Phases 2, 3, and 4. Phases 6–9 form a linear extraction-validation-approval pipeline. Phase 10 (sample data) is Lokesh's manual creation task and runs in parallel with all code phases. Phase 11 (UI) starts when API routes in Phase 9 exist. Phase 12 (tests) and Phase 13 (eval) start after Phases 9 and 10 respectively. Phase 14 (delivery) starts after both Phases 12 and 13 pass.

---

## Map to Milestones

| This file | Milestone | Target Week | Payment |
|-----------|-----------|-------------|--------:|
| Phase 1 + Phase 2 + Phase 3 | M1 — Environment & CI | Week 1 | $7,200 |
| Phase 4 + Phase 5 + Phase 6 + Phase 7 (partial) | M2 — 50-invoice Prototype | Week 4 | $10,800 |
| Phase 7 (complete) + Phase 8 + Phase 9 + Phase 10 + Phase 11 | M3 — 300-invoice Pilot | Week 8 | $10,800 |
| Phase 12 + Phase 13 + Phase 14 | M4 — Pilot Sign-Off & Hypercare | Week 12 | $7,200 |

---

## Progress Summary

| Phase | Name | Tasks | Completed |
|-------|------|-------|-----------|
| 1 | Runtime Skeleton | 6 | 6 ✅ |
| 2 | Persistence and Vendor Master | 5 | 5 ✅ |
| 3 | Identity and Security | 5 | 5 ✅ |
| 4 | Azure Storage Layer | 4 | 4 ✅ |
| 5 | Upload API and Job Queue | 5 | 5 ✅ |
| 6 | Extraction Engine and Model Gateway | 5 | 5 ✅ |
| 7 | Validation Rules Engine | 6 | 6 ✅ |
| 8 | Confidence Routing and State Machine | 3 | 3 ✅ |
| 9 | Re-Validation and Approval API | 4 | 0 ❌ |
| 10 | Synthetic Sample Data | 4 | 4 ✅ |
| 11 | Streamlit UI | 7 | 0 ❌ |
| 12 | Integration Tests | 5 | 0 ❌ |
| 13 | Automated Evaluation Suite | 4 | 0 ❌ |
| 14 | Infrastructure and Delivery | 5 | 0 ❌ |
| **Total** | | **68** | **43 (63%)** |

