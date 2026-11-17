# Enterprise AP Invoice Automation Platform

An AI-powered Accounts Payable (AP) Invoice Automation Platform designed for enterprise finance operations across US, UK, Germany, and Spain.

```
Ingest → Classify → Extract → Validate (Math + Tax + Duplicate) → Route → Review / Re-Validate → Approve → Stage for Export
```

---

## 📚 Project Documentation (`docs/`)

All core specifications, architecture decision records, and task roadmaps are maintained under [`docs/`](docs/):

- **[CLAUDE.md](docs/CLAUDE.md)** — Single Source of Truth: system architecture, domain models, layering rules, and security non-negotiables.
- **[TASKS.md](docs/TASKS.md)** — 14-Phase development plan and task progress tracker.
- **[GEMINI.md](docs/GEMINI.md)** — Workspace and agent rules.
- **[BRD (v1.0)](docs/BRD_v0.1.md)** — Business Requirements Document.
- **[PRD](docs/PRD_Product_Requirements_Document.md)** — Product Requirements Document (User Journeys, Screens, Acceptance Criteria).
- **[HLD](docs/HLD_High_Level_Design.md)** — High-Level Design (C4 Containers, Network Zones, Model Gateway, Cost Model).
- **[LLD](docs/LLD_Low_Level_Design.md)** — Low-Level Design (SQL DDL, State Machine, Arithmetic & Tax Algorithms, API Schemas).
- **[ADRs](docs/adr/)** — Architecture Decision Records (ADR-001 through ADR-007).
- **[Architecture Review & Sign-Off](docs/Architecture_Review_and_Sign_Off.md)** — Formal architecture sign-off and risk review.
- **[Implementation Plan](docs/Implementation_Planning_and_Development.md)** — Sprints, Gantt chart, and deployment runbooks.

---

## 🏗️ Architecture Summary

- **Frontend:** Streamlit 1.35+ (`src/ui/`)
- **Backend API:** FastAPI (`src/api/`)
- **Validation Engine:** Deterministic Python (`src/validation/`)
- **Model Gateway:** Azure OpenAI GPT-4o & GPT-4o-mini (`src/extraction/`)
- **Persistence:** SQLAlchemy 2 Async + Azure SQL / SQLite (`src/database/`)
- **Queue & Caching:** Redis (`src/core/`)
- **Document Storage:** Azure Blob Storage WORM (`src/storage/`)

---

## 🧪 Testing

All unit and integration tests run **100% offline** with zero external network or Azure cloud API calls:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true pytest -v tests/unit/
```
