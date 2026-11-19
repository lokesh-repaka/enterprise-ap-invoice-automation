# Phase 2: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 2 (Persistence and Vendor Master)**.  
> **Target Audience:** Solution Architects, Technical Leads, Database Engineers, and System Design Interviewers.

---

## 1. Phase 2 Mission & Architectural Baseline

At the conclusion of Phase 1, the platform possessed a resilient, observable, zero-cost runtime skeleton (`FastAPI`, PII-masked JSON logging, `RequestIDMiddleware`, offline test harness, and GitHub Actions CI), but lacked stateful financial persistence.

The mission of **Phase 2** was to introduce an enterprise-grade, dual-dialect asynchronous persistence tier that satisfies five strict invariants:

1. **Zero Floating-Point Money (CWE-682):** Every monetary amount, quantity, tax rate, and FX rate uses fixed-point SQL `DECIMAL`/`NUMERIC` mapped to Python `Decimal`.
2. **Dual-Engine Portability:** Identical SQLAlchemy 2.0 ORM models and ANSI/filtered DDL execute seamlessly across local SQLite (`aiosqlite`) and production Azure SQL Serverless (`aioodbc` + Entra ID).
3. **Immutable Financial Auditability (`CLAUDE.md §6`):** `AuditLogs` is strictly append-only at the repository interface boundary, rejecting mutations, deletions, and no-op edits (`previous_value == new_value`).
4. **Defensive Data Boundaries:** Parameterized ORM queries exclusively (CWE-89), explicit field allowlists on updates (CWE-915), bounded pagination limits (CWE-770), and seed path containment (CWE-22).
5. **Race-Safe Duplicate Elimination (CWE-362):** Database-enforced partial unique indexing on `composite_hash` (`WHERE status NOT IN ('REJECTED_DUPLICATE', 'VOID')`) paired with `IntegrityError` TOCTOU rollback recovery.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 1 Baseline (Stateless Runtime)

Entering Phase 2, `src/database/` was an empty placeholder package with zero ORM entities, migrations, or repositories.

```mermaid
flowchart LR
    API["src/api/ (FastAPI Health + Middleware)"] --> CORE["src/core/ (Config & PII Logging)"]
    API -.->|"Not Yet Wired"| DB["src/database/ (Empty Scaffold)"]

    style DB fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style API fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
```

---

### 2.2 Stage 1 (P2-1): SQLAlchemy 2.0 Async Domain Models

In **P2-1 (`feature/sqlalchemy-models`)**, we introduced [`src/database/models.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/models.py) defining all five core relational entities with SQLAlchemy 2.0 `DeclarativeBase`, typed `Mapped[...]` annotations, `Numeric` financial columns, bidirectional relationships, and PII-masked `Vendor.__repr__`.

```mermaid
erDiagram
    VENDORS ||--o{ INVOICES : "issues (CASCADE)"
    INVOICES ||--|{ INVOICE_LINES : "contains (CASCADE)"
    INVOICES ||--o{ AUDIT_LOGS : "records (APPEND-ONLY)"
    EXCHANGE_RATES }o..o{ INVOICES : "normalizes to USD by invoice_date"

    VENDORS {
        varchar vendor_tax_id PK "Masked in __repr__"
        varchar vendor_id "e.g. VEND-1001"
        varchar vendor_name
        varchar country_code "US, DE, ES, GB"
        varchar date_format_locale "MM/DD/YYYY or DD/MM/YYYY"
        varchar number_format_preference "PERIOD or COMMA"
        varchar default_currency "USD, EUR, GBP"
        varchar tax_scheme "Sales Tax / MwSt / IVA / VAT"
        numeric standard_tax_rate "Numeric(5,4)"
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    INVOICES {
        varchar invoice_id PK "UUID v4 String(36)"
        varchar vendor_tax_id FK
        varchar vendor_name
        varchar invoice_number
        date invoice_date
        date due_date
        varchar po_number
        numeric subtotal "Numeric(18,2)"
        numeric total_tax_amount "Numeric(18,2)"
        numeric total_amount "Numeric(18,2)"
        varchar currency "Default USD"
        numeric total_amount_usd "Numeric(18,2)"
        numeric confidence_macro_avg "Numeric(5,2)"
        varchar status "10-state FSM (Default UPLOADED)"
        varchar composite_hash "SHA-256 CHAR(64)"
        varchar blob_raw_url
        varchar blob_json_url
        datetime created_at
        datetime updated_at
    }

    INVOICE_LINES {
        varchar line_id PK "UUID v4 String(36)"
        varchar invoice_id FK
        int line_number
        text description
        numeric quantity "Numeric(18,4)"
        numeric unit_price "Numeric(18,4)"
        numeric line_total "Numeric(18,2)"
        numeric line_tax_rate "Numeric(5,4)"
        numeric confidence_score "Numeric(5,2)"
    }

    AUDIT_LOGS {
        varchar audit_id PK "UUID v4 String(36)"
        varchar invoice_id FK
        varchar user_id
        varchar action_type "EXTRACTION, EDIT, REVALIDATE, APPROVE, REJECT"
        varchar field_name
        text previous_value
        text new_value
        varchar reason_code "OCR_MISREAD, VENDOR_ROUNDING, etc."
        varchar comment
        datetime timestamp "UTC"
    }

    EXCHANGE_RATES {
        int rate_id PK "Autoincrement"
        date rate_date "UQ with from/to currency"
        varchar from_currency "EUR, GBP, USD"
        varchar to_currency "Default USD"
        numeric exchange_rate "Numeric(18,6)"
    }
```

#### Key Design Decisions in P2-1:
- **String(36) UUID Primary Keys:** Portable across SQLite and Azure SQL without driver-specific binary UUID conversion quirks.
- **ORM Privacy Guard (SEC-004):** `Vendor.__repr__()` renders `tax_id='***-**-6789'` so accidental debug logs never expose raw supplier Tax IDs.
- **Compatibility Properties:** `ExchangeRate` exposes `.currency` and `.rate_to_usd` properties alongside `.from_currency` and `.exchange_rate` to maintain seamless alignment with LLD §3.

---

### 2.3 Stage 2 (P2-2): Authoritative Schema DDL & Alembic Baseline

In **P2-2 (`feature/database-schema-migrations`)**, we separated **declarative code models** from **versioned production schema management** via [`src/database/schema.sql`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/schema.sql), [`alembic.ini`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/alembic.ini), [`src/database/migrations/env.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/migrations/env.py), and baseline revision `0001_initial_baseline.py`.

```mermaid
flowchart TD
    subgraph SourceOfTruth ["Schema Definitions"]
        MODELS["src/database/models.py (Base.metadata)"]
        DDL["src/database/schema.sql (Authoritative SQL DDL)"]
    end

    subgraph MigrationEngine ["Alembic Version Control"]
        INI["alembic.ini (script_location = src/database/migrations)"]
        ENV["env.py (Dynamic get_settings() + Async->Sync Driver Normalizer)"]
        V1["versions/0001_initial_baseline.py (upgrade / downgrade)"]
    end

    subgraph Targets ["Database Engines"]
        SQLITE["Local SQLite (Dev & CI)"]
        AZSQL["Azure SQL Serverless (Prod - Entra ID)"]
    end

    MODELS -->|"target_metadata"| ENV
    INI --> ENV
    ENV --> V1
    V1 -->|"alembic upgrade head"| SQLITE
    V1 -->|"alembic upgrade head"| AZSQL
    DDL -.->|"Direct DDL Verification"| SQLITE
    DDL -.->|"DBA Review / Production Audit"| AZSQL

    style MigrationEngine fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

#### Key Design Decisions in P2-2:
- **Zero Static Secrets in `alembic.ini`:** `env.py` overrides `sqlalchemy.url` dynamically using `get_settings().database_url` and automatically translates async drivers (`+aiosqlite` $\to$ `sqlite`, `+aioodbc` $\to$ `+pyodbc`) for Alembic's synchronous runner.
- **Verified Reversible Migrations:** Unit tests execute `command.upgrade(cfg, "head")` followed by `command.downgrade(cfg, "base")` to prove clean rollback order respects foreign-key dependencies.

---

### 2.4 Stage 3 (P2-3): Async Repository Layer & Security Boundaries

In **P2-3 (`feature/repository-layer`)**, we introduced [`src/database/session.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/session.py) and [`src/database/repositories.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/repositories.py), decoupling upstream services (`src/services/`) from raw SQLAlchemy session mechanics.

```mermaid
flowchart TD
    SVC["Upstream Services (Phase 5–9)"]

    subgraph RepoBoundary ["Async Repository Layer (src/database/repositories.py)"]
        V_REPO["VendorRepository (Soft Deactivate + Allowlist)"]
        I_REPO["InvoiceRepository (Eager selectinload + Hash Lookup)"]
        L_REPO["InvoiceLineRepository (Ordered Lines + Atomic Replace)"]
        A_REPO["AuditLogRepository (APPEND-ONLY + No-Op Guard)"]
        E_REPO["ExchangeRateRepository (Idempotent Upsert + Weekend Fallback)"]
    end

    subgraph SecurityGuards ["Built-In Security Guards"]
        G1["ALLOWED_UPDATE_FIELDS + Positional-Only '/' (CWE-915)"]
        G2["_clamp_limit [1..500] (CWE-770)"]
        G3["Parameterized ORM select()/delete() (CWE-89)"]
        G4["No update()/delete() on AuditLog (CWE-284)"]
    end

    SESSION["AsyncSession (src/database/session.py)"]

    SVC --> V_REPO
    SVC --> I_REPO
    SVC --> L_REPO
    SVC --> A_REPO
    SVC --> E_REPO

    V_REPO -.-> G1
    I_REPO -.-> G1
    L_REPO -.-> G1
    V_REPO -.-> G2
    I_REPO -.-> G2
    A_REPO -.-> G4

    V_REPO --> SESSION
    I_REPO --> SESSION
    L_REPO --> SESSION
    A_REPO --> SESSION
    E_REPO --> SESSION

    style SecurityGuards fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style A_REPO fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
```

#### Key Design Decisions in P2-3:
- **Positional-Only `/` ID Parameters:** `update(self, vendor_tax_id: str, /, **fields)` prevents Python `TypeError: got multiple values for argument` when an untrusted payload includes a primary-key field, allowing `_validate_update_fields()` to cleanly raise `ValueError("Disallowed update fields")`.
- **ECB Weekend Fallback:** `get_latest_rate_on_or_before(invoice_date, currency)` queries `rate_date <= target_date ORDER BY rate_date DESC LIMIT 1`, honoring `CLAUDE.md §6` (conversion always uses invoice date, never upload date).
- **Atomic Line Replacement:** `InvoiceLineRepository.replace_for_invoice()` deletes existing lines and inserts edited lines inside a single transaction for clerk re-validation workflows.

---

### 2.5 Stage 4 (P2-4): Idempotent Seeding Pipeline

In **P2-4 (`feature/seed-vendor-master`)**, we built [`src/database/seed.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/seed.py) (`python -m src.database.seed`) and [`src/database/seed.sql`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/seed.sql) to populate all **15 vendors across 4 jurisdictions (`US`, `DE`, `ES`, `GB`)** and daily **ECB FX rates (`EUR`, `GBP`, `USD`)**.

```mermaid
flowchart LR
    JSON1["sample_data/vendor_master.json (15 Vendors)"] --> PATH_GUARD["_resolve_safe_json_path() (CWE-22 Containment)"]
    JSON2["sample_data/exchange_rates.json (ECB FX)"] --> PATH_GUARD

    PATH_GUARD --> VAL["Strict Financial Validator (CWE-20: Tax in [0,1], FX > 0, ISO-3)"]
    VAL --> TAX_DERIVE["derive_tax_scheme() (Sales Tax / MwSt / IVA / VAT)"]
    TAX_DERIVE --> IDEMP["Idempotent Seeder (Insert or Update / Upsert)"]
    IDEMP --> DB["SQLite / Azure SQL"]
    IDEMP --> LOG["JSON Logger (Aggregate Counts Only - Zero PII)"]

    style PATH_GUARD fill:#ffe0b2,stroke:#f57c00,stroke-width:2px;
    style VAL fill:#ffe0b2,stroke:#f57c00,stroke-width:2px;
```

---

### 2.6 Stage 5 (P2-5): Partial Unique Index & Race-Safe Duplicate Upsert

In **P2-5 (`feature/database-composite-hash`)**, we hardened duplicate invoice prevention from an application-level check into a **database-enforced, concurrency-safe invariant**:
- Added partial unique index `UX_invoices_composite_hash` (`WHERE status NOT IN ('REJECTED_DUPLICATE', 'VOID')`) across `models.py`, `schema.sql`, and additive Alembic migration `0002_composite_hash_unique_index.py` (never modifying `0001`).
- Added canonical `compute_composite_hash()` matching 100% of `sample_data/ground_truth/` SHA-256 digests.
- Added `InvoiceRepository.upsert_duplicate_safe()` defeating TOCTOU concurrent insert race conditions (CWE-362).

```mermaid
sequenceDiagram
    autonumber
    participant W1 as Worker A (Upload 1)
    participant W2 as Worker B (Concurrent Duplicate Upload 2)
    participant Repo as InvoiceRepository.upsert_duplicate_safe()
    participant DB as SQLite / Azure SQL (UX_invoices_composite_hash)

    Note over W1,W2: Identical invoice submitted simultaneously
    W1->>Repo: upsert_duplicate_safe(inv_A)
    W2->>Repo: upsert_duplicate_safe(inv_B)

    Repo->>DB: SELECT active WHERE composite_hash = H (Worker A)
    DB-->>Repo: None
    Repo->>DB: SELECT active WHERE composite_hash = H (Worker B)
    DB-->>Repo: None (TOCTOU Window!)

    Repo->>DB: INSERT inv_A (status='UPLOADED', hash=H)
    DB-->>Repo: COMMIT OK (Winner!)
    Repo-->>W1: Return (inv_A, is_duplicate=False)

    Repo->>DB: INSERT inv_B (status='UPLOADED', hash=H)
    DB--xRepo: IntegrityError (UX_invoices_composite_hash violated!)
    Repo->>DB: ROLLBACK
    Repo->>DB: Re-fetch SELECT active WHERE composite_hash = H
    DB-->>Repo: Returns inv_A (Winner)
    Repo-->>W2: Return (inv_A, is_duplicate=True)
```

---

## 3. End of Phase 2: Complete Persistence Architecture

```mermaid
flowchart TD
    subgraph ApplicationTier ["Application & API Layers (Phase 1 + Future Phases 3–11)"]
        API["FastAPI Gateway (src/api/)"]
        CLI["Seed CLI (python -m src.database.seed)"]
        ALEMBIC_CLI["Alembic CLI (alembic upgrade head)"]
    end

    subgraph DatabaseLayer ["src/database/ Persistence Package (100% Complete)"]
        SESSION["session.py (AsyncEngine + StaticPool / Azure Pool)"]
        REPOS["repositories.py (5 Async Repositories + compute_composite_hash + upsert_duplicate_safe)"]
        MODELS["models.py (5 Declarative Models + UX_invoices_composite_hash)"]
        MIGRATIONS["migrations/ (0001 baseline -> 0002 partial unique index)"]
        SCRIPTS["schema.sql & seed.sql (Authoritative SQL Artifacts)"]
    end

    subgraph StorageEngines ["Target Relational Engines"]
        SQLITE_MEM["In-Memory SQLite (55 Unit Tests in 0.59s)"]
        SQLITE_FILE["Local File SQLite (data/enterprise.db)"]
        AZURE_SQL["Azure SQL Serverless (East US 2 - Entra ID)"]
    end

    API --> REPOS
    CLI --> REPOS
    REPOS --> MODELS
    REPOS --> SESSION
    ALEMBIC_CLI --> MIGRATIONS
    MIGRATIONS --> MODELS

    SESSION --> SQLITE_MEM
    SESSION --> SQLITE_FILE
    SESSION --> AZURE_SQL
    MIGRATIONS --> SQLITE_FILE
    MIGRATIONS --> AZURE_SQL

    style DatabaseLayer fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style StorageEngines fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
```

---

## 4. Phase 2 Architectural Scorecard

| Metric | Target | Phase 2 Actual | Status |
|---|---|---|---|
| **Core Domain Tables** | 5 normalized tables | `vendors`, `invoices`, `invoice_lines`, `audit_logs`, `exchange_rates` | Met ✅ |
| **Financial Precision** | 0 float money columns | 100% `Numeric` / `Decimal` across all monetary & rate columns | Met ✅ |
| **Audit Log Immutability** | Append-only | Zero `update`/`delete` methods + no-op edit guard enforced | Met ✅ |
| **Duplicate Race Protection** | DB-level filtered unique index | `UX_invoices_composite_hash` (`WHERE status NOT IN ('REJECTED_DUPLICATE','VOID')`) + TOCTOU recovery | Met ✅ |
| **Migration Reversibility** | Clean `base ↔ 0001 ↔ 0002` | Verified end-to-end in `test_schema_migrations.py` & `test_composite_hash.py` | Met ✅ |
| **Unit Test Suite** | 100% offline pass | **55 / 55 passing in 0.59s** (0 network calls, \$0 cloud spend) | Exceeded ✅ |
| **Security Controls Audited** | Threat modeled w/ CWE | **20 findings audited & mitigated (`SEC-001` to `SEC-020`)** | Met ✅ |

