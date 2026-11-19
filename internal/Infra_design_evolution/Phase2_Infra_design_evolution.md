# Phase 2: Infrastructure, Database Wiring & Docker Evolution

> **Document Scope:** Database driver architecture, connection pooling, Alembic migration routing, Docker volume/network topology, and Azure SQL Private Link wiring evolved during **Phase 2 (Persistence and Vendor Master)**.  
> **Target Audience:** DevOps Engineers, Cloud Solution Architects, DBAs, and Site Reliability Engineers (SREs).

---

## 1. Persistence Infrastructure Philosophy: Dual-Engine Parity

In Phase 1, the application ran completely statelessly with zero persistent storage. In **Phase 2**, we introduced stateful relational persistence without sacrificing our **\$0 local developer velocity** rule.

The persistence infrastructure uses a **single codebase, dual-driver architecture** controlled via `Settings.USE_LOCAL_SQLITE` in [`src/core/config.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/core/config.py):

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                      DUAL-ENGINE DATABASE INFRASTRUCTURE                              │
│                                                                                       │
│  LOCAL / CI RUNTIME (USE_LOCAL_SQLITE=true)      PRODUCTION (Azure East US 2)         │
│  ┌────────────────────────────────────────┐      ┌──────────────────────────────────┐ │
│  │ • Async Driver: sqlite+aiosqlite       │      │ • Async Driver: mssql+aioodbc    │ │
│  │ • Migration Driver: sqlite (stdlib)    │      │ • Migration Driver: mssql+pyodbc │ │
│  │ • Pool (:memory:): StaticPool          │      │ • Pool: QueuePool (20 + 10 ovf)  │ │
│  │ • Storage: RAM / ./data/enterprise.db  │      │ • Health: pool_pre_ping=True     │ │
│  │ • Auth: Local File Permissions         │      │ • Auth: Entra ID Managed Identity│ │
│  │ • Network: Zero TCP Sockets ($0/mo)    │      │ • Network: Private Link :1433    │ │
│  └────────────────────────────────────────┘      └──────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Subtask-by-Subtask Infrastructure & Wiring Evolution

### 2.1 Subtask P2-1: Async ORM Runtime Dependencies (`greenlet` + `aiosqlite`)

In **P2-1 (`feature/sqlalchemy-models`)**, introducing SQLAlchemy 2.0's asynchronous ORM revealed a critical runtime packaging dependency in Linux CI runners:
- SQLAlchemy's `sqlalchemy.ext.asyncio` bridges synchronous ORM state machines onto Python's `asyncio` event loop via C-level coroutines provided by **`greenlet`**.
- While macOS workstations often had `greenlet` pre-installed globally, clean Ubuntu GitHub Actions runners raised `ModuleNotFoundError: No module named 'greenlet'`.
- **Infrastructure Fix:** Explicitly pinned `"greenlet>=3.0.0"` and `"aiosqlite>=0.20.0"` in [`pyproject.toml`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/pyproject.toml), ensuring deterministic builds across developer machines, CI containers, and Docker images.

```mermaid
flowchart LR
    APP["FastAPI / Pytest Async Coroutine"] --> SA_ASYNC["sqlalchemy.ext.asyncio"]
    SA_ASYNC --> GREENLET["greenlet Bridge (Explicit in pyproject.toml)"]
    GREENLET --> AIOSQLITE["aiosqlite Thread Worker (Local)"]
    GREENLET --> AIOODBC["aioodbc / ODBC Driver 18 (Azure SQL)"]

    style GREENLET fill:#fff3e0,stroke:#e65100,stroke-width:2px;
```

---

### 2.2 Subtask P2-2: Alembic Migration Engine & Driver Normalization

In **P2-2 (`feature/database-schema-migrations`)**, we wired Alembic (`alembic.ini` + `src/database/migrations/env.py`) to operate across both local SQLite and Azure SQL without ever storing static credentials in `alembic.ini`.

```mermaid
flowchart TD
    subgraph ConfigInputs ["Runtime Configuration Inputs"]
        ENV_VAR["OS Env / Azure Key Vault (Managed Identity)"]
        ALEMBIC_INI["alembic.ini (Fallback: sqlite:///data/enterprise.db)"]
    end

    subgraph EnvPy ["src/database/migrations/env.py"]
        GET_URL["get_url() -> Reads get_settings().database_url"]
        NORMALIZE["Driver Normalizer: +aiosqlite -> '', +aioodbc -> +pyodbc"]
        POOL["NullPool (Short-lived migration connection)"]
        BATCH["render_as_batch=True (SQLite ALTER TABLE safety)"]
    end

    subgraph Targets ["Migration Targets"]
        LOCAL_DB["./data/enterprise.db (Local / Docker Volume)"]
        PROD_DB["Azure SQL Serverless (:1433 TLS 1.2+)"]
    end

    ENV_VAR --> GET_URL
    ALEMBIC_INI -.-> GET_URL
    GET_URL --> NORMALIZE
    NORMALIZE --> POOL
    POOL --> BATCH
    BATCH --> LOCAL_DB
    BATCH --> PROD_DB

    style NORMALIZE fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

#### Key Infrastructure Choices:
- **`poolclass=pool.NullPool` in `env.py`:** Migration containers are short-lived CLI jobs (`alembic upgrade head`). Using `NullPool` ensures connections close immediately after DDL commits instead of holding open idle TCP sockets on Azure SQL Serverless.
- **`render_as_batch=True`:** SQLite lacks native support for certain `ALTER TABLE` operations; enabling batch mode ensures future migrations remain 100% portable across SQLite and SQL Server.

---

### 2.3 Subtask P2-3: Async Connection Pooling & Session Lifecycle Wiring

In **P2-3 (`feature/repository-layer`)**, [`src/database/session.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/database/session.py) established production-grade connection pool routing:

```mermaid
sequenceDiagram
    autonumber
    actor Req as FastAPI Request / Worker Task
    participant Dep as get_async_session() (FastAPI Depends)
    participant Pool as SQLAlchemy AsyncEngine Pool
    participant Repo as Repository (Vendor/Invoice/Audit/FX)
    participant DB as SQLite / Azure SQL (:1433)

    Req->>Dep: Invoke Route Handler
    Dep->>Pool: Acquire Connection (pool_pre_ping=True on Azure SQL)
    Pool-->>Dep: Healthy AsyncSession (autoflush=False, expire_on_commit=False)
    Dep->>Repo: Inject AsyncSession
    Repo->>DB: Parameterized ORM Query (SELECT / INSERT / UPDATE)
    DB-->>Repo: Result Rows
    Repo-->>Req: Domain Model / DTO
    Dep->>Pool: Close Session & Return Connection to Pool
```

#### Connection Pool Matrix

| Environment | URL Scheme | Pool Strategy | Parameters | Rationale |
|---|---|---|---|---|
| **Offline Unit Tests** | `sqlite+aiosqlite:///:memory:` | `StaticPool` | `check_same_thread=False` | Shares one persistent in-memory DB across multiple async sessions within a test. |
| **Local Dev Server** | `sqlite+aiosqlite:///.../data/enterprise.db` | Default Async Pool | `check_same_thread=False` | Persistent local file volume; isolated from git via `.gitignore` (`*.db`). |
| **Azure Production** | `mssql+aioodbc://@<server>/<db>` | `QueuePool` | `pool_size=20`, `max_overflow=10`, `pool_pre_ping=True` | Auto-recovers dropped connections when Azure SQL Serverless auto-resumes from pause. |

---

### 2.4 Subtask P2-4: Containerized Seed Execution & File Containment

In **P2-4 (`feature/seed-vendor-master`)**, we wired `python -m src.database.seed` to read JSON reference files safely from `SAMPLE_DATA_DIR` (`./sample_data` locally or mounted read-only volume `/app/sample_data:ro` in Docker).

```mermaid
flowchart LR
    VOL["Read-Only Volume (/app/sample_data:ro)"] -->|"vendor_master.json & exchange_rates.json"| GUARD["_resolve_safe_json_path() (CWE-22)"]
    GUARD --> SEED_CLI["python -m src.database.seed (Idempotent Init Job)"]
    SEED_CLI -->|"15 Vendors + 3 ECB FX Rates"| DB["SQLite Volume / Azure SQL"]

    style VOL fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style GUARD fill:#ffe0b2,stroke:#f57c00,stroke-width:2px;
```

---

### 2.5 Subtask P2-5: Database-Level Index Concurrency & Zero-Downtime Upgrade Path

In **P2-5 (`feature/database-composite-hash`)**, we wired additive migration `0002_composite_hash_unique_index.py` so the database engine itself serializes concurrent duplicate invoice writes across multiple horizontally scaled FastAPI container replicas:

```mermaid
flowchart TD
    subgraph ContainerReplicas ["Horizontally Scaled FastAPI Replicas (Container Apps)"]
        R1["fastapi-replica-1 (:8000)"]
        R2["fastapi-replica-2 (:8000)"]
        R3["fastapi-replica-3 (:8000)"]
    end

    subgraph DatabaseLock ["Single Authoritative Lock (Azure SQL / SQLite)"]
        IDX["UX_invoices_composite_hash (UNIQUE WHERE status NOT IN ('REJECTED_DUPLICATE','VOID'))"]
        TBL["dbo.invoices"]
    end

    R1 -->|"Concurrent INSERT hash=H"| IDX
    R2 -->|"Concurrent INSERT hash=H"| IDX
    R3 -->|"Concurrent INSERT hash=H"| IDX
    IDX -->|"Exactly 1 Winner Commits"| TBL
    IDX -.->|"Losers receive IntegrityError -> Rollback -> Return Winner"| R2
    IDX -.->|"Losers receive IntegrityError -> Rollback -> Return Winner"| R3

    style IDX fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
```

**Why this matters at the infrastructure level:** Even when FastAPI scales from 1 container to 10 replicas behind an Azure Load Balancer, **no distributed application lock is needed** to prevent duplicate active invoices—the filtered unique B-tree index in Azure SQL guarantees atomic ACID enforcement across every replica.

---

## 3. Docker & Production Azure East US 2 Persistence Wiring

As Phase 2 merges into the production container topology (deployed in Phase 14), database migrations and seeding run as an **Init Job** before new API container revisions receive traffic:

```mermaid
flowchart TD
    subgraph AzureVNet ["Azure East US 2 VNet (10.0.0.0/16)"]
        subgraph AppSubnet ["Container Apps Subnet (10.0.1.0/24)"]
            INIT["Init Job Container: alembic upgrade head && python -m src.database.seed"]
            API1["fastapi-api Replica 1 (:8000)"]
            API2["fastapi-api Replica 2 (:8000)"]
            UI["streamlit-ui (:8501)"]
            MI["System-Assigned Managed Identity (Entra ID Token)"]
        end

        subgraph PrivateDataSubnet ["Private Endpoint Subnet (10.0.2.0/24)"]
            PE_SQL["Private Endpoint (10.0.2.10:1433)"]
            AZ_SQL["Azure SQL Serverless (sqldb-ap-staging) - Public Access DISABLED"]
        end
    end

    MI -.->|"OAuth2 Token (Zero Passwords)"| INIT
    MI -.->|"OAuth2 Token (Zero Passwords)"| API1
    MI -.->|"OAuth2 Token (Zero Passwords)"| API2

    INIT -->|"1. Apply 0001 -> 0002 & Seed"| PE_SQL
    UI -->|"Internal HTTP :8000"| API1
    UI -->|"Internal HTTP :8000"| API2
    API1 -->|"2. Async aioodbc TLS 1.2+"| PE_SQL
    API2 -->|"2. Async aioodbc TLS 1.2+"| PE_SQL
    PE_SQL --> AZ_SQL

    style PrivateDataSubnet fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style INIT fill:#fff3e0,stroke:#e65100,stroke-width:2px;
```

### Local Docker Compose Equivalent (Preview for Dev/Demo)

| Service / Volume | Mount / Network | Role |
|---|---|---|
| `ap-net` (Docker Bridge) | Internal DNS (`fastapi-backend:8000`) | Isolates inter-service HTTP traffic from host network. |
| `ap_sqlite_data` (Named Volume) | Mounted at `/app/data` | Persists `enterprise.db` across container restarts locally. |
| `./sample_data` (Bind Mount `:ro`) | Mounted at `/app/sample_data:ro` | Supplies `vendor_master.json` & `exchange_rates.json` read-only to `seed.py`. |

---

## 4. Phase 2 Infrastructure Verification Matrix

| Subtask | Infrastructure Layer | Verification Mechanism | Status |
|---|---|---|---|
| **P2-1** | Async ORM Runtime (`greenlet` + `aiosqlite`) | Verified on local macOS (Py 3.13) & Ubuntu CI (Py 3.11) | Verified ✅ |
| **P2-2** | Alembic Migration Engine & Driver Normalization | `command.upgrade("head")` $\to$ `downgrade("base")` | Verified ✅ |
| **P2-3** | `StaticPool` & Async Session Wiring | 6 async repository tests across isolated sessions | Verified ✅ |
| **P2-4** | Read-Only Seed Containment & Idempotent CLI | `test_seed_all_end_to_end_sqlite_file` + CWE-22 test | Verified ✅ |
| **P2-5** | Multi-Session Partial Unique Index Lock | Multi-session `session_a`/`session_b` race test + Alembic `0002` | Verified ✅ |

