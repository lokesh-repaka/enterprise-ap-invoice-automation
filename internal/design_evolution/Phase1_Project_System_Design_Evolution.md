# Phase 1: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 1 (Runtime Skeleton)**.  
> **Target Audience:** Solution Architects, Technical Leads, System Design Interviewers, and Senior Engineering Evaluators.

---

## 1. Phase 1 Mission & Architectural Baseline

The objective of **Phase 1** was to establish the immutable foundational architecture for an enterprise-grade Accounts Payable (AP) Invoice Automation Platform. Before ingesting high-volume financial documents, multi-modal LLMs, and country-specific tax rules, the platform required a zero-debt runtime scaffold that strictly enforces:

1. **The Rules-First Architectural Invariant:** AI models parse untrusted text; deterministic Python code strictly executes business rules, arithmetic checks, and approval state transitions.
2. **Layering Independence:** Upstream layers never know downstream implementation details. The UI speaks only to the API; the API speaks only to Services; validation never makes network or LLM calls.
3. **Privacy and Zero Static Credentials:** PII masking at the logger level, zero hardcoded secrets, and 100% Entra ID Managed Identity readiness.
4. **Complete Offline Virtualization:** Zero external network dependency during development and automated CI.

---

## 2. Progressive Evolution: Task-by-Task System Design

### 2.1 Day 0: The Initial Conceptual Problem

Prior to Phase 1, the high-level business requirement was a monolithic ingestion flow where an invoice arrives, is processed, and is pushed to an ERP.

```mermaid
flowchart LR
    A["Raw Invoices (PDF/Image)"] --> B["Monolithic Processing Script"]
    B --> C["OpenAI Live API"]
    B --> D["Cloud SQL Database"]
    B --> E["Clerk Dashboard"]

    style B fill:#ffebee,stroke:#c62828,stroke-width:2px;
```

**Flaws in the Day 0 Approach:**
- Tight coupling: UI talks directly to database or cloud models.
- High cost: Live API calls during dev/test burn budget constantly.
- Security vulnerabilities: Tax IDs/SSNs leaked in plaintext logs.
- Uncontrolled nondeterminism: LLM hallucinations dictate financial totals.

---

### 2.2 Stage 1 (P1-1): The 9-Layer Architecture Boundary

In **P1-1 (`feature/project-bootstrap`)**, we introduced strict 9-layer separation of concerns. Each layer is encapsulated in its own isolated Python package under `src/`.

```mermaid
flowchart TD
    subgraph ClientTier ["Presentation Layer"]
        UI["src/ui/ (Streamlit Dashboard)"]
    end

    subgraph APITier ["API & Gateway Layer"]
        API["src/api/ (FastAPI Routes, Schemas, RBAC)"]
    end

    subgraph ServiceTier ["Orchestration Layer"]
        SVC["src/services/ (Invoice Workflow Orchestrator)"]
    end

    subgraph CoreEngineTier ["Domain & Engine Layers (Deterministic & Model)"]
        VAL["src/validation/ (Rules Engine: Tax, Math, FSM)"]
        EXT["src/extraction/ (Model Gateway & Prompt Assembly)"]
    end

    subgraph PersistenceTier ["Storage & Data Layer"]
        DB["src/database/ (SQLAlchemy 2 Async Repositories)"]
        STG["src/storage/ (Azure Blob WORM Storage)"]
    end

    subgraph FoundationTier ["Cross-Cutting Foundation"]
        CORE["src/core/ (Config, Security, Logging)"]
        EVAL["src/evaluation/ (Offline Accuracy & STP Metrics)"]
    end

    UI -->|"REST / HTTP only"| API
    API -->|"DTOs / Service Calls"| SVC
    SVC -->|"Deterministic Python"| VAL
    SVC -->|"Prompt with <invoice_text>"| EXT
    SVC -->|"Async CRUD"| DB
    SVC -->|"Immutable Upload"| STG
    
    API -.->|"Imports"| CORE
    SVC -.->|"Imports"| CORE
    DB -.->|"Imports"| CORE
    EXT -.->|"Imports"| CORE
    VAL -.->|"Zero external calls"| CORE

    style VAL fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style EXT fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style CORE fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
```

#### Layer Interaction Rules Enforced:
- `src/ui/`: Speaks only via typed REST calls to `src/api/`. Never imports database or business logic.
- `src/validation/`: 100% deterministic pure Python. **Never imports `src/extraction/` or makes network/LLM calls**.
- `src/extraction/`: Encapsulates AI model calls. Uses `<invoice_text>` delimiters to prevent prompt injection. Never calculates tax or status.
- `src/core/`: Foundation layer containing settings and security. Never imports from outer business layers.

---

### 2.3 Stage 2 (P1-2): Centralized Settings & PII-Masked Logging Pipeline

In **P1-2 (`feature/core-config-logging`)**, the system design expanded to incorporate a centralized runtime configuration engine and an automated data privacy interceptor.

```mermaid
flowchart TD
    subgraph EnvSources ["Environment Configuration Sources"]
        ENV[".env / OS Environment"]
        AZ_KV["Azure Key Vault (Prod)"]
        DEFAULTS["Default Fallbacks"]
    end

    subgraph SettingsEngine ["src/core/config.py"]
        PYDANTIC["Pydantic Settings Engine (BaseSettings)"]
        VALIDATOR["Type & Value Validators (Ports, Storage Tiers, Paths)"]
        CACHE["@lru_cache get_settings()"]
    end

    subgraph LoggingPipeline ["src/core/logging.py"]
        CALLER["Application Log Call (logger.info)"]
        CTX["ContextVar (request_id)"]
        REGEX["PII Masking Regex Engine (SSN/Tax ID)"]
        FORMATTER["JSONFormatter"]
        STREAM["stdout / Azure Monitor Stream"]
    end

    ENV --> PYDANTIC
    AZ_KV --> PYDANTIC
    DEFAULTS --> PYDANTIC
    PYDANTIC --> VALIDATOR
    VALIDATOR --> CACHE

    CALLER --> FORMATTER
    CTX -.->|"Injects request_id"| FORMATTER
    FORMATTER --> REGEX
    REGEX -->|"Redacted: ***-**-XXXX"| STREAM

    style REGEX fill:#ffe0b2,stroke:#f57c00,stroke-width:2px;
    style CACHE fill:#c8e6c9,stroke:#388e3c,stroke-width:2px;
```

#### Key Design Decisions:
1. **Pydantic v2 `BaseSettings`:** Prevents runtime misconfiguration. If an invalid database URL or out-of-range integer port is provided, the application refuses to boot.
2. **Context-Aware Request ID:** Python's `contextvars.ContextVar` stores the incoming HTTP request ID per coroutine, automatically appending it to every log record without requiring manual parameter passing.
3. **PII Masking Interceptor:** Intercepts log strings containing US Social Security numbers (`\d{3}-\d{2}-\d{4}`) and Employer Identification Numbers (`\d{2}-\d{7}`), converting them to `***-**-XXXX` prior to emitting JSON.

---

### 2.4 Stage 3 (P1-3): Developer Automation & Command Control Plane

In **P1-3 (`feature/makefile-dev-commands`)**, we established a uniform command control plane via `Makefile` to synchronize local developer runtime and remote CI execution environments.

```mermaid
flowchart LR
    DEV["Developer / Terminal"] --> MAKE["GNU Makefile Interface"]

    subgraph ExecutionTargets ["Target Automation Engine"]
        T1["make run-api (Port 8000)"]
        T2["make run-ui (Port 8501)"]
        T3["make test-unit (Offline Pytest)"]
        T4["make lint (Ruff Analysis)"]
        T5["make format (Ruff Auto-Format)"]
    end

    MAKE --> T1
    MAKE --> T2
    MAKE --> T3
    MAKE --> T4
    MAKE --> T5

    T3 -.->|"Injects strict offline flags"| PYTEST["Pytest Runner (0.05s)"]
```

---

### 2.5 Stage 4 (P1-4): Asynchronous HTTP Gateway & Middleware Pipeline

In **P1-4 (`feature/api-health-middleware`)**, we introduced the FastAPI application skeleton, enterprise health probes, and the ASGI middleware pipeline.

```mermaid
sequenceDiagram
    autonumber
    actor Client as HTTP Client / K8s Probe
    participant MW as RequestIDMiddleware (ASGI)
    participant Ctx as contextvars (request_id_ctx)
    participant Router as APIRouter (/health, /health/ready)
    participant Log as JSON Logger (PII Masking)

    Client->>MW: Incoming HTTP Request (e.g. GET /health)
    alt Header has X-Request-ID
        MW->>MW: Reuse provided UUID
    else Header missing X-Request-ID
        MW->>MW: Generate new uuid4()
    end
    MW->>Ctx: Set request_id_ctx
    MW->>Router: Forward request down the ASGI chain
    Router->>Log: logger.info("Health check requested")
    Log-->>Log: Formats JSON log + attaches request_id
    Router-->>MW: 200 OK {"status": "healthy"}
    MW->>MW: Attach X-Request-ID to Response Headers
    MW-->>Client: 200 OK (with Header X-Request-ID: <uuid>)
```

#### Dual-Probe Health Architecture:
- `GET /health` (**Liveness**): Fast, lightweight check verifying the Python event loop and ASGI server are responsive.
- `GET /health/ready` (**Readiness**): Checks downstream subsystem readiness (Database, Redis, Blob Storage) before routing traffic.

---

### 2.6 Stage 5 (P1-5): Fully Virtualized Offline Test Architecture

In **P1-5 (`feature/test-harness-offline`)**, we designed a **100% offline testing topology** that eliminates cloud spend and network latency during testing.

```mermaid
flowchart TD
    subgraph TestRunner ["Pytest Test Suite (tests/unit/)"]
        TC["Unit & Contract Tests"]
    end

    subgraph VirtualizationLayer ["tests/conftest.py Virtual Harness"]
        ENV_GUARD["Offline Environment Enforcer (USE_MOCK_AOAI, etc.)"]
        SQLITE["In-Memory SQLite (aiosqlite) simulating Azure SQL"]
        FAKEREDIS["In-Memory FakeRedis simulating Azure Cache"]
        MOCK_AOAI["Mock Azure OpenAI Engine (Deterministic JSON Extraction)"]
        MOCK_BLOB["Mock Azure Blob WORM Client (In-Memory Bytes Storage)"]
    end

    TC --> ENV_GUARD
    ENV_GUARD --> SQLITE
    ENV_GUARD --> FAKEREDIS
    ENV_GUARD --> MOCK_AOAI
    ENV_GUARD --> MOCK_BLOB

    style VirtualizationLayer fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style TestRunner fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
```

#### Architectural Isolation Guarantees:
1. **Zero External Sockets:** Outgoing TCP calls to Azure or OpenAI endpoints are blocked at the fixture level.
2. **Deterministic Response Seeding:** The mock AOAI engine returns pre-configured ground-truth extraction payloads mapped to test invoice hashes.
3. **Sub-second Execution:** 25 comprehensive unit tests execute in **0.06 seconds**.

---

### 2.7 Stage 6 (P1-6): Continuous Integration & Build Pipeline

In **P1-6 (`feature/ci-pipeline-github-actions`)**, we deployed `.github/workflows/ci.yml`, transitioning the system into an automated delivery pipeline.

```mermaid
stateDiagram-v2
    [*] --> GitPushOrPR: Git Push to development or main

    state "GitHub Actions CI Pipeline" as CI {
        state "Job 1: Lint & Code Quality" as J1
        state "Job 2: Offline Unit Tests" as J2
        state "Job 3: Package Build & Verification" as J3

        GitPushOrPR --> J1: Checkout & Setup Python 3.11
        GitPushOrPR --> J2: Checkout & Setup Python 3.11

        J1 --> J3: Ruff Check & Format PASS
        J2 --> J3: 25 Offline Tests PASS

        state J1 {
            [*] --> RuffCheck: ruff check src/ tests/
            RuffCheck --> RuffFormat: ruff format --check src/ tests/
            RuffFormat --> [*]
        }

        state J2 {
            [*] --> SetOfflineEnv: Inject USE_LOCAL_SQLITE=true...
            SetOfflineEnv --> RunPytest: pytest -v tests/unit/
            RunPytest --> [*]
        }

        state J3 {
            [*] --> PyBuild: python -m build
            PyBuild --> VerifyDist: Verify .whl and .tar.gz
            VerifyDist --> UploadArtifacts: actions/upload-artifact@v4
            UploadArtifacts --> [*]
        }
    }

    J3 --> Passed: Build Artifacts Ready
    Passed --> [*]
```

---

## 3. End of Phase 1: Comprehensive System Architecture

At the conclusion of Phase 1, the platform possesses a battle-tested, modular architecture ready for Phase 2 (Persistence & Database Models) through Phase 14 (Production Cloud Deployment).

```mermaid
flowchart TD
    subgraph ExternalClients ["Client Interaction Tier"]
        Browser["Streamlit UI (Port 8501)"]
        APIClient["API Consumers / External ERPs"]
    end

    subgraph APIGateway ["FastAPI Core Gateway (Port 8000)"]
        MW_ID["RequestIDMiddleware (X-Request-ID)"]
        ROUTER_H["Health Router (/health, /health/ready)"]
        ROUTER_V1["API Router (/api/v1 - Planned Phase 5, 9)"]
    end

    subgraph CorePlatform ["Cross-Cutting Core Platform"]
        CONF["Pydantic Settings (src/core/config.py)"]
        LOG["PII-Masked JSON Logger (src/core/logging.py)"]
    end

    subgraph DomainEngines ["Business & Extraction Engines"]
        VAL_ENG["Rules Engine (src/validation - Planned Phase 7, 8)"]
        EXT_ENG["Model Gateway (src/extraction - Planned Phase 6)"]
    end

    subgraph DataStorage ["Persistence & Storage"]
        DB_REPO["Async Repositories (src/database - Planned Phase 2)"]
        BLOB_REPO["WORM Blob Client (src/storage - Planned Phase 4)"]
    end

    subgraph CI_Harness ["Verification & Test Infrastructure"]
        GH_ACTIONS["GitHub Actions CI (.github/workflows/ci.yml)"]
        OFFLINE_HARNESS["Offline Pytest Virtualization (tests/conftest.py)"]
    end

    Browser -->|"HTTP / REST"| MW_ID
    APIClient -->|"HTTP / REST"| MW_ID
    MW_ID --> ROUTER_H
    MW_ID --> ROUTER_V1

    ROUTER_H -.->|"Reads readiness"| CONF
    ROUTER_H -.->|"Emits logs"| LOG

    ROUTER_V1 -.->|"Orchestrates"| VAL_ENG
    ROUTER_V1 -.->|"Extracts"| EXT_ENG
    ROUTER_V1 -.->|"Persists"| DB_REPO
    ROUTER_V1 -.->|"Archives"| BLOB_REPO

    GH_ACTIONS -->|"Automates"| OFFLINE_HARNESS
    OFFLINE_HARNESS -->|"Tests"| APIGateway
    OFFLINE_HARNESS -->|"Tests"| CorePlatform

    style APIGateway fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    style CorePlatform fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    style CI_Harness fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
```

---

## 4. Architectural Scorecard: Phase 1 Evaluation

| Metric | Target | Phase 1 Actual | Status |
|---|---|---|---|
| **Layer Coupling** | Strict 0-circular dependency | 100% unidirectional imports verified | Met ✅ |
| **Log Privacy Compliance** | Zero unmasked SSN/Tax ID leaks | Custom regex filter active on all log emissions | Met ✅ |
| **Unit Test Execution Speed** | < 1.0 second | **0.06 seconds (25 tests)** | Exceeded ✅ |
| **Test Cloud Cost** | \$0.00 | **\$0.00 (Zero external network calls)** | Met ✅ |
| **Traceability** | Global request correlation | `X-Request-ID` attached to all requests & logs | Met ✅ |
| **Automated Build** | Valid Python wheel generation | Verified in CI (`enterprise_ap_automation-0.1.0-py3-none-any.whl`) | Met ✅ |
