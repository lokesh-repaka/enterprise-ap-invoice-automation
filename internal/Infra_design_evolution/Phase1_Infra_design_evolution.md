# Phase 1: Infrastructure & Component Wiring Evolution

> **Document Scope:** Infrastructure topology, component wiring, port routing, and runtime networking evolution during **Phase 1 (Runtime Skeleton)**.  
> **Target Audience:** DevOps Engineers, Cloud Architects, Site Reliability Engineers (SREs), and Infrastructure Evaluators.

---

## 1. Infrastructure Philosophy & Target Architecture

The infrastructure strategy of the **Enterprise AP Invoice Automation Platform** is architected around two core paradigms:

1. **Local Autonomous Runtime (\$0 Cloud Spend):** The local development and automated CI environment must be completely self-contained. It operates with zero external network egress, emulating all Azure cloud resources (Azure SQL, Azure Cache for Redis, Azure Blob Storage, Azure OpenAI) purely in-memory.
2. **Production Enterprise Cloud Target (Azure East US 2):** Production infrastructure leverages Azure Container Apps / App Service with Entra ID Managed Identities, private VNet endpoints, serverless databases, and immutable WORM storage.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           INFRASTRUCTURE DUALITY                                 │
│                                                                                  │
│   DEVELOPMENT / CI RUNTIME                      PRODUCTION AZURE EAST US 2       │
│   ┌──────────────────────────┐                  ┌───────────────────────────┐    │
│   │ • Localhost / Docker Net │                  │ • Private VNet / Subnets  │    │
│   │ • In-Memory SQLite       │   Identical      │ • Azure SQL Serverless    │    │
│   │ • In-Memory FakeRedis    │   Application    │ • Azure Cache for Redis   │    │
│   │ • Mock AOAI & Mock Blob  │   Codebase       │ • Azure Blob WORM Storage │    │
│   │ • Cost: $0.00 / month    │ ───────────────► │ • Azure OpenAI (Private)  │    │
│   │ • Test Latency: 0.06s    │                  │ • Zero Static Credentials │    │
│   └──────────────────────────┘                  └───────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Wiring & Network Port Allocation

In Phase 1, the core application components, ports, and internal traffic routes were established as follows:

```mermaid
flowchart TD
    subgraph HostNetwork ["Host / Local Developer Network (or Docker Bridge 'ap-net')"]
        Browser["User Web Browser"]
        Probe["K8s / Container Apps Probe"]

        subgraph PresentationContainer ["Frontend Service (Streamlit UI)"]
            UI["Streamlit Runtime (:8501)"]
            API_CLIENT["Typed HTTP API Client (src/ui/api_client.py)"]
        end

        subgraph BackendContainer ["Backend Service (FastAPI)"]
            UVICORN["Uvicorn ASGI Server (:8000)"]
            MW["RequestIDMiddleware"]
            ROUTER_HEALTH["Health Router (/health, /health/ready)"]
            ROUTER_API["API Router (/api/v1)"]
        end
    end

    Browser -->|"HTTP / Web (Port 8501)"| UI
    Probe -->|"HTTP GET /health (Port 8000)"| UVICORN
    UI --> API_CLIENT
    API_CLIENT -->|"Internal HTTP REST (Port 8000)"| UVICORN
    UVICORN --> MW
    MW --> ROUTER_HEALTH
    MW --> ROUTER_API

    style PresentationContainer fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style BackendContainer fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

### Port Mapping Table

| Component | Default Port | Environment Variable | Binding Address | Description |
|---|---|---|---|---|
| **FastAPI Backend** | `8000` | `PORT_API` | `127.0.0.1` (Dev) / `0.0.0.0` (Container) | REST API, Health Probes, and Job Status |
| **Streamlit UI** | `8501` | `PORT_UI` | `127.0.0.1` (Dev) / `0.0.0.0` (Container) | Review Workbench, Dashboard & Exception Queue |
| **Internal REST Bridge** | Direct | `API_BASE_URL` | `http://127.0.0.1:8000` | Client-to-Backend HTTP communication |

---

## 3. Subtask-by-Subtask Infrastructure Evolution

### 3.1 Subtask P1-1: Runtime Isolation & Package Boundary Wiring

In **P1-1 (`feature/project-bootstrap`)**, we isolated the application runtime from system-level Python packages using modern standard packaging:

- **Packaging Standard:** PEP 621 / `pyproject.toml` with `setuptools.build_meta`.
- **Virtual Environment Isolation:** Strict separation of application dependencies (`fastapi`, `uvicorn`, `pydantic`, `sqlalchemy`) from development/testing dependencies (`pytest`, `fakeredis`, `ruff`).
- **File System Sandboxing:** Read-only access to static invoice samples (`sample_data/invoices/`) and write-only access to isolated output directories.

---

### 3.2 Subtask P1-2: Security Wiring & PII Egress Filtering

In **P1-2 (`feature/core-config-logging`)**, the security infrastructure boundary was formalized.

```mermaid
flowchart LR
    subgraph SecretsManagement ["Credential & Secrets Hierarchy"]
        L1["Local Environment (.env)"]
        L2["System OS Environment"]
        L3["Azure Key Vault (Managed Identity)"]
    end

    subgraph ConfigBoundary ["src/core/config.py"]
        SETTINGS["Settings() Pydantic Singleton"]
    end

    subgraph LoggingEgress ["Logging Network Egress"]
        RAW_LOG["Log Message Payload"]
        FILTER["JSONFormatter Regex Masker"]
        STDOUT["stdout Stream (Console / Azure Log Analytics)"]
    end

    L1 --> SETTINGS
    L2 --> SETTINGS
    L3 --> SETTINGS

    RAW_LOG --> FILTER
    FILTER -->|"Guaranteed No SSN / Tax ID"| STDOUT

    style FILTER fill:#ffe0b2,stroke:#f57c00,stroke-width:2px;
```

- **Zero Static Credentials:** The application runtime does not accept static database passwords or Azure API keys in production. Instead, it relies on Entra ID Managed Identity (`DefaultAzureCredential`).
- **Log Egress Network Protection:** Before any log record leaves the process memory space to `stdout` or remote telemetry sinks (Azure Monitor / Application Insights), our `JSONFormatter` intercepts and redacts all US Social Security Numbers (`\d{3}-\d{2}-\d{4}`) and Tax IDs (`\d{2}-\d{7}`).

---

### 3.3 Subtask P1-3: Host Command Routing via Makefile

In **P1-3 (`feature/makefile-dev-commands`)**, a standardized host command routing layer was established to ensure parity across developer workstations and Docker containers.

```mermaid
flowchart TD
    MAKE["Developer Command (make <target>)"]
    
    MAKE -->|"make run-api"| P1["uvicorn src.api.main:app --port 8000 --reload"]
    MAKE -->|"make run-ui"| P2["streamlit run src/ui/app.py --server.port 8501"]
    MAKE -->|"make test-unit"| P3["Injects Offline Flags + pytest tests/unit/"]
    MAKE -->|"make lint"| P4["ruff check src/ tests/"]

    style MAKE fill:#eceff1,stroke:#455a64,stroke-width:2px;
```

---

### 3.4 Subtask P1-4: ASGI Network Pipeline & Ingress Health Probes

In **P1-4 (`feature/api-health-middleware`)**, the network packet lifecycle through the FastAPI ASGI server was architected.

```mermaid
sequenceDiagram
    autonumber
    actor LB as Ingress Controller / Load Balancer
    participant Socket as TCP Socket (:8000)
    participant ASGI as Uvicorn Worker
    participant MW as RequestIDMiddleware
    participant Route as Route Handler

    LB->>Socket: TCP Handshake & HTTP Request
    Socket->>ASGI: Parse HTTP Request
    ASGI->>MW: Call ASGI Application
    MW->>MW: Inspect Header "X-Request-ID"
    Note over MW: If missing, generate new uuid4()
    MW->>Route: Dispatch Request Coroutine
    Route-->>MW: Return Response Data
    MW->>MW: Inject "X-Request-ID: <uuid>" to Response Headers
    MW-->>ASGI: Send ASGI HTTP Response
    ASGI-->>Socket: Serialize HTTP Payload
    Socket-->>LB: 200 OK + X-Request-ID Header
```

#### Health Probe Routing Strategy:
- **`GET /health` (Liveness):**
  - Path: `/health`
  - Latency: < 2ms.
  - Used by Kubernetes / Azure Container Apps to detect process deadlock. If this fails, the container is restarted.
- **`GET /health/ready` (Readiness):**
  - Path: `/health/ready`
  - Latency: 5–20ms.
  - Verifies connections to downstream dependencies (SQL, Redis, Blob Storage). If this fails, the container is temporarily removed from the load balancer pool.

---

### 3.5 Subtask P1-5: Virtualized Test Network Topology ($0 Cloud Spend)

In **P1-5 (`feature/test-harness-offline`)**, we architected the **Socket-Level Virtualization Topology**:

```mermaid
flowchart TD
    subgraph TestProcess ["Isolated Pytest Process (Single Process Space)"]
        TESTS["tests/unit/test_*.py"]

        subgraph InProcessMocks ["In-Process In-Memory Emulators"]
            SQLITE["In-Memory SQLite (aiosqlite)"]
            FAKEREDIS["FakeRedis (In-Memory Pure Python Redis Server)"]
            MOCK_AOAI["Mock Azure OpenAI Gateway (No WAN Sockets)"]
            MOCK_BLOB["Mock Azure Blob Storage (In-Memory Dict of Bytes)"]
        end
    end

    subgraph BlockedWAN ["Blocked External Network Sockets (Egress Restricted)"]
        AOAI_NET["https://*.openai.azure.com (Blocked ❌)"]
        BLOB_NET["https://*.blob.core.windows.net (Blocked ❌)"]
        SQL_NET["tcp://*.database.windows.net:1433 (Blocked ❌)"]
    end

    TESTS --> SQLITE
    TESTS --> FAKEREDIS
    TESTS --> MOCK_AOAI
    TESTS --> MOCK_BLOB

    MOCK_AOAI -.->|"Egress Blocked"| AOAI_NET
    MOCK_BLOB -.->|"Egress Blocked"| BLOB_NET
    SQLITE -.->|"Egress Blocked"| SQL_NET

    style InProcessMocks fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style BlockedWAN fill:#ffebee,stroke:#c62828,stroke-width:2px;
```

#### Test Virtualization Mechanics:
1. **SQLite In-Memory Database:** Uses `sqlite+aiosqlite:///:memory:` via SQLAlchemy's `StaticPool`. Every test session gets an isolated database without requiring a running SQL server daemon.
2. **FakeRedis Socket Interceptor:** Uses `fakeredis.FakeRedis()`, which emulates all Redis strings, hashes, and queues in memory without requiring a Redis daemon on port `6379`.
3. **Mock AOAI & Blob Clients:** Implemented as async/sync mock objects returning pre-canned, valid financial extraction payloads. **Zero external HTTP requests are made.**

---

### 3.6 Subtask P1-6: GitHub Actions Runner Virtualization

In **P1-6 (`feature/ci-pipeline-github-actions`)**, the automated CI container infrastructure was implemented:

```mermaid
flowchart TD
    subgraph GitHubRunner ["GitHub-Hosted Runner (Ubuntu 22.04 LTS)"]
        subgraph PipelineExecution ["Parallel & Sequential Step Execution"]
            J1["Job 1: Lint & Code Quality (Ruff)"]
            J2["Job 2: Offline Unit Tests (25 Tests in 0.06s)"]
            J3["Job 3: Package Build (python -m build)"]
        end

        subgraph ArtifactStorage ["GitHub Actions Storage Cache"]
            PIP_CACHE["pip Cache (~/.cache/pip)"]
            DIST_ARTIFACTS["dist/ (WHL & TAR.GZ Packages - 7 Day Retention)"]
        end
    end

    J1 -->|"Pass"| J3
    J2 -->|"Pass"| J3
    PIP_CACHE -.-> J1
    PIP_CACHE -.-> J2
    J3 --> DIST_ARTIFACTS

    style GitHubRunner fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;
```

---

## 4. Production Multi-Container Docker Target (Preview)

As the project advances toward Phase 14 (Production Cloud Delivery), the components established in Phase 1 will be packaged into a multi-container Docker topology on an internal bridge network:

```mermaid
flowchart TD
    subgraph AzureVNet ["Azure East US 2 Virtual Network (10.0.0.0/16)"]
        subgraph AppSubnet ["Application Subnet (10.0.1.0/24)"]
            INGRESS["Azure Application Gateway / Reverse Proxy"]

            subgraph DockerBridge ["Internal Docker Bridge Network ('ap-net')"]
                UI_CONTAINER["streamlit-ui Container (:8501)"]
                API_CONTAINER["fastapi-backend Container (:8000)"]
            end
        end

        subgraph DataSubnet ["Data & Service Subnet (Private Endpoints)"]
            SQL_PE["Azure SQL Database (Serverless)"]
            REDIS_PE["Azure Cache for Redis (Job Queue)"]
            STORAGE_PE["Azure Blob Storage (Immutable WORM)"]
            AOAI_PE["Azure OpenAI Service (GPT-4o Vision)"]
        end
    end

    INGRESS -->|"HTTPS :443 -> :8501"| UI_CONTAINER
    INGRESS -->|"HTTPS :443 -> :8000"| API_CONTAINER
    UI_CONTAINER -->|"Internal REST http://fastapi-backend:8000"| API_CONTAINER

    API_CONTAINER -->|"Private Link"| SQL_PE
    API_CONTAINER -->|"Private Link"| REDIS_PE
    API_CONTAINER -->|"Private Link"| STORAGE_PE
    API_CONTAINER -->|"Private Link"| AOAI_PE

    style AzureVNet fill:#f0f4c3,stroke:#9e9d24,stroke-width:2px;
    style DockerBridge fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
```

---

## 5. Infrastructure Verification Matrix

| Subtask | Infrastructure Component | Verification Command | Result |
|---|---|---|---|
| **P1-1** | Virtual Environment & Dependencies | `python3 -m pip check` | 0 broken dependencies ✅ |
| **P1-2** | PII Redaction Filter | Unit test: `test_logging_masks_pii()` | Redacted `***-**-XXXX` ✅ |
| **P1-3** | Makefile Host Command Routing | `make help` | All 8 targets verified ✅ |
| **P1-4** | FastAPI ASGI & Health Probes | Unit test: `test_health_endpoint()` | 200 OK + `X-Request-ID` ✅ |
| **P1-5** | Zero-Network Virtualization | Unit test: `test_offline_isolation()` | 0 WAN sockets used ✅ |
| **P1-6** | GitHub Actions Runner Execution | CI Workflow Test: `test_ci_workflow.py` | 100% Validated in CI ✅ |
