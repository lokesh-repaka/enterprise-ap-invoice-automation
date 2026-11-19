# Phase 3: Infrastructure, Security Wiring & Docker Evolution

> **Document Scope:** Network trust boundaries, reverse-proxy header routing, Redis rate-limit wiring, Entra ID OIDC discovery egress, Managed Identity Key Vault Private Link routing, and local Docker Compose vs. Azure East US 2 topology evolved during **Phase 3 (Identity and Security)**.  
> **Target Audience:** Cloud Solution Architects, DevOps Engineers, Security Architects, and SREs.

---

## 1. Security Infrastructure Philosophy: Zero-Trust Offline Parity

In Phase 1 and Phase 2, we established dual-engine parity for FastAPI and SQL (`SQLite` locally vs. `Azure SQL` in production). In **Phase 3**, we extended that exact zero-cost, zero-static-secret parity across **all four security infrastructure boundaries**:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 3 DUAL-MODE SECURITY INFRASTRUCTURE                          │
│                                                                                        │
│  LOCAL / CI RUNTIME (100% Offline, $0)        PRODUCTION (Azure East US 2 VNet)        │
│  ┌───────────────────────────────────────┐    ┌──────────────────────────────────────┐ │
│  │ • Auth: Ephemeral RSA-2048 Keypair    │    │ • Auth: Entra ID v2.0 JWKS HTTPS     │ │
│  │   (Triple-gated dev/local/test only)  │    │   (Private/Trusted Egress Allowlist) │ │
│  │ • Rate Limit: fakeredis.aioredis      │    │ • Rate Limit: Azure Cache for Redis  │ │
│  │   (In-memory ZSET MULTI/EXEC)         │    │   (Private Endpoint :6380 TLS 1.2+)  │ │
│  │ • Audit DB: Isolated aiosqlite tx     │    │ • Audit DB: Isolated Azure SQL tx    │ │
│  │ • Secrets: LocalKeyVaultStub (empty)  │    │ • Secrets: Azure Key Vault PE (:443) │ │
│  │   (Scoped KV_STUB_ env opt-in only)   │    │   via System-Assigned Managed ID     │ │
│  │ • Proxy Trust: TRUSTED_PROXY_IPS=[]   │    │ • Proxy Trust: Front Door / WAF IPs  │ │
│  └───────────────────────────────────────┘    └──────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Subtask-by-Subtask Infrastructure & Component Wiring Evolution

### 2.1 Subtask P3-1: Entra ID JWKS Discovery, CORS Allowlisting & Dependency Packaging

In **P3-1 (`feature/entra-id-jwt-rbac`)**, we wired cryptographic JWT verification (`pyjwt[crypto]>=2.8.0` added to `pyproject.toml`) and tightened CORS ingress boundaries:
- **Outbound JWKS Discovery Pin:** `EntraJWKSClient` strictly allows HTTPS calls to `https://login.microsoftonline.com/{validated_uuid}/discovery/v2.0/keys` with `follow_redirects=False`, `5.0s` timeout, `256 KB` payload cap, and a `60s` unknown-`kid` refresh cooldown—preventing SSRF and outbound JWKS amplification storms.
- **Explicit CORS Origin Allowlist (`CORS_ALLOWED_ORIGINS`):** Replaced `allow_origins=["*"]` with explicit trusted UI origins (`["http://localhost:8501", "http://127.0.0.1:8501"]` locally; Azure Front Door HTTPS FQDN in staging/production).
- **Protected Readiness Probe:** Azure Container Apps liveness probes hit public `GET /health` (zero I/O), whereas deep diagnostic `GET /health/ready` requires an authenticated `system_admin` Bearer JWT.

```mermaid
flowchart LR
    ACA_PROBE["Azure Container Apps Liveness Probe"] -->|"GET /health (Public, Zero I/O)"| API["FastAPI (:8000)"]
    ADMIN["System Admin / Ops Tooling"] -->|"GET /health/ready + Entra RS256 JWT"| API
    API -->|"HTTPS :443 (5s timeout, no redirects, 1h cache)"| ENTRA["login.microsoftonline.com/{tid}/discovery/v2.0/keys"]
    UI["Streamlit UI (:8501)"] -->|"Allowed CORS Origin + Bearer JWT"| API

    style ENTRA fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style API fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

### 2.2 Subtask P3-2: Local Demo Auth Routing & Environment Isolation

In **P3-2 (`feature/auth-demo-tokens`)**, we wired `/api/v1/auth/demo-token`, `/api/v1/auth/demo-personas`, and `/api/v1/auth/me` directly into the FastAPI router without introducing any external identity container for local Docker development:

```mermaid
flowchart TD
    ST["Streamlit UI (:8501) - Persona Switcher"] -->|"POST /api/v1/auth/demo-token"| AUTH_RT["src/api/auth.py"]
    AUTH_RT --> ENV_GATE{"APP_ENV in dev/local/test AND ENABLE_DEMO_AUTH=true AND USE_LOCAL_SQLITE=true?"}
    ENV_GATE -->|"Production / Staging / Azure SQL"| DENY["403 Forbidden (Zero Attack Surface)"]
    ENV_GATE -->|"Local Dev Container"| MEM_KEY["Process-Local Ephemeral RSA-2048 Keypair"]
    MEM_KEY -->|"Cache-Control: no-store"| ST
    ST -->|"Authorization: Bearer <demo-jwt>"| PROTECTED["Any Protected API Route"]

    style ENV_GATE fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
    style MEM_KEY fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

**Container / Replica Note:** Because the ephemeral RSA keypair lives strictly in process memory, demo mode is intentionally scoped to single-process local development (`uvicorn --port 8000` or single-container local `docker compose`). Multi-replica staging/production containers exclusively use Microsoft Entra ID JWKS so all replicas validate the exact same Entra ID tokens statelessly.

---

### 2.3 Subtask P3-3: Redis Networking, Reverse-Proxy Trust Chain & Multi-Replica Throttling

In **P3-3 (`feature/rate-limit-redis`)**, we wired `RedisRateLimiterMiddleware` to share rate-limit state across horizontally scaled FastAPI containers via Redis (`REDIS_URL` with `2.0s` socket connect/read timeouts) and established the reverse-proxy IP trust model (`TRUSTED_PROXY_IPS`):

```mermaid
flowchart TD
    subgraph ExternalTraffic ["External Clients"]
        C1["Legitimate User (198.51.100.10)"]
        ATK["Attacker Spoofing XFF: 1.1.1.1"]
    end

    subgraph EdgeProxy ["Azure Front Door / WAF (In TRUSTED_PROXY_IPS)"]
        WAF["Appends Real Peer IP to X-Forwarded-For"]
    end

    subgraph AppSubnet ["FastAPI Container Replicas (10.0.2.0/24)"]
        API1["fastapi-replica-1 (:8000)"]
        API2["fastapi-replica-2 (:8000)"]
    end

    subgraph RedisTier ["Private Data Subnet (10.0.3.0/24)"]
        REDIS["Azure Cache for Redis PE (:6380 TLS) / Local Redis (:6379) / FakeRedis"]
    end

    C1 --> WAF
    ATK --> WAF
    WAF -->|"XFF: 1.1.1.1, <real-attacker-ip>, <waf-ip>"| API1
    WAF -->|"XFF: 198.51.100.10, <waf-ip>"| API2
    API1 -->|"Atomic MULTI/EXEC ZSET (SHA-256 Hashed Key, 2s timeout)"| REDIS
    API2 -->|"Atomic MULTI/EXEC ZSET (SHA-256 Hashed Key, 2s timeout)"| REDIS

    style WAF fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style REDIS fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
```

**Why Redis over In-Process Memory Counters:** When Azure Container Apps scales FastAPI from 1 replica to 5 replicas during month-end invoice surges (BR-022), in-process counters would allow $5\times$ the intended request rate. Centralizing atomic ZSET state in Azure Cache for Redis enforces one consistent global ceiling across every replica.

---

### 2.4 Subtask P3-4: Canonical Middleware Pipeline & Isolated Audit DB Connections

In **P3-4 (`feature/audit-middleware`)**, we locked the exact HTTP middleware execution order inside `src/api/main.py` and separated audit database commits onto their own isolated connection/transaction path:

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client / Streamlit UI
    participant M1 as 1. RequestIDMiddleware
    participant M2 as 2. CORSMiddleware
    participant M3 as 3. AuditMiddleware
    participant M4 as 4. RedisRateLimiterMiddleware
    participant Route as Route Handler + require_role()
    participant BizDB as Caller SQL Session
    participant AuditDB as Isolated Audit SQL Session

    Client->>M1: Request (X-Request-ID)
    M1->>M2: Validated/Generated req_id -> request_id_ctx
    M2->>M3: Enforce CORS_ALLOWED_ORIGINS
    M3->>M4: Reset request.state.audit_actor = "anonymous"
    M4->>Route: Check Redis ZSET (if 429 -> short-circuit back to M3!)
    Route->>Route: Verify JWT -> Set request.state.audit_actor = user.user_id
    Route->>BizDB: Begin business transaction
    Route->>AuditDB: AuditLogger.record() -> Independent COMMIT!
    Note over BizDB,AuditDB: Even if BizDB rolls back, AuditDB row persists
    Route-->>M3: Response (200 / 401 / 403 / 500)
    M3->>M3: Emit PII-safe audit log (actor_id, req_id, outcome)
    M3-->>M2: Attach CORS headers
    M2-->>M1: Attach X-Request-ID response header
    M1-->>Client: HTTP Response
```

---

### 2.5 Subtask P3-5: Keyless Managed Identity & Azure Key Vault Private Endpoint Wiring

In **P3-5 (`feature/core-keyvault-stub`)**, we wired `src/core/secrets.py` so production containers obtain short-lived tokens from the Azure Instance Metadata Service (IMDS) / Container Apps Managed Identity endpoint and talk exclusively to the private Key Vault endpoint over TLS 1.2+:

```mermaid
flowchart TD
    subgraph ContainerApp ["FastAPI Container App (East US 2 - 10.0.2.0/24)"]
        APP["src/core/secrets.py (AzureKeyVaultClient)"]
        CRED["DefaultAzureCredential (System-Assigned Managed Identity)"]
        CACHE["Thread-Safe Bounded SecretValue Cache (256 entries, 300s TTL)"]
    end

    subgraph AzurePlatform ["Azure East US 2 Private Network (10.0.3.0/24)"]
        IMDS["Entra ID Managed Identity Endpoint (Zero Static Credentials)"]
        KV_PE["Azure Key Vault Private Endpoint (10.0.3.15:443)"]
        KV["Azure Key Vault (kv-ap-eastus2.vault.azure.net - Public Access OFF)"]
    end

    APP --> CACHE
    CACHE -->|"Cache Miss"| CRED
    CRED -->|"1. Acquire Vault Access Token"| IMDS
    APP -->|"2. HTTPS GET /secrets/{name} (Host-Pinned *.vault.azure.net)"| KV_PE
    KV_PE --> KV

    style KV_PE fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style CACHE fill:#fff3e0,stroke:#e65100,stroke-width:2px;
```

---

## 3. Complete Phase 3 Local Docker Compose vs. Azure East US 2 Topology

```mermaid
flowchart TD
    subgraph AzureVNet ["Azure East US 2 VNet (10.0.0.0/16) — Zero Cross-Region Egress"]
        WAF["Azure Front Door / WAF (TLS 1.3)"]

        subgraph DMZ ["Public Subnet (10.0.1.0/24)"]
            UI["streamlit-ui (:8501) - Entra ID EasyAuth"]
        end

        subgraph AppSubnet ["Private App Subnet (10.0.2.0/24) — No Public IPs"]
            API1["fastapi-api Replica 1 (:8000) — RequestID -> CORS -> Audit -> RateLimit -> RBAC"]
            API2["fastapi-api Replica 2 (:8000) — RequestID -> CORS -> Audit -> RateLimit -> RBAC"]
            MI["System-Assigned Managed Identity"]
        end

        subgraph DataSubnet ["Air-Gapped Data Subnet (10.0.3.0/24) — Private Endpoints"]
            PE_REDIS["Redis PE (:6380) - Sliding-Window Rate Limiter"]
            PE_SQL["Azure SQL PE (:1433) - Business & Isolated Audit Sessions"]
            PE_KV["Key Vault PE (:443) - Residual Config Secrets"]
            LA["Log Analytics / App Insights - Masked JSON Audit Logs"]
        end
    end

    ENTRA_ID["Microsoft Entra ID v2.0 (JWKS Discovery HTTPS :443)"]

    WAF --> UI
    UI -->|"Bearer JWT + X-Request-ID"| API1
    UI -->|"Bearer JWT + X-Request-ID"| API2
    MI -.->|"Keyless OAuth2 Tokens"| API1
    MI -.->|"Keyless OAuth2 Tokens"| API2
    API1 --> PE_REDIS
    API2 --> PE_REDIS
    API1 --> PE_SQL
    API2 --> PE_SQL
    API1 --> PE_KV
    API2 --> PE_KV
    API1 --> ENTRA_ID
    API2 --> ENTRA_ID
    API1 -.-> LA
    API2 -.-> LA

    style DataSubnet fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    style AppSubnet fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
```

### Local Docker Compose Wiring Matrix (Phase 3 Additions)

| Service / Component | Local Docker / Offline Mode | Production Azure East US 2 |
|---|---|---|
| **Identity Provider** | `ENABLE_DEMO_AUTH=true` (in-memory RSA-2048) | Microsoft Entra ID v2.0 (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID`) |
| **Rate Limit Store** | `USE_FAKE_REDIS=true` or Docker `redis:7-alpine` (`redis://redis:6379/0`) | Azure Cache for Redis Private Endpoint (`rediss://...:6380/0`) |
| **Audit Persistence** | Isolated `aiosqlite` transaction (`/app/data/enterprise.db`) | Isolated `aioodbc` transaction on Azure SQL Private Endpoint |
| **Secrets Provider** | `USE_MOCK_KEY_VAULT=true` (`LocalKeyVaultStub`, empty by default) | `USE_MOCK_KEY_VAULT=false` (`AzureKeyVaultClient` + Managed Identity) |
| **CORS / Proxy Trust** | `CORS_ALLOWED_ORIGINS=["http://localhost:8501"]`, `TRUSTED_PROXY_IPS=[]` | Front Door origin + explicit WAF/Front Door `TRUSTED_PROXY_IPS` |

---

## 4. Phase 3 Infrastructure Verification Matrix

| Subtask | Infrastructure Control | Offline Verification | CI / Build Status |
|---|---|---|---|
| **P3-1** | `pyjwt[crypto]` + RS256 JWKS Client + Explicit CORS | 15 tests in `test_security.py` (ephemeral RSA-2048, zero network) | PR #6 Merged ✅ |
| **P3-2** | Ephemeral RSA Demo Auth + Triple Prod Gate | 10 tests in `test_demo_auth.py` (prod/staging/Azure SQL blocked) | PR #7 Merged ✅ |
| **P3-3** | `fakeredis.aioredis` ZSET Pipeline + Anti-XFF Proxy Routing | 12 tests in `test_rate_limit.py` (zero Lua, 0 warnings) | PR #8 Merged ✅ |
| **P3-4** | Canonical 4-Layer Middleware Stack + Isolated Audit Session | 10 tests in `test_audit.py` (rollback survival, CRLF + PII path safety) | PR #9 Merged ✅ |
| **P3-5** | Managed Identity Key Vault URL Pin + Offline Stub + Secret Scanner | 8 tests in `test_secrets.py` (full `src/` static-secret scan) | PR #10 Merged ✅ |
