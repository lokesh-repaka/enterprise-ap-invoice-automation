# Phase 3: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 3 (Identity and Security — P3-1 through P3-5)**.  
> **Target Audience:** Solution Architects, Security Engineers, Backend Leads, and System Design Interviewers.

---

## 1. Phase 3 Mission & Architectural Baseline

At the end of Phase 2, the platform had a stateless FastAPI runtime skeleton (Phase 1) and a dual-dialect, race-safe async SQL persistence tier with 5 domain tables and 55 passing tests (Phase 2). However, the API lacked authentication, role-based access control, abuse throttling, request-to-audit correlation, and keyless secret management.

The mission of **Phase 3** was to wrap the platform in a defense-in-depth **Identity, Security, and Observability Perimeter** enforcing six non-negotiable invariants:

1. **Asymmetric Keyless Authentication (`ADR-007`, `N1`):** Strict RS256 Microsoft Entra ID v2.0 JWT verification with JWKS caching, rotation cooldown, and fail-closed defaults—zero `HS256` shared secrets.
2. **Explicit Allow-List RBAC (`CLAUDE.md §2, §8, §9`):** Route-level `require_role()` guards returning RFC 6750 `401 Unauthorized` on identity failure and `403 Forbidden` on authorization denial.
3. **Triple-Gated Zero-Secret Local Demo Auth (`P3-2`, `CWE-489`):** Ephemeral runtime RSA-2048 keypair exercising the identical RS256 validator path, strictly blocked outside `dev`/`local`/`test` or whenever `USE_LOCAL_SQLITE=false`.
4. **Atomic Sliding-Window Rate Limiting (`P3-3`, `CWE-770`):** Redis `MULTI/EXEC` ZSET sliding window with trusted-proxy-only `X-Forwarded-For` parsing, IPv6 canonicalization, SHA-256 hashed keys, and fail-closed `503` default.
5. **Isolated-Transaction Immutable Auditing & Canonical Middleware Order (`P3-4`, `CLAUDE.md §16`):** Dedicated `AsyncSession` per `AuditLogger.record()` call (survives caller rollbacks) and locked 4-layer middleware execution order capturing `200`, `401`, `403`, `429`, and `500` events.
6. **Keyless Secret Management & Zero Static Credentials (`P3-5`, `N8`, `BR-030`):** HTTPS host-pinned Azure Key Vault client with `DefaultAzureCredential`, redacted `SecretValue` wrappers, offline `LocalKeyVaultStub`, and automated CI static-secret scanning.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 2 Baseline (Open API Surface)

Entering Phase 3, `src/api/main.py` exposed `/health` and `/health/ready` with permissive wildcard CORS (`allow_origins=["*"]` + `allow_credentials=True`), unsanitized `X-Request-ID`, no JWT authentication, no rate limiting, and no `AuditLogger`.

```mermaid
flowchart LR
    CLIENT["HTTP Client"] --> REQID["RequestIDMiddleware (Raw Header Echo)"]
    REQID --> CORS["CORSMiddleware (Wildcard '*' + Credentials)"]
    CORS --> READY["GET /health/ready (Unauthenticated Topology Leak)"]
    CORS --> DB["src/database/ (5 Tables & Repos Ready)"]

    style CORS fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style READY fill:#ffebee,stroke:#c62828,stroke-width:2px;
```

---

### 2.2 Stage 1 (P3-1): Entra ID RS256 JWT Validator, JWKS Cache & `require_role()` RBAC

In **P3-1 (`feature/entra-id-jwt-rbac`, PR #6)**, we built [`src/core/security.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/core/security.py), guarded `GET /health/ready` with `require_role(Role.SYSTEM_ADMIN)`, and replaced wildcard CORS with explicit `CORS_ALLOWED_ORIGINS`.

```mermaid
flowchart TD
    REQ["Incoming HTTP Request (Authorization: Bearer JWT)"] --> BEARER["HTTPBearer (auto_error=False -> 401 RFC 6750)"]
    BEARER --> PRE["Pre-Crypto Checks: Size <= 16KB, 3 Segments, alg == RS256, Reject jku/x5u/jwk/crit"]
    PRE --> JWKS["EntraJWKSClient (UUID-Pinned HTTPS Origin, TTL Cache, 60s Unknown-kid Cooldown)"]
    JWKS -->|"RSA sig key only (kty == RSA)"| DECODE["PyJWT RS256 Verify (iss, aud, exp, nbf, iat <= now+skew, tid, non-blank sub)"]
    DECODE -->|"Valid"| USER["Frozen AuthenticatedUser (user_id, email, frozenset Roles from roles & groups)"]
    DECODE -->|"Invalid / Expired / Tampered"| E401["401 Unauthorized (Generic Detail, Zero Token Leak)"]
    USER --> GUARD["require_role(*allowed_roles) Strict Allow-List Check"]
    GUARD -->|"Authorized"| ROUTE["Protected Route Handler (e.g. GET /health/ready)"]
    GUARD -->|"Unauthorized"| E403["403 Forbidden (Insufficient permissions)"]

    style PRE fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style JWKS fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style GUARD fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

#### Key Design Decisions in P3-1:
- **Zero Algorithm Confusion (SEC-021):** Rejects `alg: none`, `HS256`, and non-`RSA` JWKs before cryptographic verification.
- **JWKS DoS & Cache-Poisoning Immunity (SEC-023):** Bounds JWKS responses to 256 KB / 64 keys, enforces a 60s refresh cooldown against unknown-`kid` floods, and rejects empty RSA keysets without wiping valid cached keys.
- **Explicit Allow-List RBAC:** `require_role()` validates role names at route registration time (`ValueError` on typos) and requires explicit membership—preventing accidental implicit privilege escalation.

---

### 2.3 Stage 2 (P3-2): Ephemeral RS256 Demo Persona Tokens

In **P3-2 (`feature/auth-demo-tokens`, PR #7)**, we added [`src/core/demo_auth.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/core/demo_auth.py) and [`src/api/auth.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/api/auth.py) for `sarah.clerk`, `michael.manager`, and `dave.admin`—without adding a single static secret or weakening JWT verification.

```mermaid
flowchart TD
    CALLER["Local UI / Developer"] -->|"POST /api/v1/auth/demo-token"| GATE{"Triple Fail-Closed Gate: ENABLE_DEMO_AUTH==True AND APP_ENV in dev/local/test AND USE_LOCAL_SQLITE==True?"}
    GATE -->|"No (Default / Staging / Prod / Azure SQL)"| R403["403 Forbidden (Demo authentication is disabled)"]
    GATE -->|"Yes"| SCHEMA["DemoTokenRequest (extra='forbid', StrictInt TTL 60..7200s)"]
    SCHEMA --> LOOKUP["Immutable DEMO_PERSONAS Allowlist (sarah.clerk / michael.manager / dave.admin)"]
    LOOKUP --> KEY["Thread-Safe Process-Ephemeral RSA-2048 Keypair (In-Memory Only)"]
    KEY -->|"Sign RS256 JWT (Isolated Demo Tenant/Client UUIDs)"| RESP["200 OK + Cache-Control: no-store + Pragma: no-cache"]
    RESP -->|"Bearer Token"| VAL["Same EntraJWTValidator Pipeline (In-Memory Demo Public JWK)"]

    style GATE fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
    style KEY fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

#### Key Design Decisions in P3-2:
- **Identical Cryptographic Pipeline:** Demo tokens use real RS256 signatures and flow through `EntraJWTValidator`, ensuring local testing exercises the exact same verification logic as production.
- **Complete Tenant Domain Separation:** Dedicated non-routable demo tenant/client UUIDs (`00000000-0000-4000-8000-000000000001` / `...002`) make it mathematically impossible for a demo token to validate against a real Microsoft Entra ID validator.

---

### 2.4 Stage 3 (P3-3): Atomic Redis Sliding-Window Rate Limiter Middleware

In **P3-3 (`feature/rate-limit-redis`, PR #8)**, we built [`src/api/rate_limit.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/api/rate_limit.py) using atomic Redis Sorted Set (`ZSET`) transactions (`MULTI/EXEC`) compatible with both `fakeredis.aioredis` and `redis.asyncio` (zero Lua/`lupa` dependency).

```mermaid
sequenceDiagram
    autonumber
    participant Client as HTTP Client
    participant MW as RedisRateLimiterMiddleware
    participant IP as extract_client_ip()
    participant Redis as Redis / FakeRedis (ZSET)

    Client->>MW: GET /api/v1/invoices (optional X-Forwarded-For)
    MW->>IP: Resolve IP (Trust XFF ONLY if peer in TRUSTED_PROXY_IPS)
    IP-->>MW: Canonical IPv4/IPv6 -> SHA-256 Key (ap:ratelimit:api:<32-hex>)
    MW->>Redis: MULTI: ZREMRANGEBYSCORE, ZADD, ZCARD, ZRANGE, PEXPIRE -> EXEC
    alt count <= max_requests
        Redis-->>MW: count, oldest_score
        MW-->>Client: Forward to Route + X-RateLimit-Limit/Remaining/Reset
    else count > max_requests
        Redis-->>MW: count > limit
        MW->>Redis: ZREM rejected member (prevents ZSET memory DoS)
        MW-->>Client: 429 Too Many Requests + Retry-After + X-Request-ID
    else RedisError / Timeout (2.0s)
        MW-->>Client: 503 Service Unavailable (fail-closed default) or pass if fail_open=True
    end
```

#### Key Design Decisions in P3-3:
- **Anti-Spoofing IP Resolution (SEC-034, SEC-035):** Ignores `X-Forwarded-For` from untrusted peers, walks right-to-left skipping trusted proxies, and canonicalizes IPv6 & IPv4-mapped IPv6 (`::ffff:198.51.100.10` -> `198.51.100.10`) so alternate notations cannot split rate-limit buckets.
- **Bounded ZSET Memory (SEC-036):** Evicting rejected attempts via `ZREM` prevents flood attackers from bloating Redis memory or extending lockouts past the true sliding window.

---

### 2.5 Stage 4 (P3-4): Isolated-Transaction `AuditLogger`, `AuditMiddleware` & Canonical Middleware Order

In **P3-4 (`feature/audit-middleware`, PR #9)**, we created [`src/core/audit.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/core/audit.py) and [`src/api/audit_middleware.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/api/audit_middleware.py), hardened `RequestIDMiddleware` against CRLF injection, and locked the canonical middleware order in `src/api/main.py`.

```mermaid
flowchart TD
    subgraph MiddlewareOrder ["Canonical FastAPI Middleware Stack (Outermost -> Innermost)"]
        M1["1. RequestIDMiddleware (Regex Allowlist ^[A-Za-z0-9._-]{1,128}$ -> request_id_ctx)"]
        M2["2. CORSMiddleware (Explicit CORS_ALLOWED_ORIGINS Allowlist)"]
        M3["3. AuditMiddleware (Resets actor, Logs 200/401/403/429/500 with PII-Masked Path)"]
        M4["4. RedisRateLimiterMiddleware (Sliding-Window ZSET Throttling)"]
    end

    subgraph RouteExecution ["Route & Business Logic"]
        AUTH["get_current_user() -> Sets request.state.audit_actor & audit_actor_ctx"]
        BIZ["Caller Business Session (May Commit OR Roll Back)"]
    end

    subgraph IsolatedAudit ["AuditLogger (src/core/audit.py)"]
        VALID["Enum + Financial ReasonCode + No-Op + Value Bounds Guard"]
        ISO_TX["Dedicated Isolated AsyncSession (Survives Caller Rollback)"]
        REPO["AuditLogRepository.create() (Append-Only SQL Table)"]
    end

    M1 --> M2 --> M3 --> M4 --> AUTH --> BIZ
    BIZ --> VALID --> ISO_TX --> REPO

    style MiddlewareOrder fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style IsolatedAudit fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
```

#### Key Design Decisions in P3-4:
- **Surviving Caller Rollbacks (SEC-040):** `AuditLogger` accepts `session_factory` rather than an open `AsyncSession`, committing each `AuditLog` row in its own independent transaction per `CLAUDE.md §16 rule 9`.
- **Solving Starlette `BaseHTTPMiddleware` Async Context Boundaries (SEC-044):** Because Starlette runs `call_next` inside a child `anyio` task group where child `ContextVar` mutations do not propagate back to the parent task, `get_current_user()` populates both `request.state.audit_actor` (readable by outer `AuditMiddleware`) and `audit_actor_ctx` (readable by downstream route/service calls), with both strictly reset to `"anonymous"` on every request.
- **Mask-Before-Strip Path Sanitization (SEC-042):** `_sanitize_audit_path()` runs `mask_pii()` *before* stripping control characters so `\r\n` separators don't fuse Tax IDs onto adjacent words and evade regex word boundaries.

---

### 2.6 Stage 5 (P3-5): Keyless Azure Key Vault Client, Offline Stub & Zero-Secret Gate

In **P3-5 (`feature/core-keyvault-stub`, PR #10)**, we delivered [`src/core/secrets.py`](file:///Users/lokeshrepaka/Desktop/untitled%20folder/src/core/secrets.py) completing the keyless security foundation.

```mermaid
flowchart TD
    CALLER["Application / Service Component"] --> FACTORY["get_secret_provider(settings)"]
    FACTORY --> CHECK{"USE_MOCK_KEY_VAULT == True?"}
    CHECK -->|"Yes"| PROD_GUARD{"APP_ENV in dev/local/test AND USE_LOCAL_SQLITE == True?"}
    PROD_GUARD -->|"No"| FAIL["Raise SecretProviderConfigurationError (Fail-Closed)"]
    PROD_GUARD -->|"Yes"| STUB["LocalKeyVaultStub (Empty In-Memory Store + Scoped KV_STUB_ Env)"]
    CHECK -->|"No"| URL_VAL["validate_key_vault_url() (Strict HTTPS *.vault.azure.net/)"]
    URL_VAL --> AKV["AzureKeyVaultClient (DefaultAzureCredential + Thread-Safe 256-Entry TTL Cache)"]
    STUB --> WRAP["SecretValue (Redacted str/repr, Unpicklable, Constant-Time ==, <= 25KB)"]
    AKV --> WRAP

    style PROD_GUARD fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
    style WRAP fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

## 3. End of Phase 3: Complete Identity & Security Architecture

```mermaid
flowchart TD
    subgraph ExternalIngress ["North-South Ingress"]
        USER["AP Clerk / Finance Manager / Admin"]
        AFD["Azure Front Door / WAF (Trusted Proxy)"]
    end

    subgraph FastAPIPerimeter ["FastAPI Security Perimeter (Phase 3 Complete)"]
        MW1["1. RequestIDMiddleware (Sanitized UUID4)"]
        MW2["2. CORSMiddleware (Explicit Origins)"]
        MW3["3. AuditMiddleware (Verified Actor + PII-Safe Telemetry)"]
        MW4["4. RedisRateLimiterMiddleware (Atomic ZSET + Anti-XFF)"]
        RBAC["EntraJWTValidator + require_role() (RS256 + JWKS)"]
        DEMO["Demo Auth Routes (Triple-Gated Dev-Only Ephemeral RSA)"]
    end

    subgraph CoreSecurityServices ["Core Security & Persistence Services"]
        AUDIT["AuditLogger (Isolated-Tx Append-Only Writer)"]
        SECRETS["SecretProvider (Keyless Managed Identity Key Vault / Stub)"]
        REDIS["Azure Cache for Redis / FakeRedis"]
        SQL["Azure SQL / SQLite (Phase 2 Repositories)"]
        ENTRA["Microsoft Entra ID v2.0 JWKS"]
        AKV["Azure Key Vault (Private Endpoint)"]
    end

    USER --> AFD --> MW1 --> MW2 --> MW3 --> MW4 --> RBAC
    MW4 --> REDIS
    RBAC --> ENTRA
    RBAC -.->|"Dev/Test Only"| DEMO
    RBAC --> AUDIT --> SQL
    SECRETS --> AKV

    style FastAPIPerimeter fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style CoreSecurityServices fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

## 4. Phase 3 Architectural Scorecard

| Metric | Target | Phase 3 Actual | Status |
|---|---|---|---|
| **Entra ID Auth & RBAC** | RS256 JWKS + `require_role()` | Strict RS256, 3 roles + Entra group mapping, `/health/ready` protected | Met ✅ |
| **Demo Personas** | 3 personas, zero static secrets | `sarah.clerk`, `michael.manager`, `dave.admin` via ephemeral RSA-2048 + triple prod gate | Exceeded ✅ |
| **Rate Limiting** | Redis middleware | Atomic ZSET sliding window, anti-XFF spoofing, IPv6 canonicalization, fail-closed `503` | Exceeded ✅ |
| **Audit Middleware & Writer** | `request_id` + immutable `AuditLog` | Isolated-tx `AuditLogger`, sanitized `X-Request-ID`, locked 4-layer middleware order | Met ✅ |
| **Keyless Secrets** | `src/core/secrets.py` + 0 static secrets | `AzureKeyVaultClient` + `LocalKeyVaultStub` + `SecretValue` + automated CI secret scanner | Exceeded ✅ |
| **Unit Test Suite** | 100% offline pass | **110 / 110 passing in 2.45s** (0 warnings, 0 network calls, \$0 cloud spend) | Exceeded ✅ |
| **Security Findings Audited** | Threat modeled w/ CWE | **51 total findings mitigated (`SEC-001` to `SEC-051`; 31 new in Phase 3)** | Exceeded ✅ |

