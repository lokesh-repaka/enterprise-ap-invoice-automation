# Phase 3: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, security, cryptography, distributed systems, FastAPI middleware, and debugging interview preparation covering **Phase 3 (Identity and Security — P3-1 through P3-5)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, Security Engineer, Cloud/AI Solution Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [Entra ID RS256 JWT Validation & RBAC (P3-1)](#1-entra-id-rs256-jwt-validation--rbac-p3-1)
2. [Zero-Secret Ephemeral Demo Auth Tokens (P3-2)](#2-zero-secret-ephemeral-demo-auth-tokens-p3-2)
3. [Redis Sliding-Window Rate Limiter & Anti-Spoofing (P3-3)](#3-redis-sliding-window-rate-limiter--anti-spoofing-p3-3)
4. [Isolated-Transaction AuditLogger, Middleware Order & Async Traps (P3-4)](#4-isolated-transaction-auditlogger-middleware-order--async-traps-p3-4)
5. [Keyless Azure Key Vault, Secret Redaction & Hygiene Gates (P3-5)](#5-keyless-azure-key-vault-secret-redaction--hygiene-gates-p3-5)
6. [Real-World Debugging Stories & Security Threat Model Summary](#6-real-world-debugging-stories--security-threat-model-summary)

---

## 1. Entra ID RS256 JWT Validation & RBAC (P3-1)

### Q1.1: Explain the RS256-to-HS256 JWT key-confusion attack (CVE-2015-9235 / CWE-327) and how your validator defeats it.

**Answer:**
In asymmetric RS256, Microsoft Entra ID signs tokens with its private key and publishes the RSA **public key** openly via JWKS. In a vulnerable JWT implementation that trusts the token's unverified `alg` header:
1. An attacker takes the publicly known RSA public key PEM bytes.
2. They forge a JWT with `{"alg": "HS256", "roles": ["system_admin"]}` and sign it using **HMAC-SHA256** with the public key bytes as the symmetric secret.
3. A naive validator reads `alg: HS256`, passes the RSA public key into `jwt.decode()`, verifies the HMAC signature, and grants `system_admin` access!

**Our multi-layer defense in `src/core/security.py`:**
1. Strict constant allowlist `ALLOWED_JWT_ALGORITHMS = ("RS256",)` checked **both** on `jwt.get_unverified_header(token)` (before touching JWKS) and passed explicitly to `jwt.decode(..., algorithms=["RS256"])`.
2. `EntraJWKSClient` strictly ignores any non-RSA JWK (`kty != "RSA"` or `use not in (None, "sig")`), blocking `oct` symmetric key injection.
3. We also explicitly reject `alg: none` and dangerous/unsupported JWS header extensions (`jku`, `x5u`, `jwk`, `crit` per RFC 7515 §4.1.11).
4. We verify this in `tests/unit/test_security.py` by crafting a raw HMAC-SHA256 attack token with `hmac.new(pub_pem, ...)` and asserting `401 Unauthorized`.

---

### Q1.2: How do you handle Microsoft Entra ID JWKS key rotation without exposing the API to an unknown-`kid` Denial-of-Service attack?

**Answer:**
Microsoft Entra ID rotates signing keys periodically. Two naive approaches both fail in production:
- **Always caching for 1 hour without refresh on miss:** Breaks legitimate users for up to 1 hour right after Entra ID rotates keys.
- **Always fetching JWKS on every unknown `kid`:** Lets an unauthenticated attacker send 1,000 requests/second with random `kid` values (`"kid-1"`, `"kid-2"`, ...), triggering 1,000 outbound HTTPS calls/second to Microsoft (CWE-400 amplification DoS).

**Our solution in `EntraJWKSClient`:**
- Keys are cached under an `asyncio.Lock` (preventing thundering herds) for `ENTRA_JWKS_CACHE_TTL_SECONDS` (default 3600s).
- On an unknown `kid`, we trigger a forced refresh **only if** at least `refresh_cooldown_seconds` (60s) has elapsed since `_last_refresh_monotonic`.
- Legitimate key rotations refresh seamlessly on the first token carrying the new `kid`, while attacker unknown-`kid` floods hit zero outbound network calls inside the cooldown window.
- Furthermore, we cap JWKS payloads at `256 KB` / `64` keys, disable HTTP redirects (`follow_redirects=False`), pin the tenant ID to a strict UUID regex (preventing SSRF — CWE-918), and refuse to overwrite valid cached keys if a transient upstream response returns an empty keyset.

---

### Q1.3: Why did you choose `HTTPBearer(auto_error=False)` and strict explicit allow-list matching in `require_role()`?

**Answer:**
1. **`HTTPBearer(auto_error=False)`:** In FastAPI/Starlette, `HTTPBearer(auto_error=True)` historically returns `403 Forbidden` when the `Authorization` header is missing, violating RFC 6750. Setting `auto_error=False` lets `get_current_user()` consistently return **`401 Unauthorized`** with `WWW-Authenticate: Bearer` for missing/invalid/expired tokens, reserving **`403 Forbidden`** strictly for authenticated callers lacking the required role.
2. **Strict Explicit Allow-List in `require_role(*allowed_roles)`:** Rather than baking implicit role inheritance (`system_admin` automatically inherits `ap_clerk`), `CLAUDE.md §9` explicitly declares exact permitted roles per endpoint (e.g., `/revalidate` is `ap_clerk`, `/health/ready` is `system_admin`, `/audit` is all three). Enforcing strict allow-list membership prevents accidental separation-of-duties violations—and calling `require_role()` with empty roles or a misspelled role raises `ValueError` at app startup (fail-closed).

---

### Q1.4: Why did you replace `allow_origins=["*"]` with `CORS_ALLOWED_ORIGINS` in `src/api/main.py`?

**Answer:**
Combining `allow_origins=["*"]` with `allow_credentials=True` in Starlette's `CORSMiddleware` dynamically reflects **any** incoming `Origin` header alongside `Access-Control-Allow-Credentials: true` (**CWE-942**). Once Bearer JWT authentication was introduced in P3-1, any malicious website visited by an AP clerk could make authenticated cross-origin requests and read financial responses. Restricting `allow_origins` to `settings.CORS_ALLOWED_ORIGINS` (defaulting to `http://localhost:8501` / `http://127.0.0.1:8501`) with explicit methods and headers closes this vulnerability cleanly.

---

## 2. Zero-Secret Ephemeral Demo Auth Tokens (P3-2)

### Q2.1: How did you build demo login tokens for `sarah.clerk`, `michael.manager`, and `dave.admin` without violating the Zero Static Secrets rule (ADR-007 / N8)?

**Answer:**
Most developers implement local demo tokens with a hardcoded `HS256` secret like `SECRET_KEY = "dev-secret"`. That violates ADR-007, introduces `HS256` into the JWT codebase, and risks leaking a static signing key into production.

Instead, in `src/core/demo_auth.py`:
1. We generate a **process-ephemeral 2048-bit RSA keypair in memory** at runtime (`rsa.generate_private_key`), synchronized under a `threading.Lock()` (preventing cold-start race conditions — CWE-362). Zero secrets exist in code, `.env`, or disk.
2. Demo tokens are real **RS256** Entra-shaped JWTs validated through the **exact same `EntraJWTValidator` code path** (using an in-memory JWKS containing the ephemeral public key).
3. Demo tokens use dedicated non-routable demo tenant/client UUIDs (`00000000-0000-4000-8000-000000000001` / `...002`), guaranteeing they can never validate against a production Entra ID validator.

---

### Q2.2: How do you guarantee demo authentication can NEVER accidentally be active in staging or production?

**Answer:**
We enforce a **triple fail-closed safety gate** (`is_demo_auth_enabled()`):
1. `ENABLE_DEMO_AUTH` defaults to **`False`**.
2. `APP_ENV.strip().lower()` must be explicitly in `{"dev", "local", "test"}` (blocked in `staging`, `prod`, `production`, `uat`, etc.).
3. `USE_LOCAL_SQLITE` must be **`True`** — so even if a production Azure Container App accidentally forgot to override `APP_ENV` from `"dev"` *and* flipped `ENABLE_DEMO_AUTH=true`, connecting to Azure SQL (`USE_LOCAL_SQLITE=false`) still hard-blocks demo auth (`403 Forbidden` on `/api/v1/auth/demo-token` and real Entra ID enforcement on all routes — CWE-489).

Additionally, `DemoTokenRequest` uses `ConfigDict(extra="forbid")` and `StrictInt` bounded to `[60, 7200]` seconds (blocking role mass-assignment overrides — CWE-915 — and boolean TTL coercion), and responses emit `Cache-Control: no-store` and `Pragma: no-cache` per RFC 6749 §5.1 (CWE-525).

---

## 3. Redis Sliding-Window Rate Limiter & Anti-Spoofing (P3-3)

### Q3.1: Why did you choose a Redis Sorted Set (`ZSET`) sliding window over a simple `INCR`/`EXPIRE` fixed-window counter, and why use `MULTI/EXEC` instead of a Lua script?

**Answer:**
1. **Why Sliding Window (`ZSET`) over Fixed Window (`INCR`/`EXPIRE`):**
   A fixed-window counter of 100 requests/minute suffers from the **boundary-burst vulnerability**: an attacker sends 100 requests at `00:59` and 100 more at `01:01`—pushing **200 requests ($2\times$ limit) in 2 seconds**! A ZSET storing request timestamps and evicting `(-inf, now_ms - window_ms]` enforces a true continuous sliding window with exact `Retry-After` calculations.
2. **Why `ZREM` on Rejected Attempts:**
   If rejected `429` requests remain inside the ZSET, an attacker flooding the endpoint bloats Redis memory and continuously resets their own lockout window. Immediately calling `ZREM` on the rejected member caps ZSET cardinality strictly at `max_requests` (`CWE-400`).
3. **Why Transactional `MULTI/EXEC` Pipeline over Lua `EVAL`:**
   `fakeredis` requires the optional native C extension `lupa` to execute Lua scripts, which is absent in clean CI environments. A transactional `pipeline(transaction=True)` executes atomically in both production `redis.asyncio` and offline `fakeredis.aioredis` with zero extra dependencies.

---

### Q3.2: How do attackers commonly bypass IP-based rate limiters, and how does `extract_client_ip()` stop them?

**Answer:**
Attackers use three classic bypasses—all mitigated in `src/api/rate_limit.py`:
1. **`X-Forwarded-For` Spoofing (CWE-348):** Rotating `X-Forwarded-For: 1.2.3.4`, `1.2.3.5` on every request. **Mitigation:** Ignore `X-Forwarded-For` completely unless the direct TCP peer (`request.client.host`) is in `settings.TRUSTED_PROXY_IPS`.
2. **Leftmost-IP Spoofing Behind a Trusted Proxy:** When behind Azure Front Door, an attacker sends `X-Forwarded-For: fake-ip`, so the proxy forwards `X-Forwarded-For: fake-ip, real-ip, proxy-ip`. Reading index `[0]` lets the attacker spoof infinitely! **Mitigation:** Walk the chain **right-to-left**, skip trusted proxies, and pick the rightmost syntactically valid untrusted IP.
3. **IPv6 & IPv4-Mapped Canonicalization Evasion (CWE-290):** Sending `2001:db8::1`, `2001:0DB8:0000:0000:0000:0000:0000:0001`, and `::ffff:198.51.100.10` vs `198.51.100.10` to split one IP across multiple rate-limit keys. **Mitigation:** Canonicalize every valid IP via `ipaddress.ip_address()`, unwrap `.ipv4_mapped`, and SHA-256 hash the canonical IP into `ap:ratelimit:api:<32-hex>` (also preventing Redis key injection — CWE-74).

---

### Q3.3: Why does `RedisRateLimiterMiddleware` default to `RATE_LIMIT_FAIL_OPEN=False`, and why are non-CORS `OPTIONS` requests NOT exempt?

**Answer:**
- **Fail-Closed Default (`CWE-636`):** If Redis suffers an outage, returning `503 Service Unavailable` (with `Retry-After: 5` and bounded `2.0s` Redis socket timeouts) preserves DoS protection and protects Azure OpenAI spend—while `RATE_LIMIT_FAIL_OPEN=True` remains available as an explicit ops toggle if availability takes precedence.
- **No Blanket `OPTIONS` Exemption (`CWE-770`):** Because `CORSMiddleware` is mounted **outside** `RedisRateLimiterMiddleware`, legitimate browser CORS preflights are already handled by `CORSMiddleware` before hitting the rate limiter. Any `OPTIONS` request reaching `RedisRateLimiterMiddleware` is a non-preflight request, so only `GET`/`HEAD /health` liveness probes are exempt.

---

## 4. Isolated-Transaction AuditLogger, Middleware Order & Async Traps (P3-4)

### Q4.1: Why must `AuditLogger` NEVER share the caller's SQLAlchemy `AsyncSession`?

**Answer:**
Per `CLAUDE.md §7.1` and `§16 rule 9`: *"Audit log is sacred. Never call `AuditLogger` inside a transaction that might be rolled back."*
- If a service records an `AuditLog` inside the same `AsyncSession` used for business mutations, and a downstream step throws an exception triggering `await session.rollback()`, the audit record is **silently erased** (CWE-778 — Insufficient Logging)!
- In `src/core/audit.py`, `AuditLogger` takes an `async_sessionmaker` (`session_factory`) rather than an `AsyncSession`. Every `record()` call opens its own independent `async with self._session_factory() as isolated_session:`, enforces all validation invariants (canonical `AuditActionType`, mandatory `ReasonCode` on financial/tax edits, mandatory `comment` for `OTHER`, no-op edit rejection, 4096-char value cap), and commits immediately. Even if the caller's business session rolls back, the immutable audit row survives (proven directly by `test_audit_logger_survives_caller_transaction_rollback`).

---

### Q4.2: Explain the canonical 4-layer middleware order in `src/api/main.py` and why swapping layers breaks security.

**Answer:**
Remember that in Starlette/FastAPI, the **last** `app.add_middleware(...)` call runs **outermost** (first on request, last on response). Our locked order (outermost -> innermost) is:
1. **`RequestIDMiddleware`:** Sanitizes/generates `X-Request-ID` (`^[A-Za-z0-9._-]{1,128}$`, blocking CRLF injection — CWE-113/117) first so every downstream middleware and response—including `429` and `503`—carries a valid `X-Request-ID`.
2. **`CORSMiddleware`:** Handles legitimate browser preflights before rate limiting and ensures trusted Streamlit origins receive readable `429`/`401`/`403` error responses.
3. **`AuditMiddleware`:** Runs **outside** `RedisRateLimiterMiddleware` so brute-force `429` blocks, `401`/`403` auth denials, and `500` crashes are all captured in the security audit trail with `request_id` and verified `actor_id`.
4. **`RedisRateLimiterMiddleware`:** Runs **innermost** before route handlers so throttled floods never touch JWT crypto, SQL sessions, or Azure OpenAI.

---

## 5. Keyless Azure Key Vault, Secret Redaction & Hygiene Gates (P3-5)

### Q5.1: Why validate `AZURE_KEY_VAULT_URL` with a strict regex if it comes from environment configuration?

**Answer:**
`AzureKeyVaultClient` authenticates using `DefaultAzureCredential` (Managed Identity), which sends a live Azure Entra ID Bearer token scoped to `https://vault.azure.net/.default` to whatever URL is configured.
- If a misconfiguration, compromised config file, or injection sets `AZURE_KEY_VAULT_URL=https://evil.attacker.com/` or `http://kv.vault.azure.net/` (plaintext HTTP), the Managed Identity token would be **exfiltrated over the wire (CWE-918 / CWE-522)**!
- Pinning `AZURE_KEY_VAULT_URL` strictly to `^https://([a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9])\.vault\.azure\.net/?$` (and rejecting consecutive `--` per Azure DNS rules) eliminates token exfiltration completely.

---

### Q5.2: Why wrap every secret in `SecretValue` instead of returning plain `str`?

**Answer:**
Plain Python `str` secrets leak constantly through developer mistakes: `logger.debug(f"Using {key}")`, `json.dumps(payload, default=str)`, exception tracebacks, dict keys, or pickling objects into Redis/Celery queues.
`SecretValue` enforces four structural safeguards:
1. `__str__` and `__repr__` always return `"***REDACTED***"` (CWE-532).
2. Immutable (`__setattr__`/`__delattr__` raise `AttributeError`), unhashable (`__hash__` raises `TypeError`), and unpicklable (`__reduce__` raises `TypeError` — CWE-312).
3. Equality uses `hmac.compare_digest` (constant-time — CWE-208) and returns `False` against raw `str`.
4. Enforces Azure Key Vault's 25,600-byte maximum secret size (`CWE-400`).

---

## 6. Real-World Debugging Stories & Security Threat Model Summary

### Q6.1: Tell me about three real bugs or subtle security edge cases you caught via TDD and pen-testing during Phase 3.

**Answer:**
1. **Starlette `BaseHTTPMiddleware` Child Task `ContextVar` Boundary (P3-4):**
   During P3-4 TDD, `AuditMiddleware` logged `actor_id="anonymous"` even on authenticated `200 OK` requests! **Root Cause:** Starlette's `BaseHTTPMiddleware` invokes `call_next(request)` inside a child `anyio` task group. Python `ContextVar` updates made inside a child task (`get_current_user()` calling `audit_actor_ctx.set(user.user_id)`) do **not** propagate back to the parent middleware task. **Fix:** Set both `request.state.audit_actor` (shared across the task boundary for outer `AuditMiddleware`) and `audit_actor_ctx` (for downstream route/service code), resetting both to `"anonymous"` on every request.
2. **Sanitization Order Breaking PII Regex Word Boundaries (P3-4):**
   Our penetration test sent `/api/v1/vendors/US-12-3456789\r\nFAKE_LOG` to `_sanitize_audit_path()`. Because we initially stripped `\r\n` to `""` *before* calling `mask_pii()`, the string fused into `US-12-3456789FAKE_LOG`, breaking the trailing `\b` regex word boundary so the raw Tax ID escaped unmasked! **Fix:** Always run `mask_pii()` *first* while control characters act as word boundaries, then strip control characters and cap length.
3. **PyJWT Client-Side Guard Blocking HS256 Confusion Test Setup (P3-1):**
   PyJWT 2.x refuses `jwt.encode(..., pub_pem, algorithm="HS256")` on the client side, which initially masked our server-side attack test. We bypassed PyJWT's encoder by crafting the exact raw HMAC-SHA256 JWS directly with Python's stdlib `hmac.new(pub_pem, signing_input, hashlib.sha256)`, proving our server validator genuinely blocks real-world RS256-to-HS256 confusion payloads.

---

### Q6.2: Summarize the top security vulnerabilities threat-modeled and mitigated across Phase 3 (`SEC-021` to `SEC-051`).

| CWE | Vulnerability Category | Concrete Mitigation Built in Phase 3 |
|---|---|---|
| **CWE-327 / 347** | JWT Algorithm Confusion & Header Injection (`alg: none`, `HS256`, `jku`/`x5u`/`crit`) | Strict `RS256` allowlist, RSA-only JWKS parsing, explicit rejection of `jku`/`x5u`/`jwk`/`crit`. |
| **CWE-489** | Demo Auth or Mock Key Vault Active in Production | Triple fail-closed gates (`ENABLE_DEMO_AUTH=false` default, `APP_ENV in dev/local/test`, `USE_LOCAL_SQLITE=true`). |
| **CWE-798** | Hardcoded Static Secrets / Signing Keys | Ephemeral runtime RSA-2048 demo keypair, Managed Identity Key Vault, automated CI static-secret scanner across `src/`. |
| **CWE-918 / 522** | SSRF & Managed Identity Token Exfiltration | Strict UUID tenant regex for Entra JWKS + strict `https://<vault>.vault.azure.net/` pin for Key Vault (`follow_redirects=False`). |
| **CWE-942** | Permissive CORS Wildcard with Credentials | Replaced `allow_origins=["*"]` with configurable `CORS_ALLOWED_ORIGINS` allowlist. |
| **CWE-348 / 290** | `X-Forwarded-For` & IPv6 Rate-Limit Bypass | `TRUSTED_PROXY_IPS` allowlist, rightmost untrusted IP selection, IPv6/IPv4-mapped canonicalization. |
| **CWE-770 / 400** | Boundary Bursts, ZSET Bloat & JWKS Floods | Atomic Redis ZSET sliding window + `ZREM` on 429, 60s JWKS cooldown, 256KB payload cap, 256-entry secret cache cap. |
| **CWE-778 / 362** | Audit Erasure on Rollback & Actor Context Bleed | Dedicated isolated `AsyncSession` per `AuditLogger.record()`, locked 4-layer middleware order, per-request actor reset. |
| **CWE-113 / 117** | `X-Request-ID` CRLF Splitting & Log Injection | Strict `^[A-Za-z0-9._-]{1,128}$` allowlist on `X-Request-ID` + mask-then-strip URL path sanitization. |
| **CWE-532 / 312** | Token / Secret Leakage in Logs & Serialization | Redacted/unpicklable `SecretValue`, generic 401/403 bodies, zero raw JWTs in logs, `Cache-Control: no-store`. |

