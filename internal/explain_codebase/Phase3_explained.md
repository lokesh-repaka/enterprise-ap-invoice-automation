# Phase 3 Codebase Explained: Identity, Security & The Bank Security Desk

> **Audience:** Recruiters, hiring managers, non-technical stakeholders, and interview board members.  
> **Purpose:** Plain-English walkthrough of everything built in **Phase 3 (Identity and Security)**—how the platform verifies who is knocking on the door, decides which rooms they can enter, stops bots from flooding the lobby, records un-erasable security camera footage of every action, and eliminates hardcoded passwords across the entire codebase.

---

## 1. Executive Summary: Why Phase 3 Matters

In Phase 1, we built the high-security bank building (FastAPI server, privacy-shielded logging, request badges, CI checks). In Phase 2, we built the permanent financial vault (5 exact-accounting tables, 15 international vendors, ECB currency rates, and a mathematical lock against double payments).

However, at the end of Phase 2, **the bank vault had no security desk, no ID badge scanner, no crowd-control turnstile, and no security cameras**. Anyone who knew the URL could walk straight into the system!

**Phase 3: Identity and Security** installs the complete enterprise security perimeter around the platform. Specifically, it solves five critical business problems:

1. **Cryptographic ID Verification & Role Enforcement:** Only verified employees authenticated through **Microsoft Entra ID** can enter—and an AP Clerk (`sarah.clerk`) can never approve a high-value \$15,000 invoice or inspect internal server health reserved for System Administrators (`dave.admin`).
2. **Safe, Passwordless Live Demos:** Sales engineers and hiring reviewers need to test all three personas (*AP Clerk*, *Finance Manager*, *System Admin*) locally on a laptop without provisioning a corporate Azure tenant—yet demo logins must be **physically impossible** to turn on in production.
3. **Anti-Flooding Crowd Control:** A buggy script or hostile bot sending 10,000 requests per second must be politely turned away (`HTTP 429 Too Many Requests`) before it can crash the database or rack up huge Azure OpenAI bills.
4. **Crash-Proof Security Cameras:** Every login denial, rate-limit block, and financial edit is stamped with a tamper-proof request badge and written to permanent ink in its **own independent database transaction**—so even if a business operation crashes halfway through, the audit record still survives.
5. **Zero Passwords Anywhere in Code:** Hardcoded API keys and passwords are the #1 cause of corporate cloud breaches. Phase 3 introduces a keyless **Azure Key Vault** abstraction plus an automated CI scanner that blocks any commit containing static secrets.

---

## 2. Real-World Analogy: The Bank Security Desk, Turnstiles & Guard Cameras

Continuing our **High-Security Bank Analogy**, here is what each of the 5 Phase 3 deliverables builds:

| Phase 3 Component | Bank Security Analogy | What It Actually Does |
|---|---|---|
| **P3-1: Entra ID JWT & `require_role()`** (`src/core/security.py`) | Passport Scanner & Keycard Doors | Cryptographically verifies Microsoft Entra ID digital passports (`RS256` signatures) and checks exact room permissions (`AP-Clerks`, `Finance-Managers`, `AP-Admins`) before opening any door. |
| **P3-2: Demo Auth Tokens** (`src/core/demo_auth.py`, `src/api/auth.py`) | Training-Day Visitor Badges (Self-Destructing) | Prints temporary digital badges for `sarah.clerk`, `michael.manager`, and `dave.admin` using a throwaway key created in memory—and is **triple-locked off** in staging or production. |
| **P3-3: Redis Rate Limiter** (`src/api/rate_limit.py`) | Revolving Lobby Turnstile | Counts each visitor's requests over a smooth rolling 60-second window in Redis. Anyone trying to stampede the lobby gets a polite "Please wait X seconds" (`429`) without disturbing other users. |
| **P3-4: Audit Middleware & `AuditLogger`** (`src/core/audit.py`, `src/api/audit_middleware.py`) | Un-Erasable Security Cameras on Independent Backup Power | Tags every visitor with a sanitized tracking badge (`X-Request-ID`), logs every access attempt (including blocked ones), and writes invoice edits in an isolated transaction that cannot be rolled back. |
| **P3-5: Azure Key Vault Stub** (`src/core/secrets.py`) | Central Keyless Safe & Secret Redaction Envelope | Fetches any residual secrets through Microsoft's keyless Managed Identity safe, wraps them in blacked-out envelopes (`***REDACTED***`), and scans all source code on every build to prove zero passwords exist. |

---

## 3. Deep Dive into the 5 Core Deliverables

```text
┌────────────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 3: IDENTITY AND SECURITY                               │
│                                                                                    │
│  Incoming Request                                                                  │
│       │                                                                            │
│       ▼                                                                            │
│  [1] RequestIDMiddleware (P3-4)  ──► Validates/mints safe X-Request-ID badge       │
│       │                                                                            │
│       ▼                                                                            │
│  [2] CORSMiddleware (P3-1)       ──► Blocks untrusted websites (no '*' wildcard)   │
│       │                                                                            │
│       ▼                                                                            │
│  [3] AuditMiddleware (P3-4)      ──► Records verified actor & outcome (200/401/429)│
│       │                                                                            │
│       ▼                                                                            │
│  [4] RedisRateLimiter (P3-3)     ──► Sliding-window turnstile (blocks floods: 429) │
│       │                                                                            │
│       ▼                                                                            │
│  [5] require_role() (P3-1 / P3-2)──► Verifies RS256 JWT (Entra ID or dev demo key) │
│       │                                                                            │
│       ▼                                                                            │
│  Protected Route + Isolated AuditLogger (P3-4) + Keyless Key Vault (P3-5)          │
└────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Deliverable P3-1: Microsoft Entra ID Passport Scanner & Role Doors (`src/core/security.py`)

- **What we built:**
  - Full cryptographic verification of Microsoft Entra ID **RS256** tokens using Microsoft's public signing keys (JWKS), cached automatically with smart key-rotation support.
  - Three strict corporate roles matching our governance matrix:
    - **`ap_clerk`** (`AP-Clerks` group): Upload, review, edit, and approve invoices up to \$10,000.
    - **`finance_manager`** (`Finance-Managers` group): High-value approvals (> \$10,000) and PO variance overrides.
    - **`system_admin`** (`AP-Admins` group): Infrastructure telemetry, `/health/ready`, vendor master & exchange-rate administration.
  - Protected `GET /health/ready` so only authenticated `system_admin` users can inspect internal database/Redis/OpenAI status, while keeping the lightweight `GET /health` liveness check public for Azure load balancers.
  - Locked down browser Cross-Origin (CORS) rules to explicit trusted addresses (replacing dangerous `"*"` wildcards).
- **Attack Resistance:** Actively blocks forged unsigned tokens (`alg: none`), algorithm-confusion attacks (`HS256`), expired tokens, cross-tenant tokens, and malicious header injections (`jku`, `x5u`, `crit`)—and never leaks raw tokens in error messages or logs.
- **Business Value:** Guarantees that no unauthorized person or AI component can ever approve a payment or inspect internal systems.

---

### Deliverable P3-2: Zero-Secret Demo Persona Tokens (`src/core/demo_auth.py` & `src/api/auth.py`)

- **What we built:**
  - Three ready-to-use local demo personas: **`sarah.clerk`** (AP Clerk), **`michael.manager`** (Finance Manager), and **`dave.admin`** (System Admin).
  - Convenient API routes for local UI demos: `GET /api/v1/auth/demo-personas`, `POST /api/v1/auth/demo-token`, and `GET /api/v1/auth/me`.
- **Two Standout Security Designs:**
  1. **Zero Hardcoded Secrets:** Instead of putting a weak password like `"demo-secret-123"` in code, the app generates a brand-new, throwaway **2048-bit RSA cryptographic keypair in memory** every time it starts—and validates demo badges through the *exact same* strict `EntraJWTValidator` used in production!
  2. **Triple Production Lock:** Demo mode is **disabled by default** (`ENABLE_DEMO_AUTH=false`) and requires **all three** conditions simultaneously: explicit opt-in flag, non-production environment (`dev`/`local`/`test`), AND local SQLite mode (`USE_LOCAL_SQLITE=true`). If anyone deploys to staging, production, or Azure SQL, demo login automatically returns `403 Forbidden`.
- **Business Value:** Enables effortless local demos and automated testing for all three finance roles with zero risk of a backdoor reaching production.

---

### Deliverable P3-3: Redis Sliding-Window Rate Limiter (`src/api/rate_limit.py`)

- **What we built:**
  - A high-speed Redis-backed **sliding-window** traffic limiter (`100 requests / 60 seconds` configurable via settings) that runs completely offline using in-memory `fakeredis` during testing and connects seamlessly to Azure Cache for Redis in production.
  - Sends industry-standard headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After`) so the Streamlit UI knows exactly when to retry.
- **Smart Anti-Bypass Protections:**
  - **Blocks IP Spoofing:** Ignores fake `X-Forwarded-For` headers sent by untrusted callers—only trusting forwarded headers from explicitly registered enterprise reverse proxies (like Azure Front Door).
  - **Fail-Closed by Default:** If Redis ever goes down, the middleware refuses traffic safely (`503 Service Unavailable`) rather than silently dropping DoS protection, while keeping `GET /health` exempt so Azure doesn't unnecessarily restart healthy containers.
  - **Privacy-Preserving Keys:** Hashes visitor IP addresses with SHA-256 before storing them in Redis so raw IPs never sit in cache keys.
- **Business Value:** Protects database stability and Azure OpenAI token budgets from accidental infinite loops or denial-of-service floods.

---

### Deliverable P3-4: Crash-Proof Audit Trail & Canonical Middleware Order (`src/core/audit.py` & `src/api/audit_middleware.py`)

- **What we built:**
  - **`AuditLogger` (`src/core/audit.py`):** A strictly append-only audit writer that opens its **own independent database transaction** every time it records an event. Even if a business workflow fails moments later and rolls back its database changes, the audit log entry **survives permanently**.
  - **Mandatory Finance Governance Rules:** Automatically blocks fake "no-op" edits (where old value equals new value), enforces mandatory reason codes (`OCR_MISREAD`, `VENDOR_ROUNDING`, `TAX_CODE_OVERRIDE`, `VENDOR_DISCOUNT`, `OTHER`) on all financial/tax changes, and requires an explanatory comment whenever `OTHER` is chosen.
  - **`AuditMiddleware` & Hardened `X-Request-ID`:** Sanitizes incoming tracking IDs (blocking log-forging characters), attaches the cryptographically verified user ID to every audit event, masks any Tax IDs appearing in URL paths, and locks the exact 4-layer middleware order (`RequestID` -> `CORS` -> `Audit` -> `RateLimiter`) so even blocked `401`, `403`, and `429` security events are always recorded.
- **Business Value:** Delivers SOX and SOC 2 Type II auditability where neither human error nor system crashes can erase the trail of who tried to do what.

---

### Deliverable P3-5: Keyless Azure Key Vault Provider & Zero-Secret Gate (`src/core/secrets.py`)

- **What we built:**
  - **`AzureKeyVaultClient`:** Production secret loader using Microsoft Entra ID **Managed Identity** (`DefaultAzureCredential`), pinned strictly to valid `https://<vault>.vault.azure.net/` hosts with short-lived memory caching (5 minutes) and instant rotation invalidation.
  - **`LocalKeyVaultStub`:** An empty in-memory offline safe for laptop development and CI testing (hard-blocked outside local dev/test).
  - **`SecretValue` Redaction Envelope:** Every secret returned by the platform is wrapped in an immutable object that prints as `***REDACTED***`, cannot be pickled to disk, and uses timing-safe comparisons.
  - **Automated Zero-Secret CI Scanner:** A permanent unit test scans every `.py` file in `src/` and `.env.example` on every pull request to verify zero static API keys, SQL passwords, or private keys ever enter the repository.
- **Business Value:** Achieves a **100% keyless cloud architecture (ADR-007)**—eliminating leaked credentials and manual quarterly password rotations.

---

## 4. How to Pitch Phase 3 to an Interview Board

When an interviewer asks:  
**"How did you secure the API, handle authentication and rate limiting, and make sure audit logs and secrets can't be compromised?"**

Here is your exact pitch:

> *"In Phase 3, I treated security as an engineered architecture rather than an afterthought, completing five integrated layers—all verified completely offline.*
>
> *First, **Identity & RBAC**: every protected route verifies real Microsoft Entra ID RS256 JWTs against cached JWKS keys, explicitly blocking `alg: none`, `HS256` key-confusion attacks, cross-tenant tokens, and malicious header injections. For local demos of our three personas (`sarah.clerk`, `michael.manager`, `dave.admin`), I avoided hardcoded secrets completely by generating an ephemeral in-memory RSA-2048 keypair that runs through the exact same RS256 validator—and triple-gated it so it is physically impossible to enable in staging, production, or against Azure SQL.*
>
> *Second, **Abuse Protection**: I built a Redis sliding-window rate limiter using atomic ZSET transactions—no boundary bursts, immune to `X-Forwarded-For` IP spoofing, IPv6-canonicalized, and fail-closed by default.*
>
> *Third, **Tamper-Proof Auditing & Keyless Secrets**: our `AuditLogger` commits in an isolated database session so a rolled-back business transaction can never erase an audit entry, and our middleware order guarantees even `401`, `403`, and `429` blocks are audited with sanitized `X-Request-ID` badges. Finally, `src/core/secrets.py` wraps all Key Vault values in redacted `SecretValue` envelopes backed by Managed Identity, enforced by an automated CI static-secret scanner.*
>
> *With Phase 3 merged, Milestone M1's entire runtime, persistence, and security foundation is 100% complete—with **110 / 110 unit tests passing offline in 2.45 seconds** and **51 threat-modeled security findings audited and mitigated**."*

---

## 5. Summary Cheat Sheet for Non-Technical Stakeholders

| Question | Simple 1-Sentence Answer |
|---|---|
| **What was achieved in Phase 3?** | We added enterprise Microsoft Entra ID login & role guards, safe zero-secret demo logins, Redis traffic rate limiting, crash-proof audit logging, and keyless Azure Key Vault support. |
| **Can an AP Clerk approve a \$50,000 invoice or view admin health checks?** | No—every route checks the user's cryptographically verified Entra ID role and returns `403 Forbidden` if they lack permission. |
| **Are demo logins a security risk in production?** | No—demo auth is off by default, uses throwaway in-memory keys with zero passwords, and is triple-locked off in staging, production, and Azure SQL environments. |
| **What stops bots or buggy scripts from crashing the system?** | Our Redis sliding-window turnstile throttles excessive traffic (`429 Too Many Requests`), blocks fake IP spoofing, and protects downstream databases and AI budgets. |
| **What if an operation crashes halfway through—is the audit log lost?** | No—`AuditLogger` writes in its own independent database transaction, so audit history permanently survives even when business transactions roll back. |
| **Are there any passwords or API keys stored in the codebase?** | Zero—we use Microsoft Managed Identity with Azure Key Vault (`***REDACTED***` secret wrappers) and run an automated secret scanner on every CI build. |
| **How reliable is the platform at the end of Phase 3?** | **110 / 110 automated tests pass offline in 2.45 seconds** with **51 security findings audited and mitigated** and 100% green GitHub Actions CI. |

