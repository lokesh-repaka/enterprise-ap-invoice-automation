# Platform Memory & Engineering Status

> Centralised engineering log and honest project status tracker.
> Maintained autonomously across subtasks and phases.

---

## 1. Honest Status

- **Current Active Phase:** Phase 3 — Identity and Security (100% Complete ✅ — Ready for Phase 4 & Milestone M1)
- **Latest Completed Subtask:** P3-5 · Azure Key Vault stub (`src/core/secrets.py`) — zero static secrets in code
- **Total Completed Tasks:** 20 / 68 (29%)
- **Test Suite Pass Count:** **110 / 110 passing (100%)**
- **Test Execution Latency:** **2.64 seconds** (strict offline isolation mode)
- **Code Quality & Linter:** Ruff passing with 0 warnings, 0 errors (49 files formatted)
- **Security Audit Status:** Zero critical/high unmitigated vulnerabilities (51 findings audited & mitigated); Phase 3 Identity & Security layer 100% complete (Entra ID RS256 JWT + RBAC, ephemeral RSA-2048 demo tokens, Redis ZSET sliding-window rate limiter, isolated-tx `AuditLogger` + `AuditMiddleware`, and keyless Azure Key Vault provider + offline stub with automated zero-static-secret CI scan)
- **Git Branching Strategy:** Development branch is active; production releases reserved for `main`

---

## 2. Test Count Breakdown by Module

| Test Module | Coverage Domain | Passing Tests | Execution Time |
|---|---|---|---|
| `tests/unit/test_project_structure.py` | 9-layer package scaffold & `pyproject.toml` | 3 | 0.01s |
| `tests/unit/test_config.py` | Centralised settings & dynamic connection URLs | 4 | 0.01s |
| `tests/unit/test_logging.py` | Structured JSON logging & regex PII masking | 4 | 0.01s |
| `tests/unit/test_api_health.py` | FastAPI liveness, readiness, and `X-Request-ID` | 5 | 0.03s |
| `tests/unit/test_harness.py` | Offline fixtures (FakeRedis, Mock AOAI, Mock Blob) | 5 | 0.01s |
| `tests/unit/test_ci_workflow.py` | GitHub Actions CI workflow triggers & job graph | 4 | 0.02s |
| `tests/unit/test_models.py` | SQLAlchemy 2 async models, relationships, and CRUD | 6 | 0.22s |
| `tests/unit/test_schema_migrations.py` | Schema DDL, table integrity, and Alembic migrations | 5 | 0.17s |
| `tests/unit/test_repositories.py` | Async CRUD repositories, append-only audit guard, rate fallback | 6 | 0.05s |
| `tests/unit/test_seed.py` | Idempotent Vendor Master (15 vendors) & ECB FX seed scripts | 7 | 0.08s |
| `tests/unit/test_composite_hash.py` | Partial unique index, SHA-256 hash parity, race-safe duplicate upsert | 6 | 0.09s |
| `tests/unit/test_security.py` | Entra ID RS256 JWT validation, JWKS cache/rotation, `require_role()` RBAC, CORS hardening | 15 | 1.65s |
| `tests/unit/test_demo_auth.py` | Ephemeral RS256 demo tokens (`sarah.clerk`, `michael.manager`, `dave.admin`), triple prod gate, RBAC e2e | 10 | 0.27s |
| `tests/unit/test_rate_limit.py` | Redis ZSET sliding-window rate limiter, anti-XFF spoofing, IPv6 canonicalization, fail-closed 503 | 12 | 0.10s |
| `tests/unit/test_audit.py` | Isolated-tx `AuditLogger`, `AuditMiddleware`, `X-Request-ID` sanitization, canonical middleware order | 10 | 0.43s |
| `tests/unit/test_secrets.py` | Keyless Azure Key Vault client, offline stub, `SecretValue` redaction, zero-static-secret CI scan | 8 | 0.02s |
| **Total** | **All Modules Offline** | **110** | **2.64s** |

---

## 3. Architecture Non-Negotiables & Progress

1. **Rules-First Invariant:** Model extracts visual invoice data into `<invoice_text>`; deterministic Python rules validate math, tax schemes, and approvals.
2. **Layering Rules:** `src/database/` has 0 imports from `src/extraction/` or `src/storage/`. Clean separation maintained.
3. **Zero Static Credentials:** Entra ID Managed Identity exclusively for cloud resources.
4. **Offline Isolation:** All unit tests run offline with `USE_LOCAL_SQLITE=true`, `USE_FAKE_REDIS=true`, `USE_MOCK_AOAI=true`.
