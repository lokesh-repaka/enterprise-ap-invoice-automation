# Platform Memory & Engineering Status

> Centralised engineering log and honest project status tracker.
> Maintained autonomously across subtasks and phases.

---

## 1. Honest Status

- **Current Active Phase:** Phase 6 — Extraction Engine and Model Gateway (1 / 5 Tasks Complete — P6-1 Done)
- **Latest Completed Subtask:** P6-1 · Document classifier — PyMuPDF text-layer density check → `searchable_pdf`, `scanned_image`, `xlsx`
- **Total Completed Tasks:** 30 / 68 (44%)
- **Test Suite Pass Count:** **201 / 201 passing (100% — 200 unit + 1 wire-protocol integration smoke; 1 optional live-Docker smoke skipped)**
- **Test Execution Latency:** **6.22 seconds** (strict offline isolation mode)
- **Code Quality & Linter:** Ruff passing with 0 warnings, 0 errors (70 files formatted)
- **Security Audit Status:** Zero critical/high unmitigated vulnerabilities (110 findings audited & mitigated); `classify_document()` (`src/extraction/document_classifier.py`) live with binary magic-byte detection, PyMuPDF per-page alphanumeric + uniqueness density check (defeats whitespace/repeated-char spoofing & detects hybrid scanned pages), bidi/zero-width sanitization preserving EN/DE/ES diacritics, pre-decode raster pixel-bomb checks, and XLSX Zip-Slip/ZIP-bomb guards
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
| `tests/unit/test_blob_client.py` | Keyless Azure Blob WORM client, `overwrite=False`, bounded 25 MB download, SSRF/path/MIME guards | 10 | 0.15s |
| `tests/unit/test_azurite_local.py` | Azurite triple prod gate, loopback URL pin, container bootstrap, compose security hygiene | 6 | 0.08s |
| `tests/unit/test_file_validator.py` | Magic-byte MIME guard, 25 MB cap, TIFF block (GAP-004), password/active-script PDF & XLSX XXE/ZIP-bomb/Zip-Slip defenses | 13 | 0.32s |
| `tests/unit/test_blob_metadata.py` | Canonical `VendorID`/`UploadTimestamp`/`FileHash` tagging, Azure REST lowercase parsing, constant-time integrity check, key+value PII & 8 KB header guards | 10 | 0.19s |
| `tests/unit/test_invoice_upload.py` | `POST /api/v1/invoices/upload` multipart intake, RBAC, bounded 25 MB stream, WORM Blob, SQL `UPLOADED`, `INGEST` audit, Redis FIFO enqueue, fail-closed `503` | 11 | 1.55s |
| `tests/unit/test_redis_client.py` | Async Redis FIFO job queue (`RPUSH`/`LPOP`/`BLPOP`), DLQ quarantine, atomic `SET NX EX` & `WATCH/MULTI/EXEC` idempotency keys, TLS `rediss://` prod gate | 9 | 0.04s |
| `tests/unit/test_worker.py` | Background worker skeleton (`UPLOADED->EXTRACTING->outcome`), non-approval guard, blob-swap & `FileHash` checks, timeout/retry/DLQ, graceful `run_loop` | 9 | 0.32s |
| `tests/unit/test_invoice_read_routes.py` | `GET /api/v1/invoices/{id}` & `GET /api/v1/invoices/exceptions` RBAC, LIKE-escaped filters, sort allowlist, bulk PII minimization, `COUNT(*)` audit count | 7 | 0.83s |
| `tests/unit/test_idempotency_dedup.py` | Atomic upload idempotency dedup (`200 OK` + `X-Idempotency-Replayed`), live SQL status refresh, `409 Conflict` on mismatch, clerk isolation, lock rollback | 7 | 0.95s |
| `tests/unit/test_document_classifier.py` | PyMuPDF text-layer density classifier (`searchable_pdf`, `scanned_image`, `xlsx`), hybrid PDF detection, anti-spoofing, bidi sanitization, raster/XLSX guards | 8 | 0.19s |
| `tests/integration/test_azurite_smoke.py` | End-to-end real Azure Storage SDK wire-protocol WORM smoke test (`If-None-Match: *`) | 1 (+1 live skip) | 0.07s |
| **Total** | **All Modules Offline** | **201** | **6.22s** |

---

## 3. Architecture Non-Negotiables & Progress

1. **Rules-First Invariant:** Model extracts visual invoice data into `<invoice_text>`; deterministic Python rules validate math, tax schemes, and approvals.
2. **Layering Rules:** `src/database/` has 0 imports from `src/extraction/` or `src/storage/`. Clean separation maintained.
3. **Zero Static Credentials:** Entra ID Managed Identity exclusively for cloud resources.
4. **Offline Isolation:** All unit tests run offline with `USE_LOCAL_SQLITE=true`, `USE_FAKE_REDIS=true`, `USE_MOCK_AOAI=true`.
