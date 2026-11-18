# Platform Memory & Engineering Status

> Centralised engineering log and honest project status tracker.
> Maintained autonomously across subtasks and phases.

---

## 1. Honest Status

- **Current Active Phase:** Phase 9 — Re-Validation and Approval API (25% Complete — 1 / 4 Tasks Done)
- **Latest Completed Subtask:** P9-1 · `POST /api/v1/invoices/{id}/revalidate` — reason code validation, re-runs rules engine, re-evaluates confidence, writes audit log
- **Total Completed Tasks:** 44 / 68 (65%)
- **Test Suite Pass Count:** **553 / 553 passing (100% — 552 unit + 1 wire-protocol integration smoke; 1 optional live-Docker smoke skipped)**
- **Test Execution Latency:** **10.06 seconds** (strict offline isolation mode)
- **Code Quality & Linter:** Ruff passing with 0 warnings, 0 errors (98 files formatted)
- **Security Audit Status:** Zero critical/high unmitigated vulnerabilities (176 findings audited & mitigated; `SEC-173`–`SEC-176` closed in P9-1); `POST /api/v1/invoices/{id}/revalidate` (`src/api/invoices.py`) delegates all orchestration to `RevalidationService` (`src/services/revalidation.py`, zero HTTP/FastAPI imports per CLAUDE.md §4.2), enforces `ap_clerk` RBAC + anti-impersonation `clerk_id` verification, strict `ReasonCode` enum + mandatory `OTHER` comment, atomic single-transaction header+line persistence with expected-status CAS & anti-IDOR line ownership (`SEC-173`), statutory tax-override governance & zero line-rate consistency (`SEC-174`), 1 MB `Content-Length` fail-fast cap (`SEC-175`), inactive-vendor block & critical audit-failure SIEM alerting (`SEC-176`), immutable `EDIT` + `REVALIDATE` isolated-transaction audit logs, preserved model confidence scores, and ECB FX high-value/PO-variance escalation
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
| `tests/unit/test_model_gateway.py` | Hybrid Azure OpenAI Model Gateway routing (`gpt-4o-mini` vs `gpt-4o-vision`), prompt caching order, 2k token cap, LLD §6.2 429 backoff/jitter, keyless MI SSRF/API-version/JSON-bomb/Vision guards | 10 | 0.38s |
| `tests/unit/test_extraction_schemas.py` | Pydantic v2 10-header + 5-line extraction schemas, per-field confidence aggregations, credit notes, ground-truth round-trip, `extra="forbid"`, `FiniteDecimal` bomb & bidi/XSS/PII guards | 10 | 0.32s |
| `tests/unit/test_extract_engine.py` | End-to-end Extraction Engine: cached system prompt, `<invoice_text>` breakout defense, PDF/PNG/XLSX/text routing, XXE/Zip-Slip/MediaBox-clamp guards, strict Pydantic schema enforcement & PII-safe errors | 11 | 0.47s |
| `tests/unit/test_mock_aoai_client.py` | Offline `MockAOAIClient` wired to `ModelGateway` & `ExtractionEngine`: ground-truth fixture lookup, confidence overrides, scripted 429 retry, prod gate, `O_NOFOLLOW`/symlink/traversal/corrupt-file guards | 10 | 0.36s |
| `tests/unit/test_duplicate_detector.py` | P7-1 `DuplicateDetector`: 300-file SHA-256 composite key parity, SQLite `DUPLICATE_INVOICE`/VOID/self exclusion, `-REV`/`v2` & amount-diff `FLAGGED_POTENTIAL_REVISION`, negative total/line `CREDIT_NOTE`, Unicode/case/cross-vendor/CRLF/DoS/PII/layer guards | 43 | 0.87s |
| `tests/unit/test_line_arithmetic.py` | P7-2 line-item arithmetic (`Qty × Price = Total ± LINE_ROUNDING_TOLERANCE`): 1,068 ground-truth lines, settings-driven tolerance, credit-note negatives, polymorphic ORM/schema/dict inputs, duplicate line/ASCII-digit/env-tolerance/mass-assignment/salami-drift guards | 10 | 0.72s |
| `tests/unit/test_invoice_total.py` | P7-3 invoice total arithmetic (`Subtotal + Tax = Total ± INVOICE_ROUNDING_TOLERANCE`): all 300 ground-truth invoices + `INV-2026-1030` rounding flag, settings-driven tolerance, line-sum cross-check, ORM NULL fail-closed, opposite-sign tax threshold-evasion/ASCII/frozen guards | 10 | 0.68s |
| `tests/unit/test_tax_validator.py` | P7-4 multi-country tax validator (US sales tax, UK VAT 20/5/0%, DE MwSt 19/7/0%, ES IVA 21/10/4/0%, mixed-rate lines, reverse-charge/exempt): 299/300 GT pass + `INV-2026-1010` caught, partial-line VAT-evasion/homograph-country/strict-bool/US-ceiling/DoS guards | 27 | 0.46s |
| `tests/unit/test_date_normalizer.py` | P7-5 date normaliser (Vendor Master US `MM/DD/YYYY` vs EU `DD/MM/YYYY`, ISO 8601, ambiguous flagging): 299/300 GT pass + `INV-2026-1005` chronological conflict caught, cross-locale inversion/homograph/2-digit-year/SQLi/year-bounds/frozen guards | 21 | 0.47s |
| `tests/unit/test_rules_engine.py` | P7-6 `RulesEngine` orchestrator: chains P7-1..P7-5 across all 300 ground-truth files (zero crashes, exact 4 problem routes), SQLite duplicate + multi-failure precedence, clerk re-validation, unconditional credit-note/partial-tax/exponent/bool/frozen/layer guards | 7 | 0.61s |
| `tests/unit/test_confidence_router.py` | P8-1 `ConfidenceRouter`: FR-04/BR-007 tri-tier thresholds (≥90% `VALIDATED`, 80–89.99% `REQUIRES_REVIEW`, <80% `REQUIRES_APPROVAL`), sub-cent precision, worst-field-wins, 300 GT batch + Rules-First precedence, re-validation, settings-driven thresholds, credit-note/fraction-floor/key-alias/forged-rules/non-approval/layer guards | 38 | 0.26s |
| `tests/unit/test_state_machine.py` | P8-2 `InvoiceStateMachine`: 10-core / 17-status LLD §4 FSM, deeply immutable graph, 45 legal & 36 illegal transition guards, RBAC + system allowlist, SQLite `InvoiceRepository` atomic CAS persistence, high-value/FX clerk cap, credit-note/CAS/PII/layer guards | 113 | 0.25s |
| `tests/unit/test_escalation_rules.py` | P8-3 `EscalationEvaluator`: FR-13/BR-014 >$10k USD & >5% PO variance rules from `get_settings()`, sub-cent precision, invoice-date ECB FX SQLite lookup, 300 GT Phase 7+8 pipeline, exception/credit-note precedence, spoofed-USD/dual-PO/status-conflict/FX-date/settings-bounds/layer guards | 27 | 0.39s |
| `tests/unit/test_invoice_revalidate.py` | P9-1 `POST /api/v1/invoices/{id}/revalidate` & `RevalidationService`: PRD Journey 5 EU reverse-charge, arithmetic fail -> `REQUIRES_APPROVAL`, >$10k/PO-variance escalation, credit-note guard, `ReasonCode` + `OTHER` comment, `ap_clerk` RBAC + anti-spoofing, FSM 409s, `composite_hash` collision rollback, mass-assignment/IDOR/tax-override/1MB/inactive-vendor/layer guards | 15 | 2.20s |
| `tests/integration/test_azurite_smoke.py` | End-to-end real Azure Storage SDK wire-protocol WORM smoke test (`If-None-Match: *`) | 1 (+1 live skip) | 0.07s |
| **Total** | **All Modules Offline** | **553** | **10.06s** |

---

## 3. Architecture Non-Negotiables & Progress

1. **Rules-First Invariant:** Model extracts visual invoice data into `<invoice_text>`; deterministic Python rules validate math, tax schemes, and approvals.
2. **Layering Rules:** `src/database/` has 0 imports from `src/extraction/` or `src/storage/`. Clean separation maintained.
3. **Zero Static Credentials:** Entra ID Managed Identity exclusively for cloud resources.
4. **Offline Isolation:** All unit tests run offline with `USE_LOCAL_SQLITE=true`, `USE_FAKE_REDIS=true`, `USE_MOCK_AOAI=true`.
