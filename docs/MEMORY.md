
# Platform Memory & Engineering Status

> Centralised engineering log and honest project status tracker.
> Maintained autonomously across subtasks and phases.

---

## 1. Honest Status

- **Current Active Phase:** Phase 12 — Integration Tests (In Progress — 2 / 5 Tasks Done)
- **Latest Completed Subtask:** P12-2 · Integration test — full upload → extract → validate → route flow with mocked AOAI
- **Total Completed Tasks:** 56 / 68 (82%)
- **Test Suite Pass Count:** **666 / 666 passing (100% — 653 unit + 13 offline integration tests; 1 optional live-Docker smoke skipped)**
- **Test Execution Latency:** **~26 seconds** (strict offline isolation mode)
- **Code Quality & Linter:** Ruff passing with 0 warnings, 0 errors (128 files formatted)
- **Security Audit Status:** Zero critical/high unmitigated vulnerabilities (214 findings audited & mitigated; `SEC-212`–`SEC-214` closed in P12-2); wired full end-to-end `src/services/pipeline.py::InvoiceProcessingPipeline` (`upload → Redis → Worker → ExtractionEngine/MockAOAI → RulesEngine → ConfidenceRouter → EscalationEvaluator → SQL Header/Lines + WORM JSON + AuditLogs`) with anti-IDOR `InvoiceRepository.bind_extracted_vendor()` (`UNKNOWN`-only active-vendor binding & fail-closed unregistered vendor guard: `SEC-212`), race-safe duplicate `composite_hash` preservation & fail-closed missing-FX clerk-cap guard (`SEC-213`), and double-locked non-approval status allowlist + PII-free worker audit summaries (`SEC-214`)
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
| `tests/unit/test_invoice_approve.py` | P9-2 `POST /api/v1/invoices/{id}/approve` & `ApprovalService`: clerk ≤$10k one-click (`APPROVED_CLERK`), manager >$10k/PO-variance (`APPROVED_MANAGER`), live ECB FX stale-column guard, dynamic settings thresholds, unauth/admin/spoofing/double-approval/credit-note/sub-90%/placeholder/64KB/layer guards | 14 | 2.10s |
| `tests/unit/test_invoice_audit_route.py` | P9-3 `GET /api/v1/invoices/{id}/audit`: chronological timeline, 3-role RBAC + empty-role 403, `action_type`/`user_id`/pagination filters, e2e revalidate->approve->audit chain, 405 immutability, dotted-field & comment PII masking, SQLi/XSS/flood/503/nosniff/layer guards | 11 | 1.42s |
| `tests/unit/test_noop_edit_guard.py` | P9-4 No-op edit guard (`previous_value == new_value` -> 422): empty payload/containers, text/date/decimal-scale/mixed header & line no-ops, LLD §2.2 full-row diff compatibility, `-0.00`/Unicode NFD/NBSP homoglyph/explicit-null/replayed-flag/service-fast-fail/oracle-ordering guards | 11 | 1.99s |
| `tests/unit/test_ui_api_client.py` | P11-1 Typed `httpx` API client (`src/ui/api_client.py`): all 11 FastAPI routes end-to-end, typed error hierarchy (`401`/`403`/`404`/`409`/`422`/`429`/`503`), SSRF/redirect/path-traversal/CRLF/token-redaction/10MB-response/25MB-upload/timeout guards, AST `src/ui/` layering check | 7 | 0.50s |
| `tests/unit/test_ui_ingestion_dashboard.py` | P11-2 Ingestion Dashboard (`/`): multi-file drag-and-drop validation (FR-01/GAP-004), deterministic SHA-256 idempotency dedup, batch summary metrics, live status table, bounded live polling & 429 backoff, RBAC/batch-bytes/session/XSS/CSV-formula/route/layering guards, headless Streamlit renderer smoke | 10 | 0.12s |
| `tests/unit/test_ui_review_workbench.py` | P11-3 Review Workbench (`/workbench/{id}`): split-screen PyMuPDF viewer (zoom/page/25MB/TIFF/NaN guards), confidence color cues & Tax ID masking, smart-diff no-op prevention, ReasonCode/tax-override/RBAC/hidden-Approve >$10k, SSRF/URL/CSV-formula/duplicate-line/layering guards, headless renderer smoke | 8 | 0.15s |
| `tests/unit/test_ui_exception_queue.py` | P11-4 Human Exception Queue (`/exceptions`): PRD Screen 3 exception presets & strict filter validation, confidence colour coding (`#22c55e`/`#fef08a`/`#ef4444`), urgency & elapsed time, bulk assign/refresh (429 backoff)/manager-only bulk approve, XSS/CSV-formula/route/layering guards, headless renderer smoke | 9 | 0.12s |
| `tests/unit/test_ui_revision_screen.py` | P11-5 Revision Comparison (`/revision/{id}`): `-REV`/`v2`/`AMENDED` marker detection, yellow/red header & line-item diff engine, financial/tax/percentage deltas, exact duplicate & cross-vendor/`UNKNOWN` spoofing guards, original APPROVE audit provenance, fail-closed decision RBAC, XSS/CSV-formula/layering guards, headless renderer smoke | 8 | 0.14s |
| `tests/unit/test_ui_audit_viewer.py` | P11-6 Audit Trail Viewer (`/audit/{id}`): 3-role RBAC & 9-action filter allowlist, oldest-to-newest chronological timeline & KPI summary, flat/dotted PII & inline SSN/IBAN/Bearer redaction, formula-safe CSV/JSON exports, AST read-only immutability (zero `data_editor`) & layering check, headless renderer smoke | 6 | 0.12s |
| `tests/unit/test_ui_confidence_colours_rbac.py` | P11-7 Confidence colour coding (`#22c55e`/`#fef08a`/`#ef4444`) & role-aware UI (`src/ui/theme_rbac.py`): exact boundaries & fail-closed NaN/bool parsing, hidden Approve for `ap_clerk` `>$10k`/PO-variance/credit-note/stale-USD/missing-FX, dynamic `get_settings()` thresholds, headless Workbench hiding proof, full-directory `src/ui/*.py` AST layering & zero-HTML audit | 7 | 0.15s |
| `tests/unit/test_validation_unit_suite.py` | P12-1 Consolidated validation & reason-code unit suite: line arithmetic (FR-05), invoice total (FR-06), multi-country tax + reverse-charge/exempt (FR-07), date locale disambiguation (FR-08), duplicate SHA-256 hash/revision/credit-note (FR-09..11), tri-tier confidence router (FR-04), `ReasonCode` enum/UI parity/strict ASCII & dotted-field `AuditLogger` guards (FR-12, `SEC-209`–`SEC-211`), and `src/validation/` AST layering audit | 10 | 0.18s |
| `tests/integration/test_azurite_smoke.py` | End-to-end real Azure Storage SDK wire-protocol WORM smoke test (`If-None-Match: *`) | 1 (+1 live skip) | 0.07s |
| `tests/integration/test_ui_ingestion_dashboard_integration.py` | P11-2 End-to-end offline integration test: `IngestionDashboardController` -> real FastAPI (SQLite + FakeRedis + WORM Blob) upload, idempotent replay, and live SQL status polling | 1 | 0.30s |
| `tests/integration/test_ui_review_workbench_integration.py` | P11-3 End-to-end offline integration test: PRD Journey 5 DE EU reverse-charge edit -> `Re-Validate` -> `VALIDATED` -> `Approve (One-Click)` -> `APPROVED_CLERK` against real FastAPI backend | 1 | 0.30s |
| `tests/integration/test_ui_exception_queue_integration.py` | P11-4 End-to-end offline integration test: real FastAPI `/exceptions` preset filtering + `finance_manager` bulk approval on `$15k` escalated invoice skipping `DUPLICATE_INVOICE` | 1 | 0.27s |
| `tests/integration/test_ui_revision_screen_integration.py` | P11-5 End-to-end offline integration test: real FastAPI `APPROVED_CLERK` original + `FLAGGED_POTENTIAL_REVISION` `-REV` side-by-side comparison & immutable `APPROVE` audit provenance | 1 | 0.29s |
| `tests/integration/test_ui_audit_viewer_integration.py` | P11-6 End-to-end offline integration test: real FastAPI Re-Validate -> Approve -> `AuditTrailViewerController` chronological inspection as `system_admin` | 1 | 0.30s |
| `tests/integration/test_ui_confidence_colours_rbac_integration.py` | P11-7 End-to-end offline integration test: UI-backend RBAC parity (`$15k` hidden in UI + HTTP 403 on FastAPI for `ap_clerk`, approved by `finance_manager`; `$2.5k` approved by `ap_clerk`) | 1 | 0.30s |
| `tests/integration/test_upload_extract_validate_route_integration.py` | P12-2 End-to-end offline integration tests: `POST /upload` → Redis → `InvoiceBackgroundWorker` → `InvoiceProcessingPipeline` (`MockAOAIClient` mini/vision + `RulesEngine` + `ConfidenceRouter` + `EscalationEvaluator` + SQL + WORM JSON + `AuditLogs`): STP `VALIDATED`, 85%/74% tri-tier routing, >\$10k EUR FX escalation, tax mismatch/duplicate/revision/credit-note, PNG Vision + unregistered vendor/missing FX fail-closed, prompt-injection & anti-IDOR vendor rebind guards | 6 | 2.53s |
| **Total** | **All Modules Offline** | **666** | **~26s** |

---

## 3. Architecture Non-Negotiables & Progress

1. **Rules-First Invariant:** Model extracts visual invoice data into `<invoice_text>`; deterministic Python rules validate math, tax schemes, and approvals.
2. **Layering Rules:** `src/database/` has 0 imports from `src/extraction/` or `src/storage/`. Clean separation maintained.
3. **Zero Static Credentials:** Entra ID Managed Identity exclusively for cloud resources.
4. **Offline Isolation:** All unit tests run offline with `USE_LOCAL_SQLITE=true`, `USE_FAKE_REDIS=true`, `USE_MOCK_AOAI=true`.
