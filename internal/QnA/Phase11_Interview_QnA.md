# Phase 11: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, frontend/UI architecture, HTTP client hardening, state management, live polling, PDF rendering, smart diffing, RBAC parity, immutable audit display, and penetration-testing interview preparation covering **Phase 11 (Streamlit UI — P11-1 through P11-7)**.  
> **Audience:** Candidates interviewing for Senior Full-Stack Python Engineer, AI Platform Engineer, FinTech UI/Backend Architect, or Security Engineer roles.

---

## Table of Contents

1. [Typed HTTP API Client & Transport Security (P11-1)](#1-typed-http-api-client--transport-security-p11-1)
2. [Ingestion Dashboard, Idempotency & Live Polling (P11-2)](#2-ingestion-dashboard-idempotency--live-polling-p11-2)
3. [Split-Screen Review Workbench & Smart Diffs (P11-3)](#3-split-screen-review-workbench--smart-diffs-p11-3)
4. [Human Exception Queue & Safe Bulk Actions (P11-4)](#4-human-exception-queue--safe-bulk-actions-p11-4)
5. [Revision Comparison & Fraud Controls (P11-5)](#5-revision-comparison--fraud-controls-p11-5)
6. [Immutable Audit Trail Viewer & PII-Safe Exports (P11-6)](#6-immutable-audit-trail-viewer--pii-safe-exports-p11-6)
7. [Confidence Colour Coding & Role-Aware UI Policy (P11-7)](#7-confidence-colour-coding--role-aware-ui-policy-p11-7)
8. [Real-World Pentest Stories & Security Threat Model Summary (`SEC-187`–`SEC-208`)](#8-real-world-pentest-stories--security-threat-model-summary-sec-187sec-208)

---

## 1. Typed HTTP API Client & Transport Security (P11-1)

### Q1.1: Why did you build a dedicated `APInvoiceAPIClient` instead of letting each Streamlit page call `requests` or query SQLAlchemy directly?

**Answer:**
1. **Strict Tier Isolation (`CLAUDE.md §4.2`):** The Streamlit container sits in the DMZ subnet (`:8501`) and must hold zero database credentials, zero Azure SDK imports, and zero business logic. An automated AST test (`test_all_ui_modules_obey_layering_and_zero_unsafe_html`) parses every file in `src/ui/` on every CI run and fails the build if any page imports `src.database`, `src.storage`, `src.extraction`, `src.validation`, `src.services`, `sqlalchemy`, `redis`, `openai`, or `azure`.
2. **Centralized Transport Hardening:** Putting all 11 backend routes in `src/ui/api_client.py` guarantees that every single call inherits `validate_api_base_url()` (anti-SSRF), `follow_redirects=False` (anti-Bearer-token-exfiltration `CWE-601`), strict `invoice_id` path allowlists (`^[A-Za-z0-9_-]{1,64}$`), CRLF header checks, 10 MB response capping, Bearer token redaction in `__repr__`/logs, and Pydantic v2 response validation + typed exceptions (`401`/`403`/`404`/`409`/`422`/`429`/`503`).

### Q1.2: Why did you set `follow_redirects=False` on `httpx.Client`?

**Answer:**
If an internal reverse proxy, misconfigured route, or compromised upstream returns a `302`/`307` redirect to an external host, an HTTP client that auto-follows redirects with an `Authorization: Bearer <Entra JWT>` header risks leaking or mishandling session credentials (`SEC-187`, `CWE-601`). Disabling redirects and strictly validating `base_url` eliminates that attack class at the transport layer.

---

## 2. Ingestion Dashboard, Idempotency & Live Polling (P11-2)

### Q2.1: How does the Ingestion Dashboard prevent duplicate AI processing when a clerk double-clicks Upload or drops the same file twice?

**Answer:**
Per `CLAUDE.md §16.6` (*idempotency by default*), `compute_upload_idempotency_key()` hashes `f"ap-ui-upload:{normalized_vendor}:" + file_bytes` with SHA-256 and attaches `Idempotency-Key: ui-<sha256[:48]>` to `POST /api/v1/invoices/upload`. When the identical file is re-submitted, FastAPI recognizes the Redis idempotency lock and returns **`200 OK`** with `deduplicated=True` and the original `invoice_id` without re-invoking Azure OpenAI. In the dashboard's tracked batch list, `IngestionDashboardController.submit_batch()` updates the existing row in place instead of appending a duplicate row.

### Q2.2: How do you prevent Streamlit live polling from turning into a self-inflicted DoS against FastAPI and Redis?

**Answer:**
We put four hard circuit breakers around `poll_batch_once()` (`SEC-194`, `CWE-400`/`CWE-770`):
1. **Terminal Row Skipping:** Only invoices in `{"UPLOADED", "EXTRACTING", "REVALIDATING"}` are polled; completed or failed rows generate zero requests.
2. **Bounded Rate & Volume:** Poll interval is clamped to `[1.0, 30.0]` seconds, requests per poll cycle are capped at `MAX_POLL_ITEMS_PER_CYCLE = 50`, and auto-polling halts automatically after `MAX_AUTO_POLL_CYCLES = 60` cycles.
3. **Immediate HTTP `429` Backoff:** On catching `APIRateLimitError`, the loop breaks immediately, preserves untouched rows, sets `should_continue_polling=False`, and surfaces a clean backoff banner.
4. **Scoped Reruns:** Uses Streamlit's `@st.fragment(run_every=safe_interval)` when available so only the status panel ticks instead of re-executing the entire page.

---

## 3. Split-Screen Review Workbench & Smart Diffs (P11-3)

### Q3.1: How does the Review Workbench avoid tripping the Phase 9 No-Op Edit Guard (`P9-4`) when a clerk only changes one field on an invoice with 10 header fields and 20 line items?

**Answer:**
`build_revalidate_request()` computes a **semantic client-side smart diff** against the original `InvoiceDetailResponse`:
- Text fields are NFC-normalized and trimmed; `Decimal` fields compare mathematically (`1000` == `1000.00`, `-0.00` == `0.00`); dates compare as ISO `date` objects.
- Untouched header fields and untouched line items are **completely omitted** from `InvoiceHeaderEdits` and `InvoiceLineEdit`—only genuinely modified fields are serialized to `POST /api/v1/invoices/{id}/revalidate`.
- If zero fields changed and neither `is_reverse_charge` nor `is_exempt` was enabled, the workbench raises a clean client-side validation message immediately without wasting an HTTP round-trip.

### Q3.2: Why doesn't the Left Pane document viewer fetch `blob_raw_url` directly from Azure Blob Storage?

**Answer:**
Two architectural & security reasons (`CLAUDE.md §4.2` & `SEC-195`):
1. The Streamlit UI container has **zero Azure Blob SDK imports and zero storage credentials**—Azure Blob WORM is private-endpoint-only behind the FastAPI tier.
2. Fetching arbitrary URLs stored in a database field from a web frontend is a classic **SSRF (`CWE-918`)** vector (e.g., `http://169.254.169.254/latest/meta-data/` or `file:///etc/passwd`). Instead, `extract_safe_document_url()` strictly validates the URI purely for read-only reference display, while `render_document_preview()` renders local/in-memory PDF/PNG/JPG bytes via PyMuPDF with strict `ALLOWED_PREVIEW_EXTENSIONS` (blocking TIFF per GAP-004 and SVG), 25 MB / 200-page / 4096px output caps, finite zoom `[0.5, 3.0]`, and encrypted PDF rejection.

---

## 4. Human Exception Queue & Safe Bulk Actions (P11-4)

### Q4.1: How did you make Bulk Actions safe so an AP Clerk or Finance Manager cannot accidentally bulk-approve fraudulent duplicates or tax-broken invoices?

**Answer:**
- **Fail-Closed Role Gate (`SEC-198`):** `can_bulk_approve_exceptions()` and `bulk_manager_approve()` require explicit `finance_manager` role (`ap_clerk`, `system_admin`, and `user_roles=None` all fail closed with `PermissionError`, and the **Bulk Manager Approve** button is completely hidden for non-managers).
- **Status Safety Allowlist:** Even for a `finance_manager`, `bulk_manager_approve()` checks every selected invoice against `MANAGER_APPROVABLE_STATUSES` (`VALIDATED`, `REQUIRES_REVIEW`, `REQUIRES_APPROVAL`, `REQUIRES_MANAGER_APPROVAL`) and safely routes `DUPLICATE_INVOICE`, `CREDIT_NOTE`, `FLAGGED_POTENTIAL_REVISION`, and `REJECTED_TAX_MISMATCH` into `skipped_ids` without calling `POST /approve`.
- **Bounded Blast Radius (`SEC-200`):** Bulk selection is capped at `MAX_BULK_SELECTION = 50` deduplicated, regex-validated invoice IDs with immediate HTTP `429` halt.

---

## 5. Revision Comparison & Fraud Controls (P11-5)

### Q5.1: What happens if someone compares two invoices that both have placeholder `vendor_id="UNKNOWN"`?

**Answer:**
During our P11-5 security audit (`SEC-201`), we caught a subtle vendor-spoofing bug: if `_is_same_vendor()` compared `vendor_id` first, two unmapped invoices both carrying `vendor_id="UNKNOWN"` (with completely different Tax IDs like `US-11` vs `DE-22`) would falsely evaluate `same_vendor = True`! We hardened `_is_same_vendor()` to validate authoritative `vendor_tax_id` equality first (explicitly rejecting `"UNKNOWN"` placeholders) and then verify `vendor_id` parity whenever non-placeholder IDs are present. Cross-vendor `CONFIRM_AUTHORIZED_REVISION` is hard-blocked with `ValueError`.

### Q5.2: Why doesn't "Confirm as Authorized Revision" mark the invoice `APPROVED_CLERK` immediately?

**Answer:**
Per `CLAUDE.md §16.1`, **no code path may ever mark an invoice `APPROVED_*` except `POST /api/v1/invoices/{id}/approve` after passing deterministic validation and spending-limit checks.** Confirming an authorized revision records the decision with a mandatory 5–1000 char audit comment and hands off to `/workbench/{revision_id}` (`recommended_status="REVALIDATING"`) so the revision goes through full arithmetic, tax, FX, and approval-threshold verification.

---

## 6. Immutable Audit Trail Viewer & PII-Safe Exports (P11-6)

### Q6.1: How do you guarantee the Audit Trail Viewer stays immutable and never leaks PII or executes Excel formulas when exported?

**Answer:**
1. **Structural Immutability (`SEC-205`):** The screen contains zero edit/delete actions, displays a 7-year WORM statutory retention banner, and an AST test in `test_ui_audit_viewer.py` explicitly asserts `node.attr != "data_editor"` on `src/ui/audit_viewer.py`.
2. **Multi-Layer PII Redaction (`SEC-204`):** `_is_sensitive_field()` catches both flat (`vendor_tax_id`, `iban`, `ssn`) and dotted (`invoice.iban`, `vendor.tax_id`) field names and replaces values with `[REDACTED_PII]`. Additionally, `_redact_inline_pii()` scans free-text comments for raw SSNs and IBANs, while `sanitize_display_text()` strips Bearer/JWT tokens.
3. **CSV Formula Defense (`CWE-1236`):** Every cell in `build_chronological_timeline_rows()`, `export_audit_trail_csv()`, and `export_audit_trail_json()` passes through `sanitize_display_text()`, prefixing leading `=`, `+`, `-`, `@`, `\t`, or `\r` with `'` so opening downloaded CSVs in Excel/Sheets cannot trigger formula execution.

---

## 7. Confidence Colour Coding & Role-Aware UI Policy (P11-7)

### Q7.1: Explain why the Approve button is *hidden* (not disabled) for `ap_clerk` on invoices > `\$10,000`, and how you ensure UI-backend parity.

**Answer:**
- Per `CLAUDE.md §12`, hiding the button completely avoids confusing clerks with dead controls and reinforces least privilege.
- `evaluate_invoice_ui_capabilities()` in `src/ui/theme_rbac.py` reads `HIGH_VALUE_THRESHOLD_USD` and `PO_VARIANCE_TOLERANCE_PERCENT` dynamically from `get_settings()` (never hardcoded!).
- For `ap_clerk`, `show_approve_button` is `False` (and `approve_hidden_reason` explains that Finance Manager sign-off is required) whenever:
  - `effective_usd > threshold_usd` (using conservative `max(total_amount, total_amount_usd)` on USD invoices so a stale lower `total_amount_usd` column can never bypass the gate — `SEC-207`!),
  - non-USD invoice lacks FX-converted `total_amount_usd` (fail-closed!),
  - PO variance exceeds `PO_VARIANCE_TOLERANCE_PERCENT`,
  - `total_amount < 0` (credit note), `confidence < 90%`, or `status != VALIDATED`.
- **Defense-in-Depth Parity:** `tests/integration/test_ui_confidence_colours_rbac_integration.py` proves against the real FastAPI app that for `sarah.clerk` on a `\$15,000` `VALIDATED` invoice, the UI hides Approve **and** a direct `client.approve_invoice()` call is rejected with HTTP **`403 Forbidden`** (`APIAuthorizationError`), while `michael.manager` sees the button and succeeds with `APPROVED_MANAGER`.

---

## 8. Real-World Pentest Stories & Security Threat Model Summary (`SEC-187`–`SEC-208`)

> **Interview Tip:** Hiring panels love hearing concrete vulnerabilities you caught *before* shipping. Mention these three Phase 11 catches:
> 1. **Stale `total_amount_usd` Clerk Cap Bypass (`SEC-207`):** Caught that if a USD invoice's `total_amount` was edited to `\$15,000` while `total_amount_usd` still read `\$500`, reading `total_amount_usd` first would expose the Approve button to an `ap_clerk`. Fixed with conservative `max(total_amount, total_amount_usd)` for USD invoices.
> 2. **Cross-Vendor `UNKNOWN` Placeholder Supersede (`SEC-201`):** Caught that comparing `vendor_id` before `vendor_tax_id` let two `UNKNOWN` vendors pass `same_vendor=True`. Fixed by anchoring on authoritative non-`UNKNOWN` `vendor_tax_id`.
> 3. **Shared-Kiosk Cross-User Session Leakage (`SEC-193`):** Caught that signing out or switching personas in Streamlit left `batch_items`, `workbench_invoice`, `exception_assignments`, `revision_pair`, and `audit_trail` inside `st.session_state`. Fixed with centralized `_clear_session_batch_state()` purging all 12 workflow keys on Sign Out and identity change.

| Vuln ID | Component | CWE | Severity | Core Mitigation |
|---|---|---|---|---|
| `SEC-187` | `api_client.py` | CWE-918 / CWE-601 | High | `validate_api_base_url()` + `follow_redirects=False` |
| `SEC-188` | `api_client.py` | CWE-22 / CWE-113 | High | Strict `invoice_id` allowlist regex + CRLF header rejection |
| `SEC-189` | `api_client.py` | CWE-400 / CWE-532 | Medium | Bearer redaction in `__repr__`/logs + 10 MB response cap |
| `SEC-190` | `api_client.py` | CWE-22 / CWE-400 | Medium | Upload filename traversal block + 25 MB cap + timeout `[0.1, 120]`s |
| `SEC-191` | `ingestion_dashboard.py` | CWE-79 / CWE-1236 / CWE-22 | High | Strip HTML & residual `<>`, neutralize CSV formulas, validate `/workbench/{id}` |
| `SEC-192` | `ingestion_dashboard.py` | CWE-400 / CWE-434 / CWE-451 | High | 50-file / 100 MB batch caps, 500-row session cap, GAP-004 TIFF & bidi block |
| `SEC-193` | `app.py` | CWE-200 / CWE-287 / CWE-384 | Medium | Cross-user session purge on Sign Out/switch + fail-closed `user_roles=[]` |
| `SEC-194` | `ingestion_dashboard.py` | CWE-400 / CWE-770 | Medium | `[1, 30]`s poll bounds, 50 items/cycle, 60 cycles max, HTTP 429 halt |
| `SEC-195` | `review_workbench.py` | CWE-918 / CWE-79 / CWE-400 | High | Safe URL filter (no auto-fetch), preview ext allowlist (no TIFF/SVG), finite zoom, 4096px cap |
| `SEC-196` | `review_workbench.py` | CWE-915 / CWE-285 / CWE-863 | High | Field allowlists, duplicate `line_number` rejection, resilient grid parsing, non-USD FX fail-closed |
| `SEC-197` | `review_workbench.py` | CWE-200 / CWE-384 / CWE-1236 | Medium | `mask_tax_id()`, CSV formula sanitization, workbench session purge |
| `SEC-198` | `exception_queue.py` | CWE-863 / CWE-285 / CWE-1236 | High | Fail-closed `finance_manager`-only bulk approve, status skip, alphanumeric-start assignee |
| `SEC-199` | `exception_queue.py` | CWE-79 / CWE-1236 / CWE-22 | High | Strict route allowlists (`/workbench/{id}`, `/revision/{id}`), XSS/CSV sanitization |
| `SEC-200` | `exception_queue.py` | CWE-400 / CWE-770 / CWE-384 | Medium | 50-item bulk cap, 1000-assignment cap, 429 halt, session purge |
| `SEC-201` | `revision_screen.py` | CWE-840 / CWE-345 | High | Authoritative `vendor_tax_id` check blocking `UNKNOWN` spoofing + currency swap alert |
| `SEC-202` | `revision_screen.py` | CWE-79 / CWE-1236 / CWE-22 | High | Sanitized header/line diffs, masked Tax ID, validated handoff routes |
| `SEC-203` | `revision_screen.py` | CWE-863 / CWE-384 / CWE-1333 | Medium | Fail-closed decision RBAC, 200-item history cap, 256-char linear suffix regex (anti-ReDoS) |
| `SEC-204` | `audit_viewer.py` | CWE-200 / CWE-532 / CWE-1236 | High | Flat/dotted sensitive-field masking, inline SSN/IBAN redaction, formula-safe CSV/JSON exports |
| `SEC-205` | `audit_viewer.py` | CWE-79 / CWE-285 / CWE-732 | High | AST-enforced zero `data_editor` & zero `unsafe_allow_html`, fail-closed 3-role RBAC |
| `SEC-206` | `audit_viewer.py` | CWE-22 / CWE-384 / CWE-400 | Medium | Export filename stem allowlist, `limit<=200`, Sign Out session purge |
| `SEC-207` | `theme_rbac.py` | CWE-863 / CWE-602 / CWE-285 | High | Exact `CANONICAL_ROLES`, conservative USD `max()`, fail-closed NaN/negative/FX/PO checks |
| `SEC-208` | `theme_rbac.py` | CWE-20 / CWE-79 | Medium | Fail-closed `[0, 100]` confidence bounds + full-directory `src/ui/*.py` AST layering & HTML audit |

