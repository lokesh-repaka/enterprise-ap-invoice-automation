# Phase 2: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, architectural, database, concurrency, and security interview preparation covering **Phase 2 (Persistence and Vendor Master — P2-1 through P2-5)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, Data/Persistence Architect, AI Solution Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [SQLAlchemy 2.0 Async ORM & Schema Modeling (P2-1)](#1-sqlalchemy-20-async-orm--schema-modeling-p2-1)
2. [Schema DDL & Alembic Migrations (P2-2)](#2-schema-ddl--alembic-migrations-p2-2)
3. [Async Repository Pattern & Connection Pooling (P2-3)](#3-async-repository-pattern--connection-pooling-p2-3)
4. [Idempotent Seeding & Reference Data Integrity (P2-4)](#4-idempotent-seeding--reference-data-integrity-p2-4)
5. [Duplicate Detection, Partial Unique Indexes & Race Conditions (P2-5)](#5-duplicate-detection-partial-unique-indexes--race-conditions-p2-5)
6. [Security Audit, Threat Modeling & Real-World Debugging](#6-security-audit-threat-modeling--real-world-debugging)

---

## 1. SQLAlchemy 2.0 Async ORM & Schema Modeling (P2-1)

### Q1.1: Why did you map all monetary fields as `Numeric(18, 2)` / `Decimal` instead of `FLOAT`?

**Answer:**
IEEE 754 binary floating-point numbers (`float` / `DOUBLE`) cannot accurately represent base-10 fractions like `0.1` or `0.2` (for example, `0.1 + 0.2 == 0.30000000000000004`). In an Accounts Payable platform:
- Summing 50 invoice line items and validating `line_total == quantity * unit_price ± 0.02` or tax rates (`19% MwSt`, `21% IVA`, `8.25% Sales Tax`) with binary floats causes **cumulative rounding drift (CWE-682)**, triggering false-positive rejections or silent penny discrepancies.
- Using fixed-point SQL `Numeric(18, 2)` for totals, `Numeric(18, 4)` for quantities/unit prices, `Numeric(5, 4)` for tax rates, and `Numeric(18, 6)` for FX rates—bound to Python's `decimal.Decimal`—guarantees exact base-10 financial arithmetic across SQLite and Azure SQL.

---

### Q1.2: Why use `String(36)` UUID primary keys instead of auto-incrementing integers or native database UUID types?

**Answer:**
1. **Security (Anti-Enumeration):** Auto-incrementing integers (`/api/v1/invoices/1001`, `/1002`) expose total invoice volume and allow attackers to probe predictable IDs (IDOR risk). Random UUID v4 strings (`uuid.uuid4()`) eliminate sequential guessing.
2. **Dual-Dialect Portability:** SQLite has no native `UNIQUEIDENTIFIER` binary type, whereas Azure SQL uses `UNIQUEIDENTIFIER`. Representing UUIDs as canonical `String(36)` guarantees identical behavior, serialization, and testing semantics across local SQLite and production Azure SQL without dialect-specific binary encoding issues.

---

### Q1.3: Why did you override `Vendor.__repr__()` to mask `vendor_tax_id`?

**Answer:**
Even though Phase 1 already masks Tax IDs/SSNs at the `JSONFormatter` level, security requires **Defense-in-Depth**:
- During debugging, exception tracebacks (`Sentry`, `pytest` failure dumps, REPL inspection), or third-party library logging, Python calls `repr(obj)`.
- Overriding `Vendor.__repr__()` to output `tax_id='***-**-6789'` ensures raw supplier Tax IDs never leak via object stringification (mitigating **CWE-200 / SEC-004**).

---

## 2. Schema DDL & Alembic Migrations (P2-2)

### Q2.1: Why maintain BOTH `src/database/schema.sql` AND Alembic migrations?

**Answer:**
They serve two complementary enterprise governance purposes:
1. **`src/database/schema.sql` (Authoritative Point-in-Time Snapshot):** Enterprise DBAs and security review boards audit a single readable DDL script to verify table structures, column precision, foreign keys, and indexing strategies before production sign-off. It also enables rapid single-command database bootstrapping in CI or SQLite verification.
2. **Alembic Migrations (`0001`, `0002`, ...):** Production databases cannot be dropped and recreated on every release. Alembic tracks applied schema state in `alembic_version`, executing incremental, transactional, **reversible** (`upgrade()` / `downgrade()`) schema transitions with zero data loss.

---

### Q2.2: Why did you create migration `0002_composite_hash_unique_index.py` instead of editing `0001_initial_baseline.py`?

**Answer:**
This is a fundamental rule of production database engineering (explicitly documented in `CLAUDE.md §6`): **Never edit a migration that has already been merged or applied.**
- If staging or another developer's environment has already applied revision `0001`, editing `0001` causes silent schema drift—Alembic sees `alembic_version == '0001'` and skips it completely, leaving production missing the new index!
- Adding an additive migration `0002` with `down_revision = "0001"` guarantees every environment transitions deterministically from `0001` $\to$ `0002` and can roll back cleanly to `0001`.

---

### Q2.3: How does `env.py` avoid storing plaintext production passwords in `alembic.ini` while supporting async drivers?

**Answer:**
- `alembic.ini` stores only a safe local fallback (`sqlite:///data/enterprise.db`)—never a production password (**CWE-798 / SEC-008**).
- Inside `src/database/migrations/env.py`, `get_url()` dynamically reads `get_settings().database_url` (which uses keyless Microsoft Entra ID Managed Identity `Authentication=ActiveDirectoryMsi` in Azure SQL).
- Because Alembic's standard migration engine runs synchronously, `get_url()` automatically normalizes async driver schemes (`+aiosqlite` $\to$ `""`, `+aioodbc` $\to$ `+pyodbc`) and runs with `pool.NullPool` so migration jobs release connections immediately on completion.

---

## 3. Async Repository Pattern & Connection Pooling (P2-3)

### Q3.1: Why implement a dedicated Repository Layer instead of querying SQLAlchemy directly inside FastAPI routes or services?

**Answer:**
1. **Strict Layer Separation (`CLAUDE.md §4.2`):** Services orchestrate business workflows; they should not leak ORM query details, `selectinload` strategies, or session commits.
2. **Centralized Security Invariants:** Security controls live in one auditable place:
   - Explicit `ALLOWED_UPDATE_FIELDS` allowlists preventing **Mass Assignment (CWE-915)**.
   - `_clamp_limit()` clamping pagination to `[1, 500]` preventing **Unbounded Result-Set Memory DoS (CWE-770)**.
   - 100% parameterized SQLAlchemy 2.0 expressions preventing **SQL Injection (CWE-89)**.
3. **Interface-Level Immutability:** `AuditLogRepository` physically omits `update()` and `delete()` methods, enforcing `CLAUDE.md §6`'s append-only audit requirement at the Python API contract level.

---

### Q3.2: Explain the positional-only `/` parameter trick you used in `VendorRepository.update()` and `InvoiceRepository.update_fields()`.

**Answer:**
Consider a method defined as:
```python
async def update(self, vendor_tax_id: str, **fields: Any) -> Vendor | None:
```
If an API layer or caller unpacks a payload containing the primary key (`await repo.update("US-12-3456789", **{"vendor_tax_id": "HACKED"})`), Python raises an unhandled:
`TypeError: VendorRepository.update() got multiple values for argument 'vendor_tax_id'`
**before** our `_validate_update_fields()` security check even executes!

By declaring the identifier parameter **positional-only** using PEP 570 syntax (`/`):
```python
async def update(self, vendor_tax_id: str, /, **fields: Any) -> Vendor | None:
```
Python binds the first positional argument cleanly to `vendor_tax_id` while routing **any** keyword key (including `vendor_tax_id`) into `fields`, where `_validate_update_fields()` deterministically rejects it with `ValueError("Disallowed update fields: ['vendor_tax_id']")`.

---

### Q3.3: Why does `ExchangeRateRepository` implement `get_latest_rate_on_or_before(invoice_date)` instead of an exact date lookup?

**Answer:**
Two real-world financial rules (`CLAUDE.md §6`):
1. **Accounting Rule:** Foreign-currency invoices must always be converted to USD using the **invoice date**, never the upload date (otherwise delaying an upload changes whether an invoice exceeds the \$10,000 manager approval threshold!).
2. **Banking Calendar Reality:** The European Central Bank (ECB) does not publish FX feeds on Saturdays, Sundays, or European bank holidays. If a German invoice is dated Sunday, February 15, an exact equality query (`rate_date == '2026-02-15'`) returns `None` and crashes validation. Querying `rate_date <= target_date ORDER BY rate_date DESC LIMIT 1` cleanly resolves to Friday's closing ECB rate.

---

### Q3.4: Why use `StaticPool` for in-memory SQLite in `session.py`, and `pool_pre_ping=True` for Azure SQL?

**Answer:**
- **In-Memory SQLite (`StaticPool`):** With standard pooling, opening a second async connection to `sqlite+aiosqlite:///:memory:` creates a brand-new, empty in-memory database! `StaticPool` reuses the exact same underlying SQLite connection across multiple sessions (`session_a`, `session_b`), allowing realistic multi-session concurrency and race-condition tests in memory.
- **Azure SQL Serverless (`pool_pre_ping=True`, `pool_size=20`, `max_overflow=10`):** Azure SQL Serverless auto-pauses during idle periods to save cost. Without `pool_pre_ping=True`, the first request after auto-resume grabs a stale TCP socket and fails with a 500 error. `pool_pre_ping` issues a lightweight liveness check before handing a connection to a coroutine, transparently replacing dead sockets.

---

## 4. Idempotent Seeding & Reference Data Integrity (P2-4)

### Q4.1: Why must database seed scripts be idempotent, and how did you design `src/database/seed.py` for idempotency?

**Answer:**
In cloud-native deployments (Azure Container Apps / Kubernetes), startup init jobs may retry automatically on transient timeouts or execute on every deployment rollout. A non-idempotent seed script crashes on run #2 with `IntegrityError: UNIQUE constraint failed`.
- **`seed_vendors()`** checks `get_by_tax_id()` for each of the 15 vendors: inserts if missing, updates mutable attributes if already present, and tracks exact `{"inserted", "updated", "total"}` counts.
- **`seed_exchange_rates()`** calls `ExchangeRateRepository.upsert()`, updating the existing `(rate_date, from_currency, to_currency)` row or inserting a fresh one.
- **`src/database/seed.sql`** uses `INSERT OR IGNORE` so executing the SQL script repeatedly leaves exactly 15 vendors and 3 FX rates with zero errors.

---

### Q4.2: What security controls did you add to the seed script?

**Answer:**
1. **Path Traversal Guard (CWE-22 / SEC-015):** `_resolve_safe_json_path()` resolves both `sample_data_dir` and the target JSON path and asserts `target.is_relative_to(base_dir)`, blocking escapes like `../etc/passwd`.
2. **Financial Reference Data Validation (CWE-20 / SEC-016):** Rejects malformed JSON with `StandardTaxRate` outside `[0.0, 1.0]`, non-positive `ExchangeRate <= 0`, or non-3-letter ISO currency codes before touching the database.
3. **Zero PII in Seed Logs (CWE-532 / SEC-017):** CLI output logs only aggregate counts (`15 vendors, 3 exchange rates`), never printing raw supplier Tax IDs.

---

## 5. Duplicate Detection, Partial Unique Indexes & Race Conditions (P2-5)

### Q5.1: Why use a **partial (filtered) unique index** on `composite_hash` instead of a standard `UNIQUE` constraint?

**Answer:**
A standard `UNIQUE (composite_hash)` constraint causes a critical business bug:
- Suppose a clerk uploads an invoice with a bad scan, marks it `VOID` (or the system flags an erroneous submission as `REJECTED_DUPLICATE`), and then the vendor sends a clean copy of that exact invoice.
- A standard `UNIQUE` constraint would **permanently block** the legitimate resubmission because the `VOID` row still holds that `composite_hash` in the table!
- Our **partial unique index**:
  ```sql
  CREATE UNIQUE INDEX UX_invoices_composite_hash
  ON invoices (composite_hash)
  WHERE status NOT IN ('REJECTED_DUPLICATE', 'VOID');
  ```
  enforces strict uniqueness across all *active* invoices while transparently allowing resubmissions after `VOID` or `REJECTED_DUPLICATE`—and works natively on **both** SQLite 3.8+ (`sqlite_where`) and Azure SQL Server (`mssql_where`).

---

### Q5.2: How does `InvoiceRepository.upsert_duplicate_safe()` defeat concurrent double-payment race conditions (CWE-362)?

**Answer:**
Application-only duplicate checks suffer from a classic **TOCTOU (Time-of-Check to Time-of-Use)** race condition:
- Worker A and Worker B receive the identical invoice simultaneously.
- Both run `SELECT ... WHERE composite_hash = H` and both see `None`.
- Both proceed to `INSERT`. Without a database constraint, **both succeed**, creating two active invoices and risking a double payment!

Our defense combines **database-level serialization** with **graceful ORM recovery**:
1. Canonical `compute_composite_hash()` strips whitespace and quantizes `total_amount` to `Decimal("0.01")` before SHA-256 hashing—blocking formatting evasion (`"INV-1 "` or `"100.0"` vs `"100.00"`).
2. Fast-path `get_by_composite_hash()` catches sequential duplicates cleanly without triggering exceptions.
3. On a concurrent race, `UX_invoices_composite_hash` guarantees **exactly one** worker commits; the losing worker catches `sqlalchemy.exc.IntegrityError`, executes `await self._session.rollback()`, re-fetches the winning active invoice via `get_by_composite_hash()`, and returns `(winner, True)`.
4. **Error Safety (CWE-755 / SEC-020):** If re-fetching returns `None`, the `IntegrityError` was caused by a genuine non-duplicate failure (such as a missing `vendor_tax_id` foreign key), so `upsert_duplicate_safe()` explicitly **re-raises** the error instead of swallowing it.

---

## 6. Security Audit, Threat Modeling & Real-World Debugging

### Q6.1: What real CI/CD bug did you hit during Phase 2, and how did you diagnose and fix it?

**Answer:**
When opening PR #1 (`P2-1`), all 31 unit tests passed locally on macOS, but GitHub Actions CI (Ubuntu 22.04 + Python 3.11) failed in `Offline Unit Tests` with:
`ModuleNotFoundError: No module named 'greenlet'` inside `sqlalchemy/util/concurrency.py`.

**Root Cause:** SQLAlchemy 2.0's `sqlalchemy.ext.asyncio` requires `greenlet` as an optional extra (`sqlalchemy[asyncio]`), which happened to be globally installed on my Mac but was absent in a fresh Linux runner when `pyproject.toml` listed only `"sqlalchemy>=2.0.28"`.

**Fix:** Added `"greenlet>=3.0.0"` (and later `"alembic>=1.13.0"`) explicitly to `pyproject.toml` `dependencies` and applied `ruff format` across all 24 pre-existing files so all 3 CI stages (`Lint`, `Offline Unit Tests`, `Build Wheel`) turned green.

---

### Q6.2: Summarize the top security vulnerabilities threat-modeled and mitigated in Phase 2.

| CWE | Vulnerability | Mitigation Implemented in Phase 2 |
|---|---|---|
| **CWE-89** | SQL Injection | 100% parameterized SQLAlchemy 2.0 ORM queries; zero raw SQL string interpolation. |
| **CWE-915** | Mass Assignment / PK Tampering | `ALLOWED_UPDATE_FIELDS` frozensets + positional-only `/` ID parameters on every `update` method. |
| **CWE-284** | Audit Trail Tampering | `AuditLogRepository` physically omits `update`/`delete` and blocks no-op `EDIT` logs. |
| **CWE-362** | TOCTOU Double-Payment Race | Partial unique index `UX_invoices_composite_hash` + `IntegrityError` rollback recovery. |
| **CWE-682** | Financial Float Precision Loss | Fixed-point `Numeric` SQL columns bound strictly to Python `Decimal`. |
| **CWE-770** | Unbounded Pagination Memory DoS | `_clamp_limit()` bounds all list queries to `[1, 500]`. |
| **CWE-22** | Path Traversal in Seeding | `_resolve_safe_json_path()` enforces strict containment within `sample_data_dir`. |
| **CWE-20** | Poisoned Reference Data | Strict validation on tax rate bounds `[0, 1]`, positive FX rates, and ISO-3 currencies. |
| **CWE-200** | PII Exposure in Object Reprs | Masked `Vendor.__repr__` (`***-**-XXXX`) + aggregate-only seed CLI logs. |

