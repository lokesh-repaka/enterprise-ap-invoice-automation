# PLAN-NNN: <Feature Title>

**TASKS.md ref:** P<phase>-<task> (e.g., P1-1)  
**Status:** DRAFT | APPROVED | COMPLETED  
**Author:** planner (pro tier)  
**Date:** YYYY-MM-DD  
**Target Milestone:** M1 | M2 | M3 | M4  

---

## 1. Objective & Scope
Briefly summarize what is being built and which Functional Requirement(s) (FR-01 to FR-14) or Non-Functional Requirement(s) (N1 to N8) are addressed.

## 2. Affected Files & Layers
List every file to be created, modified, or deleted, respecting `CLAUDE.md` Section 4.2 layering rules.
- **Created:**
  - `src/...`
  - `tests/...`
- **Modified:**
  - `...`
- **Unchanged / Protected:**
  - (Confirm no boundary crossings)

## 3. Database / Schema Changes
- **Migration Required:** Yes / No
- **Tables affected:** (e.g., `dbo.Invoices`, `dbo.Vendors`)
- **DDL script:** `src/database/migrations/000N_<name>.sql` (if applicable)

## 4. Step-by-Step Implementation Sequence
1. Step 1 description (e.g., Pydantic schema or database model)
2. Step 2 description (e.g., repository CRUD or rule function)
3. Step 3 description (e.g., API route or integration point)
4. Step 4 description (e.g., unit tests mapping to FR-XX)

## 5. Test Coverage Specifications
- **Unit Tests:**
  - `tests/unit/<test_file>.py::<test_func>` — `# Tests: FR-XX`
- **Integration Tests:**
  - `tests/integration/<test_file>.py::<test_func>`
- **Offline flags required:**
  - `USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true`

## 6. Security & Guardrails Checklist
- [ ] No hardcoded thresholds (uses `get_settings()`)
- [ ] Input wrapped in `<invoice_text>...</invoice_text>` (if LLM call)
- [ ] `response_format={"type": "json_object"}` with Pydantic validation (if LLM call)
- [ ] RBAC enforced via `require_role()` (if API route)
- [ ] Audit log append-only maintained
- [ ] Zero static secrets / Managed Identity used

## 7. Rollback Procedure
Specific steps to revert if tests fail or unexpected regressions occur.

