You have access to the project's root specification files: `CLAUDE.md` (authoritative single source of truth), `GEMINI.md` (workspace rules & layer contracts), and `TASKS.md` (development roadmap & branch mappings).

Go ahead and complete **P1-2 · Centralised settings (src/core/config.py) and JSON logging** as defined in `TASKS.md`.

---

### Execution Workflow:

**1. Pre-Conditions & Contract Verification:**
- Verify in `TASKS.md` that all predecessor tasks listed in the phase header are marked `Completed ✅`.
- Consult `CLAUDE.md` (architecture, domain models, non-negotiables, and layering rules).
- Identify the explicit requirements this task satisfies (`FR-01 to FR-14` and `N1 to N8`).
- Strict Rule: Rules first, model second. Python decides arithmetic, tax, and status transitions; the model only extracts.

**2. Branching & Workspace:**
- Work on the assigned branch/feature from `TASKS.md`: `feature/<branch-name>`.

**3. Test-Driven Development (TDD) & Offline Isolation:**
- Write unit/contract tests under `tests/` before or alongside implementation code.
- **Strict Offline Rule**: All tests must run with zero external network or Azure API calls:
  `USE_LOCAL_SQLITE=true`, `USE_FAKE_REDIS=true`, `USE_MOCK_AOAI=true`.
- Adhere strictly to the layer rules from `CLAUDE.md §4.2`:
  - `src/ui/` → REST calls via api_client only. Never call Azure or business rules directly.
  - `src/api/` → Routes, schemas, RBAC. No validation logic.
  - `src/services/` → Orchestrates repositories + extraction + rules.
  - `src/database/` → SQLAlchemy async. No LLM calls.
  - `src/extraction/` → Model Gateway, prompt assembly with `<invoice_text>`. No business rules.
  - `src/validation/` → Deterministic Python only. Never calls LLMs.
  - `src/storage/` → Blob WORM client. No business logic.
  - `src/core/` → Config, security, logging. Never imports extraction or validation.
- Run tests and verify they pass:
  `pytest -v tests/<target_path>`

**4. Security Audit & Guardrail Verification:**
- **Prompt Injection Defense**: All invoice content wrapped in `<invoice_text>...</invoice_text>`.
- **Zero Static Secrets**: All Azure auth via Entra ID Managed Identity. No connection strings or API keys in code or `.env`.
- **RBAC**: Enforce `require_role()` on every endpoint; verify clerk cannot approve > $10,000.
- **Audit Logs**: Ensure `AuditLogs` is append-only (no update/delete; no no-op logs where old == new).
- **Thresholds**: All tolerances and amounts from `get_settings()`, never hardcoded magic numbers.

**5. Pre-Commit Verification:**
- Run syntax and pre-commit checks:
  `bash .agents/hooks/pre-commit.sh`

**6. Housekeeping & Documentation:**
- Update `TASKS.md`:
  - Mark this sub-task status as `Completed ✅`.
  - Increment the completed count in the **Progress summary** table at the bottom of `TASKS.md`.
- Verify `.gitignore` ignores any `.env`, `*.db`, or local logs.