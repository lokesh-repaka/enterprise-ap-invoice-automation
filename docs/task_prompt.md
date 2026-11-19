You have access to the project's authoritative documentation: `docs/TASKS.md`, `docs/CLAUDE.md`, `docs/SKILLS.md`, and `docs/MEMORY.md`.

Go ahead and complete **<TASK_ID> · <TASK_TITLE>**, as defined in `docs/TASKS.md`.

---

### Dual-Persona Execution Workflow (Author + Senior Code Reviewer)

This workflow incorporates the official **roadmap.sh Code Review Standard**, enforcing a rigorous separation between **Author (Implementation)** and **Reviewer (Quality & Security Gate)** before any code is merged.

---

### 1. Requirements & Context Verification (Before Development)
* **Definition of Done (DoD):** Review relevant user stories, acceptance criteria, and DoD in `TASKS.md` and `CLAUDE.md`. Ensure expectations are unambiguous before touching code.
* **Architecture & Layer Invariants:** Verify which architectural layers and contracts this task touches. Do not invent requirements or duplicate existing modules.
* **Pre-condition Check:** Ensure all predecessor tasks in `TASKS.md` are marked `Completed ✅`.
* **Branching:** Create and switch to the assigned feature branch from `TASKS.md` off `development`:
  ```bash
  git checkout development && git pull origin development
  git checkout -b feature/<branch-name>
  ```

---

### 2. Test-Driven Development (TDD) (Author Phase)
* **Failing Test First:** Write comprehensive unit/integration test cases under `tests/` before implementing code.
* **Strict Offline Isolation:** All tests must run with zero external network or Azure API calls:
  `USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true`
* **Confirm Expected Failure:** Run tests first to verify they fail for the expected reason:
  ```bash
  uv run pytest tests/<target_path> -v
  ```
* **Minimal Implementation:** Write clean, minimal, production-grade code adhering strictly to the layer rules in `CLAUDE.md`.
* **Verify Green:** Re-run pytest to verify all tests pass:
  ```bash
  uv run pytest tests/<target_path> -v
  ```

---

### 3. Post-Development Self-Review (Author Phase)
*Before handing off code for review, the Author must perform self-inspection on the git diff:*
* **Diff Audit:** Run `git diff` and verify every changed line is intentional, complete, and necessary.
* **Hygiene Check:** Confirm zero dead code, no leftover debug `print()` statements, and no hardcoded magic numbers or credentials.
* **Automated Code Quality:** Execute local linters and type checkers as the baseline authority:
  ```bash
  uv run ruff check src/ tests/
  uv run ruff format --check src/ tests/
  ```

---

### 4. Rigorous Code Review & Adversarial Audit (Reviewer Persona)
*Adopt the persona of an objective **Senior Staff Software Architect & Lead Security Reviewer**. Conduct a thorough, structured audit of the git diff using the roadmap.sh review criteria:*

#### A. Review Dimensions:
1. **Architectural & Layering Integrity:**
   - Does the change strictly respect the project's boundaries (e.g. UI never calls DB directly, validation engine never calls LLMs, models never perform raw math)?
   - Does it stay consistent with existing system design patterns and ADRs?
2. **Logic, Correctness & Edge Cases:**
   - Are null values, empty collections, division by zero, floating-point rounding, and timeouts handled gracefully?
   - Are error exceptions caught specifically rather than swallowed blindly?
3. **Test Quality & Completeness:**
   - Do tests cover boundary conditions and failure paths, or just the happy path?
   - Are assertions meaningful and verifiable?
4. **Performance & Scalability:**
   - Are there N+1 database queries, unclosed file/socket handles, or memory leaks?
   - Are async operations non-blocking?
5. **Security & Penetration Audit (CWE / Threat Modeling):**
   - Check for injection vulnerabilities (Prompt injection, SQLi, command injection).
   - Verify delimiter wrapping (e.g., `<invoice_text>`), keyless identity usage, and RBAC permission checks.

#### B. Review Output Format:
Emit a structured review scorecard with prioritized, actionable feedback:
* **`[BLOCKING]`**: Architecture violations, security vulnerabilities, edge-case bugs, or missing tests. *(Must be resolved before merge)*
* **`[WARNING]`**: Sub-optimal performance, confusing naming, or high cognitive complexity. *(Must be addressed or justified)*
* **`[NIT]`**: Minor style refinements or documentation wording. *(Non-blocking)*

---

### 5. Review Remediation & Verification Loop (Author Phase)
* **Address Findings:** Resolve all `[BLOCKING]` and `[WARNING]` issues raised during the review.
* **Explain Fixes:** Document the specific code adjustments made in response to each review item.
* **Zero Regressions:** Re-run the full unit test suite and linters to verify zero regressions:
  ```bash
  uv run ruff check src/ tests/
  uv run pytest tests/ -v
  ```

---

### 6. Housekeeping & Documentation
* **Test Ledger:** Update `docs/TEST_CASES.xlsx` with any new test cases, IDs, and pass statuses.
* **Security Ledger:** Update `docs/SECURITY_VULNERABILITIES.xlsx` with any audited findings, severity ratings, and remediation notes.
* **Git Hygiene:** Update `.gitignore` if any new tool, cache, or artifact files were generated.
* **Roadmap Progress:** In `docs/TASKS.md`, mark the task as `Completed ✅` and increment the completed count in the progress summary table.
* **Honest Memory:** In `docs/MEMORY.md`, record the verified test counts and status under Honest Status.

---

### 7. GitHub PR & Terminal Merge (`gh`)
* **Atomic Commit:** Stage and commit all changes using standard conventional commit messages:
  ```bash
  git add . && git commit -m "feat(<scope>): <concise description>"
  git push origin feature/<branch-name>
  ```
* **Create PR:** Open a Pull Request targeting `base: development` with the code review summary:
  ```bash
  gh pr create --base development --title "feat(<scope>): <title>" --body "<summary_and_review_scorecard>"
  ```
* **Verify CI Status:** Wait for all GitHub Actions CI checks to pass:
  ```bash
  gh pr checks
  ```
* **Terminal Merge:** Merge cleanly via terminal and delete the remote branch:
  ```bash
  gh pr merge --merge --delete-branch
  ```
* **Local Sync:** Switch back to `development` and pull the latest merged state:
  ```bash
  git checkout development && git pull origin development
  ```
