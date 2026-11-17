---
name: review
description: >-
  Invoke the code-reviewer agent to audit the latest git diff for security
  issues, layer violations, prompt injection gaps, and CLAUDE.md contract
  compliance.
---

# /review — Security and Architecture Review

Use this skill after every implementation before merging to `development`.

## Steps

1. **Invoke the code-reviewer agent** (flash tier):
   - Role: `code-reviewer`
   - Brief: "Review the latest git diff. Check all 6 items in your checklist:
     layer violations, prompt injection, hardcoded thresholds, RBAC, audit log
     safety, secrets. Report findings as PASS/FAIL per checklist item."

2. **Review the report** — code-reviewer outputs a PASS/FAIL per category.

3. **If any FAIL** — invoke `implementer` with the specific fix required.

4. **Final check** — run:
   ```bash
   git diff HEAD --stat
   python -m json.tool .agents/hooks.json  # validate hooks are still valid JSON
   ```

## Checklist Summary
| Item | Trigger |
|------|---------|
| Layer violations | Any import across layer boundaries |
| Prompt injection | Missing `<invoice_text>` delimiters |
| Hardcoded thresholds | Magic numbers 10000, 0.05, 0.02, 0.90, 0.80 |
| RBAC | Missing `require_role()` on FastAPI routes |
| Audit append-only | UPDATE/DELETE on AuditLogs table |
| Secrets | Static strings, API keys, `.env` values in code |

