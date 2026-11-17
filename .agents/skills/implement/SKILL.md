---
name: implement
description: >-
  Invoke the implementer agent to execute an approved plan from docs/plans/.
  Always run /plan first. Implementer uses flash tier.
---

# /implement — Execute an Approved Plan

Use this skill to implement a feature that has an approved plan in `docs/plans/`.

## Prerequisite
An approved `docs/plans/PLAN-NNN-<slug>.md` must exist. If not, run `/plan` first.

## Steps

1. **Confirm the plan is approved** — open `docs/plans/PLAN-NNN-<slug>.md` and
   check the status header.

2. **Invoke the implementer agent** (flash tier):
   - Role: `implementer`
   - Brief: "Implement the plan in `docs/plans/PLAN-NNN-<slug>.md`. Read CLAUDE.md
     first. Run `pytest tests/unit/ -q` with `USE_MOCK_AOAI=true
     USE_FAKE_REDIS=true USE_LOCAL_SQLITE=true` before marking done."

3. **Wait for completion** — implementer will report:
   - Every file created or modified
   - Test results (pass/fail)
   - Any open issues

4. **Post-implementation** — run `/review` to check for security and layer
   violations before merging.

## Rules
- Implementer uses `flash` tier (never `pro`).
- Thresholds must come from `get_settings()` — the implementer is briefed on this.
- If implementer reports a test failure, invoke `test-engineer` to fix it.

