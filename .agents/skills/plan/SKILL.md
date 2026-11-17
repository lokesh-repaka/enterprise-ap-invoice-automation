---
name: plan
description: >-
  Invoke the planner agent to write a step-by-step implementation plan into
  docs/plans/ before any code is written. Use for any non-trivial feature.
---

# /plan — Generate an Implementation Plan

Use this skill whenever a feature or task requires changes to more than one
file, or touches the extraction/validation/approval pipeline.

## When to Use
- Starting a new TASKS.md phase (P1 through P14).
- Adding a new API endpoint.
- Changing validation rules, tax rates, or approval thresholds.
- Any change that touches the database schema.

## Steps

1. **Identify the task** — read the relevant row in `TASKS.md` and the
   corresponding FR in `CLAUDE.md` Section 3.

2. **Invoke the planner agent** (pro tier):
   - Role: `planner`
   - Brief: "Write an implementation plan for `<feature>`. Task ref: `<P#-#>`.
     Read CLAUDE.md, TASKS.md, and the relevant LLD section first. Output to
     `docs/plans/PLAN-NNN-<slug>.md`."

3. **Review the plan** — confirm it lists:
   - Affected files
   - Migration steps (if schema changes)
   - Test coverage targets with FR-XX references
   - Rollback procedure

4. **Approve** — only proceed to `/implement` after the plan is approved.

## Notes
- Plans live in `docs/plans/`. Never skip to implementation without a plan.
- The planner uses `pro` tier (gated by `agent_guard.py`).

