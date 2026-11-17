---
name: cost-report
description: >-
  Reads .agents/agent-calls.jsonl and summarizes subagent invocations, model
  tier usage, and blocked calls. Use to audit agent cost and guard effectiveness.
---

# /cost-report — Agent Usage Audit

Use this skill to audit how many subagent calls have been made, which model
tiers were used, and how many were blocked by `agent_guard.py`.

## Steps

1. **Read `.agents/agent-calls.jsonl`** — each line is one subagent invocation.

2. **Summarise** — count:
   - Total invocations
   - Breakdown by model tier (`pro`, `flash`, `flash_lite`, `inherit`)
   - Breakdown by role
   - Blocked calls (where `blocked: true`) with reason

3. **Report format**:
   ```
   AGENT USAGE REPORT — <date>
   ─────────────────────────────
   Total invocations: N
   
   By tier:
     pro          :  N (N blocked)
     flash        :  N (N blocked)
     flash_lite   :  N (N blocked)
   
   By role:
     planner      :  N
     implementer  :  N
     ...
   
   Blocked calls (N):
     <ts> role=<role> model=<model> — <prompt_preview>
   
   RECOMMENDATION: <one-line cost optimization if applicable>
   ```

## Notes
- If `agent-calls.jsonl` does not exist yet, report "No agent calls logged yet."
- This skill does not invoke any subagent — it reads the log file directly.
- Use this after each sprint to verify the guard is working and costs are on
  track for the $36,000 fixed-fee engagement.

