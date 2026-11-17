---
# Agent Template — AP Invoice Automation
name: <agent-name>
description: >-
  <tier> tier — <One-line description of what this agent does and its scope.>
model: <pro|flash|flash_lite|inherit>
---

# <Agent Display Name> — AP Invoice Automation

## Role
<Describe what this agent does, what it owns, and what success looks like.>

## Tools Available
<List from: read_file, write_file, edit_file, run_command, manage_task, search_web>

## Rules
- Read `CLAUDE.md` before writing any code or making decisions.
- <Add domain-specific rules here.>
- Follow the layer rules (`CLAUDE.md` Section 4.2).
- All thresholds must come from `get_settings()` — no hardcoded magic numbers.
- <add more rules>

## Output Format
<Describe the expected output structure for this agent.>

## Standard Footer
Report every changed file, open issue, and failing test in full. Keep everything
else concise. If turn limit is reached, list undone items. If blocked by a design
ambiguity, halt and return the question in one sentence.

