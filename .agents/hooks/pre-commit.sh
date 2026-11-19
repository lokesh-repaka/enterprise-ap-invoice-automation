#!/usr/bin/env bash
# .agents/hooks/pre-commit.sh
# Lightweight pre-commit lint/test gate for AP Invoice Automation.
# IMPORTANT: Only valid JSON must be emitted to stdout with exit code 0.

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT" 2>/dev/null || true

# 1. Guard: check if anything is staged. If nothing is staged, fast-allow.
if command -v git &>/dev/null; then
  STAGED=$(git diff --cached --name-only 2>/dev/null || true)
  if [ -z "$STAGED" ]; then
    printf '{"decision":"allow"}\n'
    exit 0
  fi
  if echo "$STAGED" | grep -qE '\.env$|\.db$|agent-calls\.jsonl'; then
    printf '{"decision":"deny","reason":"Blocked: attempted to stage .env, *.db, or agent-calls.jsonl. Remove from index first."}\n'
    exit 0
  fi
fi

# 2. Ruff lint (if ruff installed and src/ exists)
if command -v ruff &>/dev/null && [ -d "src" ]; then
  if ! ruff check src/ tests/ >/dev/null 2>&1; then
    ERR=$(ruff check src/ tests/ 2>&1 | tr '\n' ' ' | sed 's/"/\\"/g' | cut -c 1-200)
    printf '{"decision":"deny","reason":"Ruff lint failed: %s"}\n' "$ERR"
    exit 0
  fi
fi

# 3. Fast offline unit tests (if pytest + tests/unit exist)
if command -v pytest &>/dev/null && [ -d "tests/unit" ]; then
  if ! PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true pytest tests/unit/ >/dev/null 2>&1; then
    ERR=$(PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest tests/unit/ 2>&1 | grep -E "FAILED|ERROR" | tr '\n' ' ' | sed 's/"/\\"/g' | cut -c 1-200)
    printf '{"decision":"deny","reason":"Pytest failed: %s"}\n' "$ERR"
    exit 0
  fi
fi

printf '{"decision":"allow"}\n'
exit 0
