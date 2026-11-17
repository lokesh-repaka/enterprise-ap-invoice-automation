---
name: test
description: >-
  Invoke the test-engineer agent to write or run targeted offline pytest suites.
  All tests run with USE_MOCK_AOAI=true, USE_FAKE_REDIS=true, USE_LOCAL_SQLITE=true.
---

# /test — Write or Run Targeted Tests

Use this skill to add tests for a new feature or to debug failing tests.

## Steps

1. **Specify the target** — identify the FR, file, or TASKS.md phase to test.

2. **Invoke the test-engineer agent** (flash tier):
   - Role: `test-engineer`
   - Brief: "Write/run tests for `<target>`. Map each test to FR-XX with a
     `# Tests: FR-XX` comment. Run with `USE_MOCK_AOAI=true USE_FAKE_REDIS=true
     USE_LOCAL_SQLITE=true`. Report pass/fail counts and any failures."

3. **Review results** — test-engineer reports:
   - Tests added (file + function names)
   - Pass/fail summary
   - Any FR gaps (FRs without coverage)

4. **Triage failures** — if tests fail, invoke `log-triage` to summarize the
   output, then `implementer` to fix.

## Useful pytest commands
```bash
# Fast offline unit tests
USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true pytest tests/unit/ -v

# Integration tests (mocked Azure)
USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true pytest tests/integration/ -v

# Full evaluation (slow — run before milestone sign-off only)
USE_LOCAL_SQLITE=true USE_FAKE_REDIS=true USE_MOCK_AOAI=true pytest tests/evaluation/ -v
```

