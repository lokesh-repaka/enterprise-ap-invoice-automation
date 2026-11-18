"""Unit tests for GitHub Actions CI pipeline configuration."""

from pathlib import Path

import yaml


def test_ci_workflow_file_exists() -> None:
    """Verify that .github/workflows/ci.yml exists."""
    workflow_path = Path(".github/workflows/ci.yml")
    assert workflow_path.exists(), f"Workflow file not found at {workflow_path.resolve()}"
    assert workflow_path.is_file(), "Workflow path must be a regular file"


def test_ci_workflow_valid_yaml() -> None:
    """Verify that .github/workflows/ci.yml is valid YAML and has required root keys."""
    workflow_path = Path(".github/workflows/ci.yml")
    with workflow_path.open() as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict), "Workflow YAML must parse as a dictionary"
    assert "name" in data, "Workflow must declare a 'name'"
    assert "on" in data or True in data, "Workflow must declare triggers ('on')"
    assert "jobs" in data, "Workflow must declare 'jobs'"


def test_ci_workflow_triggers() -> None:
    """Verify triggers on push and PR to development and main branches."""
    workflow_path = Path(".github/workflows/ci.yml")
    with workflow_path.open() as f:
        data = yaml.safe_load(f)

    triggers = data.get("on") or data.get(True)  # in case YAML parses 'on' as boolean True
    assert isinstance(triggers, dict), "Triggers must be a dictionary"

    assert "push" in triggers, "Workflow must trigger on 'push'"
    assert "pull_request" in triggers, "Workflow must trigger on 'pull_request'"

    push_branches = triggers["push"].get("branches", [])
    pr_branches = triggers["pull_request"].get("branches", [])

    assert "development" in push_branches
    assert "main" in push_branches
    assert "development" in pr_branches
    assert "main" in pr_branches


def test_ci_workflow_jobs_and_offline_isolation() -> None:
    """Verify required CI jobs and strict offline isolation environment variables."""
    workflow_path = Path(".github/workflows/ci.yml")
    with workflow_path.open() as f:
        data = yaml.safe_load(f)

    jobs = data.get("jobs", {})
    assert "lint-and-security" in jobs, "Must have a lint-and-security job"
    assert "offline-unit-tests" in jobs, "Must have an offline-unit-tests job"
    assert "build-package" in jobs, "Must have a build-package job"

    # Check build-package dependencies
    build_job = jobs["build-package"]
    assert "needs" in build_job
    assert "lint-and-security" in build_job["needs"]
    assert "offline-unit-tests" in build_job["needs"]

    # Check offline test environment variables
    test_job = jobs["offline-unit-tests"]
    steps = test_job.get("steps", [])
    test_step = next(
        (s for s in steps if "env" in s and "USE_LOCAL_SQLITE" in s["env"]),
        None,
    )
    assert test_step is not None, "Test job must define offline isolation env vars"

    env = test_step["env"]
    assert env.get("USE_LOCAL_SQLITE") == "true"
    assert env.get("USE_FAKE_REDIS") == "true"
    assert env.get("USE_MOCK_AOAI") == "true"
    assert env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1"


def test_ci_workflow_evaluation_threshold_gate_and_least_privilege() -> None:
    """# Tests: FR-14, SEC-227 — Verify evaluation-threshold-gates blocks build-package with least-privilege permissions."""
    workflow_path = Path(".github/workflows/ci.yml")
    with workflow_path.open() as f:
        data = yaml.safe_load(f)

    # Least-privilege GITHUB_TOKEN permissions (SEC-227, CWE-250 / CWE-732)
    assert data.get("permissions") == {"contents": "read"}

    jobs = data.get("jobs", {})
    assert "evaluation-threshold-gates" in jobs, "Must have an evaluation-threshold-gates job"
    assert "evaluation-threshold-gates" in jobs["build-package"]["needs"]

    for job_name, job_cfg in jobs.items():
        timeout = job_cfg.get("timeout-minutes")
        assert isinstance(timeout, int) and 1 <= timeout <= 30, (
            f"CI job '{job_name}' must set bounded timeout-minutes (got {timeout!r})"
        )

    eval_job = jobs["evaluation-threshold-gates"]
    eval_step = next(
        (s for s in eval_job.get("steps", []) if "tests/evaluation/" in str(s.get("run", ""))),
        None,
    )
    assert eval_step is not None, (
        "evaluation-threshold-gates job must run pytest on tests/evaluation/"
    )
    eval_env = eval_step.get("env", {})
    assert eval_env.get("APP_ENV") == "test"
    assert eval_env.get("USE_LOCAL_SQLITE") == "true"
    assert eval_env.get("USE_FAKE_REDIS") == "true"
    assert eval_env.get("USE_MOCK_AOAI") == "true"
    assert eval_env.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") == "1"
