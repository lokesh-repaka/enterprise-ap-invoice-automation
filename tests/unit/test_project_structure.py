"""
Unit tests for Project Structure and Environment Contract.

Tests: N1, N8, FR-01
"""

import tomllib
from pathlib import Path


def test_layer_directories_exist():
    """Verify that all architectural layers specified in CLAUDE.md §4.2 exist with __init__.py."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    expected_layers = [
        "src/api",
        "src/core",
        "src/database",
        "src/evaluation",
        "src/extraction",
        "src/services",
        "src/storage",
        "src/ui",
        "src/validation",
    ]

    for layer in expected_layers:
        layer_path = base_dir / layer
        assert layer_path.is_dir(), f"Layer directory missing: {layer}"
        init_file = layer_path / "__init__.py"
        assert init_file.is_file(), f"__init__.py missing in: {layer}"


def test_pyproject_toml_configuration():
    """Verify pyproject.toml defines project metadata and essential dependencies."""
    base_dir = Path(__file__).resolve().parent.parent.parent
    pyproject_path = base_dir / "pyproject.toml"

    assert pyproject_path.is_file(), "pyproject.toml is missing"

    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    project = data.get("project", {})
    assert project.get("name") == "enterprise-ap-automation"
    assert project.get("requires-python") == ">=3.11"

    deps = " ".join(project.get("dependencies", []))
    assert "fastapi" in deps
    assert "pydantic" in deps
    assert "sqlalchemy" in deps
    assert "streamlit" in deps
    assert "openai" in deps
    assert "azure-identity" in deps
    assert "azure-storage-blob" in deps


def test_env_example_matches_claude_spec():
    """
    Verify .env.example defines all environment variables from CLAUDE.md §11.1
    and contains no hardcoded static secrets.
    """
    base_dir = Path(__file__).resolve().parent.parent.parent
    env_example_path = base_dir / ".env.example"

    assert env_example_path.is_file(), ".env.example is missing"

    with open(env_example_path, encoding="utf-8") as f:
        content = f.read()

    # Required variables per CLAUDE.md §11.1
    required_vars = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_BLOB_ACCOUNT_URL",
        "AZURE_BLOB_WORM_CONTAINER",
        "AZURE_SQL_SERVER",
        "AZURE_SQL_DATABASE",
        "REDIS_URL",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_GPT4O_DEPLOYMENT",
        "AZURE_OPENAI_MINI_DEPLOYMENT",
        "AZURE_OPENAI_API_VERSION",
        "HIGH_VALUE_THRESHOLD_USD",
        "PO_VARIANCE_TOLERANCE_PERCENT",
        "LINE_ROUNDING_TOLERANCE",
        "INVOICE_ROUNDING_TOLERANCE",
        "USE_LOCAL_SQLITE",
        "USE_FAKE_REDIS",
        "USE_MOCK_AOAI",
        "SAMPLE_DATA_DIR",
    ]

    for var_name in required_vars:
        assert f"{var_name}=" in content, f"Missing required variable in .env.example: {var_name}"

    # Verify no raw secrets/passwords are embedded (N1, N8)
    forbidden_terms = ["password=", "secret=", "api_key=sk-", "key=accountkey"]
    lower_content = content.lower()
    for term in forbidden_terms:
        assert term not in lower_content, f"Found potential static secret keyword: {term}"
