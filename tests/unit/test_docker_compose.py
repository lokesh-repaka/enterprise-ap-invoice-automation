"""
Unit tests for P14-3: docker-compose.yml (Local development stack).

Orchestrates FastAPI, Streamlit, Redis, Azurite, and SQLite local storage.
Maps to CLAUDE.md §4, §11, §14, ADR-007, SEC-233, CWE-668, CWE-250.
Fast, offline static & security verification (<0.05s).
"""

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"


def _load_compose() -> dict[str, Any]:
    """Load and parse root docker-compose.yml."""
    assert COMPOSE_FILE.is_file(), "docker-compose.yml must exist at repository root"
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    assert isinstance(data, dict), "docker-compose.yml must be a valid YAML dictionary"
    return data


def test_docker_compose_file_exists_and_declares_required_services() -> None:
    """# Tests: P14-3, CLAUDE.md §4 — Root docker-compose.yml declares api, ui, redis, and azurite."""
    data = _load_compose()
    assert "services" in data, "docker-compose.yml must define top-level services key"
    services = data["services"]

    required_services = {"api", "ui", "redis", "azurite"}
    missing = required_services - set(services.keys())
    assert not missing, f"docker-compose.yml is missing required services: {missing}"

    # Verify build targets / pinned images
    api = services["api"]
    assert "build" in api, "api service must specify build configuration"
    build_api = api["build"]
    if isinstance(build_api, dict):
        assert build_api.get("dockerfile") == "Dockerfile.api", (
            "api service must build from Dockerfile.api"
        )
    else:
        assert build_api == ".", "api build context should be root repository"

    ui = services["ui"]
    assert "build" in ui, "ui service must specify build configuration"
    build_ui = ui["build"]
    if isinstance(build_ui, dict):
        assert build_ui.get("dockerfile") == "Dockerfile.ui", (
            "ui service must build from Dockerfile.ui"
        )
    else:
        assert build_ui == ".", "ui build context should be root repository"

    redis = services["redis"]
    redis_image = redis.get("image", "")
    assert "redis:7" in redis_image or "redis:7-alpine" in redis_image, (
        f"redis service must use pinned redis:7 image, got: {redis_image!r}"
    )
    assert ":latest" not in redis_image.lower(), "redis floating :latest tag is prohibited"

    azurite = services["azurite"]
    azurite_image = azurite.get("image", "")
    assert "azurite:3.33.0" in azurite_image, (
        f"azurite service must use pinned azurite:3.33.0 image, got: {azurite_image!r}"
    )


def test_docker_compose_binds_ports_strictly_to_loopback() -> None:
    """# Tests: P14-3, SEC-233, CWE-668 — All published host ports are pinned strictly to 127.0.0.1."""
    data = _load_compose()
    services = data.get("services", {})

    expected_ports = {
        "api": "8000",
        "redis": "6379",
        "azurite": "10000",
    }

    for svc_name, expected_port in expected_ports.items():
        svc = services.get(svc_name, {})
        ports = svc.get("ports", [])
        assert ports, f"Service {svc_name} must declare published ports"

        for port_entry in ports:
            port_str = str(port_entry).strip()
            # Must start strictly with 127.0.0.1: (never 0.0.0.0: or bare port like "8000:8000")
            assert port_str.startswith("127.0.0.1:"), (
                f"Service {svc_name} port {port_str!r} must be pinned strictly to 127.0.0.1: "
                "to prevent external LAN exposure (CWE-668 / SEC-233)"
            )
            assert expected_port in port_str, (
                f"Service {svc_name} should expose container port {expected_port}"
            )

    # UI service ports check (supports modern React 5173 and legacy 8501)
    ui_svc = services.get("ui", {})
    ui_ports = [str(p).strip() for p in ui_svc.get("ports", [])]
    assert ui_ports, "Service ui must declare published ports"
    for p in ui_ports:
        assert p.startswith("127.0.0.1:"), f"UI port {p!r} must be pinned to 127.0.0.1:"
    assert any("5173" in p or "8501" in p for p in ui_ports), (
        "UI must publish port 5173 or 8501 on loopback"
    )


def test_docker_compose_enforces_service_healthchecks_and_dependencies() -> None:
    """# Tests: P14-3, CLAUDE.md §4, §14 — Services define healthchecks and startup condition dependencies."""
    data = _load_compose()
    services = data.get("services", {})

    # 1. Redis healthcheck
    redis = services["redis"]
    assert "healthcheck" in redis, "redis must declare a healthcheck probe"
    redis_test = str(redis["healthcheck"].get("test", ""))
    assert "redis-cli" in redis_test and "ping" in redis_test

    # 2. Azurite healthcheck
    azurite = services["azurite"]
    assert "healthcheck" in azurite, "azurite must declare a healthcheck probe"
    azurite_test = str(azurite["healthcheck"].get("test", ""))
    assert "10000" in azurite_test

    # 3. API healthcheck and depends_on
    api = services["api"]
    assert "healthcheck" in api, "api must declare a healthcheck probe"
    api_test = str(api["healthcheck"].get("test", ""))
    assert "8000" in api_test and "/health" in api_test

    api_deps = api.get("depends_on", {})
    assert "redis" in api_deps, "api must depend on redis"
    assert "azurite" in api_deps, "api must depend on azurite"
    if isinstance(api_deps, dict):
        assert api_deps["redis"].get("condition") == "service_healthy"
        assert api_deps["azurite"].get("condition") == "service_healthy"

    # 4. UI healthcheck and depends_on
    ui = services["ui"]
    assert "healthcheck" in ui, "ui must declare a healthcheck probe"
    ui_test = str(ui["healthcheck"].get("test", ""))
    assert "8080" in ui_test or "8501" in ui_test or "health" in ui_test

    ui_deps = ui.get("depends_on", {})
    assert "api" in ui_deps, "ui must depend on api"
    if isinstance(ui_deps, dict):
        assert ui_deps["api"].get("condition") == "service_healthy"


def test_docker_compose_enforces_container_security_hardening() -> None:
    """# Tests: P14-3, SEC-233, CWE-250, CWE-400 — no-new-privileges, cap_drop, mem_limit & pids_limit."""
    data = _load_compose()
    services = data.get("services", {})

    for svc_name in ["api", "ui", "redis", "azurite"]:
        svc = services[svc_name]

        # Security options
        sec_opts = svc.get("security_opt", [])
        assert "no-new-privileges:true" in sec_opts, (
            f"Service {svc_name} must enforce security_opt: [no-new-privileges:true]"
        )

        # Linux capability drop
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop, (
            f"Service {svc_name} must drop all capabilities via cap_drop: [ALL]"
        )

        # Resource limits (prevent DoS / noisy neighbor)
        assert "mem_limit" in svc, f"Service {svc_name} must declare mem_limit"
        assert "pids_limit" in svc, f"Service {svc_name} must declare pids_limit"

        # Restart policy
        assert svc.get("restart") in {"unless-stopped", "always", "on-failure"}, (
            f"Service {svc_name} should define restart policy"
        )


def test_docker_compose_environment_variables_volumes_and_networks() -> None:
    """# Tests: P14-3, CLAUDE.md §4.2, §12, N8, SEC-233 — Safe dev config, named volumes, custom network."""
    data = _load_compose()
    services = data.get("services", {})

    # Dedicated internal network
    assert "networks" in data, "docker-compose.yml must define top-level networks"
    networks = data["networks"]
    network_names = set(networks.keys())
    assert any("ap" in name or "network" in name for name in network_names), (
        "docker-compose.yml must declare a dedicated application network"
    )

    # Named volumes for persistence
    assert "volumes" in data, "docker-compose.yml must define top-level volumes"
    volumes = set(data["volumes"].keys())
    assert "sqlite_data" in volumes or "data" in volumes, (
        "Must declare persistent volume for SQLite database"
    )
    assert "azurite_data" in volumes, "Must declare persistent volume for Azurite storage"

    # API environment checks
    api_env = services["api"].get("environment", {})
    if isinstance(api_env, list):
        api_env_dict = dict(item.split("=", 1) for item in api_env if "=" in item)
    else:
        api_env_dict = api_env

    assert api_env_dict.get("APP_ENV") in {"dev", "local"}, (
        "API container APP_ENV must be dev/local"
    )
    assert api_env_dict.get("USE_LOCAL_SQLITE") in {"true", "True", True}
    assert api_env_dict.get("USE_FAKE_REDIS") in {"false", "False", False}
    assert "redis://redis:6379/0" in str(api_env_dict.get("REDIS_URL"))
    assert api_env_dict.get("USE_AZURITE_EMULATOR") in {"true", "True", True}
    assert api_env_dict.get("USE_MOCK_BLOB_STORAGE") in {"false", "False", False}
    assert "azurite" in str(api_env_dict.get("AZURITE_BLOB_URL"))

    # UI environment checks
    ui_env = services["ui"].get("environment", {})
    if isinstance(ui_env, list):
        ui_env_dict = dict(item.split("=", 1) for item in ui_env if "=" in item)
    else:
        ui_env_dict = ui_env

    assert "http://api:8000" in str(ui_env_dict.get("AP_API_BASE_URL")), (
        "UI must communicate with API container via http://api:8000"
    )
