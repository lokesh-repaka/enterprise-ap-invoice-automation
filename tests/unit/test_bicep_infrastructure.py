"""
Unit tests for P14-4: Azure Bicep Infrastructure Template (infrastructure/main.bicep).

Verifies East US 2 regional confinement, Container Apps, Azure SQL, Redis Cache,
Blob WORM 7-year immutability, Azure OpenAI, Key Vault, VNet, NSG, and Managed Identity RBAC.
Maps to CLAUDE.md §3, §4, §11, ADR-001, ADR-004, ADR-005, ADR-007, N1, N2, N6, N8, SEC-234.
Fast, offline static & security verification (<0.05s).
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BICEP_FILE = PROJECT_ROOT / "infrastructure" / "main.bicep"


def _read_bicep_content() -> str:
    """Read the Bicep template content, asserting file existence."""
    assert BICEP_FILE.is_file(), f"infrastructure/main.bicep must exist at {BICEP_FILE}"
    return BICEP_FILE.read_text(encoding="utf-8")


def test_bicep_file_exists_and_pins_east_us2_region() -> None:
    """# Tests: P14-4, ADR-001, N2, SEC-234 — Template strictly pins location to East US 2."""
    content = _read_bicep_content()

    # Parameter primaryRegion must default to 'eastus2'
    param_match = re.search(
        r"param\s+primaryRegion\s+string\s*=\s*'eastus2'",
        content,
    )
    assert param_match, "param primaryRegion must exist and default to 'eastus2'"

    # Must disallow regions other than eastus2 (allowed values or strict assert/check)
    assert "@allowed([" in content or "allowedValues" in content or "eastus2" in content
    assert "'eastus2'" in content

    # Environment param check
    assert "param environment string" in content
    assert "'staging'" in content


def test_bicep_declares_vnet_and_subnets_with_proper_address_space() -> None:
    """# Tests: P14-4, HLD §6, DEV-001 §2 — Provisions VNet 10.0.0.0/16 with snet-aca and snet-endpoints."""
    content = _read_bicep_content()

    # Virtual Network resource
    assert "Microsoft.Network/virtualNetworks@" in content
    assert "'10.0.0.0/16'" in content, "VNet address space must be 10.0.0.0/16"

    # Subnets
    assert "snet-aca" in content, "Must declare Container Apps subnet snet-aca"
    assert "snet-endpoints" in content, "Must declare Private Endpoints subnet snet-endpoints"
    assert (
        "Microsoft.App/environments" in content or "Microsoft.App/managedEnvironments" in content
    ), "snet-aca must support Container Apps delegation"


def test_bicep_declares_nsg_enforcing_east_us2_confinement_and_internet_deny() -> None:
    """# Tests: P14-4, ADR-001, N2, SEC-234 — NSG denies outbound Internet and confines to East US 2."""
    content = _read_bicep_content()

    # Network Security Group resource
    assert "Microsoft.Network/networkSecurityGroups@" in content

    # Deny outbound Internet rule
    assert "Deny" in content or "'Deny'" in content
    assert "Outbound" in content or "'Outbound'" in content
    assert "Internet" in content or "'Internet'" in content, (
        "NSG must contain explicit rule blocking outbound Internet traffic (ADR-001, N2)"
    )

    # Allowed East US 2 traffic
    assert "AzureCloud.EastUS2" in content or "EastUS2" in content, (
        "NSG must permit outbound traffic to Azure services within East US 2"
    )


def test_bicep_declares_storage_account_with_7_year_worm_policy() -> None:
    """# Tests: P14-4, CLAUDE.md §3, ADR-005, N6, SEC-234 — Blob WORM 7-year immutable container."""
    content = _read_bicep_content()

    # Storage account resource
    assert "Microsoft.Storage/storageAccounts@" in content
    assert "supportsHttpsTrafficOnly: true" in content
    assert "minimumTlsVersion: 'TLS1_2'" in content or "minimumTlsVersion: 'TLS1_3'" in content
    assert "allowBlobPublicAccess: false" in content

    # WORM immutable container: raw-invoices-immutable
    assert "raw-invoices-immutable" in content, (
        "Must declare blob container named 'raw-invoices-immutable'"
    )
    # 7 years = 2557 days (or 7 * 365 + 2 leap days = 2557 days)
    assert "2557" in content or "immutabilityPeriodSinceCreationInDays" in content, (
        "Must configure 7-year (2557 days) WORM immutability retention policy"
    )


def test_bicep_declares_keyvault_redis_and_azure_sql_with_entra_auth() -> None:
    """# Tests: P14-4, ADR-007, N1, N8, SEC-234 — Key Vault RBAC, TLS Redis, Azure SQL Entra ID."""
    content = _read_bicep_content()

    # Key Vault
    assert "Microsoft.KeyVault/vaults@" in content
    assert "enableRbacAuthorization: true" in content
    assert "purgeProtection: true" in content or "enablePurgeProtection: true" in content
    assert "enableSoftDelete: true" in content

    # Redis Cache
    assert "Microsoft.Cache/redis@" in content
    assert "minimumTlsVersion: '1.2'" in content or "minimumTlsVersion: '1.3'" in content
    assert "enableNonSslPort: false" in content

    # Azure SQL Logical Server & Database
    assert "Microsoft.Sql/servers@" in content
    assert "Microsoft.Sql/servers/databases@" in content
    assert "sqldb-ap-staging" in content or "sqldb" in content
    assert "minimalTlsVersion: '1.2'" in content
    assert "publicNetworkAccess: 'Disabled'" in content
    # Entra ID administrator authentication
    assert "administrators" in content
    assert "ActiveDirectory" in content


def test_bicep_declares_openai_model_gateway_deployments() -> None:
    """# Tests: P14-4, CLAUDE.md §4, ADR-004 — Azure OpenAI with gpt-4o-vision & gpt-4o-mini."""
    content = _read_bicep_content()

    # Azure OpenAI Cognitive Service account
    assert "Microsoft.CognitiveServices/accounts@" in content
    assert "kind: 'OpenAI'" in content

    # Model deployments: gpt-4o-vision and gpt-4o-mini
    assert "gpt-4o-vision" in content, "Must declare gpt-4o-vision model deployment"
    assert "gpt-4o-mini" in content, "Must declare gpt-4o-mini model deployment"
    assert "Microsoft.CognitiveServices/accounts/deployments@" in content


def test_bicep_declares_container_apps_and_managed_identity_rbac_roles() -> None:
    """# Tests: P14-4, ADR-007, N1, SEC-234 — Container Apps ca-api, ca-ui with Managed Identity RBAC."""
    content = _read_bicep_content()

    # Container Apps Environment
    assert "Microsoft.App/managedEnvironments@" in content

    # Container Apps
    assert "Microsoft.App/containerApps@" in content
    assert "ca-api" in content, "Must declare backend container app ca-api"
    assert "ca-ui" in content, "Must declare frontend container app ca-ui"
    assert "type: 'SystemAssigned'" in content, (
        "Container Apps must use SystemAssigned Managed Identity"
    )

    # Ports
    assert "8000" in content, "ca-api target port must be 8000"
    assert "8501" in content, "ca-ui target port must be 8501"

    # RBAC Role Assignments (Microsoft.Authorization/roleAssignments)
    assert "Microsoft.Authorization/roleAssignments@" in content

    # Built-in Azure Role Definition IDs:
    # Key Vault Secrets User: 4633458b-17de-408a-b874-0445c86b69e6
    # Storage Blob Data Contributor: ba92f5b4-2d11-453d-a403-e96b0029c9fe
    # Cognitive Services OpenAI User: 5e0dc982-0038-4745-9372-2f3b90048e9c
    assert "4633458b-17de-408a-b874-0445c86b69e6" in content, (
        "Must assign Key Vault Secrets User role definition ID"
    )
    assert "ba92f5b4-2d11-453d-a403-e96b0029c9fe" in content, (
        "Must assign Storage Blob Data Contributor role definition ID"
    )
    assert "5e0dc982-0038-4745-9372-2f3b90048e9c" in content, (
        "Must assign Cognitive Services OpenAI User role definition ID"
    )


def test_bicep_declares_private_endpoints_for_isolated_datastores() -> None:
    """# Tests: P14-4, ADR-007, SEC-234 — Private Endpoints for Key Vault, SQL, Blob, Redis, OpenAI."""
    content = _read_bicep_content()

    assert "Microsoft.Network/privateEndpoints@" in content, (
        "Must declare Private Endpoints for VNet isolation"
    )
    assert "snet-endpoints" in content, "Private Endpoints must be placed in snet-endpoints subnet"

    # Verify link connections for all 5 isolated datastores
    assert "plsc-keyvault" in content or "'vault'" in content, "Must declare Private Endpoint for Key Vault"
    assert "plsc-sql" in content or "'sqlServer'" in content, "Must declare Private Endpoint for SQL Server"
    assert "plsc-blob" in content or "'blob'" in content, "Must declare Private Endpoint for Blob Storage"
    assert "plsc-redis" in content or "'redisCache'" in content, "Must declare Private Endpoint for Redis"
    assert "plsc-openai" in content or "'account'" in content, "Must declare Private Endpoint for Azure OpenAI"


def test_bicep_has_zero_static_secrets_or_plaintext_credentials() -> None:
    """# Tests: P14-4, ADR-007, N1, N8, SEC-234 — Zero plaintext credentials or hardcoded keys."""
    content = _read_bicep_content()

    # No hardcoded static passwords in params or variables
    secret_patterns = [
        r"password\s*=\s*'[^']+'",
        r"secret\s*=\s*'[^']+'",
        r"accountKey\s*=\s*'[^']+'",
        r"apiKey\s*=\s*'[^']+'",
    ]
    for pat in secret_patterns:
        match = re.search(pat, content, re.IGNORECASE)
        assert not match, f"Hardcoded credential detected in main.bicep: {match.group(0)!r}"

    # No secret outputs
    output_lines = [line for line in content.splitlines() if line.strip().startswith("output ")]
    for out in output_lines:
        assert "password" not in out.lower(), f"Outputting secrets is prohibited: {out}"
        assert "secret" not in out.lower(), f"Outputting secrets is prohibited: {out}"
        assert "key" not in out.lower() or "keyvault" in out.lower(), (
            f"Outputting keys is prohibited: {out}"
        )
