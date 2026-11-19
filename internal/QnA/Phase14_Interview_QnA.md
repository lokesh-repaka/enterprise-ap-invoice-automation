# Phase 14: Comprehensive Interview Questions & Answers — Infrastructure, Container Hardening & Azure East US 2

> **Document Scope:** Deep-dive technical, cloud infrastructure, container security hardening, Azure East US 2 regional confinement, zero-secret Entra ID Managed Identity architecture, and deployment hygiene covering **Phase 14 (Infrastructure & Delivery — P14-1 through P14-5)**.  
> **Audience:** Candidates interviewing for Principal Cloud Architect, Staff Platform Engineer, Lead DevOps / DevSecOps Engineer, or Security Architect roles.

---

## 1. Container Hardening & Local Orchestration

### Q1.1: What container security hardening techniques were implemented in `Dockerfile.api` and `Dockerfile.ui`?

**Answer:**
We implemented five enterprise container hardening controls (`SEC-231`, `SEC-232`):
1. **Multi-Stage Builds:** The builder stage compiles wheels; the runtime stage copies only the isolated `/opt/venv` and application code, omitting compilation tools, git, and dev packages.
2. **Dedicated Non-Root User:** Containers create system group/user `appuser:appgroup` (UID/GID `10001`) with `/usr/sbin/nologin` shell, switching `USER appuser` before `CMD`.
3. **Read-Only Application Source:** Application files in `/app/src/` are owned by `root:appgroup` with permissions `chmod -R a-w /app/src`. Even if an attacker achieves remote code execution within the container, they cannot modify Python scripts on disk (`CWE-732`).
4. **Zero-Dependency Healthchecks:** Probes use Python's standard library `urllib.request` against `/health` and `/_stcore/health` without installing `curl` or `wget`.
5. **Executable Array Form:** `CMD ["uvicorn", ...]` and `CMD ["streamlit", ...]` use exec JSON array form, ensuring the Python process is PID 1 to handle SIGTERM signals cleanly.

### Q1.2: Why must `docker-compose.yml` published ports be pinned strictly to `127.0.0.1:*` rather than bare `8000:8000`?

**Answer:**
In Docker Compose, writing `ports: - "8000:8000"` or `ports: - "0.0.0.0:8000:8000"` binds the container port to all network interfaces on the host machine (`CWE-668 / CWE-1327 / SEC-233`). Anyone on the same office Wi-Fi, coffee shop network, or VPN can connect directly to the developer's local database or API. Pinning ports strictly to `"127.0.0.1:8000:8000"` ensures that services are only accessible from the local loopback adapter.

---

## 2. Azure East US 2 Cloud Architecture & Zero-Secret Policy

### Q2.1: How does `infrastructure/main.bicep` enforce zero static secrets and keyless authentication?

**Answer:**
Per `ADR-007`, `N1`, and `N8`:
1. **Disabled Shared Keys:** The Storage Account specifies `allowSharedKeyAccess: false`, physically disabling storage account access keys.
2. **Entra ID ActiveDirectory-Only Auth:** The Azure SQL server configures `azureADOnlyAuthentication: true`. No SQL Server administrator password (`sa_password`) exists.
3. **System-Assigned Managed Identity:** Container Apps `ca-api` and `ca-ui` declare `identity: { type: 'SystemAssigned' }`.
4. **Granular RBAC Assignments:** Bicep assigns built-in Azure RBAC role definitions directly to the container app's principal ID:
   - Key Vault Secrets User (`4633458b-17de-408a-b874-0445c86b69e6`)
   - Storage Blob Data Contributor (`ba92f5b4-2d11-453d-a403-e96b0029c9fe`)
   - Cognitive Services OpenAI User (`5e0dc982-0038-4745-9372-2f3b90048e9c`)
5. No passwords, tokens, or keys exist in parameters, variables, code, or outputs (`SEC-234`).

### Q2.2: How does the Network Security Group enforce data residency within Azure East US 2?

**Answer:**
Per `ADR-001` and `N2`:
- Invoices contain sensitive commercial records and European employee data subject to GDPR.
- In `infrastructure/main.bicep`, the NSG contains an explicit high-priority rule:
  ```bicep
  name: 'Deny-Internet-Outbound'
  properties: {
    priority: 900
    direction: 'Outbound'
    access: 'Deny'
    destinationAddressPrefix: 'Internet'
  }
  ```
- Allowed outbound traffic is strictly limited to `VirtualNetwork` and `AzureCloud.EastUS2` (Priority 300).
- This guarantees at the network packet level that data cannot egress outside East US 2 regional boundaries.

---

## 3. Seven-Year WORM Storage & Immutability

### Q3.1: How is 7-year WORM compliance configured in Azure Blob Storage via Bicep?

**Answer:**
Per `ADR-005` and `BR-026`:
1. The container `raw-invoices-immutable` is provisioned under `Microsoft.Storage/storageAccounts/blobServices/containers`.
2. A child resource `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies` specifies:
   - `immutabilityPeriodSinceCreationInDays: 2557` (365 days $\times$ 7 years + 2 leap days).
   - `allowProtectedAppendWrites: true`.
3. Once placed under legal hold or locked, blobs in this container cannot be overwritten, modified, or deleted by any user or administrator until the 7-year retention period expires.

