# Architecture Decision Records (ADRs)
## Enterprise AP Invoice Automation Platform

**Document ID:** ADR-001  
**Version:** 1.0 (Baseline Approved)  
**Status:** Approved by Lead Cloud Architect & Business Sponsor  
**Project:** Enterprise AP Invoice Automation Platform  
**Related Documents:** [HLD_High_Level_Design.md](file:///Users/lokeshrepaka/Desktop/untitled%20folder/docs/HLD_High_Level_Design.md), [LLD_Low_Level_Design.md](file:///Users/lokeshrepaka/Desktop/untitled%20folder/docs/LLD_Low_Level_Design.md)

---

## Index of Architectural Decisions

* **[ADR-001](#adr-001-confinement-to-azure-east-us-2):** Confinement to Azure East US 2 Regional Boundaries
* **[ADR-002](#adr-002-deterministic-workflow-pipeline-vs-autonomous-agent):** Deterministic Workflow Pipeline vs. Autonomous Multi-Agent Loop
* **[ADR-003](#adr-003-streamlit-for-internal-enterprise-ap-review-interface):** Streamlit for Internal Enterprise AP Review Interface
* **[ADR-004](#adr-004-model-gateway-pattern-with-hybrid-text-vs-vision-routing):** Model Gateway Pattern with Hybrid Text vs. Vision Routing
* **[ADR-005](#adr-005-seven-year-immutable-storage-worm-and-gdpr-pseudonymization):** Seven-Year Immutable Storage (WORM) and GDPR Pseudonymization
* **[ADR-006](#adr-006-composite-business-key-hashing-and-side-by-side-revision-workflow):** Composite Business-Key Hashing and Side-by-Side Revision Workflow
* **[ADR-007](#adr-007-keyless-architecture-via-microsoft-entra-id-managed-identities):** Keyless Architecture via Microsoft Entra ID Managed Identities

---

## ADR-001: Confinement to Azure East US 2

### Status
**ACCEPTED** (Reconciled from OICR-001 Q-08)

### Context & Problem Statement
The client’s enterprise tenant mandates strict data residency. Invoices contain sensitive commercial records, supplier bank account details, and European employee data subject to GDPR. The team evaluated whether to implement an active-active multi-region deployment or confine all resources to a single primary region.

### Decision
Deploy all compute (FastAPI, Streamlit, Celery), storage (Azure Blob, Azure SQL), AI model deployments (Azure OpenAI GPT-4o), and observability telemetry strictly within **Azure East US 2**. Prohibit cross-region data egress at the Azure network policy level.

### Options Considered
1. **Option 1 (Active-Active Multi-Region - East US 2 & West Europe):** Provides disaster recovery and geographic routing. *Rejected:* Violates corporate tenant residency rules; introduces complex cross-region data replication and significantly higher cloud infrastructure costs.
2. **Option 2 (Single Region - East US 2 with Local Zone Redundancy):** All components stay in East US 2 using Azure Availability Zones for high availability. *Chosen.*

### Consequences & Trade-Offs
* **Positive:** 100% compliance with data residency; zero risk of unauthorized cross-border data transfer; simplified networking and lower operational cost.
* **Negative:** If a catastrophic Azure platform-wide outage hits the entire East US 2 region, the platform will be unavailable until Microsoft restores regional services.
* **Mitigation:** The agreed SLA explicitly excludes upstream Microsoft Azure platform outages from the 99.5% uptime commitment (Q-10).

---

## ADR-002: Deterministic Workflow Pipeline vs. Autonomous Agent

### Status
**ACCEPTED** (Aligned with Architectural Principle: *"Choose the least powerful, most deterministic mechanism that reliably solves the problem"* )

### Context & Problem Statement
Autonomous AI agents that decide their own execution paths using open-ended reasoning loops can suffer from hallucinations, non-deterministic branching, unexpected costs, and high latency. For financial processing (tax, totals, PO checks), predictability and auditability are non-negotiable.

### Decision
Implement a **deterministic workflow pipeline** in Python for invoice ingestion, duplicate hashing, arithmetic calculation, and approval routing. Restrict generative AI models strictly to extraction, OCR parsing, and visual document structuring within a constrained sandbox.

### Options Considered
1. **Option 1 (Full Autonomous ReAct Multi-Agent Loop):** An agent decides dynamically whether to check tax, search vendor master, or approve invoices. *Rejected:* High risk of unpredictable decisions; impossible to guarantee 100% mathematical auditability; high token costs and latency.
2. **Option 2 (Deterministic Pipeline with Model Extraction):** The execution path is hardcoded in Python; models extract structured JSON, and deterministic code validates the numbers. *Chosen.*

### Consequences & Trade-Offs
* **Positive:** 100% predictable, auditable mathematical calculations; zero risk of model overriding financial checks or approving unauthorized amounts; reproducible results for audit logs.
* **Negative:** Adding new validation rules requires updating Python code rather than prompting an LLM in natural language.

---

## ADR-003: Streamlit for Internal Enterprise AP Review Interface

### Status
**ACCEPTED** (Preferred by Client Sponsor & Reconciled in Phase 1 Scope)

### Context & Problem Statement
The platform requires an internal UI for AP clerks to upload batches, inspect split-screen invoices, review highlighted low-confidence fields, edit line items, and execute re-validations. The team needed to choose between building a custom React/Next.js frontend or using Streamlit.

### Decision
Build the internal review workbench using **Streamlit (v1.35+)** backed by Python, integrated into the FastAPI backend.

### Options Considered
1. **Option 1 (Custom React / Next.js + Tailwind UI):** Highly customizable and performant. *Rejected:* Significant frontend engineering overhead that would exceed the $36,000 fixed consulting fee and jeopardize the 4-week prototype / 8-week pilot milestones.
2. **Option 2 (Streamlit Framework):** Rapid UI development in Python, native data table editing, PDF viewing components, and immediate integration with Python backend models. *Chosen.*

### Consequences & Trade-Offs
* **Positive:** Delivered in less than half the time; highly responsive to finance team feedback; native Python data handling; fits comfortably within the $36,000 budget.
* **Negative:** Limited complex custom UI animations; less suited for external public consumer apps (acceptable since this is strictly an internal enterprise tool).

---

## ADR-004: Model Gateway Pattern with Hybrid Text vs. Vision Routing

### Status
**ACCEPTED** (Aligned with Architectural Pattern: *Model Gateway & Token Budgeting*)

### Context & Problem Statement
Invoices arrive in diverse formats: clean digital PDFs, low-resolution mobile photos, scanned multi-page documents, and XLSX spreadsheets. Sending all 10,000 monthly invoices through top-tier multi-modal vision models is cost-prohibitive and introduces unnecessary latency.

### Decision
Implement a **Model Gateway layer** that inspects document properties and routes to the cheapest capable model:
* Searchable digital PDFs $\implies$ Text layer extracted and routed to **GPT-4o-mini**.
* Scanned images, messy tables, or handwritten receipts $\implies$ Routed to **GPT-4o Vision**.
* Enable Azure OpenAI Prompt Caching on shared system schemas to cut input token costs by up to 50%.

### Options Considered
1. **Option 1 (Single Model - GPT-4o Vision for Everything):** Simpler architecture. *Rejected:* Monthly token costs would exceed $500, with average latency >18s per invoice.
2. **Option 2 (Hybrid Model Routing Gateway):** Dynamic routing based on MIME type and text layer density. *Chosen.*

### Consequences & Trade-Offs
* **Positive:** Lowers monthly token consumption by ~60%; reduces average processing latency to <10 seconds for clean digital PDFs.
* **Negative:** Requires pre-flight classification logic in the Orchestrator component.

---

## ADR-005: Seven-Year Immutable Storage (WORM) and GDPR Pseudonymization

### Status
**ACCEPTED** (Reconciled from OICR-001 Q-09 & BRD BR-026)

### Context & Problem Statement
Under commercial and tax regulations, original invoices and financial audit logs must be retained for seven (7) years without modification. However, GDPR Article 17 grants individuals the right to erasure of personal data (e.g., employee contact names, individual supplier email addresses).

### Decision
1. Store original invoice files and extracted raw JSON payloads in **Azure Blob Storage under a 7-year time-based Immutable Storage Policy (WORM)**.
2. Implement **application-level pseudonymization** in the Azure SQL database: upon a verified GDPR erasure request, personal contact names and phone numbers are replaced with pseudonymized tokens (`GDPR_REDACTED_USER_XXXX`), while retaining core commercial transaction records (corporate tax ID, monetary totals, line items).
3. **Governance Disclaimer:** This policy is recorded as a client business/compliance decision, not an independent legal opinion from the consultant. Client legal/privacy teams must formally validate this configuration prior to production rollout.

### Consequences & Trade-Offs
* **Positive:** Satisfies statutory financial audit laws without breaching immutable storage; accommodates GDPR data subject requests; clear governance boundary.
* **Negative:** Requires specialized database masking queries and audit procedures for verified erasure tickets.

---

## ADR-006: Composite Business-Key Hashing and Side-by-Side Revision Workflow

### Status
**ACCEPTED** (Reconciled from OICR-001 Q-06)

### Context & Problem Statement
Suppliers occasionally submit revised invoices with the same invoice number but updated totals, or send re-scanned duplicate documents. Simple duplicate checking either silently overwrites records or rejects legitimate revisions.

### Decision
1. Detect exact duplicates using a composite hash: $\text{SHA256}(\text{Vendor Tax ID} + \text{Invoice Number} + \text{Total Amount})$.
2. If an invoice matches Vendor Tax ID and Invoice Number but has a different Total Amount or `-REV` suffix, assign status `FLAGGED_POTENTIAL_REVISION` and trigger a **side-by-side comparison screen** in the Streamlit UI.
3. Automatically classify negative-balance invoices as `CREDIT_NOTE` and route them to credit netting.

### Consequences & Trade-Offs
* **Positive:** Eliminates double payments while ensuring genuine vendor revisions are captured and resolved by human AP clerks.
* **Negative:** Requires maintaining multiple document versions in the database and building a custom comparison interface.

---

## ADR-007: Keyless Architecture via Microsoft Entra ID Managed Identities

### Status
**ACCEPTED** (Reconciled from OICR-001 Q-08 & BRD BR-030)

### Context & Problem Statement
Storing static database passwords, Azure OpenAI API keys, and Blob connection strings in application configuration files creates critical security vulnerabilities, secret leakage risks, and operational overhead during key rotation.

### Decision
Adopt a **100% Keyless Architecture**. All inter-service authentication (FastAPI to Azure SQL, Celery to Azure Blob, Backend to Azure OpenAI) must use **Microsoft Entra ID System-Assigned Managed Identities** and Azure Role-Based Access Control (RBAC).

### Options Considered
1. **Option 1 (Static API Keys in Azure Key Vault):** Secrets rotated quarterly. *Rejected:* Keys can still leak into logs or local developer environments; rotation causes intermittent service downtime.
2. **Option 2 (Managed Identities & Entra Token Exchange):** Zero static credentials exist anywhere. *Chosen.*

### Consequences & Trade-Offs
* **Positive:** Zero secret management overhead; automated token rotation; granular Azure RBAC auditing; eliminates credential exfiltration risks.
* **Negative:** Local development requires developers to sign in via Azure CLI (`az login`) or use Azure sandbox service principals.

---
*End of Architecture Decision Records*

