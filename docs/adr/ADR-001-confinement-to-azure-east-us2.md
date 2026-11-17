# ADR-001: Confinement to Azure East US 2 Regional Boundaries

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** OICR-001 Q-08, BRD §6.8, HLD §6  

---

## Context & Problem Statement
The client’s enterprise tenant mandates strict data residency. Invoices contain sensitive commercial records, supplier bank account details, and European employee data subject to GDPR. The team evaluated whether to implement an active-active multi-region deployment or confine all resources to a single primary region.

## Decision
Deploy all compute (FastAPI, Streamlit, Celery), storage (Azure Blob, Azure SQL), AI model deployments (Azure OpenAI GPT-4o), and observability telemetry strictly within **Azure East US 2**. Prohibit cross-region data egress at the Azure network policy level.

## Options Considered
1. **Option 1 (Active-Active Multi-Region - East US 2 & West Europe):** Provides disaster recovery and geographic routing. *Rejected:* Violates corporate tenant residency rules; introduces complex cross-region data replication and significantly higher cloud infrastructure costs.
2. **Option 2 (Single Region - East US 2 with Local Zone Redundancy):** All components stay in East US 2 using Azure Availability Zones for high availability. *Chosen.*

## Consequences & Trade-Offs
- **Positive:** 100% compliance with data residency; zero risk of unauthorized cross-border data transfer; simplified networking and lower operational cost.
- **Negative:** If a catastrophic Azure platform-wide outage hits the entire East US 2 region, the platform will be unavailable until Microsoft restores regional services.
- **Mitigation:** The agreed SLA explicitly excludes upstream Microsoft Azure platform outages from the 99.5% uptime commitment (Q-10).

