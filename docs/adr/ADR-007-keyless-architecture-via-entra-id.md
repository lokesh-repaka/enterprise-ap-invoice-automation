# ADR-007: Keyless Architecture via Microsoft Entra ID Managed Identities

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** OICR-001 Q-08, BRD §6.8, CLAUDE.md §8  

---

## Context & Problem Statement
Storing static database passwords, Azure OpenAI API keys, and Blob connection strings in application configuration files creates critical security vulnerabilities, secret leakage risks, and operational overhead during key rotation.

## Decision
Adopt a **100% Keyless Architecture**. All inter-service authentication (FastAPI to Azure SQL, Celery to Azure Blob, Backend to Azure OpenAI) must use **Microsoft Entra ID System-Assigned Managed Identities** and Azure Role-Based Access Control (RBAC).

## Options Considered
1. **Option 1 (Static API Keys in Azure Key Vault):** Secrets rotated quarterly. *Rejected:* Keys can still leak into logs or local developer environments; rotation causes intermittent service downtime.
2. **Option 2 (Managed Identities & Entra Token Exchange):** Zero static credentials exist anywhere. *Chosen.*

## Consequences & Trade-Offs
- **Positive:** Zero secret management overhead; automated token rotation; granular Azure RBAC auditing; eliminates credential exfiltration risks.
- **Negative:** Local development requires developers to sign in via Azure CLI (`az login`) or use Azure sandbox service principals.

