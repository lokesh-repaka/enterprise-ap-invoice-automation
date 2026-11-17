# ADR-005: Seven-Year Immutable Storage (WORM) and GDPR Pseudonymization

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** OICR-001 Q-09, BRD §6.8, HLD §6  

---

## Context & Problem Statement
Under commercial and tax regulations, original invoices and financial audit logs must be retained for seven (7) years without modification. However, GDPR Article 17 grants individuals the right to erasure of personal data (e.g., employee contact names, individual supplier email addresses).

## Decision
1. Store original invoice files and extracted raw JSON payloads in **Azure Blob Storage under a 7-year time-based Immutable Storage Policy (WORM)**.
2. Implement **application-level pseudonymization** in the Azure SQL database: upon a verified GDPR erasure request, personal contact names and phone numbers are replaced with pseudonymized tokens (`GDPR_REDACTED_USER_XXXX`), while retaining core commercial transaction records (corporate tax ID, monetary totals, line items).
3. **Governance Disclaimer:** This policy is recorded as a client business/compliance decision, not an independent legal opinion from the consultant. Client legal/privacy teams must formally validate this configuration prior to production rollout.

## Consequences & Trade-Offs
- **Positive:** Satisfies statutory financial audit laws without breaching immutable storage; accommodates GDPR data subject requests; clear governance boundary.
- **Negative:** Requires specialized database masking queries and audit procedures for verified erasure tickets.

