# ADR-NNN: <Short Title>

**Status:** Proposed | Accepted | Deprecated | Superseded by ADR-NNN  
**Date:** YYYY-MM-DD  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Technical Story / Reference:** [CLAUDE.md](CLAUDE.md), [HLD_High_Level_Design.md](HLD_High_Level_Design.md)  

---

## Context & Problem Statement
Describe the context, technical constraints, business drivers, and the exact problem being solved.

## Decision
State the architectural decision clearly and concisely. Reference relevant architectural principles (e.g., East US 2 data residency, deterministic Python pipeline, keyless architecture).

## Options Considered
1. **Option 1 (<Title>):** Description. *Rejected:* Reason for rejection.
2. **Option 2 (<Title>):** Description. *Chosen:* Reason for selection.

## Consequences & Trade-Offs
- **Positive:** Benefits gained, risks eliminated.
- **Negative:** Limitations accepted, operational complexities introduced.
- **Mitigations:** How negative trade-offs are handled.

## Compliance & Layering Verification
- [ ] Confined to Azure East US 2 (ADR-001)
- [ ] Preserves deterministic rules-first execution (ADR-002)
- [ ] Complies with `CLAUDE.md` Section 4.2 layering rules
- [ ] Zero static credentials required (ADR-007)

