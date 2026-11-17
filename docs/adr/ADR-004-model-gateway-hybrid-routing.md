# ADR-004: Model Gateway Pattern with Hybrid Text vs. Vision Routing

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** HLD §7, LLD §1, CLAUDE.md §7.3  

---

## Context & Problem Statement
Invoices arrive in diverse formats: clean digital PDFs, low-resolution mobile photos, scanned multi-page documents, and XLSX spreadsheets. Sending all 10,000 monthly invoices through top-tier multi-modal vision models is cost-prohibitive and introduces unnecessary latency.

## Decision
Implement a **Model Gateway layer** (`src/extraction/model_gateway.py`) that inspects document properties and routes to the cheapest capable model:
- Searchable digital PDFs $\implies$ Text layer extracted and routed to **GPT-4o-mini**.
- Scanned images, messy tables, or handwritten receipts $\implies$ Routed to **GPT-4o Vision**.
- Enable Azure OpenAI Prompt Caching on shared system schemas to cut input token costs by up to 50%.

## Options Considered
1. **Option 1 (Single Model - GPT-4o Vision for Everything):** Simpler architecture. *Rejected:* Monthly token costs would exceed $500, with average latency >18s per invoice.
2. **Option 2 (Hybrid Model Routing Gateway):** Dynamic routing based on MIME type and text layer density. *Chosen.*

## Consequences & Trade-Offs
- **Positive:** Lowers monthly token consumption by ~60%; reduces average processing latency to <10 seconds for clean digital PDFs.
- **Negative:** Requires pre-flight classification logic in the Orchestrator component.

