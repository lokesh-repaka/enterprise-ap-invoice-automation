# ADR-002: Deterministic Workflow Pipeline vs. Autonomous Agent

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** Architectural Principle: *"Choose the least powerful, most deterministic mechanism that reliably solves the problem"*  

---

## Context & Problem Statement
Autonomous AI agents that decide their own execution paths using open-ended reasoning loops can suffer from hallucinations, non-deterministic branching, unexpected costs, and high latency. For financial processing (tax, totals, PO checks), predictability and auditability are non-negotiable.

## Decision
Implement a **deterministic workflow pipeline** in Python for invoice ingestion, duplicate hashing, arithmetic calculation, and approval routing. Restrict generative AI models strictly to extraction, OCR parsing, and visual document structuring within a constrained sandbox.

## Options Considered
1. **Option 1 (Full Autonomous ReAct Multi-Agent Loop):** An agent decides dynamically whether to check tax, search vendor master, or approve invoices. *Rejected:* High risk of unpredictable decisions; impossible to guarantee 100% mathematical auditability; high token costs and latency.
2. **Option 2 (Deterministic Pipeline with Model Extraction):** The execution path is hardcoded in Python; models extract structured JSON, and deterministic code validates the numbers. *Chosen.*

## Consequences & Trade-Offs
- **Positive:** 100% predictable, auditable mathematical calculations; zero risk of model overriding financial checks or approving unauthorized amounts; reproducible results for audit logs.
- **Negative:** Adding new validation rules requires updating Python code rather than prompting an LLM in natural language.

