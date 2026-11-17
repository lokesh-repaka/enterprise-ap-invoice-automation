# ADR-003: Streamlit for Internal Enterprise AP Review Interface

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** BRD §6.6, PRD Screens 1–5  

---

## Context & Problem Statement
The platform requires an internal UI for AP clerks to upload batches, inspect split-screen invoices, review highlighted low-confidence fields, edit line items, and execute re-validations. The team needed to choose between building a custom React/Next.js frontend or using Streamlit.

## Decision
Build the internal review workbench using **Streamlit (v1.35+)** backed by Python, integrated into the FastAPI backend via a typed HTTP API client (`src/ui/api_client.py`).

## Options Considered
1. **Option 1 (Custom React / Next.js + Tailwind UI):** Highly customizable and performant. *Rejected:* Significant frontend engineering overhead that would exceed the $36,000 fixed consulting fee and jeopardize the 4-week prototype / 8-week pilot milestones.
2. **Option 2 (Streamlit Framework):** Rapid UI development in Python, native data table editing, PDF viewing components, and immediate integration with Python backend models. *Chosen.*

## Consequences & Trade-Offs
- **Positive:** Delivered in less than half the time; highly responsive to finance team feedback; native Python data handling; fits comfortably within the $36,000 budget.
- **Negative:** Limited complex custom UI animations; less suited for external public consumer apps (acceptable since this is strictly an internal enterprise tool).

