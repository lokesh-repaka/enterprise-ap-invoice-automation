# ADR-006: Composite Business-Key Hashing and Side-by-Side Revision Workflow

**Status:** ACCEPTED  
**Date:** 2026-11-16  
**Deciders:** Lead Cloud Architect, Business Sponsor, Platform Architect  
**Reference:** OICR-001 Q-06, BRD §6.5, LLD §1  

---

## Context & Problem Statement
Suppliers occasionally submit revised invoices with the same invoice number but updated totals, or send re-scanned duplicate documents. Simple duplicate checking either silently overwrites records or rejects legitimate revisions.

## Decision
1. Detect exact duplicates using a composite hash: $\text{SHA256}(\text{Vendor Tax ID} + \text{Invoice Number} + \text{Total Amount})$.
2. If an invoice matches Vendor Tax ID and Invoice Number but has a different Total Amount or `-REV` suffix, assign status `FLAGGED_POTENTIAL_REVISION` and trigger a **side-by-side comparison screen** in the Streamlit UI.
3. Automatically classify negative-balance invoices as `CREDIT_NOTE` and route them to credit netting.

## Consequences & Trade-Offs
- **Positive:** Eliminates double payments while ensuring genuine vendor revisions are captured and resolved by human AP clerks.
- **Negative:** Requires maintaining multiple document versions in the database and building a custom comparison interface.

