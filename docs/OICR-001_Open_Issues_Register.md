# Open Issues & Clarifications Register (OICR-001)

**Project:** Enterprise AP Invoice Automation Platform  
**Version:** 2.0  
**Status:** All Issues Resolved — Pending Document Reconciliation  
**Related Document:** BRD  
**Resolution Source:** Client's Official Clarification and Sign-Off

## Issue Resolution Summary

| ID | Priority | Owner | Status | Final Resolution |
|---|---|---|---|---|
| Q-01 | Critical | Business Sponsor / Finance Manager | CLOSED | Header accuracy ≥95% macro-average, with ≥92% hard floor on critical fields. Line-item accuracy ≥90%. Pilot STP ≥65% across 300 invoices. |
| Q-02 | High | AP Team | CLOSED | AP team will supply 100 additional sanitized invoices within 10 calendar days, bringing the dataset to 300 across 15 vendors. |
| Q-03 | Critical | AP Manager / Business Sponsor | CLOSED | ≥90% confidence: eligible for one-click clerk approval if validation passes. 80–89%: light-yellow highlight and visual confirmation. Below 80%: REQUIRES_APPROVAL, amber/red highlight and Human Exception Queue. |
| Q-04 | High | AP Manager | CLOSED | Use Vendor Master Locale table. US vendors use MM/DD/YYYY; European vendors use DD/MM/YYYY. Unknown or ambiguous dates require human verification. |
| Q-05 | Critical | Finance Manager | CLOSED | Support US sales tax and specified UK, German and Spanish VAT rates. Validated exemptions and reverse-charge cases are accepted with appropriate annotations and valid Vendor Tax ID. Rounding tolerance: ±0.02 per line and ±0.05 at invoice level. |
| Q-06 | High | AP Manager / Finance Manager | CLOSED | Same invoice number with updated total or -REV suffix becomes FLAGGED_POTENTIAL_REVISION for side-by-side human review. Negative-balance credit notes are classified as CREDIT_NOTE. |
| Q-07 | High | Finance Manager / AP Manager | CLOSED | AP Clerks can edit line items and tax rates, select a mandatory correction reason and click Re-Validate. Full change history is audited. |
| Q-08 | Critical | Dave — Lead Cloud Architect | CLOSED | Azure East US 2 is the approved primary region. Azure OpenAI / Foundry deployments, SQL, Blob and Log Analytics must reside there. Cross-region data egress is prohibited. |
| Q-09 | Critical | Compliance Representative / Dave | CLOSED | Client's approved policy retains invoices and financial audit logs for seven years under immutable storage policies. Personal contact data may be pseudonymized upon verified request. Core invoice records remain intact under the stated legal-retention basis. |
| Q-10 | High | Dave / IT Operations | CLOSED | 99.5% uptime during Monday–Friday, 8 AM–8 PM US Eastern Time, observing EST/EDT. Planned Sunday maintenance from 12 AM–4 AM EST with 48 hours' notice and Azure platform-level disruptions are excluded. |
| Q-11 | Critical | Business Sponsor / Consultant | CLOSED | Prototype in Weeks 3–4: 50 invoices from 3–5 vendors in development/sandbox. Production pilot in Weeks 8–10: 300 invoices across 15 vendors in enterprise Azure staging. |
| Q-12 | High | Business Sponsor / Consultant | CLOSED | 30-day hypercare starts the first business day after formal pilot acceptance. Severity 1: acknowledgement within 4 hours, fix/workaround within 24 hours. Severity 2/3: response within 2 business days. Bugs, prompt adjustments and crashes are covered; new features excluded. |
| Q-13 | Critical | Business Sponsor / Consultant | CLOSED | Fixed consulting fee: $36,000. Four milestone payments, five-business-day review period per milestone and approved change orders at $150/hour for out-of-scope work. |
| Q-14 | Critical | Finance Team / Consultant | CLOSED | Finance team supplies human-verified ground-truth JSON for all 300 invoices in Azure Blob. Consultant supplies automated evaluation script for batch inference and comparison, reporting precision, recall and STP. Acceptance follows Q-01 targets. |

## Detailed Commercial Resolution — Q-13

**Total Consulting Fee: USD $36,000**

| Milestone | Payment | Amount | Target |
|---|---:|---:|---|
| M1 — BRD sign-off and environment setup | 20% | $7,200 | Week 1 |
| M2 — Prototype delivery and successful demo | 30% | $10,800 | Week 4 |
| M3 — Production Pilot deployment in Azure | 30% | $10,800 | Week 8 |
| M4 — Pilot sign-off and completion of 30-day hypercare | 20% | $7,200 | Week 12 |

**Review Period:** Five business days per milestone.

**Change Control:** Out-of-scope work requires an approved Change Order at USD $150/hour.

**Infrastructure and AI token costs:** Billed directly to the client's Azure tenant, outside the consulting fee.

## Resolution Governance

1. All 14 issues are recorded as closed based on the supplied client decisions.
2. Resolutions must be incorporated into the relevant project documents.
3. Any subsequent change to an approved resolution must be recorded through change control.
4. Closed issues must retain their resolution history for traceability.
5. Any implementation detail still requiring validation must be tracked in the relevant technical design or delivery risk register.

## Sign-Off Record

| Role | Name / Title | Status | Date |
|---|---|---|---|
| Business Sponsor | Head of Global Finance Operations | APPROVED | Today |
| Technical Approver | Dave M. — Lead Cloud Architect | APPROVED | Today |
| Lead Consultant | AI Engineering Consultant | ACCEPTED | Today |

**Register Status:** All 14 issues CLOSED.