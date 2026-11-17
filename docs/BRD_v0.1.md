# Business Requirements Document (BRD)

## Project: Enterprise AP Invoice Automation Platform

**Document Version:** 1.0 (Reconciled Baseline)  
**Document Status:** Approved Baseline — Reconciled with OICR-001 v2.0  
**Project Type:** Enterprise AI Automation  
**Prepared By:** AI Engineering Consultant  
**Business Sponsor:** Head of Global Finance Operations  
**Technical Approver:** Dave M. — Lead Cloud Architect  
**Agreed Budget:** USD $36,000 (fixed consulting and development fee)  
**Target Delivery:** Week 4 (Prototype); Week 8 (Production Pilot); Week 12 (Pilot Sign-off & Hypercare Completion)

---

## 1. Executive Summary

The client intends to develop an AI-powered Accounts Payable (AP) Invoice Automation Platform to reduce manual invoice-processing effort, improve extraction accuracy, detect duplicate invoices, validate financial information and provide an auditable invoice-processing workflow.

The existing invoice-processing workflow relies heavily on manual data entry and legacy OCR/rule-based extraction. These systems struggle with scanned documents, changing invoice layouts, irregular line-item tables and international supplier formats.

The proposed solution will automate invoice ingestion, data extraction, business validation, duplicate detection and exception handling, while retaining human oversight for low-confidence or exceptional cases.

The initial release will support PDF, JPG, PNG and XLSX files, with TIFF support deferred to Phase 2.

The system will integrate with the client's Azure environment and provide validated structured invoice data in an Azure SQL staging database. Direct SAP posting is explicitly excluded from Phase 1.

---

## 2. Business Background and Problem Statement

### 2.1 Current Business Situation

The organization processes approximately 8,000–10,000 vendor invoices every month, with volumes reaching approximately 15,000 during peak quarters.

Invoices arrive through email and vendor portals in different formats, languages and layouts.

AP employees manually:
- Open invoice documents.
- Read vendor and invoice information.
- Extract header and line-item details.
- Verify purchase order information.
- Calculate and verify tax amounts.
- Perform currency conversions.
- Enter invoice information into internal systems.

### 2.2 Existing Challenges

The existing OCR and rule-based systems experience approximately 30–40% failure rates.

Major business problems include:

1. High manual processing effort.
2. Poor extraction reliability across different invoice layouts.
3. Difficulty processing scanned documents and irregular tables.
4. Duplicate payment risks.
5. Tax and currency calculation errors.
6. Lack of comprehensive audit trails.
7. Limited real-time financial visibility.

Complex invoices can take approximately 10–15 minutes to process manually.

---

## 3. Business Objectives

The project aims to achieve the following outcomes:

| ID | Business Objective | Target | Notes / Alignment |
|---|---|---|---|
| BO-001 | Reduce manual invoice-processing effort | 5x–10x improvement | Replaces manual data entry with AI-assisted extraction |
| BO-002 | Improve header extraction accuracy | $\ge95\%$ macro-average | Hard floor of $\ge92\%$ on critical fields (Tax ID, Invoice #, Date, Total) |
| BO-003 | Improve line-item extraction accuracy | $\ge90\%$ | Line-level extraction across items, quantities, unit prices, totals |
| BO-004 | Increase straight-through processing (STP) | **Business Objective:** 70% STP<br>**Pilot Acceptance Threshold:** 65% STP | 70% represents the desired long-term business outcome; 65% is the agreed contractual pilot threshold across the 300 pilot invoices |
| BO-005 | Detect duplicate invoices | Composite business-key detection | Identifies duplicates, potential revisions, and credit notes |
| BO-006 | Improve financial validation | Tax, totals, rounding, and PO checks | US sales tax, UK/DE/ES VAT, $\pm0.02$ line / $\pm0.05$ invoice tolerance |
| BO-007 | Improve auditability | Complete human and agent action history | Full audit logging of all extractions, edits, and reason codes |
| BO-008 | Improve exception management | Human review for flagged invoices | Tri-tiered confidence review (<80%, 80–89%, $\ge90\%$) and exception queue |

> [!NOTE]
> **STP Target Alignment:** The client's long-term business objective is to achieve **70% straight-through processing**. The contractual acceptance threshold for the production pilot is agreed at **65% STP** across the 300-invoice pilot dataset. This distinction ensures the client retains 70% as the target business vision while establishing 65% as the formal contractual acceptance baseline for pilot sign-off. All measurement definitions and acceptance criteria have been confirmed and baseline-approved per OICR-001 v2.0.

---

## 4. Stakeholders and User Groups

| Stakeholder | Responsibilities |
|---|---|
| Business Sponsor | Business requirements, budget, priorities and final milestone sign-off |
| Lead Cloud Architect — Dave | Technical architecture, security compliance and Azure deployment approval |
| AP Clerks | Upload, review, correct and approve invoices |
| Finance Managers | High-value approvals, exception reports and financial oversight |
| System Administrators / IT | Reliability, monitoring, token usage, latency and audit logs |
| AI Engineering Consultant | Requirements documentation, development, testing and delivery |

---

## 5. Project Scope

### 5.1 Phase 1 — Included Scope

The initial project scope includes:

1. Invoice file ingestion.
2. Support for PDF, scanned PDF, JPG, PNG and XLSX.
3. English, German and Spanish invoice processing.
4. Header-level invoice extraction.
5. Complete line-item extraction.
6. Invoice validation against business rules.
7. Duplicate invoice detection.
8. Human review and correction workflow.
9. Finance approval workflow.
10. Structured JSON export.
11. Azure SQL staging database storage.
12. Audit logging.
13. Streamlit-based internal user interface.
14. Azure-based deployment and pilot validation.

### 5.2 Phase 2 — Excluded Scope

The following items are explicitly excluded from Phase 1:

- TIFF invoice support.
- Direct automated SAP posting.
- Full automated SAP synchronization.
- Features not agreed in the Phase 1 scope.
- Ongoing managed support beyond the included 30-day warranty/hypercare period.

Phase 2 requirements will be assessed separately.

---

## 6. Business Requirements

### 6.1 Invoice Ingestion

**BR-001: Multiple Invoice Formats**

The system must accept:
- PDF (searchable and scanned)
- JPG
- PNG
- XLSX

TIFF support will be considered in Phase 2.

**BR-002: International Invoice Support**

The system must process invoices primarily in English, with additional support for German and Spanish.

It must accommodate US and Western European date and number conventions.

**BR-003: Handwritten Content**

The system must tolerate occasional handwritten content, estimated at approximately 5% of documents, without causing system crashes.

### 6.2 Invoice Data Extraction

**BR-004: Header-Level Extraction**

The system must extract:

- Vendor Name
- Vendor Tax ID / VAT
- Invoice Number
- Invoice Date
- Due Date
- Purchase Order Number
- Subtotal
- Total Tax Amount
- Total Amount
- Currency

**BR-005: Line-Item Extraction**

The system must extract every invoice line item, including:

- Line Description
- Quantity
- Unit Price
- Line Total
- Line Tax Rate

Line-item extraction is mandatory to support downstream purchase order matching.

### 6.3 Accuracy and Confidence

**BR-006: Extraction Accuracy Targets (Q-01)**

The agreed extraction accuracy thresholds for the production pilot are:

- **Header Fields:** Macro-average accuracy of **$\ge95\%$** across all pilot invoices, with a mandatory hard floor of **$\ge92\%$** on critical fields (Vendor Tax ID, Invoice Number, Invoice Date, Total Amount).
- **Line-Item Fields:** Extraction accuracy of **$\ge90\%$** across all line items (Description, Quantity, Unit Price, Line Total, Line Tax Rate).

**BR-007: Confidence-Based Review and Routing (Q-03)**

The system evaluates confidence scores for all extracted fields and applies a tri-tiered routing workflow:

1. **High Confidence ($\ge90\%$):** Fields with extraction confidence $\ge90\%$ that pass all financial and business validation checks are eligible for expedited **one-click AP clerk approval**.
2. **Medium Confidence (80%–89%):** Fields with extraction confidence between 80% and 89% are displayed with a **light-yellow highlight** in the review interface, prompting the AP clerk for visual verification before approval.
3. **Low Confidence (<80%):** Any field with extraction confidence below 80% automatically triggers a `REQUIRES_APPROVAL` flag, is displayed with an **amber/red highlight**, and routes the invoice to the **Human Exception Queue** for mandatory manual inspection and verification.

**BR-008: Straight-Through Processing (STP) Targets (Q-01)**

- **Business Objective:** The long-term desired business outcome is to achieve at least **70%** straight-through processing across total organizational invoice volumes.
- **Pilot Acceptance Threshold:** The contractual acceptance threshold for the production pilot is set at **$\ge65\%$** straight-through processing across the 300-invoice pilot dataset without requiring human intervention.

### 6.4 Financial Validation

**BR-009: Line-Item Calculation and Rounding Tolerance (Q-05)**

The system must validate line-item arithmetic:

$$\text{Line Item Total} = \text{Quantity} \times \text{Unit Price}$$

- **Permitted Rounding Tolerance:** **$\pm0.02$** per line item to accommodate minor rounding discrepancies in vendor calculations.

**BR-010: Invoice Total Validation and Rounding Tolerance (Q-05)**

The system must validate header-level arithmetic:

$$\text{Subtotal} + \text{Total Tax Amount} = \text{Total Invoice Amount}$$

- **Permitted Rounding Tolerance:** **$\pm0.05$** at the invoice header level.

**BR-011: Multi-National Tax Rate Validation (Q-05)**

The system must compare calculated tax against stated invoice amounts and validate applicable country-specific tax rules:

- **United States:** US sales tax validated against vendor jurisdiction rates maintained in the Vendor Master table.
- **United Kingdom (UK VAT):** Standard rate of **20%**, reduced rate of **5%**, and zero rate of **0%**.
- **Germany (MwSt):** Standard rate of **19%**, reduced rate of **7%**, and zero rate of **0%**.
- **Spain (IVA):** Standard rate of **21%**, reduced rate of **10%**, super-reduced rate of **4%**, and zero rate of **0%**.
- **Tax Exemptions and Reverse-Charge:** Validated tax exemptions and EU reverse-charge transactions are accepted without triggering tax rejection, provided they contain valid annotations and a verified Vendor Tax ID / VAT number.

**BR-012: Date Format and Locale Interpretation (Q-04)**

The system must resolve date ambiguities using the Vendor Master Locale mapping:
- **US Vendors:** Formatted as `MM/DD/YYYY`.
- **European Vendors (UK, Germany, Spain):** Formatted as `DD/MM/YYYY`.
- Invoices from unlisted vendors or with indeterminate dates must be flagged for clerk verification.

**BR-012a: Currency Conversion**

Daily exchange rates must be obtained from the existing Azure SQL exchange-rate table, synchronized with European Central Bank (ECB) rates. The conversion date must match the invoice date.

### 6.5 Duplicate Detection

**BR-013: Duplicate Invoice Identification (Composite Business Key)**

The system must identify duplicate invoices using a composite business key:

$$\text{Composite Key} = \text{Hash}(\text{Vendor Tax ID} + \text{Invoice Number} + \text{Total Amount})$$

The solution must recognize re-scanned or re-submitted identical invoices and flag them as `DUPLICATE_INVOICE`.

**BR-013a: Invoice Revision Handling (Q-06)**

Invoices received with an identical Invoice Number but a modified Total Amount, or bearing a revision suffix (e.g., `-REV`, `Rev1`, `v2`), must not be silently rejected or overwritten. The system must:
1. Assign the status `FLAGGED_POTENTIAL_REVISION`.
2. Present a side-by-side comparison screen in the Streamlit UI displaying the original invoice and the revised submission.
3. Require AP clerk review to confirm replacement or flag as an unauthorized duplicate.

**BR-013b: Credit Note Classification (Q-06)**

Incoming documents featuring negative line-item balances or negative total amounts must be classified as `CREDIT_NOTE`:
1. Distinguish credit notes from calculation errors or duplicate invoices.
2. Route credit notes to the designated credit-note matching and netting workflow against original purchase orders or open vendor balances.

### 6.6 Approval and Exception Management

**BR-014: Finance Manager Approval Thresholds**

Manager approval is mandatory when:
- Invoice total exceeds USD $10,000; OR
- Extracted invoice total differs from the Purchase Order (PO) amount by more than 5%.

**BR-015: AP Clerk One-Click Approval (Q-03)**

Invoices under USD $10,000 with:
- Extraction confidence **$\ge90\%$** across all header and line-item fields; AND
- Successful automated financial, tax, and PO validation checks,

may be approved by AP clerks via an expedited one-click approval process. Invoices with confidence between 80% and 89% require visual clerk inspection before approval. Invoices with any field below 80% route to the Human Exception Queue.

**BR-016: AP Clerk Manual Editing Capabilities (Q-07)**

AP clerks must have full editing access in the review UI to correct:
- Header fields (Invoice Number, Invoice Date, Due Date, PO Number).
- Line-item fields (Description, Quantity, Unit Price, Line Total, Line Tax Rate).
- Applicable tax codes and exemption flags.

**BR-017: Mandatory Correction Reason Codes (Q-07)**

Any manual adjustment made to invoice values (specifically line totals, tax rates, subtotals, or grand totals) requires the clerk to select a mandatory reason code from a predefined dropdown, with optional explanatory notes:
- `OCR Misread / Scan Distortion`
- `Vendor Rounding Discrepancy`
- `Tax Code / Exemption Override`
- `Vendor Discount Applied`
- `Other (Mandatory Comment Required)`

**BR-018: Tax Mismatch Exception and Re-Validation Workflow (Q-05, Q-07)**

1. Invoices failing automated tax calculation or rate validation are assigned the status `REJECTED_TAX_MISMATCH` and routed to the Human Exception Queue.
2. An AP clerk inspects the tax discrepancy, reviews vendor annotations (e.g., reverse charge or zero-rate qualification), and makes necessary edits or tax code assignments.
3. The clerk selects a mandatory correction reason code and clicks **"Re-Validate"**.
4. The system re-executes all financial and tax validation rules against the modified values. If the validation passes, the status transitions to `VALIDATED` (or `REQUIRES_MANAGER_APPROVAL` if over $10,000), clearing the exception.
5. All edit actions, previous values, new values, user identity, timestamps, and reason codes are written to an immutable audit log.

**BR-019: SAP Integration Boundary**

Phase 1 explicitly excludes direct automated SAP posting. Validated invoice data must be exported as structured JSON and stored in the Azure SQL staging database for manual batch ingestion and verification.

### 6.7 Performance and Availability

**BR-020: Single Invoice Processing**

Single invoice uploads through the user interface must return complete extraction and validation results within **15 seconds**.

**BR-021: Batch Processing**

A batch of 100 invoices must be processed asynchronously within **20–25 minutes**.

**BR-022: Monthly Peak Handling**

The platform must support:
- 8,000–10,000 invoices per month under normal operating conditions.
- Up to 15,000 invoices per month during peak financial quarters.
- Approximately 50% of monthly volume arriving during the final four business days of the month.
- Concurrent bulk uploads of 50–100 invoices without degradation.

**BR-023: Queue Processing**

Invoices queued for asynchronous batch processing must not remain unprocessed for more than **one hour**.

**BR-024: Availability, Maintenance Schedule, and SLA Exclusions (Q-10)**

- **Target Uptime:** **99.5% availability** during designated business hours:
  - **Operating Window:** Monday through Friday, 8:00 AM to 8:00 PM US Eastern Time (observing EST/EDT as applicable).
- **Approved Scheduled Maintenance Windows:**
  - Scheduled maintenance is restricted to **Sundays between 12:00 AM and 4:00 AM EST**.
  - Any scheduled maintenance requires a minimum of **48 hours' prior written notice** to client IT operations.
- **SLA Exclusions:**
  - Planned Sunday maintenance windows meeting the notice criteria.
  - Upstream Microsoft Azure platform-level outages, regional infrastructure disruptions, or Azure OpenAI service incidents occurring outside the solution boundary.

### 6.8 Security and Data Governance

**BR-025: Data Residency and Azure East US 2 Boundary (Q-08)**

All data, storage, and AI compute resources must strictly reside within **Azure East US 2**:
- Azure OpenAI / Microsoft Foundry model deployments.
- Azure SQL staging database.
- Azure Blob Storage (invoice files and JSON payloads).
- Azure Log Analytics and Application Insights telemetry.
- **Cross-region data egress is strictly prohibited.**

**BR-026: Seven-Year Retention Policy and GDPR Governance (Q-09)**

- **Statutory Retention Policy:** Original invoice files, extracted JSON payloads, and financial audit logs must be retained for **seven (7) years** under Azure Blob Storage **immutable storage policies** (time-based WORM / Write Once, Read Many) to comply with statutory commercial, tax, and audit requirements.
- **GDPR / Privacy Handling:** Upon a verified data subject erasure request under GDPR Article 17, personal contact data (e.g., individual employee names, direct email addresses, and phone numbers) may be **pseudonymized** in the database and audit records, while core commercial transaction records (vendor corporate name, Tax ID, line items, monetary amounts) remain intact under the client's legal-retention basis.
- **Governance & Legal Disclaimer:**
  > [!IMPORTANT]
  > **Legal Disclaimer & Validation Responsibility:** The client's legal interpretation (retaining financial records for seven years under statutory obligation while pseudonymizing personal contact data upon verified request) is recorded as a **formal business and compliance decision of the client**, and **does not constitute an independent legal opinion from the consulting team**. During implementation, the client's internal privacy, compliance, and legal teams must formally review and validate the specific retention policy, immutable storage configurations, and pseudonymization mechanism prior to production deployment.

**BR-027: Sensitive Information Access**

Only authorized AP staff and Finance Managers may access vendor bank account information and tax IDs via Entra ID RBAC.

**BR-028: Sensitive Data Masking**

Sensitive financial identifiers and bank details must be masked in general application logs and observability metrics.

**BR-029: Enterprise Identity and Access**

The platform must integrate with Microsoft Entra ID for role-based access control (AP Clerk, Finance Manager, System Administrator).

**BR-030: Key Management and Managed Identities**

Hardcoded secrets and static API keys are strictly prohibited. The architecture must utilize Azure Managed Identities and Azure Key Vault for keyless authentication across all services.

**BR-031: Comprehensive Auditability**

The platform must log immutable audit records for both AI agent actions (ingestion, model classification, confidence scores, validation checks) and human actions (manual edits, reason codes, approvals, rejections).

**BR-032: Compliance Standards**

The platform architecture and operational controls must align with the client's SOC 2 Type II and GDPR enterprise policies.

**BR-033: AI Boundary and Data Privacy**

External third-party AI APIs or public endpoints are prohibited. All model inference must occur strictly within the client's private Azure enterprise tenant.

---

## 7. User Experience Requirements

The initial user interface must support:

- Invoice drag-and-drop upload.
- Batch invoice uploads.
- Extracted field display.
- Highlighting of low-confidence fields.
- Manual field correction.
- Approval and rejection actions.
- Human exception queue.
- Review of invoice validation results.

The client has expressed a preference for Streamlit as the internal user interface.

---

## 8. Delivery Milestones

The delivery schedule is structured across four sequential milestones spanning 12 weeks:

### 8.1 Milestone Schedule (Q-11, Q-13)

| Milestone | Deliverable Scope | Target Timeline | Payment (% / USD) |
|---|---|---|---|
| **M1 — Architecture Baseline & Setup** | BRD sign-off, Azure East US 2 environment provisioning, Entra ID setup, repository and pipeline baseline | Week 1 | 20% ($7,200) |
| **M2 — Prototype Delivery & Demo** | **50-invoice prototype** across 3–5 representative vendors in Azure sandbox; Streamlit UI; Orchestrator agent; header/line extraction; basic duplicate detection; live demo | Week 4 | 30% ($10,800) |
| **M3 — Production Pilot Deployment** | **300-invoice production pilot** across 15 vendors in Azure staging; full validation rules, confidence routing, duplicate & revision handling, exception queue, automated evaluation suite | Week 8 | 30% ($10,800) |
| **M4 — Pilot Sign-Off & Hypercare Completion** | Formal pilot acceptance sign-off, completion of **30-day post-pilot hypercare period**, final knowledge transfer, project closure | Week 12 | 20% ($7,200) |

> [!IMPORTANT]
> **Week 12 Milestone & Hypercare Scheduling:** Milestone 4 includes the successful completion of the **30-day hypercare period**. To ensure that the 30-day hypercare period finishes by **Week 12**, formal pilot acceptance and sign-off (Milestone 3) must take place at **Week 8** (accommodating the agreed 5-business-day review window), allowing the 30-calendar-day hypercare period to run from Week 8 through Week 12.

### 8.2 Hypercare Scope and Support SLA (Q-12)

- **Commencement:** Hypercare begins on the first business day following formal pilot acceptance (Milestone 3 sign-off at Week 8).
- **Duration:** 30 calendar days (concluding by Week 12).
- **Scope of Support:** Prompt refinements, bug fixes, edge-case tuning, and system stability issues. Scope explicitly excludes new feature requests or out-of-scope enhancements.
- **Service Level Agreements (SLAs):**
  - **Severity 1 (Critical / System Outage / Extraction Blocker):** Acknowledgement within **4 hours**; fix or viable workaround delivered within **24 hours**.
  - **Severity 2 & 3 (Medium / Low / Minor Discrepancy):** Response and triage within **2 business days**.

### 8.3 Pilot Dataset Specification (Q-02, Q-11)

The production pilot evaluation dataset consists of **300 sanitized invoices** representing **15 distinct suppliers**:
- **Existing Dataset:** 200 sanitized invoices previously provided by the client (including 30 historical complex/edge-case invoices).
- **Additional Dataset (Q-02):** **100 additional sanitized invoices** to be provided by the client AP team within **10 calendar days** of project kickoff, expanding vendor coverage and layout variability.

---

## 9. Acceptance Criteria

The formal acceptance criteria for the Production Pilot (Milestone 3) and Project Sign-Off (Milestone 4) are defined below, replacing previous draft assumptions with approved, quantitative targets (Q-01, Q-12, Q-14):

| Criteria ID | Category | Metric / Requirement | Acceptance Threshold | Verification Method |
|---|---|---|---|---|
| **AC-001** | Header Extraction | Macro-average accuracy across all header fields on the 300 pilot invoices | **$\ge95\%$** macro-average | Automated evaluation script comparing model inference against ground-truth JSON (Q-14) |
| **AC-002** | Critical Field Floor | Extraction accuracy on critical header fields (Vendor Tax ID, Invoice Number, Invoice Date, Total Amount) | **$\ge92\%$ hard floor** per critical field | Automated evaluation script field-level scoring (Q-01) |
| **AC-003** | Line-Item Extraction | Extraction accuracy across all line items (Description, Quantity, Unit Price, Line Total, Tax Rate) | **$\ge90\%$** overall line accuracy | Automated evaluation script line-item matching (Q-01) |
| **AC-004** | Straight-Through Processing | Invoices processed end-to-end without requiring manual intervention | **$\ge65\%$ STP** across 300 pilot invoices | Automated evaluation report calculation (Q-01); advancing toward 70% long-term objective |
| **AC-005** | Platform Stability | Batch processing stability under load | **Zero unhandled crashes** or memory exceptions during 300-invoice batch execution | Azure Application Insights logs and system execution telemetry |
| **AC-006** | User Interface Usability | AP Clerk operational efficiency and workflow satisfaction | **Affirmative written sign-off** from at least two (2) active AP clerks confirming interface usability and time savings | Formal AP clerk evaluation survey / sign-off document |
| **AC-007** | Automated Evaluation Suite | Ground-truth benchmark verification | Human-verified ground-truth JSON supplied by Finance Team in Azure Blob; Consultant automated evaluation script outputs precision, recall, accuracy, and STP | Finance Team & Consultant joint evaluation execution (Q-14) |
| **AC-008** | Hypercare Completion | Resolution of all critical defects post-pilot | 30 calendar days completed; zero unresolved Severity 1 issues; prompt optimizations executed | Sign-off at Week 12 by Business Sponsor (Q-12) |

---

## 10. Commercial Requirements

### 10.1 Agreed Consulting Fee (Q-13)

The agreed fixed consulting and development fee is:

$$\text{\textbf{USD \$36,000}}$$

This fixed fee encompasses all professional services, engineering, architecture, configuration, testing, and hypercare support outlined in the Phase 1 scope.

### 10.2 Milestone Payment Schedule (Q-13)

Payments are tied strictly to verified milestone deliverables:

| Milestone | Deliverable Description | Target Week | Fee % | Amount (USD) |
|---|---|---|---:|---:|
| **Milestone 1** | BRD sign-off and Azure East US 2 environment setup | Week 1 | 20% | $7,200 |
| **Milestone 2** | 50-invoice prototype delivery and successful demo | Week 4 | 30% | $10,800 |
| **Milestone 3** | 300-invoice production pilot deployment in Azure | Week 8 | 30% | $10,800 |
| **Milestone 4** | Pilot sign-off and completion of 30-day hypercare | Week 12 | 20% | $7,200 |
| **Total** | | | **100%** | **$36,000** |

### 10.3 Milestone Review Period and Change Governance (Q-13)

- **Deliverable Review Window:** The client has a review period of **five (5) business days** following delivery of each milestone deliverable to inspect and provide formal sign-off or detailed defect reports.
- **Change Control Policy:** Any work outside the agreed Phase 1 functional and technical scope requires an approved formal Change Order, billed at the agreed hourly rate of **USD $150 / hour**.
- **Excluded Infrastructure Costs:** All Microsoft Azure cloud infrastructure costs (Azure OpenAI token consumption, Azure SQL, Blob Storage, Compute, App Service) are billed directly to the client's Azure enterprise subscription and are excluded from the $36,000 consulting fee.

### 10.4 Hypercare Terms and Support Governance (Q-12)

- The consulting engagement includes **30 calendar days of hypercare support** following Milestone 3 acceptance (running from Week 8 through Week 12).
- Supported items include bug fixes, runtime crashes, and prompt adjustments. Out-of-scope feature requests and ongoing managed services beyond Week 12 require a separate service retainer agreement.

---

## 11. Assumptions

1. The client has legal authority to provide the sanitized invoice dataset.
2. The client will provide the required Azure resources and access.
3. Vendor master data and exchange-rate information are available in Azure SQL.
4. The client will make business and technical stakeholders available for reviews.
5. The client will provide the necessary PO and tax-validation business rules.
6. The client will review and approve project deliverables within agreed review periods.
7. External AI model APIs will not be required.
8. The project will use the agreed Phase 1 scope as its delivery baseline.

---

## 12. Constraints

1. **Regional and Boundary Constraints (Q-08):** All compute, data, Azure OpenAI / Foundry models, Azure SQL staging tables, Azure Blob storage, and monitoring must reside strictly within **Azure East US 2**. Cross-region data egress or external network calls are prohibited.
2. **Statutory Retention & Privacy Constraints (Q-09):** Invoices and financial audit logs must be retained for seven (7) years under Azure immutable storage policies. Personal data must support pseudonymization on verified GDPR erasure request. The client's legal/privacy team must formally validate this configuration during implementation.
3. **Fixed Commercial & Schedule Constraints (Q-13):** The project is bound to the fixed consulting fee of **USD $36,000** and a strict **12-week schedule** (Week 8 pilot acceptance; Week 12 hypercare completion). Out-of-scope work requires an approved Change Order at **USD $150/hour**.
4. **Integration Scope Limits:** Direct automated posting to SAP is strictly excluded from Phase 1; output is delivered to the Azure SQL staging table.
5. **Format Limits:** Ingestion is limited to PDF, JPG, PNG, and XLSX. TIFF invoice processing is deferred to Phase 2.
6. **Keyless Security:** Static credentials and third-party API keys are prohibited; all authentication must leverage Microsoft Entra ID Managed Identities.

---

## 13. Dependencies

| Dependency ID | Description | Responsible Party | Required By | Impact if Delayed |
|---|---|---|---|---|
| **DEP-001** | Provisioning of Azure East US 2 sandbox & staging environments, Entra ID groups, and Managed Identities | Dave / Client IT Operations | Week 1 | Delays M1 completion and prototype pipeline deployment |
| **DEP-002** | Provisioning of 100 additional sanitized invoices (reaching 300 total across 15 vendors) (Q-02) | Client AP Team | Within 10 calendar days of kickoff | Blocks completion and full benchmarking of the 300-invoice pilot dataset |
| **DEP-003** | Provisioning of human-verified ground-truth JSON files for all 300 pilot invoices in Azure Blob (Q-14) | Client Finance Team | Week 6 | Blocks automated evaluation script execution and M3 acceptance scoring |
| **DEP-004** | Development and deployment of automated evaluation script for batch scoring against ground-truth (Q-14) | AI Engineering Consultant | Week 7 | Required to generate precision, recall, accuracy, and STP metrics for M3 |
| **DEP-005** | Vendor Master Locale table (US vs European date formats) and tax jurisdiction mapping (Q-04, Q-05) | Dave / Client Finance Team | Week 2 | Delays implementation of multi-national tax and date validation rules |
| **DEP-006** | Daily exchange-rate feed synchronization in Azure SQL (ECB rates) | Dave / Client IT Operations | Week 2 | Impacts multi-currency invoice conversion validation |
| **DEP-007** | Stakeholder availability for weekly sprint reviews and 5-day milestone deliverable reviews | Business Sponsor & Dave | Ongoing (Weeks 1–12) | Schedule slippage beyond Week 12 hypercare completion |

---

## 14. Key Business Risks

| Risk | Potential Impact |
|---|---|
| Poor-quality scanned invoices | Lower extraction accuracy |
| Ambiguous date formats | Incorrect invoice dates |
| Complex international tax rules | Incorrect validation decisions |
| Insufficient pilot data | Inaccurate pilot evaluation |
| Azure access delays | Delivery schedule slippage |
| Peak month-end volume | Processing delays |
| Sensitive data exposure | Compliance and security impact |
| Unclear approval rules | Incorrect invoice routing |

---

## 15. Open Issues & Clarifications

All fourteen (14) open business, technical, operational, and commercial questions identified during the draft v0.1 requirements elicitation phase have been formally resolved and approved by client stakeholders.

For the full historical audit trail, rationale, discussion notes, and individual sign-off records, refer to:
$$\text{\textbf{OICR-001 — Open Issues \& Clarifications Register (Version 2.0, Status: CLOSED)}}$$

### Summary of Reconciled Issues

- **Q-01 (Accuracy & STP):** Incorporated into Sections 3, 6.3, and 9 ($\ge95\%$ header macro-average, $\ge92\%$ floor, $\ge90\%$ line-item, 70% long-term STP objective vs. 65% pilot acceptance threshold).
- **Q-02 (Dataset Expansion):** Incorporated into Sections 8.3 and 13 (AP team supplies 100 additional sanitized invoices within 10 days).
- **Q-03 (Confidence Routing):** Incorporated into Sections 6.3 and 6.6 ($\ge90\%$ one-click clerk approval, 80%–89% visual check, <80% Human Exception Queue).
- **Q-04 (Date Formatting & Locale):** Incorporated into Section 6.4 (Vendor Master Locale table for US MM/DD/YYYY vs. EU DD/MM/YYYY).
- **Q-05 (Tax Rules & Rounding):** Incorporated into Section 6.4 (US sales tax, UK/DE/ES VAT rates, exemptions/reverse-charge, $\pm0.02$ line / $\pm0.05$ invoice tolerance).
- **Q-06 (Revisions & Credit Notes):** Incorporated into Section 6.5 (`FLAGGED_POTENTIAL_REVISION` side-by-side review; `CREDIT_NOTE` classification).
- **Q-07 (Manual Editing & Re-Validation):** Incorporated into Section 6.6 (clerk line/tax editing, mandatory reason code, Re-Validate action, audit log).
- **Q-08 (Azure East US 2 Residency):** Incorporated into Sections 6.8 and 12 (all services and data in East US 2; cross-region egress prohibited).
- **Q-09 (Seven-Year Retention & GDPR):** Incorporated into Sections 6.8 and 12 (7-year WORM storage; personal data pseudonymization; client legal validation).
- **Q-10 (Availability & Maintenance):** Incorporated into Section 6.7 (99.5% business hours uptime; Sunday 12 AM–4 AM EST maintenance with 48h notice; Azure platform exclusions).
- **Q-11 (Prototype & Pilot Scope):** Incorporated into Section 8 (50-invoice prototype in Weeks 3–4; 300-invoice pilot in Weeks 8–10).
- **Q-12 (Hypercare Support & SLA):** Incorporated into Sections 8.2 and 10.4 (30-day hypercare from Week 8 to Week 12; Sev 1: 4h ack / 24h fix; Sev 2/3: 2 business days).
- **Q-13 (Commercial Pricing & Milestones):** Incorporated into Section 10 ($36,000 fixed fee, 4 milestone payments, 5-day review, $150/hr change order rate).
- **Q-14 (Ground-Truth & Evaluation Suite):** Incorporated into Sections 9 and 13 (Finance team provides 300 ground-truth JSONs; Consultant provides automated evaluation script).

**Current Status:** All 14 issues CLOSED. Baseline requirements locked. Any further scope changes require formal Change Control at USD $150/hour.

---

## 16. Approval and Sign-Off

This Business Requirements Document has been updated and formally approved as the delivery baseline, reconciling all client decisions from OICR-001 v2.0.

| Role | Name / Title | Status | Date |
|---|---|---|---|
| **Business Sponsor** | Head of Global Finance Operations | **APPROVED** | Baseline Sign-Off |
| **Technical Approver** | Dave M. — Lead Cloud Architect | **APPROVED** | Baseline Sign-Off |
| **Lead Consultant** | AI Engineering Consultant | **ACCEPTED** | Baseline Sign-Off |

**Document Status:** Approved Baseline v1.0 — Reconciled with OICR-001 v2.0  
**Next Document:** Product Requirements Document (PRD) and Architecture Design Document (ADD).
