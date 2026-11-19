# Phase 11 Codebase Explained: The Bank's Modern Lobby, Smart Teller Screens, Side-by-Side Fraud Desk & Traffic-Light Safety Controls

> **Audience:** Recruiters, hiring managers, non-technical stakeholders, and interview board members.  
> **Purpose:** Plain-English walkthrough of everything built in **Phase 11 (Streamlit UI — P11-1 through P11-7)**—how we turned our behind-the-scenes AI & accounting engine into a clean, safe, human-friendly **5-screen web workspace** where AP Clerks, Finance Managers, and Auditors can drag-and-drop invoices, compare documents side-by-side, clear exceptions, review un-erasable audit timelines, and stay automatically protected by traffic-light confidence colours and role-based button controls.

---

## 1. Executive Summary: Why Phase 11 Matters

Think back to the high-security digital bank we built across Phases 1 through 10:
- **Phases 1–4:** Built the building, the ledger vault, badge scanners, security cameras, and the 7-year write-once document safe.
- **Phases 5–6:** Built the express drop-off counter, conveyor belt, and AI reading room (GPT-4o-mini & GPT-4o Vision).
- **Phases 7–8:** Built the 5 accounting auditors, the traffic-light confidence sorter, the unbreakable workflow switchboard, and the `$10,000` executive escalation gate.
- **Phase 9:** Opened the secure behind-the-counter API windows so approved software could re-validate edits, sign off payments, and inspect audit trails.
- **Phase 10:** Stocked the bank with 300 realistic international invoices across 15 vendors (US, UK, Germany, Spain) and human-verified answer keys.

Before Phase 11, **the entire back office worked—but Sarah (the AP Clerk), Michael (the Finance Manager), and Dave (the System Admin/Auditor) had no visual screens to actually click and work on!** They would have needed developer tools just to upload a PDF or approve a bill.

**Phase 11: Streamlit UI** builds the complete, polished front-of-house workspace in pure Python (zero fragile JavaScript frameworks!) across **seven carefully layered building blocks**:

1. **The Armored Intercom (`src/ui/api_client.py` — P11-1):** The *only* telephone line connecting the front lobby screens to the back-office FastAPI bank. No screen is ever allowed to reach directly into the vault (Azure SQL) or document safe (Azure Blob)—every single click goes over this typed, encrypted, tamper-checked intercom.
2. **Screen 1 · The Express Drop-Off Lobby (`/` — `src/ui/ingestion_dashboard.py` & `src/ui/app.py` — P11-2):** Sarah drags and drops up to 50 PDF, PNG, JPG, or Excel invoices at once. She immediately sees a live summary board (*Total Uploaded, Processing, Passed, Needs Review*) and watches each bill update automatically in real time without hitting refresh.
3. **Screen 2 · The Split-Screen Review Desk (`/workbench/{invoice_id}` — `src/ui/review_workbench.py` — P11-3):** The scanned PDF sits on the left half of the screen (with zoom and multi-page controls) while the extracted fields and editable line-item table sit on the right. If the AI misread a tax number, Sarah edits only that field, picks a mandatory reason code (like `OCR_MISREAD` or `TAX_CODE_OVERRIDE`), and clicks **Re-Validate**.
4. **Screen 3 · The Exception Triage Room (`/exceptions` — `src/ui/exception_queue.py` — P11-4):** Instead of hunting through hundreds of clean bills, staff filter straight to problem bills (*Tax Mismatch, Low Confidence, Duplicate/Revision, Credit Note, High Value > \$10k*), sorted by urgency and elapsed wait time, with safe bulk actions (assign to clerk, refresh status, or manager-only bulk approve).
5. **Screen 4 · The Side-by-Side Fraud & Revision Desk (`/revision/{invoice_id}` — `src/ui/revision_screen.py` — P11-5):** When a vendor sends `INV-1001-REV` after `INV-1001` was already approved, both invoices appear side-by-side—original approved bill (plus who approved it and when) on the left, incoming revision on the right, with text changes highlighted yellow and dollar changes highlighted red.
6. **Screen 5 · The Glass Audit Museum (`/audit/{invoice_id}` — `src/ui/audit_viewer.py` — P11-6):** A strictly read-only, oldest-to-newest chronological timeline showing every AI read, clerk edit, re-validation, and manager sign-off—with zero edit or delete buttons, automatic privacy masking of Tax IDs/IBANs/SSNs, and safe CSV/JSON audit exports.
7. **Traffic-Light Colours & Smart Disappearing Buttons (`src/ui/theme_rbac.py` — P11-7):** One unified brain powering every screen:
   - **Green (`#22c55e`, ≥ 90%):** High confidence — safe for one-click approval.
   - **Light-Yellow (`#fef08a`, 80–89%):** Double-check recommended.
   - **Red (`#ef4444`, < 80%):** Low confidence — manual review required.
   - **Role-Aware Disappearing Approve Button:** If a bill is `$10,000.01` or higher (or has > 5% PO price variance, or is a credit note), the **Approve** button literally *vanishes* for an AP Clerk (not just greyed out—completely hidden!) and displays a clear note that Finance Manager sign-off is required. When Michael (the Finance Manager) signs in, his **Approve (Finance Manager)** button appears.

---

## 2. Real-World Analogy: Walking Through the Bank Lobby

Imagine walking into our digital Accounts Payable bank as a guest on an interview tour:

| Phase 11 Screen / Component | Real-World Bank Analogy | What Non-Technical Users Experience |
|---|---|---|
| **P11-1 · Typed API Client** (`api_client.py`) | Armored Intercom Tube | The *only* channel from the front lobby to the back-office servers. Checks addresses, hides secret badges from logs, and blocks giant responses. |
| **P11-2 · Ingestion Dashboard** (`/`) | Express Drop-Off Counter & Departure Board | Drag-and-drop multiple bills at once, pick a vendor (or Auto-Detect), and watch a live airport-style status board tick from `UPLOADED` → `EXTRACTING` → `VALIDATED`. |
| **P11-3 · Review Workbench** (`/workbench/{id}`) | Split-Screen Clerk Desk | Paper invoice on the left desk mat (zoom + page flip), digital ledger sheet on the right. Only changed numbers are sent back to the auditors with a mandatory reason code. |
| **P11-4 · Exception Queue** (`/exceptions`) | Priority Escalation Inbox | Filter bills by problem type, spot red/yellow/green confidence markers immediately, assign batches to clerks, and let managers batch-approve escalated bills. |
| **P11-5 · Revision Comparison** (`/revision/{id}`) | Dual-Screen Fraud Comparison Desk | Put the already-paid invoice next to the new `-REV` bill. Dollar changes glow red; cross-vendor mix-ups are blocked automatically. |
| **P11-6 · Audit Trail Viewer** (`/audit/{id}`) | Locked Glass Museum Case | Read-only chronological history for auditors. No eraser, no edit button, sensitive bank/tax IDs masked, and safe one-click CSV/JSON export. |
| **P11-7 · Confidence Colours & Role Policy** (`theme_rbac.py`) | Universal Traffic Lights & Keycard Locks | One single rulebook that colours every confidence score identically and physically hides high-value Approve buttons from clerks while keeping managers empowered. |

---

## 3. A Day in the Life: How Three Personas Use Phase 11 Together

1. **8:30 AM — Sarah (AP Clerk) uploads 12 vendor invoices on Screen 1 (`/`):**
   - One accidental `.tiff` scan is caught instantly with a clear explanation (*"TIFF files are not supported"*), while the other 11 valid PDFs/PNGs upload cleanly.
   - Sarah accidentally clicks Upload twice on the same PDF—our automatic digital fingerprint (`Idempotency-Key`) recognizes the duplicate click and shows *"Replayed (Idempotent)"* instead of charging AI credits twice.
   - The live board automatically polls in the background and stops polling as soon as every bill finishes—never wasting server resources.
2. **8:35 AM — Sarah opens Screen 3 (`/exceptions`) and clicks a flagged German bill into Screen 2 (`/workbench/{id}`):**
   - On the left she zooms into the German PDF footer and sees *"Reverse Charge — 0% VAT"*.
   - On the right she checks **EU Reverse Charge**, selects reason code `TAX_CODE_OVERRIDE`, adds a comment, and clicks **Re-Validate**.
   - All 4 accounting checks flip green (`VALIDATED`). Because the bill is `€2,000` (`$2,180` USD — under `$10,000`), Sarah's **Approve (One-Click)** button appears and she signs it off in one click.
3. **8:45 AM — Sarah opens a `$15,000` invoice in Screen 2 (`/workbench/{id}`):**
   - Even though the invoice is clean and green (`96.5%`), the **Approve** button is **completely hidden** for Sarah—instead she sees: *"Requires Finance Manager approval (total \$15,000.00 USD exceeds \$10,000.00 USD clerk threshold)."*
4. **9:00 AM — Michael (Finance Manager) signs in:**
   - His sidebar badge reads **Finance Manager (Full Approval)**.
   - He opens the `$15,000` bill (or selects multiple escalated bills in `/exceptions`), clicks **Approve (Finance Manager)**, and signs them off with an automatic audit record.
5. **10:00 AM — Dave (System Admin / Compliance Auditor) opens Screen 5 (`/audit/{id}`):**
   - Dave cannot upload invoices or approve payments—his role is strictly read-only for operational governance.
   - He pulls up the exact chronological timeline (`INGEST → EXTRACTION → EDIT → REVALIDATE → APPROVE`), confirms zero sensitive Tax IDs or IBANs are exposed, and downloads a clean, spreadsheet-safe CSV for external auditors.

---

## 4. Built-In Safety Protections (Explained Simply)

During Phase 11, we ran security penetration tests on every single screen and closed **22 security findings (`SEC-187` through `SEC-208`)**:
- **Zero Direct Vault Access:** Automated code scanners verify on every build that *not a single UI file* touches the database, Azure Blob Storage, Redis, or OpenAI directly.
- **Anti-Excel-Attack Export Shield:** If a malicious vendor names an invoice file `=CMD|'calc'!A0.pdf`, our UI neutralizes the formula prefix before displaying or exporting to CSV so opening a report in Excel can never run malicious commands.
- **Anti-Screen-Injection Shield:** Zero raw HTML (`unsafe_allow_html=True`) is permitted anywhere in the UI, and all hidden text tricks (invisible right-to-left characters, `<script>` tags, leaked login tokens) are stripped automatically.
- **Shared-Computer Privacy:** The moment Sarah clicks **Sign Out** or switches users, every cached invoice, batch upload list, exception assignment, revision comparison, and audit record is instantly wiped from browser session memory.
- **UI + Backend Double Lock:** Hiding the Approve button in the UI makes the experience clean and mistake-proof—and even if a hacker bypassed the browser and sent a raw HTTP request directly to the server, Phase 9's backend still slams the door with `403 Forbidden`.

---

## 5. Phase 11 Proof by Numbers (Honest Engineering Status)

- **Phase 11 Completion:** **7 / 7 subtasks completed (100% ✅)** — PRs `#38` through `#44` all passed GitHub Actions CI (`Lint & Code Quality`, `Offline Unit Tests`, `Build Wheel`) and merged cleanly into `development`.
- **Overall Project Progress:** **54 / 68 tasks completed (79%)**.
- **Automated Tests Passing:** **650 / 650 offline tests passing (100%)** in **23.84 seconds** (including **55 brand-new unit tests** and **6 end-to-end live-FastAPI UI integration tests** added in Phase 11).
- **Security Posture:** **208 total security findings audited & mitigated (`SEC-187`–`SEC-208` closed in Phase 11)**, **0 critical/high unmitigated vulnerabilities**, **125 Python files passing Ruff with 0 warnings/errors**.
