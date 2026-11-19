# Phase 4: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, cloud storage, application security, file-parsing, Azure SDK wire protocol, and debugging interview preparation covering **Phase 4 (Azure Storage Layer — P4-1 through P4-4)**.  
> **Audience:** Candidates interviewing for Senior Backend Engineer, Cloud/AI Solution Architect, AppSec Engineer, or Staff Software Engineer roles.

---

## Table of Contents

1. [Azure Blob WORM Client & Keyless Managed Identity (P4-1)](#1-azure-blob-worm-client--keyless-managed-identity-p4-1)
2. [Azurite Local Emulator, Docker Hardening & Wire-Protocol Testing (P4-2)](#2-azurite-local-emulator-docker-hardening--wire-protocol-testing-p4-2)
3. [Deep File Intake Validator & Anti-Malware Defenses (P4-3)](#3-deep-file-intake-validator--anti-malware-defenses-p4-3)
4. [Canonical Blob Metadata Tagging & Integrity Verification (P4-4)](#4-canonical-blob-metadata-tagging--integrity-verification-p4-4)
5. [Real-World Debugging Stories & Security Threat Model Summary](#5-real-world-debugging-stories--security-threat-model-summary)

---

## 1. Azure Blob WORM Client & Keyless Managed Identity (P4-1)

### Q1.1: How do you enforce WORM (Write-Once, Read-Many) immutability at both the cloud infrastructure layer and the application code layer?

**Answer:**
We use **defense-in-depth** across three independent layers so a single misconfiguration cannot compromise our 7-year statutory audit archive (`ADR-005`, `BR-026`, `N6`):
1. **Azure Infrastructure Layer:** The production container (`raw-invoices-immutable`) runs with an Azure Immutable Storage time-based retention policy (`2555` days / 7 years), and `AzureBlobWORMClient` optionally attaches per-blob `ImmutabilityPolicy(expiry_time=now + 2555d)` on upload.
2. **Storage Wire-Protocol Layer:** Every `upload_blob()` call unconditionally passes `overwrite=False`, which makes the Azure SDK emit the HTTP precondition header `If-None-Match: *`. If a blob already exists at that path, Azure returns `409 BlobAlreadyExists`, which we map to `BlobAlreadyExistsError` while leaving the original bytes untouched.
3. **Application API Surface Layer:** Neither `BlobWORMClientProtocol`, `AzureBlobWORMClient`, nor `InMemoryWORMBlobClient` exposes any `delete`, `delete_blob`, `overwrite`, `update`, or `set_blob_metadata` method. We enforce this structurally via automated negative-reflection unit tests (`assert not hasattr(client, "delete_blob")`).

---

### Q1.2: Why did you pin `AZURE_BLOB_ACCOUNT_URL` to `^https://([a-z0-9]{3,24})\.blob\.core\.windows\.net/?$` before calling `DefaultAzureCredential`?

**Answer:**
This prevents **Managed Identity Bearer token exfiltration via SSRF (`SEC-053`, `CWE-918` / `CWE-522`)**.
When an Azure SDK client initialized with `DefaultAzureCredential` sends a request, it automatically fetches a valid Entra ID OAuth2 Bearer token scoped for `https://storage.azure.com/.default` and injects `Authorization: Bearer <token>` into the outbound HTTP request.
If an attacker or misconfigured environment variable pointed `AZURE_BLOB_ACCOUNT_URL` to `https://evil.attacker.example/` or `http://169.254.169.254/`, the SDK would hand a live cloud Storage Bearer token straight to the attacker!
Our strict regex pin also rejects plaintext `http://`, embedded credentials (`https://user:pass@...`), and leaked SAS query strings (`?sv=...&sig=...`), ensuring keyless Managed Identity works **only** against authentic Azure Blob Storage hosts over HTTPS.

---

### Q1.3: How does your `download_blob()` defend against a worker Out-of-Memory (OOM) Denial-of-Service attack?

**Answer:**
A naive `blob_client.download_blob().readall()` streams the entire remote blob into Python RAM without limit—so if a corrupted or externally uploaded 4 GB object existed in the container, a single worker call would OOM-kill the container (`SEC-054`, `CWE-400`).
We apply a **two-stage bounded read**:
1. We pass `offset=0, length=MAX_BLOB_SIZE_BYTES + 1, max_concurrency=1` directly to `blob_client.download_blob(...)`, capping network transfer at `25 MB + 1 byte`.
2. Before calling `downloader.readall()`, we inspect `downloader.properties.size`; if it already exceeds `25 MB`, we raise `ValueError` immediately without reading a single byte of payload.
3. After `readall()`, we verify `len(raw_bytes) <= MAX_BLOB_SIZE_BYTES` as a final belt-and-suspenders guard.

---

## 2. Azurite Local Emulator, Docker Hardening & Wire-Protocol Testing (P4-2)

### Q2.1: How do you test real Azure Storage Blob SDK wire behavior in an offline CI pipeline without running Docker or opening TCP sockets?

**Answer:**
Mocking `blob_client.upload_blob` alone misses real SDK bugs—like wrong SharedKey signatures, missing `If-None-Match: *` headers, broken `x-ms-meta-*` serialization, or mishandled XML error responses.
In `tests/integration/test_azurite_smoke.py` (and `tests/unit/test_blob_metadata.py`), we construct a **real** `azure.storage.blob.BlobServiceClient` backed by an in-process `azure.core.pipeline.transport.HttpTransport`.
Every call traverses the full production Azure SDK pipeline:
- URL construction & query string encoding (`?restype=container`)
- Real `SharedKey` HMAC-SHA256 Authorization header signing
- Real `If-None-Match: *` WORM header & `x-ms-meta-*` metadata header emission
- Real XML error parsing (`409 BlobAlreadyExists` -> `ResourceExistsError` -> `BlobAlreadyExistsError`)
- Real `HTTP 206 Partial Content` + `Content-Range` range-download deserialization

It runs in **0.07 seconds** with **zero TCP sockets** and **zero Docker dependency**, while an opt-in live Docker smoke test (`RUN_LIVE_AZURITE_SMOKE=true`) validates the real Azurite container locally.

---

### Q2.2: Why did you refuse to include Microsoft's publicly documented Azurite test key in `src/storage/azurite.py`, and how is Azurite kept out of production?

**Answer:**
1. **Zero-Static-Secret Invariant (`SEC-062`, `CWE-798`, `ADR-007`):** Even though Microsoft's Azurite default key (`Eby8vdM...`) is public documentation, hardcoding any `AccountKey` material inside `src/` violates our non-negotiable static-secret hygiene gate (`test_codebase_hygiene_zero_static_secrets_in_src_and_env_example`) and trains teams to make exceptions for "dev keys." Instead, `AZURITE_ACCOUNT_KEY` is read strictly from the developer's local environment (`.env`, gitignored) and validated as non-empty Base64.
2. **Triple Production Gate (`SEC-060`, `CWE-489`):** `create_azurite_worm_client()` fails closed unless **all three** hold simultaneously:
   - `APP_ENV` is in `{"dev", "local", "test"}`
   - `USE_AZURITE_LOCAL=True`
   - `USE_LOCAL_SQLITE=True` (blocking Azurite whenever connected to real Azure SQL)
3. **Loopback-Only Binding (`SEC-059`, `SEC-061`):** Both `docker-compose.azurite.yml` (`127.0.0.1:10000:10000`, `cap_drop: ALL`, `no-new-privileges:true`, `mem_limit: 256m`, `pids_limit: 128`) and `validate_azurite_url()` restrict traffic strictly to `http://(127.0.0.1|localhost|azurite):10000/{account}/`, blocking SSRF to arbitrary internal ports or cloud IMDS.

---

## 3. Deep File Intake Validator & Anti-Malware Defenses (P4-3)

### Q3.1: Why isn't checking the filename extension and FastAPI's `UploadFile.content_type` sufficient for validating invoice uploads?

**Answer:**
Both the filename extension and the HTTP `Content-Type` header are **100% attacker-controlled strings** (`CWE-434`). An attacker can upload `<script>alert(1)</script>` named `invoice.pdf` with `Content-Type: application/pdf`, or rename a macro-enabled `.xlsm` or `.docx` archive to `.xlsx`.
In `src/storage/file_validator.py`, we enforce **four independent validation layers**:
1. **Filename & Header Sanitization:** `SAFE_FILENAME_PATTERN` blocks path traversal (`../`), slashes, null bytes, and CRLF (`CWE-22`, `CWE-113`).
2. **Size Cap (`FR-01`):** Rejects empty files (`422`) and `> 25 MB` files (`413`) before parsing.
3. **Binary Magic-Byte Sniffing:** Reads raw leading bytes (`%PDF-`, `\x89PNG\r\n\x1a\n`, `\xff\xd8\xff`, `PK\x03\x04`, and explicitly rejects TIFF `II*\x00`/`MM\x00*` per `GAP-004`) and verifies strict consistency between magic bytes, extension, and declared `Content-Type` (allowing generic `application/octet-stream` to defer safely to magic bytes).
4. **Format-Specific Deep Structural Parsing:** Validates the internal structure of PDF, PNG, JPEG, and XLSX archives in memory.

---

### Q3.2: How does your validator detect password-protected PDFs and malicious active PDFs without breaking legitimate invoices?

**Answer:**
We open the PDF strictly in memory via PyMuPDF (`fitz.open(stream=data, filetype="pdf")`):
- **Password-Protected PDFs:** PyMuPDF sets `doc.needs_pass == True` whenever a user password is required to open/read the document (including AES-256 encrypted PDFs). We immediately raise `PasswordProtectedPDFError` (`HTTP 422`), rather than failing downstream in OCR.
- **Active PDF Scripts & Droppers (`SEC-065`, `CWE-94`):** Legitimate accounting invoices never need JavaScript execution or OS shell launches. Instead of naively regex-scanning raw PDF bytes (which misses FlateDecode-compressed object streams or false-positives on invoice text), we iterate through MuPDF's decompressed xref object dictionaries (`doc.xref_object(xref, compressed=False)`, capped at `10,000` objects) and reject `/JavaScript`, `/JS`, and `/Launch` actions—plus we inspect `doc.embfile_names()` to block executable embedded attachments (`.exe`, `.bat`, `.ps1`, `.js`, `.vbs`, `.sh`, `.dll`, `.msi`). Note: we intentionally do **not** blanket-ban `/OpenAction` (which legitimate PDFs use for "Fit Page") or benign XML attachments (used by EU ZUGFeRD/Factur-X e-invoices).

---

### Q3.3: Explain how image pixel decompression bombs work and how you block them for both PNG and JPEG.

**Answer:**
A **pixel decompression bomb (`SEC-066`, `CWE-400`)** is a tiny compressed image (often <50 KB) whose header declares massive dimensions—for example, `50,000 × 50,000` pixels (2.5 billion pixels). If an application passes it straight to an image decoder or OCR rasterizer, decompressing 4 bytes/pixel (RGBA) allocates **10 GB of RAM**, crashing the worker immediately.
- **PNG Defense:** Before invoking MuPDF, `_validate_png()` unpacks the big-endian `width, height` directly from the mandatory 13-byte `IHDR` chunk at byte offsets `16..24` (`struct.unpack(">II", data[16:24])`).
- **JPEG Defense:** Because JPEG stores dimensions inside variable-offset `SOF0..SOF15` (Start-Of-Frame) markers (`0xFFC0`–`0xFFCF`, excluding `C4/C8/CC`), `_extract_jpeg_sof_dimensions()` walks the JPEG marker segments in pure Python before calling `fitz.open()`.
- Both enforce `1 <= width, height <= 20,000` and `width * height <= 50,000,000` pixels (~200 MB worst-case RGBA ceiling) *prior* to decoding.

---

### Q3.4: What are all the attack vectors unique to `.xlsx` spreadsheets, and how did you avoid false positives on real Excel files?

**Answer:**
An `.xlsx` file is an OOXML ZIP archive containing XML files, making it susceptible to **six distinct attack classes**:
1. **Disguised Non-XLSX ZIPs (`.zip`, `.docx`, `.pptx`):** We require canonical `[Content_Types].xml` and `xl/workbook.xml`.
2. **Zip-Slip Path Traversal (`CWE-22`):** Rejects archive entries with `..`, leading `/`, backslashes, drive colons (`:`), or control characters.
3. **Duplicate-Entry Parser Differentials (`CWE-434`):** Rejects case-insensitive duplicate member names (e.g., two `xl/workbook.xml` entries where a validator reads entry #1 and `openpyxl` parses entry #2).
4. **ZIP Bombs & Forged Headers (`CWE-409`):** Enforces `<= 500` entries, `<= 100 MB` declared uncompressed size, `<= 100:1` compression ratio, rejects encrypted ZIP flags (`flag_bits & 0x1`), and reads XML members with bounded `read(MAX_XML_SCAN_BYTES + 1)` rejecting any member whose actual decompressed bytes exceed its central-directory `info.file_size` header!
5. **UTF-8 & UTF-16 XXE Injection (`CWE-611`):** Scans **all** `.xml` and `.rels` entries (not just worksheets—catching `xl/sharedStrings.xml`, `_rels/.rels`, `docProps/core.xml`) against ASCII/UTF-8, UTF-16LE, and UTF-16BE `<!DOCTYPE`/`<!ENTITY` signatures within a 10 MB cumulative budget.
6. **Macros & OLE Droppers without False Positives:** Rather than banning all `.bin` files (which breaks legitimate Microsoft Excel exports containing benign `xl/printerSettings/printerSettings1.bin`), we specifically block `vbaProject.bin`, `xl/macrosheets/`, `xl/dialogsheets/`, `xl/activeX/`, `xl/embeddings/`, `.vba`, and `macroEnabled` Content-Types.

---

## 4. Canonical Blob Metadata Tagging & Integrity Verification (P4-4)

### Q4.1: Why did you build case-insensitive parsing into `parse_invoice_blob_metadata()` when you write PascalCase (`VendorID`, `UploadTimestamp`, `FileHash`)?

**Answer:**
Because **Azure Blob Storage and Azurite lowercase HTTP `x-ms-meta-*` header names on storage and retrieval!**
When the Azure SDK uploads `metadata={"VendorID": "VND-001", "UploadTimestamp": "...", "FileHash": "..."}`, the REST API returns `{"vendorid": "VND-001", "uploadtimestamp": "...", "filehash": "..."}` on `get_blob_properties()`.
If our reader did a naive `meta["VendorID"]`, unit tests using an in-memory dict would pass while production Azure Blob Storage would crash with `KeyError`!
`parse_invoice_blob_metadata()` handles both PascalCase and Azure lowercased keys seamlessly—while explicitly detecting and rejecting **case-colliding duplicate keys** (e.g., `{"VendorID": "A", "vendorid": "B"}`, `SEC-073`, `CWE-436`).

---

### Q4.2: Why do you block PII in BOTH metadata keys AND metadata values, and why use `hmac.compare_digest` for `FileHash` verification?

**Answer:**
1. **Key + Value PII Defense (`SEC-072`, `CWE-359` / `CWE-200`):** Azure Blob metadata headers (`x-ms-meta-*`) appear in Azure Portal listings, HTTP telemetry, and diagnostic logs. Blocking only sensitive key names (`TaxID`, `IBAN`, `SSN`, `Password`, `ApiKey`, `Token`) wouldn't stop a buggy caller or prompt-injected payload from stuffing a German IBAN (`DE89370400440532013000`), JWT (`eyJ...`), or SAS token (`?sig=...`) under an innocent key like `Notes`. Our validator inspects both key tokens and value patterns (safely exempting the 64-char hex `FileHash`).
2. **Constant-Time Hash Comparison (`SEC-071`, `CWE-345` / `CWE-354`):** Computing `FileHash` authoritatively from the raw bytes on write and verifying via `hmac.compare_digest()` prevents both caller hash spoofing at upload time and timing side-channels during integrity verification on read.
3. **Azure 8 KB Wire Budget (`SEC-074`) & RFC 7230 Whitespace (`SEC-075`):** Azure Storage counts the `x-ms-meta-<key>: <value>\r\n` wire-header overhead (14 bytes per entry) toward its 8,192-byte metadata limit and strips leading/trailing spaces from HTTP header values. Enforcing the exact wire-header budget and rejecting empty or leading/trailing-space values guarantees 100% behavioral parity between local mock storage and live Azure East US 2.

---

## 5. Real-World Debugging Stories & Security Threat Model Summary

### Story 1: Catching the Real Azure SDK `HTTP 206 Partial Content` + `Content-Range` Contract
When building our in-process `HttpTransport` wire-protocol test for `AzureBlobWORMClient.download_blob()`, our initial transport returned `HTTP 200 OK` without a `Content-Range` header. Because our production client explicitly passes `offset=0, length=MAX_BLOB_SIZE_BYTES + 1` to defend against OOM downloads (`SEC-054`), the real `azure-storage-blob` SDK sends an `x-ms-range` header and expects `HTTP 206` with `Content-Range: bytes 0-{n-1}/{n}`! Exercising the real SDK pipeline instead of simple mocks surfaced this exact protocol requirement immediately.

### Story 2: Eliminating False Positives on Real Microsoft Excel `.xlsx` Exports
During our P4-3 security audit, our initial XLSX macro check rejected any archive entry ending in `.bin`. On deeper inspection, real Microsoft Excel `.xlsx` files routinely include benign `xl/printerSettings/printerSettings1.bin` binary DEVMODE blobs. Narrowing the guard to `vbaProject.bin`, `xl/macrosheets/`, `xl/dialogsheets/`, `xl/activeX/`, `xl/embeddings/`, and `macroEnabled` Content-Types (backed by a dedicated regression test `test_xlsx_allows_benign_printer_settings_bin_in_legitimate_excel_export`) preserved full macro/dropper security with zero vendor friction.

### Story 3: Aligning `BlobUploadResult.uploaded_at` with `UploadTimestamp` & Avoiding Entry-Limit Shadowing
During P4-4 security review, we caught two subtle bugs:
1. `BlobUploadResult.uploaded_at` called `datetime.now(UTC)` a few microseconds *after* `prepare_upload_metadata()` generated `UploadTimestamp`, causing microsecond drift between the Python receipt and the WORM blob tag. Deriving `uploaded_at` directly from `parse_invoice_blob_metadata(clean_metadata).upload_timestamp` locked them into exact parity (`SEC-076`).
2. Our first 8 KB budget test generated 32 extra tags on top of the 3 canonical tags (`35 > MAX_METADATA_ENTRIES=32`), hitting the entry-count check before the 8,192-byte wire check. Fixing the test to use 29 long-key tags (`3 + 29 = 32` entries, `> 8,192` bytes) proved the 8 KB wire-budget guard actually fires independently!

---

### Phase 4 Security Threat Model Summary (25 Findings — All Mitigated ✅)

| Severity | Count | Findings (`SEC-052`–`SEC-076`) |
|---|---:|---|
| **Critical** | 2 | `SEC-052` (WORM bypass), `SEC-053` (Managed Identity SSRF/token exfiltration) |
| **High** | 14 | `SEC-054` (OOM download), `SEC-055` (blob path traversal), `SEC-057` (mock blob in prod), `SEC-060` (Azurite in prod), `SEC-061` (Azurite SSRF), `SEC-062` (hardcoded Azurite key), `SEC-064` (MIME spoofing), `SEC-065` (active PDF JS/Launch), `SEC-066` (PNG/JPEG pixel bombs), `SEC-067` (UTF-8/UTF-16 XXE), `SEC-068` (ZIP bombs/forged headers), `SEC-069` (Zip-Slip/duplicates), `SEC-071` (FileHash spoofing), `SEC-072` (PII/secrets in metadata keys & values) |
| **Medium** | 8 | `SEC-056` (Content-Type XSS/CRLF), `SEC-058` (storage log PII), `SEC-059` (Azurite LAN exposure), `SEC-070` (Excel macros/CRLF), `SEC-073` (case-colliding metadata), `SEC-074` (8 KB wire header DoS), `SEC-075` (whitespace/naive timestamp), `SEC-076` (metadata mutability/timestamp drift) |
| **Low** | 1 | `SEC-063` (SharedKey account-name mismatch) |
| **Total** | **25** | **100% Mitigated ✅ · Verified by 40 Automated Offline Tests** |

