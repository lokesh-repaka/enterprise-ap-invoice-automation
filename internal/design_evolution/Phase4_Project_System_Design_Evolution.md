# Phase 4: Project System Design Evolution

> **Document Scope:** Architectural journey and system design evolution throughout **Phase 4 (Azure Storage Layer — P4-1 through P4-4)**.  
> **Target Audience:** Solution Architects, Security Engineers, Backend Leads, and System Design Interviewers.

---

## 1. Phase 4 Mission & Architectural Baseline

At the end of Phase 3, the platform had a stateless FastAPI runtime skeleton (Phase 1), a dual-dialect async SQL persistence tier with 5 tables and race-safe duplicate guards (Phase 2), and a complete Entra ID RBAC + Redis sliding-window rate limiter + isolated-transaction audit + keyless Key Vault security perimeter (Phase 3), backed by **110 passing offline tests**.

However, `src/storage/` was still an empty placeholder package. There was no immutable object storage client for raw invoices or extraction snapshots, no local storage emulator parity, no pre-storage file intake security scanner, and no standardized blob metadata tagging or tamper-evidence verification.

The mission of **Phase 4** was to construct an enterprise-grade, zero-business-logic **Immutable Document Storage Layer (`src/storage/`)** enforcing six architectural invariants:

1. **Strict Layer Isolation (`CLAUDE.md §4.2`):** `src/storage/` owns WORM blob I/O, intake file validation, and metadata tagging ONLY—**zero imports** from `src/database/`, `src/extraction/`, `src/validation/`, or `src/api/`.
2. **Defense-in-Depth WORM Immutability (`ADR-005`, `N6`, `BR-026`):** Every write enforces `overwrite=False` (`If-None-Match: *`) alongside optional Azure 7-year `ImmutabilityPolicy` (`2555` days), while **omitting all delete, overwrite, and metadata-mutation methods** from the client protocol and implementations.
3. **Keyless Cloud Authentication (`ADR-007`, `N1`, `N8`):** Production storage authenticates exclusively via `DefaultAzureCredential` pinned strictly to `https://<account>.blob.core.windows.net/` (blocking SSRF and Managed Identity Bearer token exfiltration).
4. **Triple-Gated Zero-Cost Local Parity (`GAP-002`):** Local development supports both `InMemoryWORMBlobClient` and an official loopback-hardened **Azurite** emulator (`127.0.0.1:10000`), hard-blocked outside `dev`/`local`/`test` or whenever `USE_LOCAL_SQLITE=false`.
5. **Pre-Storage Deep File Security (`FR-01`, `BR-001`, `GAP-004`):** Binary magic-byte sniffing, 25 MB size enforcement, explicit TIFF blocking, password-protected & active-script PDF rejection, pre-decode image pixel-bomb guards, and deep OOXML XLSX inspection (Zip-Slip, ZIP bombs, forged headers, macros, UTF-8/UTF-16 XXE).
6. **Authoritative Canonical Metadata Tagging (`CLAUDE.md §7.3`):** Every upload is atomically tagged with `VendorID`, UTC ISO-8601 `UploadTimestamp`, and authoritative SHA-256 `FileHash` with key-and-value PII filtering, Azure 8 KB wire-header budget enforcement, and constant-time read verification.

---

## 2. Progressive Evolution: Subtask-by-Subtask System Design

### 2.1 Stage 0: End of Phase 3 Baseline (Empty Storage Tier)

Entering Phase 4, the API and security middleware were operational, and SQL tables (`Invoices.blob_url`, `Invoices.file_hash`) were ready—but `src/storage/` had no client, no intake guard, and no blob metadata contract.

```mermaid
flowchart LR
    API["FastAPI + Phase 3 Security Perimeter"] --> DB["src/database/ (5 Async SQL Tables)"]
    API -.->|"Not Implemented"| ST["src/storage/ (Empty Placeholder)"]

    style ST fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style API fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

### 2.2 Stage 1 (P4-1): Keyless Azure Blob WORM Client (`src/storage/blob_client.py`)

In **P4-1 (`feature/storage-blob-worm-client`, PR #11)**, we designed the dual-mode `BlobWORMClientProtocol` with two strictly write-once implementations (`AzureBlobWORMClient` and `InMemoryWORMBlobClient`) resolved via a cached factory `get_blob_worm_client(settings)`.

```mermaid
flowchart TD
    CALLER["Caller (Upload API / Worker)"] --> FACTORY["get_blob_worm_client(settings)"]
    FACTORY -->|"dev/local/test + USE_MOCK_BLOB_STORAGE=true + USE_LOCAL_SQLITE=true"| MEM["InMemoryWORMBlobClient (Thread-Safe, Max 500 Blobs)"]
    FACTORY -->|"staging / production (Mock Hard-Blocked)"| AZ["AzureBlobWORMClient (Keyless DefaultAzureCredential)"]

    AZ --> URL_PIN["URL Host Pin: ^https://[a-z0-9]{3,24}.blob.core.windows.net/$"]
    URL_PIN --> PATH_GUARD["Path Guard: raw-invoices/{id}/{file} & json-extractions/{id}/extraction.json"]
    PATH_GUARD --> WORM_WRITE["upload_blob(overwrite=False, ContentSettings, optional 2555-day ImmutabilityPolicy)"]
    WORM_WRITE -->|"409 ResourceExistsError"| ERR_DUP["BlobAlreadyExistsError (Original Intact)"]
    WORM_WRITE -->|"201 Created"| RECEIPT["Frozen BlobUploadResult (blob_url, sha256_hash, etag)"]

    AZ --> DL_GUARD["download_blob(offset=0, length=25MB+1) + Pre-Read properties.size Check"]
    DL_GUARD -->|"<= 25 MB"| BYTES["Verified Raw Bytes"]
    DL_GUARD -->|"> 25 MB"| ERR_OOM["ValueError (Anti-OOM CWE-400)"]

    style URL_PIN fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style WORM_WRITE fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style DL_GUARD fill:#fce4ec,stroke:#ad1457,stroke-width:2px;
```

**Key Architectural Decisions in P4-1:**
- **Zero Delete/Overwrite API Surface (`SEC-052`):** Neither `AzureBlobWORMClient` nor `InMemoryWORMBlobClient` exposes `delete`, `delete_blob`, `overwrite`, or `update` methods—verified by negative reflection tests.
- **SSRF & Token Exfiltration Pin (`SEC-053`):** `validate_blob_account_url()` blocks HTTP, userinfo (`user:pass@`), SAS query strings (`?sig=`), and foreign domains so `DefaultAzureCredential` can never transmit an Entra ID Bearer token to an attacker-controlled host.
- **Bounded Download Read (`SEC-054`):** Passes `offset=0, length=MAX_BLOB_SIZE_BYTES + 1` AND checks `downloader.properties.size` *before* calling `readall()`—eliminating worker OOM DoS from oversized blobs.

---

### 2.3 Stage 2 (P4-2): Hardened Local Azurite Emulator & Wire-Protocol Smoke (`src/storage/azurite.py`)

In **P4-2 (`feature/storage-azurite-local`, PR #12)**, we added local Azure Blob REST protocol parity without compromising the zero-static-secret or production-safety invariants.

```mermaid
flowchart TD
    SET["Settings (APP_ENV, USE_AZURITE_LOCAL, USE_LOCAL_SQLITE)"] --> GATE{"Triple Production Gate"}
    GATE -->|"Non-dev OR SQLite=false"| BLOCK["BlobStorageConfigurationError (Fail Closed)"]
    GATE -->|"dev/local/test + Azurite=true + SQLite=true"| URL["validate_azurite_url() -> http://(127.0.0.1|localhost|azurite):10000/{acct}/"]
    URL --> KEY["Read AZURITE_ACCOUNT_KEY from Env Only (Zero Hardcoded Key in Code)"]
    KEY --> SVC["Real azure.storage.blob.BlobServiceClient (SharedKey Signing)"]
    SVC --> INIT["ensure_worm_container() (Idempotent 201 / 409 ResourceExistsError)"]
    SVC --> CLIENT["AzureBlobWORMClient(allow_local_emulator=True)"]
    CLIENT -->|"Real HTTP PUT (If-None-Match: *)"| AZURITE["Docker Azurite (127.0.0.1:10000) OR In-Process HttpTransport"]

    style GATE fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style URL fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style CLIENT fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

**Key Architectural Decisions in P4-2:**
- **Real SDK Wire-Protocol Verification Offline:** Instead of mocking `BlobServiceClient` methods alone, `tests/integration/test_azurite_smoke.py` injects a custom `azure.core.pipeline.transport.HttpTransport` into the **real** `BlobServiceClient`, exercising genuine SharedKey signing, `If-None-Match: *` WORM header emission, XML `409 BlobAlreadyExists` deserialization, and HTTP `206` range downloads with **zero TCP sockets** in offline CI.
- **Account Name Derived from URL (`SEC-063`):** Rather than accepting a separate `AZURITE_ACCOUNT_NAME` that could drift from the URL path, the account name is derived canonically from the validated Azurite URL segment.

---

### 2.4 Stage 3 (P4-3): Multi-Stage Deep File Intake Validator (`src/storage/file_validator.py`)

In **P4-3 (`feature/storage-file-validator`, PR #13)**, we placed a deterministic, zero-network security inspection gate directly upstream of WORM blob ingestion.

```mermaid
flowchart TD
    IN["Upload: (filename, bytes, optional Content-Type)"] --> S1["1. Filename & Header Guard (SAFE_FILENAME_PATTERN, No Traversal/CRLF/TIFF)"]
    S1 --> S2["2. Size Guard (Empty -> 422, >25 MB -> 413 FileTooLargeError)"]
    S2 --> S3["3. Binary Magic-Byte Sniffer (Never Trusts Headers/Extensions)"]

    S3 -->|"II*\0 or MM\0*"| TIFF["415 UnsupportedFileTypeError (GAP-004: TIFF Phase 2)"]
    S3 -->|"Signature != Extension or Declared MIME"| SPOOF["415 UnsupportedFileTypeError (CWE-434 Spoof)"]

    S3 -->|"%PDF-"| PDF["PDF Inspector (PyMuPDF): needs_pass -> 422 PasswordProtectedPDFError, Pages 1..200, Xref /JavaScript|/JS|/Launch & .exe Attachment Block"]
    S3 -->|"\x89PNG"| PNG["PNG Inspector: Pre-Decode IHDR <=20k px & <=50M px + MuPDF Verify"]
    S3 -->|"\xff\xd8\xff"| JPG["JPEG Inspector: Pure-Python SOF0..SOF15 <=20k px & <=50M px + MuPDF Verify"]
    S3 -->|"PK\x03\x04"| XLSX["XLSX OOXML Inspector: Zip-Slip, Duplicate Entry, Encrypted ZIP, Ratio <=100:1, Forged Header Size, VBA/XLM/ActiveX/OLE Block, UTF-8 & UTF-16 XXE Scan Across All .xml/.rels"]

    PDF & PNG & JPG & XLSX -->|"All Checks Pass"| OUT["Frozen ValidatedFile (filename, ext, detected_mime, size_bytes, sha256_hash, page_count)"]

    style S3 fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style PDF fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    style XLSX fill:#fce4ec,stroke:#ad1457,stroke-width:2px;
    style OUT fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

**Key Architectural Decisions in P4-3:**
- **Structured HTTP Error Semantics:** Every exception subclass (`FileTooLargeError -> 413`, `UnsupportedFileTypeError -> 415`, `PasswordProtectedPDFError -> 422`, `CorruptedOrMaliciousFileError -> 422`) carries typed `error_code` and `http_status` attributes so Phase 5 (`POST /api/v1/invoices/upload`) can map failures cleanly without leaking internals.
- **Zero False Positives on Legitimate Vendor Excel Invoices:** Rather than banning all `.bin` files inside `.xlsx` (which would break legitimate Microsoft Excel exports containing `xl/printerSettings/printerSettings1.bin`), macro blocking targets `vbaProject.bin`, `xl/macrosheets/`, `xl/dialogsheets/`, `xl/activeX/`, `xl/embeddings/`, and `macroEnabled` content types.
- **Pre-Decode Decompression Bomb Defense:** Both PNG (`IHDR`) and JPEG (`SOF0..SOF15`) dimensions are parsed directly in pure Python *before* MuPDF allocates pixel buffers.

---

### 2.5 Stage 4 (P4-4): Canonical Blob Metadata Tagging & Integrity Layer (`src/storage/metadata.py`)

In **P4-4 (`feature/storage-blob-metadata`, PR #14)**, we unified all metadata validation into a single authoritative module and wired it directly into both WORM clients.

```mermaid
flowchart TD
    UPLOAD["upload_raw_invoice() / upload_extraction_json()"] --> PREP["prepare_upload_metadata(data, vendor_id, upload_timestamp, extra_metadata)"]
    PREP --> HASH["Authoritative SHA-256 Computation from Raw Bytes (Verify vs Caller FileHash via hmac.compare_digest)"]
    PREP --> TS["UTC ISO-8601 Normalization (Reject Naive Timestamps -> Canonical ...Z)"]
    PREP --> VEND["VendorID Guard (^[A-Za-z0-9_-]{1,64}$, Default UNKNOWN, Reject Conflicts)"]
    PREP --> PII["Key + Value PII/Secret Filter (Block TaxID/VATID/IBAN/SSN/JWT/AccountKey/SAS)"]
    PREP --> BUDGET["Azure Wire-Header Budget (<=32 Entries, <=8192 Bytes Including 'x-ms-meta-: \\r\\n')"]
    PREP --> WS["RFC 7230 Whitespace Guard (Reject Empty or Leading/Trailing Spaces)"]

    HASH & TS & VEND & PII & BUDGET & WS --> WRITE["Atomic WORM PUT with x-ms-meta-VendorID, x-ms-meta-UploadTimestamp, x-ms-meta-FileHash"]
    WRITE --> RECEIPT["BlobUploadResult (metadata dict + uploaded_at == UploadTimestamp)"]

    READ["get_blob_metadata(blob_name) (Read-Only Defensive Copy)"] --> PARSE["parse_invoice_blob_metadata() (PascalCase & Azure Lowercase, Block Case Collisions)"]
    PARSE --> VERIFY["verify_blob_metadata_integrity(bytes, meta) (Constant-Time SHA-256 Parity)"]

    style PREP fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    style PII fill:#ffebee,stroke:#c62828,stroke-width:2px;
    style VERIFY fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

## 3. Complete End-of-Phase 4 Architecture

```mermaid
flowchart LR
    subgraph CALLERS["Upstream Consumers (Phase 5+)"]
        UP_API["POST /api/v1/invoices/upload"]
        WORKER["Background Extraction Worker"]
    end

    subgraph STORAGE["src/storage/ (Zero Business Logic — CLAUDE.md §4.2)"]
        VAL["file_validator.py (P4-3): Magic-Byte MIME, 25 MB, TIFF/GAP-004, Encrypted/JS PDF, Pixel & ZIP/XXE Guards"]
        META["metadata.py (P4-4): VendorID, UTC UploadTimestamp, SHA-256 FileHash, PII Filter, 8 KB Wire Cap"]
        CLIENT["blob_client.py (P4-1): BlobWORMClientProtocol (Write-Once, Read-Only Metadata, Zero Delete)"]
        AZ_MOD["azurite.py (P4-2): Triple-Gated Local Azurite Factory & Container Bootstrap"]
    end

    subgraph BACKENDS["Storage Backends"]
        MEM["InMemoryWORMBlobClient (Unit Tests / Local Dev)"]
        AZURITE["Azurite Docker Container (127.0.0.1:10000)"]
        AZURE["Azure Blob Storage East US 2 (WORM 7-Year Lock + Managed Identity)"]
    end

    UP_API --> VAL
    VAL -->|"ValidatedFile"| CLIENT
    WORKER --> CLIENT
    CLIENT --> META
    AZ_MOD --> CLIENT
    CLIENT --> MEM
    CLIENT --> AZURITE
    CLIENT --> AZURE

    style STORAGE fill:#f3f8ff,stroke:#1565c0,stroke-width:2px;
    style AZURE fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
```

---

## 4. Key Architectural Trade-Offs Made in Phase 4

| Design Decision | Alternative Considered | Why We Chose Our Approach |
|---|---|---|
| **Dedicated `src/storage/metadata.py` integrated into `blob_client.py`** | Leaving loose `dict[str, str]` metadata in `blob_client.py` | Prevents drift between two validators, guarantees every WORM upload automatically receives `VendorID`/`UploadTimestamp`/`FileHash`, and enables case-insensitive Azure REST parsing + constant-time integrity checks. |
| **Pure-Python PNG `IHDR` & JPEG `SOF` parsing before PyMuPDF** | Letting `fitz.open()` or Pillow decode first | Blocks decompression bombs in O(KB) bytes before any C-level raster buffer is allocated (`SEC-066`). |
| **In-process `HttpTransport` wire-protocol smoke test** | Requiring Docker daemon in GitHub Actions CI | Runs real `azure-storage-blob` SharedKey signing, `If-None-Match: *`, `x-ms-meta-*`, and `206` range parsing in **0.07s** with zero sockets, while keeping optional `RUN_LIVE_AZURITE_SMOKE=true` for local Docker verification. |
| **Allowing `xl/printerSettings/*.bin` while banning VBA/XLM/ActiveX/OLE** | Blanket rejection of all `.bin` ZIP entries | Blanket `.bin` bans break real Microsoft Excel `.xlsx` exports from enterprise vendors; targeted OOXML path + `macroEnabled` Content-Type inspection eliminates false positives without lowering security. |
| **Zero `set_blob_metadata()` method on WORM clients** | Allowing post-upload metadata updates (e.g., updating `VendorID` after OCR) | Preserves true WORM immutability (`ADR-005`). Once OCR resolves a vendor, the authoritative vendor link lives in Azure SQL (`Invoices.vendor_id`), while the raw blob's original intake tags remain permanently unaltered. |

---

## 5. Verification & Security Evolution Across Phase 4

| Subtask | PR | New Tests | Cumulative Offline Tests | Security Findings Mitigated |
|---|---|---|---|---|
| Phase 3 Baseline | #6–#10 | — | 110 | 51 (`SEC-001`–`SEC-051`) |
| **P4-1** Blob WORM Client | #11 | +10 | 120 | +7 (`SEC-052`–`SEC-058`: 2 Critical, 3 High, 2 Medium) |
| **P4-2** Azurite Local Emulator | #12 | +7 (+1 live skip) | 127 | +5 (`SEC-059`–`SEC-063`: 3 High, 1 Medium, 1 Low) |
| **P4-3** File Validator | #13 | +13 | 140 | +7 (`SEC-064`–`SEC-070`: 6 High, 1 Medium) |
| **P4-4** Blob Metadata Tagging | #14 | +10 | **150** | +6 (`SEC-071`–`SEC-076`: 2 High, 4 Medium) |
| **Phase 4 Total** | **#11–#14** | **+40 tests** | **150 passing (3.04s)** | **+25 findings (76 total, 0 open)** |

