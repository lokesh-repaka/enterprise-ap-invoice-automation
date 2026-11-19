# Phase 6: Comprehensive Interview Questions & Answers

> **Document Scope:** Deep-dive technical, LLM architecture, prompt security, Pydantic v2 contract design, cost optimization, keyless cloud auth, and debugging interview preparation covering **Phase 6 (Extraction Engine and Model Gateway — P6-1 through P6-5)**.  
> **Audience:** Candidates interviewing for Senior AI/Backend Engineer, LLM Platform Engineer, Cloud Solution Architect, or Staff Software Engineer roles.

---

## Table of Contents

1. [Document Classification & Anti-Spoofing (P6-1)](#1-document-classification--anti-spoofing-p6-1)
2. [Hybrid Model Gateway, Cost Optimization & Resilience (P6-2)](#2-hybrid-model-gateway-cost-optimization--resilience-p6-2)
3. [Pydantic v2 Extraction Schemas & Financial Precision (P6-3)](#3-pydantic-v2-extraction-schemas--financial-precision-p6-3)
4. [Extraction Engine, Prompt Injection Defense & Multimodal Prep (P6-4)](#4-extraction-engine-prompt-injection-defense--multimodal-prep-p6-4)
5. [Offline Mock AOAI Client & Zero-Network Testing (P6-5)](#5-offline-mock-aoai-client--zero-network-testing-p6-5)
6. [Real-World Debugging Stories & Security Threat Model Summary](#6-real-world-debugging-stories--security-threat-model-summary)

---

## 1. Document Classification & Anti-Spoofing (P6-1)

### Q1.1: How do you decide whether an invoice PDF should go to GPT-4o-mini or GPT-4o Vision, and how do you handle hybrid PDFs?

**Answer:**
Our classifier (`src/extraction/document_classifier.py::classify_document()`) inspects raw binary bytes using magic-byte signatures first (never trusting filenames, and rejecting unsupported TIFF per GAP-004). For PDFs, it opens the document in memory with **PyMuPDF (`fitz`)** and evaluates every page (capped at 200 pages) using **two thresholds**:
1. At least **50 meaningful alphanumeric characters** (`ch.isalnum()`), AND
2. At least **10 unique lowercase alphanumeric characters** (`len(set(alnum)) >= 10`).

That defeats whitespace/punctuation noise and repeated-character spoofing (like `'A' * 400`). Crucially, if **even a single page** in a multi-page PDF fails the density threshold (a **hybrid PDF** where page 1 is digital text and page 2 is a scanned receipt), the classifier classifies the document as `DocumentType.SCANNED_IMAGE` and records `scanned_page_indices` so Vision renders the scanned pages first rather than silently dropping line items!

---

### Q1.2: How do you protect the classifier against decompression bombs and pixel bombs before decoding?

**Answer:**
We enforce pre-decode binary limits (`SEC-106`, `SEC-108`, `CWE-400` / `CWE-409`):
- **PDFs:** Hard `25 MB` byte cap, `200`-page cap, password-protection rejection (`doc.needs_pass`), and an **incremental `200,000`-char extraction budget inside the page loop** (preventing a 200-page text bomb from spiking worker RAM before truncation).
- **PNG/JPEG:** We parse width and height directly from binary headers (`IHDR` for PNG, `SOF` markers for JPEG) via `struct.unpack` *before* decoding, rejecting any image `> 20,000 px` on either axis or `> 50 megapixels`.
- **XLSX:** We inspect the ZIP central directory for Zip-Slip (`..` / absolute paths), cap entries at `500`, total uncompressed size at `100 MB`, and compression ratio at `100x`.

---

## 2. Hybrid Model Gateway, Cost Optimization & Resilience (P6-2)

### Q2.1: How does your Model Gateway reduce Azure OpenAI costs without sacrificing extraction accuracy on messy scans?

**Answer:**
We combine **three architectural levers (`ADR-004`, `HLD §7.1`)**:
1. **Hybrid Model Routing:** Clean `searchable_pdf` and `xlsx` documents route to **GPT-4o-mini** (~80% cheaper per token and faster than GPT-4o Vision), while `scanned_image` documents—or any invoice explicitly escalated via `force_vision=True`—route to **GPT-4o Vision**.
2. **Azure Prompt Caching:** `ExtractionEngine.build_system_prompt()` is `@lru_cache(maxsize=1)` with deterministic sorted JSON schema serialization, and `ModelGateway.invoke()` ALWAYS places the static `system` message before variable `user` content—unlocking up to **50% input token discounts** on cached prefixes.
3. **Hard Output Token Ceiling (`HLD §243`):** `select_route()` enforces `1 <= max_output_tokens <= 2000` (also rejecting Python booleans) so runaway completions can never inflate spend.

---

### Q2.2: Why did you disable the OpenAI SDK's built-in retries (`max_retries=0`) and implement retry logic inside `ModelGateway`?

**Answer:**
`LLD §6.2` specifies an exact backoff policy for Azure OpenAI East US 2 quota bursts: **`2**attempt + Uniform(0, 1)` seconds with a maximum of 4 total attempts** (`[2+j, 4+j, 8+j]` sleeps). Setting `max_retries=0` on `AsyncAzureOpenAI` prevents hidden double-retries (SDK retries × gateway retries = 16× amplification during outages!), gives us deterministic injectable `sleep_fn` and `jitter_fn` hooks for millisecond unit testing, and ensures clear error classification:
- **Retried:** `RateLimitError`, `APITimeoutError`, `APIConnectionError`, and `APIStatusError` with status `429` or `500–599`.
- **Fail Fast (Attempt 1):** HTTP `400`, `401`, `403`, and malformed JSON (`ModelResponseParseError`).
- **Sanitized Errors (`CWE-209`):** All raised errors (`ModelRateLimitError`, `ModelGatewayError`) use `from None` with generic messages so internal Azure endpoints or Bearer denial bodies never leak to callers.

---

### Q2.3: How do you prevent Managed Identity Bearer token exfiltration (SSRF) on Azure OpenAI calls?

**Answer:**
Two strict controls (`SEC-111`, `SEC-112`, `SEC-116`, `CWE-918` / `CWE-522`):
1. **Endpoint & Query Pinning:** `validate_azure_openai_endpoint()` pins `AZURE_OPENAI_ENDPOINT` strictly to `^https://([a-z0-9][a-z0-9-]{0,62}[a-z0-9])\.openai\.azure\.com/?$`—blocking plaintext HTTP, attacker subdomains, embedded credentials, query strings, and CRLF headers. `validate_api_version()` pins `YYYY-MM-DD[-(preview|alpha|beta)]` to block query-parameter injection (`&api-key=evil`).
2. **Vision Image SSRF Blocking:** `_validate_user_content()` restricts `image_url.url` strictly to base64 `data:image/png;base64,...` or `data:image/jpeg;base64,...` data URIs, rejecting external `http://`/`https://`/IMDS (`169.254.169.254`) and SVG URLs, while capping images at `<= 10`, single image `<= 10 MB`, cumulative payload `<= 25 MB`, and allowlisting `detail` to `{"auto", "low", "high"}`.

---

## 3. Pydantic v2 Extraction Schemas & Financial Precision (P6-3)

### Q3.1: Why did you choose a strict `[0.00, 100.00]` confidence scale with NO automatic rescaling (e.g., turning `0.85` into `85.0`)?

**Answer:**
Automatic heuristic rescaling (`if conf <= 1.0: conf *= 100`) is a **subtle financial safety bug (`SEC-122`, `CWE-682`)**. On a `0–100%` percentage scale (which matches Azure SQL `DECIMAL(5, 2)` and PRD `BR-007` thresholds `>=90%`, `80–89%`, `<80%`), a genuinely terrible `0.85%` confidence score would be silently multiplied into `85.00%`—**bypassing the `<80%` `REQUIRES_APPROVAL` exception queue!** Instead, we enforce `[0.00, 100.00]` strictly in `ExtractedField`, instruct the model explicitly in the system prompt, and write an automated unit test proving `0.85` stays `Decimal("0.85")`.

---

### Q3.2: What financial and security attacks did you harden against in `src/extraction/schemas.py`?

**Answer:**
1. **Rules-First / Prompt-Injection Extra Fields (`SEC-119`, `CWE-915`):** `ConfigDict(extra="forbid", frozen=True)` on all 4 models rejects undeclared fields like `status: "APPROVED_CLERK"` or `skip_validation: true` at any nesting level.
2. **Unicode Bidi & Zero-Width Duplicate-Hash Bypass (`SEC-120`, `CWE-74` / `CWE-451`):** An attacker injecting a single invisible zero-width space `\u200b` or RLO `\u202e` into `invoice_number` or `vendor_tax_id` would fool human reviewers while changing `SHA256(vendor_tax_id + invoice_number + total_amount)` to slip past duplicate detection. We block all bidi/zero-width ranges across text & identifier fields while preserving valid German (`äöüß`) and Spanish (`ñáéíóú`) diacritics.
3. **Decimal Exponent Bombs & Boolean Coercion (`SEC-121`, `CWE-400` / `CWE-20`):** A custom `FiniteDecimal` (`BeforeValidator`) blocks Python `bool` (`True` must never become `Decimal(1)`), `NaN`/`Infinity`, oversized strings (`> 32` chars), scientific-notation bombs like `1E-5000000`, `> 6` fractional digits, and SQL `DECIMAL(18, 2/4)` overflow—while still allowing negative quantities/totals for Credit Notes (`FR-11`).
4. **PII-Safe `repr()` (`SEC-125`, `CWE-532`):** Masks `vendor_tax_id` as `***-**-XXXX` so tracebacks never leak raw Tax IDs.

---

## 4. Extraction Engine, Prompt Injection Defense & Multimodal Prep (P6-4)

### Q4.1: How does `<invoice_text>` delimiter defense hold up if a malicious vendor literally writes `</invoice_text>` inside their invoice PDF?

**Answer:**
Naive f-string wrapping (`f"<invoice_text>{text}</invoice_text>"`) is trivially bypassed by closing-tag injection! In `src/extraction/extract_engine.py`, `sanitize_invoice_text()` runs **before** `wrap_invoice_text()` and applies a defense-in-depth regex neutralizing:
- Standard tags (`</invoice_text>`, `<invoice_text>`),
- Case and whitespace variations (`</ INVOICE_TEXT >`, `< /invoice_text\n>`),
- **Unclosed tags** (`</invoice_text` without `>`),
- **Fullwidth Unicode lookalikes** (`＜/invoice_text＞`, which LLM tokenizers often NFKC-normalize to ASCII!), and
- `<untrusted_data>` / `</untrusted_data>` tags—replacing all matches with `[REDACTED_DELIMITER_TAG]`.

Combined with our **Rules-First architecture (`CLAUDE.md §7.2`)**—where arithmetic, tax tables, duplicate hashes, and approval thresholds live in deterministic Python completely isolated from the LLM—even a successful prompt injection cannot approve a single dollar.

---

### Q4.2: How do you safely handle XLSX workbooks and scanned PDFs without introducing XXE vulnerabilities or OOM crashes?

**Answer:**
- **XLSX (`extract_xlsx_text()` — `SEC-127`):** We parse OOXML `xl/sharedStrings.xml` and `xl/worksheets/sheet*.xml` using Python stdlib `zipfile` + `xml.etree.ElementTree` (zero extra runtime packages). We enforce `<= 25 MB` archive size, Zip-Slip `../` rejection, `<= 10 MB` XML cap, `<= 100x` compression ratio guard, explicit `<!DOCTYPE` / `<!ENTITY` blocking (`CWE-611`), `<= 50,000` shared strings, `<= 2,000`-char cell clamping, `<= 10` sheets, and `<= 2,000` rows/sheet.
- **Vision PDF Rendering (`_render_vision_images()` — `SEC-128`):** A tiny malicious PDF can declare a `10,000 × 10,000 pt` MediaBox, which at 150 DPI would allocate >400 megapixels (~1.3 GB RAM). We compute `scale = min(VISION_RENDER_DPI / 72.0, 2400 / max(width, height))` so every rendered page is guaranteed `<= 2400 px` on both axes, capped at `<= 10` pages and `<= 25 MB` cumulative base64 size.

---

## 5. Offline Mock AOAI Client & Zero-Network Testing (P6-5)

### Q5.1: How does your team test the full extraction pipeline (PDF → Classifier → Prompt → Gateway → Schema) offline in CI at \$0 without mocking away real bugs?

**Answer:**
In **P6-5 (`src/extraction/mock_aoai_client.py`)**, `MockAOAIClient` implements the exact same `AOAIChatClientProtocol` as `KeylessAzureOpenAIClient` and is wired directly into `get_model_gateway()` when `USE_MOCK_AOAI=true`:
- Every real component—`classify_document()`, `extract_xlsx_text()`, `_render_vision_images()`, `build_system_prompt()`, `wrap_invoice_text()`, `ModelGateway` retry/backoff/guards, and `InvoiceExtractionSchema.model_validate()`—executes **for real**.
- Only the final HTTPS call to Azure OpenAI is replaced by `MockAOAIClient`, which matches canonical `INV-YYYY-NNNN[-REV]` tokens against our 300 real files in `sample_data/ground_truth/`, supports `confidence_overrides` (for testing `<80%` and `80–89%` routing), supports FIFO `scripted_errors` (for testing HTTP 429 retries), and simulates Azure Prompt Caching (`cached_tokens > 0`).
- **Safety:** Both `get_model_gateway()` and `MockAOAIClient.__init__()` hard-block mock instantiation outside `{dev, local, test}` or whenever `USE_LOCAL_SQLITE=False` (`CWE-489`), and fixture file reads use `O_NOFOLLOW` + `os.fstat()` regular-file checks + `<= 1 MB` bounded reads (`CWE-22` / `CWE-59` / `CWE-367`).

---

## 6. Real-World Debugging Stories & Security Threat Model Summary

### Q6.1: Tell me about a subtle bug or security edge case you caught during Phase 6 testing.

**Answer (Two Concrete Examples):**
1. **Python 3.13's C `_json` Parser Allowed a Depth-2,000 JSON Bomb (`SEC-114`):** When penetration-testing `ModelGateway._parse_completion()` with `'{"a":' * 2000 + '1' + '}' * 2000`, we initially expected Python's `json.loads()` to raise `RecursionError`. In Python 3.13, the C `_json` scanner actually parsed depth 2,000 cleanly—meaning an upstream JSON nesting bomb would slip past `json.loads()` and blow up downstream serializers! We caught this immediately via our red-team test and added an **iterative (non-recursive) `_enforce_max_json_depth(max_depth=32)`** walk right after `json.loads()`, making JSON depth bombs impossible across all Python versions.
2. **Direct Instantiation Bypass on Generic `ExtractedField[Decimal]` (`SEC-121`):** Putting a `mode="before"` boolean check only on `InvoiceHeaderExtraction` protected dict parsing, *but* someone instantiating `ExtractedField[Decimal](value=True, confidence=95)` directly still triggered Pydantic's default `bool -> Decimal(1)` coercion. Replacing `Decimal` with a reusable `FiniteDecimal = Annotated[Decimal, BeforeValidator(_parse_finite_decimal)]` closed the bypass at the type boundary everywhere—and simultaneously blocked `1E-5000000` Decimal exponent DoS bombs!

---

### Q6.2: Summarize Phase 6's Security Posture for an Executive / Security Architect Review.

| Threat Category | Primary CWEs | Phase 6 Controls Verified |
|---|---|---|
| **SSRF & Managed Identity Token Theft** | `CWE-918`, `CWE-522` | Strict `https://<resource>.openai.azure.com/` pin, API version regex pin, base64-only Vision `data:image/png\|jpeg` allowlist |
| **Prompt Injection & Rules-First Bypass** | `CWE-74`, `CWE-94`, `CWE-915` | `<invoice_text>` delimiters + literal/unclosed/fullwidth breakout neutralization + `extra="forbid"` immutable schemas + zero DB/validation imports |
| **Duplicate-Hash Homograph Fraud** | `CWE-74`, `CWE-451` | Bidi (`\u202e`) and zero-width (`\u200b`) blocking across all identifiers/text while preserving EN/DE/ES diacritics |
| **DoS / Memory / CPU Exhaustion** | `CWE-400`, `CWE-409`, `CWE-674` | 2,000-token cap, 128 KiB / depth-32 JSON bomb cap, `FiniteDecimal` exponent cap, `<=2400px` PDF MediaBox clamp, `<=25 MB` cumulative Vision cap, XLSX ratio/cell caps |
| **XXE / Zip-Slip / Symlink Traversal** | `CWE-22`, `CWE-59`, `CWE-367`, `CWE-611` | `<!DOCTYPE`/`<!ENTITY` blocking, Zip-Slip rejection, `O_NOFOLLOW` + `fstat(S_ISREG)` + `try/finally` FD cleanup on fixture reads |
| **Mock Bypass & PII / Secret Leakage** | `CWE-209`, `CWE-489`, `CWE-532`, `CWE-798` | Prod/staging & Azure-SQL mock gates, zero `api_key=`, masked `***-**-XXXX` `repr()`, sanitized exceptions, zero PII in logs |

