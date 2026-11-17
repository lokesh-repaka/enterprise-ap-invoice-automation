---
trigger: glob
globs: "**/tests/**, **/*_test.py, **/test_*.py"
---

# Test Guidelines — AP Invoice Automation

## Offline-First (Non-Negotiable)
All tests must run with **zero external network calls**. Set before importing the app:

```python
# tests/conftest.py
os.environ["USE_LOCAL_SQLITE"] = "true"
os.environ["USE_FAKE_REDIS"] = "true"
os.environ["USE_MOCK_AOAI"] = "true"
os.environ["SAMPLE_DATA_DIR"] = "./sample_data"
```

## Fixtures Required
- Database: SQLite temp file via `pytest-asyncio` async fixture.
- Redis: `fakeredis` instance.
- Azure OpenAI: Mock returning fixture JSON from `sample_data/ground_truth/`.
- Blob Storage: `unittest.mock.AsyncMock` for `BlobServiceClient`.

## FR Coverage Mapping
Every test file must carry `# Tests: FR-XX` comments. Every FR-01 through FR-14
must have at least one test. Gaps fail the CI pipeline.

## Precision Assertions (Critical)
- Line arithmetic: assert tolerance is exactly ±0.02 (FR-05).
- Invoice total: assert tolerance is exactly ±0.05 (FR-06).
- Tax rates: test all country codes + reverse-charge + exemption (FR-07).
- Date locale: test MM/DD/YYYY, DD/MM/YYYY, and ambiguous `05/06/2026` (FR-08).
- Confidence bands: test at exactly 90%, 89%, 80%, 79% (FR-04).

## Evaluation Thresholds (Fail the Build)
Run via `pytest tests/evaluation/` before each milestone sign-off:
- Header Macro-Average Accuracy ≥ 95%
- Critical Field Hard Floor ≥ 92% each (Vendor Tax ID, Invoice Number, Invoice Date, Total Amount)
- Line-Item Accuracy ≥ 90%
- Pilot STP Rate ≥ 65%
- Zero unhandled exceptions in 300-invoice batch

