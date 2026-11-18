"""
Document Classifier — PyMuPDF Text-Layer Density Check (P6-1).

Classifies raw invoice bytes into one of three canonical routing classes per
ADR-004, HLD §241, and CLAUDE.md §7.1:
- ``searchable_pdf`` -> Clean digital PDF text layer -> routes to **GPT-4o-mini** (~80% token savings).
- ``scanned_image``  -> Raster image (PNG/JPEG), image-only PDF, sparse-OCR scan PDF,
  or hybrid PDF containing scanned pages -> routes to **GPT-4o Vision**.
- ``xlsx``           -> Verified OOXML spreadsheet workbook -> routes to tabular extraction.

Security & Layering Rules (CLAUDE.md §4.2, §7.1):
- Zero imports from ``src/database/`` or ``src/validation/``.
- Magic-byte signature detection exclusively (never trusts caller filenames: CWE-434).
- Rejects TIFF (GAP-004), >25 MB payloads, password-protected PDFs, Zip-Slip (CWE-22),
  and ZIP bombs (CWE-409).
- Meaningful alphanumeric character counting defeats whitespace/control-char text-layer spoofing.
- Zero document text or PII emitted to logs (CWE-532).
"""

import io
import re
import struct
import zipfile
from enum import StrEnum
from pathlib import Path

import fitz
from pydantic import BaseModel, ConfigDict

from src.core.logging import get_logger

logger = get_logger("ap.extraction.document_classifier")

# Bounded operational limits (FR-01 / CWE-400 / CWE-409)
MAX_CLASSIFIER_SIZE_BYTES: int = 25 * 1024 * 1024
MAX_CLASSIFIER_PDF_PAGES: int = 200
MAX_EXTRACTED_TEXT_CHARS: int = 200_000
MAX_IMAGE_DIMENSION: int = 20_000
MAX_IMAGE_PIXELS: int = 50_000_000
MAX_XLSX_ENTRIES: int = 500
MAX_XLSX_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024
MAX_XLSX_COMPRESSION_RATIO: float = 100.0

# Default PyMuPDF text-layer density thresholds (ADR-004)
DEFAULT_MIN_CHARS_PER_PAGE: int = 50
DEFAULT_MIN_UNIQUE_ALNUM_CHARS: int = 10
DEFAULT_MIN_DENSE_PAGE_RATIO: float = 0.5

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

# Strip invisible control & Unicode bidi/zero-width spoofing chars from extracted text
# while preserving English, German (äöüß), and Spanish (ñáéíóú¿¡) characters (FR-02)
_UNSAFE_TEXT_CHARS_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)
_JPEG_SOF_MARKERS: frozenset[int] = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
_JPEG_STANDALONE_MARKERS: frozenset[int] = frozenset(
    {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9}
)


class DocumentType(StrEnum):
    """Canonical classifier routing classes per CLAUDE.md §7.1 and TASKS.md P6-1."""

    SEARCHABLE_PDF = "searchable_pdf"
    SCANNED_IMAGE = "scanned_image"
    XLSX = "xlsx"


class DocumentClassificationError(ValueError):
    """Raised when document bytes are empty, oversized, encrypted, corrupted, or malicious."""


class UnsupportedDocumentError(DocumentClassificationError):
    """Raised on unsupported binary formats (e.g., TIFF per GAP-004, HTML, DOCX, plain ZIP)."""


class DocumentClassificationResult(BaseModel):
    """Immutable classification receipt consumed by Model Gateway (P6-2) & Extraction Engine (P6-4)."""

    model_config = ConfigDict(frozen=True)

    document_type: DocumentType
    detected_mime: str
    page_count: int
    total_text_chars: int
    mean_chars_per_page: float
    text_density_ratio: float
    scanned_page_indices: tuple[int, ...] = ()
    extracted_text: str | None = None
    reason: str


def _sniff_mime(data: bytes) -> str:
    """Detect binary document format strictly from magic bytes (never trusting filenames)."""
    if data.startswith((b"II*\x00", b"MM\x00*")):
        raise UnsupportedDocumentError("TIFF format is not supported in Phase 1 (GAP-004)")
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"PK\x03\x04"):
        return XLSX_MIME
    raise UnsupportedDocumentError("Unsupported or unrecognized binary file signature")


def _sanitize_extracted_text(text: str) -> str:
    """Remove invisible control/bidi/zero-width characters while preserving EN/DE/ES diacritics."""
    return _UNSAFE_TEXT_CHARS_RE.sub("", text)


def _count_meaningful_chars(text: str) -> tuple[int, int]:
    """
    Return (total_alnum_chars, unique_lowercase_alnum_chars) to resist whitespace,
    zero-width, punctuation noise, and repeated-character ('AAAA...') density spoofing.
    """
    alnum = [ch.lower() for ch in text if ch.isalnum()]
    return len(alnum), len(set(alnum))


def _check_raster_bounds(width: int, height: int, fmt_label: str) -> None:
    if (
        width <= 0
        or height <= 0
        or width > MAX_IMAGE_DIMENSION
        or height > MAX_IMAGE_DIMENSION
        or (width * height) > MAX_IMAGE_PIXELS
    ):
        raise DocumentClassificationError(f"{fmt_label} image dimensions exceed safe bounds")


def _extract_jpeg_dimensions(data: bytes) -> tuple[int, int]:
    """Parse JPEG SOF dimensions directly from bytes before decode (anti-pixel-bomb: CWE-400)."""
    n = len(data)
    idx = 2
    while idx < n:
        if data[idx] != 0xFF:
            raise DocumentClassificationError("Malformed JPEG image structure")
        while idx < n and data[idx] == 0xFF:
            idx += 1
        if idx >= n:
            break
        marker = data[idx]
        idx += 1
        if marker in _JPEG_STANDALONE_MARKERS:
            if marker == 0xD9:
                break
            continue
        if marker == 0xDA:
            break
        if idx + 2 > n:
            raise DocumentClassificationError("Truncated JPEG header")
        seg_len = struct.unpack(">H", data[idx : idx + 2])[0]
        if seg_len < 2 or idx + seg_len > n:
            raise DocumentClassificationError("Malformed JPEG segment length")
        if marker in _JPEG_SOF_MARKERS:
            if seg_len < 7:
                raise DocumentClassificationError("Truncated JPEG SOF header")
            height, width = struct.unpack(">HH", data[idx + 3 : idx + 7])
            return width, height
        idx += seg_len
    raise DocumentClassificationError("JPEG image is missing a valid Start-Of-Frame header")


def _classify_raster_image(data: bytes, detected_mime: str) -> DocumentClassificationResult:
    """Validate raster image headers & pixel bounds before classifying as scanned_image (CWE-400/434)."""
    if detected_mime == "image/png":
        if len(data) < 24 or data[12:16] != b"IHDR":
            raise DocumentClassificationError("Malformed PNG header (missing IHDR chunk)")
        width, height = struct.unpack(">II", data[16:24])
        _check_raster_bounds(width, height, "PNG")
        fitz_type = "png"
    else:
        width, height = _extract_jpeg_dimensions(data)
        _check_raster_bounds(width, height, "JPEG")
        fitz_type = "jpeg"

    try:
        doc = fitz.open(stream=data, filetype=fitz_type)
        try:
            if doc.page_count < 1:
                raise DocumentClassificationError(f"Unreadable {fitz_type.upper()} image")
        finally:
            doc.close()
    except DocumentClassificationError:
        raise
    except Exception:
        raise DocumentClassificationError(f"Corrupted {fitz_type.upper()} image") from None

    return DocumentClassificationResult(
        document_type=DocumentType.SCANNED_IMAGE,
        detected_mime=detected_mime,
        page_count=1,
        total_text_chars=0,
        mean_chars_per_page=0.0,
        text_density_ratio=0.0,
        scanned_page_indices=(0,),
        extracted_text=None,
        reason="raster_image_input",
    )


def _classify_xlsx(data: bytes) -> DocumentClassificationResult:
    """Verify safe OOXML XLSX structure and count worksheet tabs (blocks Zip-Slip & ZIP bombs)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise DocumentClassificationError("Corrupted or invalid XLSX archive") from None

    with zf:
        infos = zf.infolist()
        if len(infos) == 0 or len(infos) > MAX_XLSX_ENTRIES:
            raise DocumentClassificationError("XLSX archive entry count outside permitted bounds")

        names: set[str] = set()
        seen_lower: set[str] = set()
        total_uncompressed = 0
        total_compressed = 0

        for info in infos:
            member = info.filename
            if (
                not member
                or member.startswith(("/", "\\"))
                or ".." in Path(member).parts
                or "\\" in member
                or ":" in member
            ):
                raise DocumentClassificationError("XLSX contains unsafe archive path (Zip-Slip)")
            if info.flag_bits & 0x1:
                raise DocumentClassificationError("Encrypted XLSX archives are not supported")

            lower_name = member.lower()
            if lower_name in seen_lower:
                raise DocumentClassificationError("XLSX archive contains duplicate member entries")
            seen_lower.add(lower_name)

            total_uncompressed += info.file_size
            total_compressed += max(info.compress_size, 1)
            names.add(member)

        if total_uncompressed > MAX_XLSX_UNCOMPRESSED_BYTES:
            raise DocumentClassificationError(
                "XLSX uncompressed size exceeds safe limit (ZIP bomb)"
            )
        if (
            total_uncompressed > 1_048_576
            and (total_uncompressed / max(total_compressed, 1)) > MAX_XLSX_COMPRESSION_RATIO
        ):
            raise DocumentClassificationError(
                "XLSX compression ratio exceeds safe threshold (ZIP bomb)"
            )

        if "[Content_Types].xml" not in names or "xl/workbook.xml" not in names:
            raise UnsupportedDocumentError("ZIP archive is not a valid XLSX spreadsheet workbook")

        sheet_count = sum(
            1
            for name in names
            if name.lower().startswith("xl/worksheets/") and name.lower().endswith(".xml")
        )
        return DocumentClassificationResult(
            document_type=DocumentType.XLSX,
            detected_mime=XLSX_MIME,
            page_count=max(sheet_count, 1),
            total_text_chars=0,
            mean_chars_per_page=0.0,
            text_density_ratio=1.0,
            scanned_page_indices=(),
            extracted_text=None,
            reason="ooxml_xlsx_workbook",
        )


def _classify_pdf(
    data: bytes,
    *,
    min_chars_per_page: int,
    min_dense_page_ratio: float,
    extract_text: bool,
) -> DocumentClassificationResult:
    """Inspect PDF pages via PyMuPDF to distinguish searchable digital PDFs from scanned/hybrid PDFs."""
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        raise DocumentClassificationError("Corrupted or unreadable PDF document") from None

    try:
        if doc.needs_pass:
            raise DocumentClassificationError(
                "Password-protected PDF documents cannot be classified or extracted"
            )
        page_count = doc.page_count
        if page_count < 1:
            raise DocumentClassificationError("PDF document contains zero pages")
        if page_count > MAX_CLASSIFIER_PDF_PAGES:
            raise DocumentClassificationError(
                f"PDF page count ({page_count}) exceeds maximum allowed ({MAX_CLASSIFIER_PDF_PAGES})"
            )

        page_texts: list[str] = []
        accumulated_text_len = 0
        dense_pages = 0
        scanned_pages: list[int] = []
        total_meaningful_chars = 0

        for idx in range(page_count):
            page = doc[idx]
            raw_text = _sanitize_extracted_text(page.get_text("text") or "")
            meaningful_chars, unique_chars = _count_meaningful_chars(raw_text)
            has_images = len(page.get_images(full=False)) > 0

            is_dense_page = meaningful_chars >= min_chars_per_page and unique_chars >= min(
                DEFAULT_MIN_UNIQUE_ALNUM_CHARS, min_chars_per_page
            )
            total_meaningful_chars += meaningful_chars
            if is_dense_page:
                dense_pages += 1
            elif has_images:
                # Sparse, empty, or repeated-padding text on an image-bearing page indicates a scan
                scanned_pages.append(idx)

            if extract_text and accumulated_text_len < MAX_EXTRACTED_TEXT_CHARS:
                stripped = raw_text.strip()
                if stripped:
                    remaining = MAX_EXTRACTED_TEXT_CHARS - accumulated_text_len
                    chunk = stripped[:remaining]
                    page_texts.append(chunk)
                    accumulated_text_len += len(chunk) + 2

        mean_chars = round(total_meaningful_chars / page_count, 2)
        density_ratio = round(dense_pages / page_count, 4)

        is_searchable = (
            total_meaningful_chars >= min_chars_per_page
            and mean_chars >= min_chars_per_page
            and density_ratio >= min_dense_page_ratio
            and len(scanned_pages) == 0
        )

        if is_searchable:
            combined_text: str | None = None
            if extract_text:
                joined = "\n\n".join(t for t in page_texts if t)
                combined_text = joined[:MAX_EXTRACTED_TEXT_CHARS]
            return DocumentClassificationResult(
                document_type=DocumentType.SEARCHABLE_PDF,
                detected_mime="application/pdf",
                page_count=page_count,
                total_text_chars=total_meaningful_chars,
                mean_chars_per_page=mean_chars,
                text_density_ratio=density_ratio,
                scanned_page_indices=(),
                extracted_text=combined_text,
                reason="pdf_dense_text_layer",
            )

        reason = (
            "pdf_hybrid_or_scanned_pages_detected"
            if scanned_pages
            else "pdf_insufficient_text_layer_density"
        )
        return DocumentClassificationResult(
            document_type=DocumentType.SCANNED_IMAGE,
            detected_mime="application/pdf",
            page_count=page_count,
            total_text_chars=total_meaningful_chars,
            mean_chars_per_page=mean_chars,
            text_density_ratio=density_ratio,
            scanned_page_indices=tuple(scanned_pages),
            extracted_text=None,
            reason=reason,
        )
    finally:
        doc.close()


def classify_document(
    data: bytes,
    *,
    filename: str | None = None,
    min_chars_per_page: int = DEFAULT_MIN_CHARS_PER_PAGE,
    min_dense_page_ratio: float = DEFAULT_MIN_DENSE_PAGE_RATIO,
    extract_text: bool = True,
) -> DocumentClassificationResult:
    """
    Classify raw invoice bytes into ``searchable_pdf``, ``scanned_image``, or ``xlsx`` (P6-1).

    Uses binary magic-byte detection and PyMuPDF per-page text-layer density checks so
    Model Gateway (P6-2) can route digital PDFs to GPT-4o-mini and scans/images to GPT-4o Vision.
    """
    if not isinstance(data, bytes) or len(data) == 0:
        raise DocumentClassificationError("Document payload is empty")
    if len(data) > MAX_CLASSIFIER_SIZE_BYTES:
        raise DocumentClassificationError(
            f"Document payload ({len(data)} bytes) exceeds maximum limit of {MAX_CLASSIFIER_SIZE_BYTES} bytes"
        )
    if (
        isinstance(min_chars_per_page, bool)
        or not isinstance(min_chars_per_page, int)
        or not (1 <= min_chars_per_page <= 10_000)
    ):
        raise ValueError("min_chars_per_page must be an integer within [1, 10000]")
    if isinstance(min_dense_page_ratio, bool) or not (0.0 < float(min_dense_page_ratio) <= 1.0):
        raise ValueError("min_dense_page_ratio must be within (0.0, 1.0]")

    detected_mime = _sniff_mime(data)

    if detected_mime == "application/pdf":
        result = _classify_pdf(
            data,
            min_chars_per_page=min_chars_per_page,
            min_dense_page_ratio=float(min_dense_page_ratio),
            extract_text=extract_text,
        )
    elif detected_mime in ("image/png", "image/jpeg"):
        result = _classify_raster_image(data, detected_mime)
    elif detected_mime == XLSX_MIME:
        result = _classify_xlsx(data)
    else:  # pragma: no cover - defensive fallback
        raise UnsupportedDocumentError(f"Unsupported MIME type: {detected_mime}")

    logger.info(
        "Classified invoice document",
        extra={
            "document_type": result.document_type.value,
            "detected_mime": result.detected_mime,
            "page_count": result.page_count,
            "mean_chars_per_page": result.mean_chars_per_page,
            "scanned_page_count": len(result.scanned_page_indices),
            "reason": result.reason,
        },
    )
    return result
