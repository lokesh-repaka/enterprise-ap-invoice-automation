"""
Invoice File Validator — Magic-Byte MIME Guard, 25 MB Limit & Encrypted PDF Rejection (P4-3).

Enforces FR-01, BR-001, GAP-004, and CLAUDE.md §7.1 before raw files enter WORM storage:
- Allowed formats: PDF (searchable & scanned), JPG/JPEG, PNG, XLSX (max 25 MB).
- Explicitly rejects TIFF (Phase 2 scope: GAP-004) across extension, MIME, and magic bytes.
- Rejects password-protected PDFs via PyMuPDF (``needs_pass``), corrupted PDFs, and PDFs
  containing active scripts (/JavaScript, /JS, /Launch) or executable attachments.
- Pre-decode JPEG SOF & PNG IHDR dimension bounds block pixel decompression bombs (CWE-400).
- XLSX OOXML validation defends against Zip-Slip (CWE-22), ZIP bombs & forged ZIP headers
  (CWE-409), password-protected ZIPs, duplicate-entry parser differentials, VBA/XLM macros
  & OLE droppers (CWE-434), and UTF-8/UTF-16 XXE payloads across all XML/RELS parts (CWE-611).
"""

import hashlib
import io
import re
import struct
import zipfile
from pathlib import Path

import fitz
from pydantic import BaseModel, ConfigDict

from src.core.logging import get_logger
from src.storage.blob_client import MAX_BLOB_SIZE_BYTES, SAFE_FILENAME_PATTERN

logger = get_logger("ap.storage.file_validator")

# FR-01: 25 MB maximum upload size per file
MAX_UPLOAD_SIZE_BYTES: int = MAX_BLOB_SIZE_BYTES

# Bounded structural limits to block DoS / decompression bombs (CWE-400 / CWE-409)
MAX_PDF_PAGES: int = 200
MAX_PDF_XREF_SCAN: int = 10_000
MAX_IMAGE_DIMENSION: int = 20_000
MAX_IMAGE_PIXELS: int = 50_000_000
MAX_XLSX_ENTRIES: int = 500
MAX_XLSX_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024
MAX_XLSX_COMPRESSION_RATIO: float = 100.0
MAX_XML_SCAN_BYTES: int = 2 * 1024 * 1024
MAX_XLSX_XML_TOTAL_SCAN_BYTES: int = 10 * 1024 * 1024

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

EXTENSION_TO_MIME: dict[str, str] = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".xlsx": XLSX_MIME,
}
ALLOWED_EXTENSIONS: frozenset[str] = frozenset(EXTENSION_TO_MIME.keys())
TIFF_EXTENSIONS: frozenset[str] = frozenset({".tif", ".tiff"})
TIFF_MIMES: frozenset[str] = frozenset({"image/tiff", "image/x-tiff"})

_DANGEROUS_PDF_ATTACHMENT_EXTS: frozenset[str] = frozenset(
    {".exe", ".bat", ".cmd", ".ps1", ".js", ".jse", ".vbs", ".vbe", ".sh", ".dll", ".scr", ".msi"}
)

# JPEG SOF0..SOF15 frame markers carrying image height/width (excluding DHT=C4, JPG=C8, DAC=CC)
_JPEG_SOF_MARKERS: frozenset[int] = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
# Standalone JPEG markers that carry no 2-byte length field
_JPEG_STANDALONE_MARKERS: frozenset[int] = frozenset(
    {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9}
)

_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")
_PDF_ACTIVE_ACTION_RE = re.compile(r"/(?:JavaScript|JS|Launch)\b")
_XXE_ASCII_RE = re.compile(rb"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XXE_UTF16LE_RE = re.compile(
    rb"<\x00!\x00(?:D\x00O\x00C\x00T\x00Y\x00P\x00E\x00|E\x00N\x00T\x00I\x00T\x00Y\x00)",
    re.IGNORECASE,
)
_XXE_UTF16BE_RE = re.compile(
    rb"\x00<\x00!(?:\x00D\x00O\x00C\x00T\x00Y\x00P\x00E|\x00E\x00N\x00T\x00I\x00T\x00Y)",
    re.IGNORECASE,
)
_MACRO_CONTENT_TYPE_RE = re.compile(rb"macroenabled", re.IGNORECASE)


class FileValidationError(ValueError):
    """Base file intake validation error carrying structured code and HTTP status."""

    def __init__(self, message: str, *, error_code: str = "INVALID_FILE", http_status: int = 422):
        super().__init__(message)
        self.error_code = error_code
        self.http_status = http_status


class FileTooLargeError(FileValidationError):
    """Raised when an uploaded file exceeds the 25 MB limit (FR-01 -> HTTP 413)."""

    def __init__(self, message: str):
        super().__init__(message, error_code="FILE_TOO_LARGE", http_status=413)


class UnsupportedFileTypeError(FileValidationError):
    """Raised on unsupported format, TIFF, or extension/MIME mismatch (-> HTTP 415)."""

    def __init__(self, message: str):
        super().__init__(message, error_code="UNSUPPORTED_FILE_TYPE", http_status=415)


class PasswordProtectedPDFError(FileValidationError):
    """Raised when a PDF requires a user password to open (-> HTTP 422)."""

    def __init__(self, message: str):
        super().__init__(message, error_code="PASSWORD_PROTECTED_PDF", http_status=422)


class CorruptedOrMaliciousFileError(FileValidationError):
    """Raised on corrupted, macro-bearing, XXE, Zip-Slip, active-PDF, or bomb files (-> HTTP 422)."""

    def __init__(self, message: str):
        super().__init__(message, error_code="CORRUPTED_OR_MALICIOUS_FILE", http_status=422)


class ValidatedFile(BaseModel):
    """Immutable metadata receipt returned for a file that passed all intake security guards."""

    model_config = ConfigDict(frozen=True)

    filename: str
    extension: str
    detected_mime: str
    size_bytes: int
    sha256_hash: str
    page_count: int | None = None


def _validate_filename(filename: str) -> tuple[str, str]:
    """Validate safe basename (blocking traversal/nulls/CRLF) and return (filename, lower_ext)."""
    if (
        not isinstance(filename, str)
        or not filename
        or "/" in filename
        or "\\" in filename
        or ".." in filename
        or _CONTROL_CHAR_RE.search(filename)
        or not SAFE_FILENAME_PATTERN.match(filename)
    ):
        raise FileValidationError("Invalid or unsafe filename")

    ext = Path(filename).suffix.lower()
    if ext in TIFF_EXTENSIONS:
        raise UnsupportedFileTypeError("TIFF format is not supported in Phase 1 (GAP-004)")
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedFileTypeError(
            f"Unsupported file extension '{ext or '<none>'}'; allowed: PDF, JPG, PNG, XLSX"
        )
    return filename, ext


def _normalize_declared_mime(declared_content_type: str | None) -> str | None:
    """Sanitize optional client-declared Content-Type header and reject CRLF/TIFF."""
    if declared_content_type is None:
        return None
    if not isinstance(declared_content_type, str) or _CONTROL_CHAR_RE.search(declared_content_type):
        raise FileValidationError("Invalid declared Content-Type header")
    base_mime = declared_content_type.split(";", 1)[0].strip().lower()
    if not base_mime:
        return None
    if base_mime in TIFF_MIMES:
        raise UnsupportedFileTypeError("TIFF format is not supported in Phase 1 (GAP-004)")
    return base_mime


def _sniff_magic_mime(data: bytes) -> str:
    """Detect file MIME strictly from binary magic-byte signatures (never trusting headers)."""
    if data.startswith((b"II*\x00", b"MM\x00*")):
        raise UnsupportedFileTypeError("TIFF format is not supported in Phase 1 (GAP-004)")
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"PK\x03\x04"):
        return XLSX_MIME
    raise UnsupportedFileTypeError("Unsupported or unrecognized file signature")


def _check_image_bounds(width: int, height: int, fmt_label: str) -> None:
    """Enforce pixel dimension and area ceilings to prevent decompression bombs (CWE-400)."""
    if (
        width <= 0
        or height <= 0
        or width > MAX_IMAGE_DIMENSION
        or height > MAX_IMAGE_DIMENSION
        or (width * height) > MAX_IMAGE_PIXELS
    ):
        raise CorruptedOrMaliciousFileError(
            f"{fmt_label} image dimensions exceed safe processing bounds"
        )


def _extract_jpeg_sof_dimensions(data: bytes) -> tuple[int, int]:
    """Parse JPEG SOF marker dimensions directly from bytes before invoking MuPDF (CWE-400)."""
    n = len(data)
    idx = 2  # Skip leading SOI (0xFFD8)
    while idx < n:
        # Advance to next 0xFF marker prefix
        if data[idx] != 0xFF:
            raise CorruptedOrMaliciousFileError("Malformed JPEG marker structure")
        while idx < n and data[idx] == 0xFF:
            idx += 1
        if idx >= n:
            break
        marker = data[idx]
        idx += 1

        if marker in _JPEG_STANDALONE_MARKERS:
            if marker == 0xD9:  # EOI reached without SOF
                break
            continue
        if marker == 0xDA:  # Start Of Scan reached without SOF
            break

        if idx + 2 > n:
            raise CorruptedOrMaliciousFileError("Truncated JPEG segment header")
        seg_len = struct.unpack(">H", data[idx : idx + 2])[0]
        if seg_len < 2 or idx + seg_len > n:
            raise CorruptedOrMaliciousFileError("Malformed JPEG segment length")

        if marker in _JPEG_SOF_MARKERS:
            if seg_len < 7:
                raise CorruptedOrMaliciousFileError("Truncated JPEG SOF frame header")
            height, width = struct.unpack(">HH", data[idx + 3 : idx + 7])
            return width, height

        idx += seg_len

    raise CorruptedOrMaliciousFileError("JPEG image is missing a valid Start-Of-Frame header")


def _validate_pdf(data: bytes) -> int:
    """Verify PDF parses cleanly, is unlocked, respects page limits, and has no active scripts."""
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        raise CorruptedOrMaliciousFileError("Corrupted or unreadable PDF document") from None

    try:
        if doc.needs_pass:
            raise PasswordProtectedPDFError(
                "Password-protected PDF files are not supported; please upload an unlocked PDF"
            )
        page_count = doc.page_count
        if page_count < 1:
            raise CorruptedOrMaliciousFileError("PDF document contains zero pages")
        if page_count > MAX_PDF_PAGES:
            raise CorruptedOrMaliciousFileError(
                f"PDF page count ({page_count}) exceeds maximum allowed ({MAX_PDF_PAGES})"
            )

        # Inspect embedded filenames for dangerous executable payloads (CWE-434)
        for emb_name in doc.embfile_names():
            if Path(emb_name).suffix.lower() in _DANGEROUS_PDF_ATTACHMENT_EXTS:
                raise CorruptedOrMaliciousFileError(
                    "Executable embedded attachment detected in PDF document"
                )

        # Inspect PDF xref object dictionaries (decompressed by MuPDF) for active JS / Launch (CWE-94)
        xref_total = min(doc.xref_length(), MAX_PDF_XREF_SCAN)
        for xref in range(1, xref_total):
            obj_str = doc.xref_object(xref, compressed=False)
            if _PDF_ACTIVE_ACTION_RE.search(obj_str):
                raise CorruptedOrMaliciousFileError(
                    "Active PDF script or launch action (/JavaScript, /JS, /Launch) is not permitted"
                )

        return page_count
    finally:
        doc.close()


def _validate_png(data: bytes) -> None:
    """Verify PNG IHDR dimensions (anti-pixel-bomb) and confirm MuPDF decodes the image."""
    if len(data) < 24 or data[12:16] != b"IHDR":
        raise CorruptedOrMaliciousFileError("Malformed PNG header (missing IHDR chunk)")

    width, height = struct.unpack(">II", data[16:24])
    _check_image_bounds(width, height, "PNG")

    try:
        doc = fitz.open(stream=data, filetype="png")
        try:
            if doc.page_count < 1:
                raise CorruptedOrMaliciousFileError("Unreadable PNG image")
        finally:
            doc.close()
    except FileValidationError:
        raise
    except Exception:
        raise CorruptedOrMaliciousFileError("Corrupted or unreadable PNG image") from None


def _validate_jpeg(data: bytes) -> None:
    """Verify JPEG SOF dimensions pre-decode and confirm MuPDF decodes cleanly (CWE-400)."""
    width, height = _extract_jpeg_sof_dimensions(data)
    _check_image_bounds(width, height, "JPEG")

    try:
        doc = fitz.open(stream=data, filetype="jpeg")
        try:
            if doc.page_count < 1:
                raise CorruptedOrMaliciousFileError("Unreadable JPEG image")
            rect = doc[0].rect
            _check_image_bounds(int(rect.width), int(rect.height), "JPEG")
        finally:
            doc.close()
    except FileValidationError:
        raise
    except Exception:
        raise CorruptedOrMaliciousFileError("Corrupted or unreadable JPEG image") from None


def _has_xxe_payload(sample: bytes) -> bool:
    """Detect XML DOCTYPE/ENTITY declarations across UTF-8/ASCII and UTF-16LE/BE encodings."""
    return bool(
        _XXE_ASCII_RE.search(sample)
        or _XXE_UTF16LE_RE.search(sample)
        or _XXE_UTF16BE_RE.search(sample)
    )


def _validate_xlsx(data: bytes) -> None:
    """
    Validate OOXML XLSX archive integrity and defend against ZIP-based attacks:
    - Zip-Slip path traversal & control chars in member names (CWE-22)
    - Duplicate archive entry parser differentials (CWE-434)
    - Encrypted / password-protected ZIP entries
    - ZIP bombs (entry count, declared & actual decompressed size, ratio — CWE-409)
    - Disguised non-XLSX ZIPs / DOCX / PPTX (requires [Content_Types].xml & xl/workbook.xml)
    - VBA/XLM macros, ActiveX controls, and OLE embedded objects (allowing printerSettings.bin)
    - UTF-8 and UTF-16 XXE DOCTYPE/ENTITY payloads across all .xml/.rels members (CWE-611)
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise CorruptedOrMaliciousFileError("Corrupted or invalid XLSX archive") from None

    with zf:
        infos = zf.infolist()
        if len(infos) == 0 or len(infos) > MAX_XLSX_ENTRIES:
            raise CorruptedOrMaliciousFileError("XLSX archive entry count outside permitted bounds")

        names: set[str] = set()
        seen_lower: set[str] = set()
        info_by_name: dict[str, zipfile.ZipInfo] = {}
        total_uncompressed = 0
        total_compressed = 0

        for info in infos:
            member_name = info.filename
            # Zip-Slip & control-char guard (CWE-22)
            if (
                not member_name
                or _CONTROL_CHAR_RE.search(member_name)
                or member_name.startswith(("/", "\\"))
                or ".." in Path(member_name).parts
                or "\\" in member_name
                or ":" in member_name
            ):
                raise CorruptedOrMaliciousFileError("XLSX contains unsafe archive path (Zip-Slip)")

            if info.flag_bits & 0x1:
                raise CorruptedOrMaliciousFileError(
                    "Password-protected or encrypted XLSX archives are not supported"
                )

            lower_name = member_name.lower()
            if lower_name in seen_lower:
                raise CorruptedOrMaliciousFileError(
                    "XLSX archive contains duplicate member entries (parser differential risk)"
                )
            seen_lower.add(lower_name)

            # Macro / ActiveX / OLE dropper guard (allows benign xl/printerSettings/*.bin)
            if (
                "vbaproject.bin" in lower_name
                or lower_name.startswith(
                    ("xl/macrosheets/", "xl/dialogsheets/", "xl/activex/", "xl/embeddings/")
                )
                or lower_name.endswith(".vba")
            ):
                raise CorruptedOrMaliciousFileError(
                    "Macro-enabled or embedded-object spreadsheets are not permitted; upload a standard .xlsx file"
                )

            total_uncompressed += info.file_size
            total_compressed += max(info.compress_size, 1)
            names.add(member_name)
            info_by_name[member_name] = info

        if total_uncompressed > MAX_XLSX_UNCOMPRESSED_BYTES:
            raise CorruptedOrMaliciousFileError(
                "XLSX uncompressed size exceeds maximum permitted limit (ZIP bomb guard)"
            )
        if (
            total_uncompressed > 1_048_576
            and (total_uncompressed / max(total_compressed, 1)) > MAX_XLSX_COMPRESSION_RATIO
        ):
            raise CorruptedOrMaliciousFileError(
                "XLSX compression ratio exceeds safe threshold (ZIP bomb guard)"
            )

        # Must contain canonical OOXML spreadsheet structure (rejects plain .zip and .docx)
        if "[Content_Types].xml" not in names or "xl/workbook.xml" not in names:
            raise UnsupportedFileTypeError("ZIP archive is not a valid XLSX spreadsheet workbook")

        # XXE & macro content-type inspection across ALL .xml and .rels members (CWE-611 / CWE-409)
        total_xml_read = 0
        for member_name in sorted(names):
            lower_name = member_name.lower()
            if not (lower_name.endswith(".xml") or lower_name.endswith(".rels")):
                continue

            member_info = info_by_name[member_name]
            try:
                with zf.open(member_info) as member_fp:
                    sample = member_fp.read(MAX_XML_SCAN_BYTES + 1)
            except (zipfile.BadZipFile, RuntimeError, ValueError):
                raise CorruptedOrMaliciousFileError("Corrupted XML member inside XLSX") from None

            # Detect forged central-directory size headers / hidden decompression bombs (CWE-409)
            if len(sample) > member_info.file_size or len(sample) > MAX_XML_SCAN_BYTES:
                raise CorruptedOrMaliciousFileError(
                    "XLSX XML member exceeds safe uncompressed size limit (ZIP bomb guard)"
                )
            total_xml_read += len(sample)
            if total_xml_read > MAX_XLSX_XML_TOTAL_SCAN_BYTES:
                raise CorruptedOrMaliciousFileError(
                    "Cumulative XLSX XML payload exceeds safe processing budget"
                )

            if _has_xxe_payload(sample):
                raise CorruptedOrMaliciousFileError(
                    "Disallowed XML DOCTYPE/ENTITY (XXE) payload detected in XLSX"
                )
            if member_name == "[Content_Types].xml" and _MACRO_CONTENT_TYPE_RE.search(sample):
                raise CorruptedOrMaliciousFileError(
                    "Macro-enabled spreadsheet content type detected; upload a standard .xlsx file"
                )


def validate_invoice_file(
    filename: str,
    data: bytes,
    declared_content_type: str | None = None,
    *,
    max_size_bytes: int = MAX_UPLOAD_SIZE_BYTES,
) -> ValidatedFile:
    """
    Validate an uploaded invoice document before WORM Blob ingestion (FR-01, BR-001, GAP-004).

    Verifies filename safety, 25 MB size bound, magic-byte MIME signature, declared
    Content-Type consistency, and deep format integrity (including password-protected PDF
    rejection, active PDF script blocking, pre-decode image bounds, and XLSX security guards).
    """
    clean_name, ext = _validate_filename(filename)
    declared_mime = _normalize_declared_mime(declared_content_type)

    if not isinstance(data, bytes) or len(data) == 0:
        raise FileValidationError("Uploaded file is empty")
    if len(data) > max_size_bytes:
        raise FileTooLargeError(
            f"Uploaded file size ({len(data)} bytes) exceeds maximum limit of {max_size_bytes} bytes"
        )

    detected_mime = _sniff_magic_mime(data)
    expected_mime_for_ext = EXTENSION_TO_MIME[ext]
    if detected_mime != expected_mime_for_ext:
        raise UnsupportedFileTypeError(
            f"File content signature ({detected_mime}) does not match extension '{ext}'"
        )

    if (
        declared_mime is not None
        and declared_mime != "application/octet-stream"
        and declared_mime != detected_mime
    ):
        raise UnsupportedFileTypeError(
            f"Declared Content-Type ({declared_mime}) does not match detected type ({detected_mime})"
        )

    page_count: int | None = None
    if detected_mime == "application/pdf":
        page_count = _validate_pdf(data)
    elif detected_mime == "image/png":
        _validate_png(data)
    elif detected_mime == "image/jpeg":
        _validate_jpeg(data)
    elif detected_mime == XLSX_MIME:
        _validate_xlsx(data)

    sha256_hex = hashlib.sha256(data).hexdigest()
    logger.info(
        "Validated invoice upload file",
        extra={
            "extension": ext,
            "detected_mime": detected_mime,
            "size_bytes": len(data),
            "sha256_prefix": sha256_hex[:12],
        },
    )
    return ValidatedFile(
        filename=clean_name,
        extension=ext,
        detected_mime=detected_mime,
        size_bytes=len(data),
        sha256_hash=sha256_hex,
        page_count=page_count,
    )
