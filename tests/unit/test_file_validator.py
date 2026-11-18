"""
Unit and Security Penetration Tests for File Validator (P4-3).

Tests: FR-01, BR-001, GAP-004, CWE-22, CWE-113, CWE-400, CWE-409, CWE-434, CWE-611
"""

import hashlib
import io
import struct
import zipfile

import fitz
import pytest

from src.storage.file_validator import (
    MAX_UPLOAD_SIZE_BYTES,
    CorruptedOrMaliciousFileError,
    FileTooLargeError,
    FileValidationError,
    PasswordProtectedPDFError,
    UnsupportedFileTypeError,
    ValidatedFile,
    validate_invoice_file,
)


def _make_valid_pdf(*, pages: int = 1, user_password: str | None = None) -> bytes:
    """Create a genuine in-memory PDF via PyMuPDF (optionally AES-256 password-protected)."""
    doc = fitz.open()
    for i in range(pages):
        page = doc.new_page()
        page.insert_text((72, 72), f"Synthetic Invoice Page {i + 1}")
    try:
        if user_password is not None:
            return doc.tobytes(
                encryption=fitz.PDF_ENCRYPT_AES_256,
                user_pw=user_password,
                owner_pw="owner-secret",
            )
        return doc.tobytes()
    finally:
        doc.close()


def _make_valid_image(fmt: str) -> bytes:
    """Create a genuine small in-memory PNG or JPEG via PyMuPDF."""
    doc = fitz.open()
    try:
        page = doc.new_page(width=64, height=64)
        pix = page.get_pixmap()
        return pix.tobytes(output=fmt)
    finally:
        doc.close()


def _make_xlsx(
    *,
    entries: dict[str, bytes] | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    """Create an in-memory OOXML ZIP archive (valid XLSX by default)."""
    default_entries = {
        "[Content_Types].xml": (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>'
        ),
        "xl/workbook.xml": (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"></workbook>'
        ),
    }
    files = default_entries if entries is None else entries
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=compression) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_valid_pdf_png_jpeg_and_xlsx_pass_validation() -> None:
    """Verify all four FR-01 allowed formats pass validation with exact MIME and SHA-256."""
    pdf_bytes = _make_valid_pdf(pages=2)
    png_bytes = _make_valid_image("png")
    jpg_bytes = _make_valid_image("jpeg")
    xlsx_bytes = _make_xlsx()

    pdf_res = validate_invoice_file("INV-1001.pdf", pdf_bytes, "application/pdf")
    assert isinstance(pdf_res, ValidatedFile)
    assert pdf_res.detected_mime == "application/pdf"
    assert pdf_res.extension == ".pdf"
    assert pdf_res.page_count == 2
    assert pdf_res.sha256_hash == hashlib.sha256(pdf_bytes).hexdigest()

    png_res = validate_invoice_file("scan.png", png_bytes, "image/png")
    assert png_res.detected_mime == "image/png"
    assert png_res.page_count is None

    jpg_res = validate_invoice_file("scan.JPG", jpg_bytes, "image/jpeg")
    assert jpg_res.detected_mime == "image/jpeg"
    assert jpg_res.extension == ".jpg"

    xlsx_mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    xlsx_res = validate_invoice_file("schedule.xlsx", xlsx_bytes, xlsx_mime)
    assert xlsx_res.detected_mime == xlsx_mime

    # Generic application/octet-stream declared header falls back safely to magic-byte MIME
    octet_res = validate_invoice_file("INV-1002.pdf", pdf_bytes, "application/octet-stream")
    assert octet_res.detected_mime == "application/pdf"


def test_rejects_empty_and_over_25mb_files_with_413() -> None:
    """Verify empty uploads and >25 MB uploads fail cleanly with HTTP 413 on oversize (FR-01)."""
    with pytest.raises(FileValidationError) as exc_empty:
        validate_invoice_file("empty.pdf", b"")
    assert exc_empty.value.http_status == 422

    assert MAX_UPLOAD_SIZE_BYTES == 25 * 1024 * 1024
    oversized = b"%PDF-1.4" + b"0" * MAX_UPLOAD_SIZE_BYTES
    with pytest.raises(FileTooLargeError) as exc_big:
        validate_invoice_file("huge.pdf", oversized)
    assert exc_big.value.http_status == 413

    # Custom max_size_bytes boundary test
    pdf_bytes = _make_valid_pdf()
    with pytest.raises(FileTooLargeError):
        validate_invoice_file("small.pdf", pdf_bytes, max_size_bytes=len(pdf_bytes) - 1)
    assert validate_invoice_file(
        "small.pdf", pdf_bytes, max_size_bytes=len(pdf_bytes)
    ).size_bytes == len(pdf_bytes)


def test_rejects_tiff_by_extension_mime_and_magic_bytes_gap_004() -> None:
    """Verify TIFF files are explicitly rejected across extension, MIME, and magic bytes (GAP-004)."""
    tiff_le = b"II*\x00\x08\x00\x00\x00" + b"\x00" * 32
    tiff_be = b"MM\x00*\x00\x00\x00\x08" + b"\x00" * 32

    for fname, data, mime in [
        ("scan.tiff", tiff_le, "image/tiff"),
        ("scan.tif", tiff_be, "image/tiff"),
        ("disguised.pdf", tiff_le, "application/pdf"),
        ("disguised.png", tiff_be, "image/png"),
        ("invoice.pdf", _make_valid_pdf(), "image/tiff"),
    ]:
        with pytest.raises(UnsupportedFileTypeError) as exc_info:
            validate_invoice_file(fname, data, mime)
        assert exc_info.value.http_status == 415
        assert "TIFF" in str(exc_info.value)


def test_rejects_password_protected_and_corrupted_pdfs() -> None:
    """Verify password-protected PDFs and corrupted PDFs are rejected with HTTP 422."""
    encrypted_pdf = _make_valid_pdf(user_password="locked-pdf-password")
    with pytest.raises(PasswordProtectedPDFError) as exc_pw:
        validate_invoice_file("locked.pdf", encrypted_pdf, "application/pdf")
    assert exc_pw.value.http_status == 422

    corrupted_pdf = b"%PDF-1.7\nThis is not a valid PDF xref table"
    with pytest.raises(CorruptedOrMaliciousFileError) as exc_corrupt:
        validate_invoice_file("corrupt.pdf", corrupted_pdf, "application/pdf")
    assert exc_corrupt.value.http_status == 422


def test_rejects_mime_spoofing_and_extension_magic_mismatch() -> None:
    """Verify spoofed extensions, forged Content-Type headers, and banned types fail closed (CWE-434)."""
    pdf_bytes = _make_valid_pdf()
    png_bytes = _make_valid_image("png")

    # HTML disguised as PDF
    with pytest.raises(UnsupportedFileTypeError):
        validate_invoice_file(
            "evil.pdf", b"<html><script>alert(1)</script></html>", "application/pdf"
        )

    # PNG bytes renamed to .pdf
    with pytest.raises(UnsupportedFileTypeError):
        validate_invoice_file("renamed.pdf", png_bytes, "application/pdf")

    # Valid PDF sent with mismatched declared MIME image/png
    with pytest.raises(UnsupportedFileTypeError):
        validate_invoice_file("mismatch.pdf", pdf_bytes, "image/png")

    # Banned file extensions
    for bad_ext in ("malware.exe", "page.html", "vector.svg", "archive.zip", "doc.docx", "old.xls"):
        with pytest.raises(UnsupportedFileTypeError) as exc_info:
            validate_invoice_file(bad_ext, pdf_bytes)
        assert exc_info.value.http_status == 415


def test_xlsx_rejects_plain_zip_docx_macros_zip_slip_zip_bomb_and_xxe() -> None:
    """Verify XLSX validator blocks non-XLSX ZIPs, macros, Zip-Slip, ZIP bombs, and XXE (CWE-22/409/611)."""
    # 1. Plain ZIP renamed to .xlsx
    plain_zip = _make_xlsx(entries={"readme.txt": b"hello"})
    with pytest.raises(UnsupportedFileTypeError):
        validate_invoice_file("not_xlsx.xlsx", plain_zip)

    # 2. DOCX renamed to .xlsx
    fake_docx = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w:document/>",
        }
    )
    with pytest.raises(UnsupportedFileTypeError):
        validate_invoice_file("word_doc.xlsx", fake_docx)

    # 3. Macro-enabled spreadsheet (vbaProject.bin) disguised as .xlsx
    macro_xlsx = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/vbaProject.bin": b"VBA_MACRO_PAYLOAD",
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)macro"):
        validate_invoice_file("macros.xlsx", macro_xlsx)

    # 4. Zip-Slip path traversal entry inside XLSX (CWE-22)
    zip_slip = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "../../etc/passwd": b"root:x:0:0",
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="unsafe archive path"):
        validate_invoice_file("zipslip.xlsx", zip_slip)

    # 5. ZIP bomb: 20 MB of zeros compresses to ~20 KB (>100:1 ratio, CWE-409)
    zip_bomb = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/worksheets/sheet1.xml": b"0" * (20 * 1024 * 1024),
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="compression"):
        validate_invoice_file("bomb.xlsx", zip_bomb)

    # 6. XXE DOCTYPE/ENTITY injection inside xl/workbook.xml (CWE-611)
    xxe_xlsx = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": (
                b'<?xml version="1.0"?>'
                b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                b"<workbook>&xxe;</workbook>"
            ),
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="XXE"):
        validate_invoice_file("xxe.xlsx", xxe_xlsx)


def test_rejects_image_decompression_bomb_and_spoofed_image_headers() -> None:
    """Verify corrupted images and pixel-flood PNG decompression bombs are rejected (CWE-400)."""
    # Spoofed PNG magic bytes with invalid IHDR
    with pytest.raises(CorruptedOrMaliciousFileError):
        validate_invoice_file("fake.png", b"\x89PNG\r\n\x1a\n" + b"garbage-bytes")

    # Crafted PNG IHDR claiming 50,000 x 50,000 pixels (2.5B pixel bomb)
    ihdr_data = struct.pack(">IIBBBBB", 50000, 50000, 8, 2, 0, 0, 0)
    png_bomb = (
        b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="dimensions"):
        validate_invoice_file("bomb.png", png_bomb)

    # Spoofed JPEG magic bytes with garbage body
    with pytest.raises(CorruptedOrMaliciousFileError):
        validate_invoice_file("fake.jpg", b"\xff\xd8\xff\xe0" + b"not-valid-jpeg-data")


def test_rejects_path_traversal_null_bytes_and_crlf_in_filename_or_content_type() -> None:
    """Verify filenames and declared Content-Type headers reject traversal and CRLF (CWE-22/113)."""
    pdf_bytes = _make_valid_pdf()

    for bad_name in (
        "",
        "../evil.pdf",
        "dir/sub.pdf",
        "dir\\sub.pdf",
        "inv\x00.pdf",
        "inv\r\n.pdf",
    ):
        with pytest.raises(FileValidationError):
            validate_invoice_file(bad_name, pdf_bytes, "application/pdf")

    with pytest.raises(FileValidationError):
        validate_invoice_file("clean.pdf", pdf_bytes, "application/pdf\r\nX-Injected: evil")


def test_rejects_pdf_with_active_javascript_launch_or_executable_attachment() -> None:
    """Verify PDFs with /JavaScript, /Launch actions, or executable attachments are blocked (CWE-94/434)."""
    # 1. PDF containing embedded /JavaScript OpenAction
    doc_js = fitz.open()
    doc_js.new_page().insert_text((72, 72), "Invoice with JS")
    js_xref = doc_js.get_new_xref()
    doc_js.update_object(js_xref, "<< /S /JavaScript /JS (app.alert('xss')) >>")
    doc_js.xref_set_key(doc_js.pdf_catalog(), "OpenAction", f"{js_xref} 0 R")
    js_pdf = doc_js.tobytes()
    doc_js.close()

    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)script"):
        validate_invoice_file("js_invoice.pdf", js_pdf, "application/pdf")

    # 2. PDF containing OS /Launch action
    doc_launch = fitz.open()
    doc_launch.new_page().insert_text((72, 72), "Invoice with Launch")
    launch_xref = doc_launch.get_new_xref()
    doc_launch.update_object(launch_xref, "<< /S /Launch /F (cmd.exe) >>")
    doc_launch.xref_set_key(doc_launch.pdf_catalog(), "OpenAction", f"{launch_xref} 0 R")
    launch_pdf = doc_launch.tobytes()
    doc_launch.close()

    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)launch"):
        validate_invoice_file("launch_invoice.pdf", launch_pdf, "application/pdf")

    # 3. PDF containing an embedded executable attachment (.exe)
    doc_emb = fitz.open()
    doc_emb.new_page().insert_text((72, 72), "Invoice with EXE attachment")
    doc_emb.embfile_add("payload.exe", b"MZ\x90\x00fake-pe-binary")
    emb_pdf = doc_emb.tobytes()
    doc_emb.close()

    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)attachment"):
        validate_invoice_file("dropper.pdf", emb_pdf, "application/pdf")


def test_rejects_jpeg_sof_decompression_bomb_before_decode() -> None:
    """Verify crafted JPEG SOF0 header claiming 40,000x40,000 pixels fails before decode (CWE-400)."""
    # SOI + SOF0 segment: length=11, precision=8, height=40000, width=40000, 1 component + EOI
    sof0_payload = struct.pack(">BHHBBBB", 8, 40000, 40000, 1, 1, 0x11, 0)
    jpeg_bomb = (
        b"\xff\xd8\xff\xc0" + struct.pack(">H", len(sof0_payload) + 2) + sof0_payload + b"\xff\xd9"
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="dimensions"):
        validate_invoice_file("bomb.jpg", jpeg_bomb, "image/jpeg")


def test_xlsx_blocks_utf16_xxe_in_shared_strings_and_rels_plus_duplicate_entries_and_xlm_macros() -> (
    None
):
    """Verify UTF-16 XXE in sharedStrings/.rels, duplicate ZIP members, XLM macros, and OLE embeddings fail."""
    # 1. UTF-16LE encoded XXE inside xl/sharedStrings.xml (CWE-611 bypass attempt)
    utf16_xxe = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE sst [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'
        "<sst>&leak;</sst>"
    ).encode("utf-16-le")
    xlsx_utf16_xxe = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/sharedStrings.xml": b"\xff\xfe" + utf16_xxe,
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="XXE"):
        validate_invoice_file("utf16_xxe.xlsx", xlsx_utf16_xxe)

    # 2. XXE hidden inside _rels/.rels
    xlsx_rels_xxe = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "_rels/.rels": b'<!DOCTYPE rels [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><Relationships/>',
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="XXE"):
        validate_invoice_file("rels_xxe.xlsx", xlsx_rels_xxe)

    # 3. Duplicate member parser differential (two xl/workbook.xml entries)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
        zf.writestr("xl/Workbook.xml", b"<workbook/>")
    with pytest.raises(CorruptedOrMaliciousFileError, match="duplicate"):
        validate_invoice_file("dup_entry.xlsx", buf.getvalue())

    # 4. Excel 4.0 XLM macro sheet and OLE embedded object
    for evil_member in (
        "xl/macrosheets/sheet1.xml",
        "xl/embeddings/oleObject1.bin",
        "xl/activeX/activeX1.xml",
    ):
        evil_xlsx = _make_xlsx(
            entries={
                "[Content_Types].xml": b"<Types/>",
                "xl/workbook.xml": b"<workbook/>",
                evil_member: b"evil",
            }
        )
        with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)macro"):
            validate_invoice_file("xlm.xlsx", evil_xlsx)

    # 5. Macro-enabled Content-Type declaration in [Content_Types].xml
    macro_ct_xlsx = _make_xlsx(
        entries={
            "[Content_Types].xml": (
                b'<Types><Override PartName="/xl/workbook.xml" '
                b'ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>'
            ),
            "xl/workbook.xml": b"<workbook/>",
        }
    )
    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)macro"):
        validate_invoice_file("macro_ct.xlsx", macro_ct_xlsx)


def test_xlsx_allows_benign_printer_settings_bin_in_legitimate_excel_export() -> None:
    """Verify legitimate Excel exports containing xl/printerSettings/printerSettings1.bin pass validation."""
    legit_xlsx = _make_xlsx(
        entries={
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/printerSettings/printerSettings1.bin": b"\x00\x01printer-devmode-bytes",
        }
    )
    res = validate_invoice_file("excel_export.xlsx", legit_xlsx)
    assert res.detected_mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_xlsx_rejects_encrypted_zip_entries() -> None:
    """Verify password-protected / encrypted ZIP entries inside an XLSX archive are rejected."""
    raw_xlsx = bytearray(_make_xlsx())
    # Set bit 0 (encrypted flag) in the first Local File Header (offset 6) and Central Directory entry
    cd_offset = raw_xlsx.index(b"PK\x01\x02")
    raw_xlsx[6] |= 0x01
    raw_xlsx[cd_offset + 8] |= 0x01

    with pytest.raises(CorruptedOrMaliciousFileError, match="(?i)encrypted"):
        validate_invoice_file("encrypted.xlsx", bytes(raw_xlsx))
