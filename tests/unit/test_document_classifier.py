"""
Unit and Security Tests for Document Classifier (P6-1).

Tests: ADR-004, HLD §241, CLAUDE.md §4.2, §7.1, GAP-004, CWE-22, CWE-400, CWE-409, CWE-434, CWE-532
"""

import io
import logging
import zipfile
from pathlib import Path

import fitz
import pytest

from src.extraction.document_classifier import (
    MAX_CLASSIFIER_SIZE_BYTES,
    DocumentClassificationError,
    DocumentClassificationResult,
    DocumentType,
    UnsupportedDocumentError,
    classify_document,
)


def _make_raster_image(fmt: str = "png", *, width: int = 120, height: int = 120) -> bytes:
    """Create a genuine small in-memory PNG or JPEG via PyMuPDF."""
    doc = fitz.open()
    try:
        page = doc.new_page(width=width, height=height)
        page.draw_rect(fitz.Rect(10, 10, width - 10, height - 10), color=(0, 0, 0))
        return page.get_pixmap().tobytes(output=fmt)
    finally:
        doc.close()


def _make_digital_pdf(
    page_texts: list[str],
    *,
    user_password: str | None = None,
    embed_image_on_pages: set[int] | None = None,
) -> bytes:
    """Create an in-memory PDF with controlled per-page text and optional embedded raster images."""
    doc = fitz.open()
    img_bytes = _make_raster_image("png") if embed_image_on_pages else None
    try:
        for idx, text in enumerate(page_texts):
            page = doc.new_page()
            if text:
                page.insert_text((72, 72), text)
            if embed_image_on_pages and idx in embed_image_on_pages and img_bytes is not None:
                page.insert_image(fitz.Rect(50, 150, 300, 400), stream=img_bytes)
        if user_password is not None:
            return doc.tobytes(
                encryption=fitz.PDF_ENCRYPT_AES_256,
                user_pw=user_password,
                owner_pw="owner-secret",
            )
        return doc.tobytes()
    finally:
        doc.close()


def _make_xlsx(*, sheet_count: int = 1, extra_entries: dict[str, bytes] | None = None) -> bytes:
    """Create a valid minimal OOXML XLSX archive in memory."""
    entries: dict[str, bytes] = {
        "[Content_Types].xml": b"<Types/>",
        "xl/workbook.xml": b"<workbook/>",
    }
    for i in range(1, sheet_count + 1):
        entries[f"xl/worksheets/sheet{i}.xml"] = b"<worksheet/>"
    if extra_entries:
        entries.update(extra_entries)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_classifies_digital_searchable_pdf_with_dense_text_layer() -> None:
    """Verify digital PDFs (including logo-bearing & short-footer multi-page PDFs) classify as searchable_pdf."""
    page_1 = (
        "ACME TECHNOLOGIES INC. INVOICE #INV-2026-1001 "
        "Bill To: Enterprise Corp Date: 02/05/2026 PO: PO-9000-2001 "
        "Line 1: Heavy Duty Steel Fasteners Qty 10 Unit 125.00 Total 1250.00 Subtotal 1250.00 Tax 100.00 Grand Total 1350.00"
    )
    page_2_footer = "Thank you for your prompt payment. Page 2 of 2."

    # 1. Pure digital 1-page PDF
    pdf_single = _make_digital_pdf([page_1])
    res_single = classify_document(pdf_single)
    assert isinstance(res_single, DocumentClassificationResult)
    assert res_single.document_type == DocumentType.SEARCHABLE_PDF
    assert res_single.detected_mime == "application/pdf"
    assert res_single.page_count == 1
    assert res_single.scanned_page_indices == ()
    assert res_single.text_density_ratio == 1.0
    assert res_single.extracted_text is not None
    assert "INV-2026-1001" in res_single.extracted_text

    # 2. Digital 2-page PDF with company logo on dense page 1 + short image-free footer on page 2
    pdf_multi = _make_digital_pdf([page_1, page_2_footer], embed_image_on_pages={0})
    res_multi = classify_document(pdf_multi)
    assert res_multi.document_type == DocumentType.SEARCHABLE_PDF
    assert res_multi.page_count == 2
    assert res_multi.scanned_page_indices == ()


def test_classifies_scanned_image_only_pdf_and_sparse_ocr_pdf_as_scanned_image() -> None:
    """Verify image-only PDFs, sparse-OCR scan PDFs, and blank PDFs route to scanned_image (GPT-4o Vision)."""
    # 1. Pure image-only scanned PDF (0 text chars + embedded raster scan)
    scanned_pdf = _make_digital_pdf([""], embed_image_on_pages={0})
    res_scan = classify_document(scanned_pdf)
    assert res_scan.document_type == DocumentType.SCANNED_IMAGE
    assert res_scan.detected_mime == "application/pdf"
    assert res_scan.scanned_page_indices == (0,)
    assert res_scan.extracted_text is None

    # 2. Low-quality sparse OCR scan PDF (image + only 10 chars of noise)
    sparse_pdf = _make_digital_pdf(["INV 1001"], embed_image_on_pages={0})
    res_sparse = classify_document(sparse_pdf)
    assert res_sparse.document_type == DocumentType.SCANNED_IMAGE
    assert res_sparse.scanned_page_indices == (0,)

    # 3. Blank PDF (0 chars, 0 images -> conservative fallback to scanned_image)
    blank_pdf = _make_digital_pdf([""])
    res_blank = classify_document(blank_pdf)
    assert res_blank.document_type == DocumentType.SCANNED_IMAGE


def test_classifies_hybrid_pdf_with_digital_cover_and_scanned_attachment_as_scanned_image() -> None:
    """Verify hybrid PDF (dense digital page 1 + scanned image page 2) routes to scanned_image to prevent data loss."""
    digital_cover = (
        "ACME GLOBAL LOGISTICS SUMMARY COVER SHEET INVOICE #INV-2026-2050 "
        "Please see attached scanned delivery receipt and handwritten quantity adjustments on page 2."
    )
    hybrid_pdf = _make_digital_pdf([digital_cover, ""], embed_image_on_pages={1})
    res = classify_document(hybrid_pdf)
    assert res.document_type == DocumentType.SCANNED_IMAGE
    assert res.page_count == 2
    assert res.scanned_page_indices == (1,)
    assert res.extracted_text is None


def test_classifies_png_jpeg_and_xlsx_strictly_by_magic_bytes() -> None:
    """Verify PNG, JPEG, and XLSX classify strictly from binary signatures regardless of filename."""
    png_res = classify_document(_make_raster_image("png"), filename="misleading.pdf")
    assert png_res.document_type == DocumentType.SCANNED_IMAGE
    assert png_res.detected_mime == "image/png"
    assert png_res.page_count == 1

    jpg_res = classify_document(_make_raster_image("jpeg"), filename="scan.jpg")
    assert jpg_res.document_type == DocumentType.SCANNED_IMAGE
    assert jpg_res.detected_mime == "image/jpeg"
    assert jpg_res.page_count == 1

    xlsx_res = classify_document(_make_xlsx(sheet_count=2), filename="schedule.xlsx")
    assert xlsx_res.document_type == DocumentType.XLSX
    assert (
        xlsx_res.detected_mime
        == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    assert xlsx_res.page_count == 2


def test_rejects_tiff_corrupted_encrypted_oversized_and_non_xlsx_zip_files() -> None:
    """Verify TIFF (GAP-004), locked/corrupted PDFs, non-XLSX ZIPs, empty, and >25 MB files fail closed."""
    # TIFF little-endian & big-endian (GAP-004)
    for tiff_bytes in (
        b"II*\x00\x08\x00\x00\x00" + b"\x00" * 16,
        b"MM\x00*\x00\x00\x00\x08" + b"\x00" * 16,
    ):
        with pytest.raises(UnsupportedDocumentError, match="TIFF"):
            classify_document(tiff_bytes)

    # Unsupported HTML payload
    with pytest.raises(UnsupportedDocumentError):
        classify_document(b"<html><body>not an invoice</body></html>")

    # Plain ZIP / DOCX disguised as OOXML
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("word/document.xml", b"<w:document/>")
    with pytest.raises(UnsupportedDocumentError):
        classify_document(buf.getvalue())

    # Password-protected PDF
    locked_pdf = _make_digital_pdf(["Confidential invoice"], user_password="locked")
    with pytest.raises(DocumentClassificationError, match="(?i)password"):
        classify_document(locked_pdf)

    # Corrupted PDF
    with pytest.raises(DocumentClassificationError):
        classify_document(b"%PDF-1.7\ncorrupted-xref")

    # Empty & oversized (>25 MB)
    with pytest.raises(DocumentClassificationError, match="empty"):
        classify_document(b"")
    with pytest.raises(DocumentClassificationError, match="maximum"):
        classify_document(b"%PDF-1.4" + b"0" * MAX_CLASSIFIER_SIZE_BYTES)


def test_defeats_whitespace_and_control_char_text_density_spoofing() -> None:
    """Verify invisible whitespace/punctuation padding on a scanned PDF cannot spoof searchable_pdf."""
    spoof_padding = ("   \t\n   " * 80) + ("| ~ ^ ` " * 40)
    spoofed_scan = _make_digital_pdf([spoof_padding], embed_image_on_pages={0})
    res = classify_document(spoofed_scan)
    assert res.document_type == DocumentType.SCANNED_IMAGE
    assert res.total_text_chars < 50
    assert res.scanned_page_indices == (0,)


def test_blocks_xlsx_zip_slip_zip_bomb_never_logs_pii_and_respects_layering(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify XLSX Zip-Slip/ZIP-bomb fail closed, logs omit PII (CWE-532), and zero DB/validation imports exist."""
    # Layering check (CLAUDE.md §4.2): src/extraction/ MUST NOT import database or validation
    src_code = Path("src/extraction/document_classifier.py").read_text(encoding="utf-8")
    for forbidden in ("src.database", "src.validation", "sqlalchemy"):
        assert forbidden not in src_code

    # Zip-Slip inside XLSX
    zip_slip = _make_xlsx(extra_entries={"../../etc/passwd": b"root:x:0:0"})
    with pytest.raises(DocumentClassificationError, match="unsafe"):
        classify_document(zip_slip)

    # ZIP bomb inside XLSX (>100:1 compression ratio)
    zip_bomb = _make_xlsx(extra_entries={"xl/worksheets/sheet2.xml": b"0" * (20 * 1024 * 1024)})
    with pytest.raises(DocumentClassificationError, match="compression"):
        classify_document(zip_bomb)

    # PII log hygiene check
    pii_pdf = _make_digital_pdf(
        [
            "INVOICE #INV-PII-999 Vendor Tax ID US-12-3456789 "
            "Bank IBAN DE89370400440532013000 Total USD 4500.00 Payment Terms Net 30"
        ]
    )
    with caplog.at_level(logging.DEBUG, logger="ap.extraction.document_classifier"):
        res = classify_document(pii_pdf)
    assert res.document_type == DocumentType.SEARCHABLE_PDF
    combined_logs = " ".join(r.getMessage() for r in caplog.records)
    assert "US-12-3456789" not in combined_logs
    assert "DE89370400440532013000" not in combined_logs


def test_defeats_repeated_char_padding_bidi_spoofing_and_corrupted_raster_bombs() -> None:
    """Verify repeated-char padding, bidi/zero-width chars, and spoofed/bomb PNG/JPEG fail safely."""
    import struct

    # 1. Repeated-character padding ('A' * 400) on a scanned PDF must NOT spoof searchable_pdf
    repeated_pad = _make_digital_pdf(["A" * 400], embed_image_on_pages={0})
    res_pad = classify_document(repeated_pad)
    assert res_pad.document_type == DocumentType.SCANNED_IMAGE
    assert res_pad.scanned_page_indices == (0,)

    # 2. Invisible bidi override / zero-width chars are stripped while preserving DE/ES diacritics (FR-02)
    multilingual_pdf = _make_digital_pdf(
        [
            "M\u00fcnster Analytics GmbH \u202e\u200b Rechnung Nr. RE-2026-44 "
            "Espa\u00f1a IVA 21% MwSt 19% Betrag 1.250,00 EUR Zahlbar in 30 Tagen"
        ]
    )
    res_ml = classify_document(multilingual_pdf)
    assert res_ml.document_type == DocumentType.SEARCHABLE_PDF
    assert res_ml.extracted_text is not None
    assert "\u202e" not in res_ml.extracted_text
    assert "\u200b" not in res_ml.extracted_text
    assert "M\u00fcnster" in res_ml.extracted_text
    assert "Espa\u00f1a" in res_ml.extracted_text

    # 3. Corrupted PNG & PNG pixel bomb rejected inside classifier too (CWE-400/434)
    with pytest.raises(DocumentClassificationError):
        classify_document(b"\x89PNG\r\n\x1a\n" + b"garbage")

    ihdr = struct.pack(">IIBBBBB", 50000, 50000, 8, 2, 0, 0, 0)
    png_bomb = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"
    with pytest.raises(DocumentClassificationError, match="dimensions"):
        classify_document(png_bomb)

    # 4. Corrupted JPEG & JPEG SOF pixel bomb rejected
    sof0 = struct.pack(">BHHBBBB", 8, 40000, 40000, 1, 1, 0x11, 0)
    jpeg_bomb = b"\xff\xd8\xff\xc0" + struct.pack(">H", len(sof0) + 2) + sof0 + b"\xff\xd9"
    with pytest.raises(DocumentClassificationError, match="dimensions"):
        classify_document(jpeg_bomb)
