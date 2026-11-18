"""
Unit and Security Tests for Pydantic Extraction Schemas (P6-3).

Tests: FR-02, FR-03, FR-11, BR-004, BR-005, BR-006, CLAUDE.md §4.2, §7.2, §8,
       CWE-20, CWE-74, CWE-190, CWE-400, CWE-532, CWE-915
"""

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from src.extraction.schemas import (
    CRITICAL_HEADER_FIELD_NAMES,
    HEADER_FIELD_NAMES,
    LINE_ITEM_FIELD_NAMES,
    MAX_LINE_ITEMS,
    MAX_MONETARY_AMOUNT,
    ExtractedField,
    FiniteDecimal,
    InvoiceExtractionSchema,
    InvoiceHeaderExtraction,
    InvoiceLineItemExtraction,
)


def _sample_payload() -> dict[str, Any]:
    """Build a valid full extraction JSON payload with 10 header fields + 2 line items."""
    return {
        "header": {
            "vendor_name": {"value": "Mediterraneo Quimica SA", "confidence": "98.50"},
            "vendor_tax_id": {"value": "ESA98765432", "confidence": "96.00"},
            "invoice_number": {"value": "INV-2026-1001", "confidence": "99.00"},
            "invoice_date": {"value": "04/02/2026", "confidence": "95.00"},
            "due_date": {"value": "06/03/2026", "confidence": "92.00"},
            "po_number": {"value": "PO-9000-2001", "confidence": "94.00"},
            "subtotal": {"value": "2851.00", "confidence": "97.50"},
            "tax_amount": {"value": "598.71", "confidence": "97.00"},
            "total_amount": {"value": "3449.71", "confidence": "99.50"},
            "currency": {"value": "eur", "confidence": "100.00"},
        },
        "line_items": [
            {
                "description": {"value": "Digital Temperature Sensor Pack", "confidence": "94.00"},
                "quantity": {"value": "4", "confidence": "98.00"},
                "unit_price": {"value": "75.25", "confidence": "96.00"},
                "line_total": {"value": "301.00", "confidence": "97.00"},
                "tax_rate": {"value": "0.21", "confidence": "95.00"},
            },
            {
                "description": {"value": "Laser Calibration Service", "confidence": "91.00"},
                "quantity": {"value": "3", "confidence": "99.00"},
                "unit_price": {"value": "850.00", "confidence": "95.00"},
                "line_total": {"value": "2550.00", "confidence": "96.00"},
                "tax_rate": {"value": "0.21", "confidence": "94.00"},
            },
        ],
        "is_reverse_charge": False,
        "is_exempt": False,
        "detected_language": "es",
    }


def test_valid_extraction_schema_parses_all_10_header_fields_and_5_line_fields_with_confidence() -> (
    None
):
    """Verify FR-03 / BR-004 / BR-005 exact 10 header fields, 5 line fields, types, and immutability."""
    assert len(HEADER_FIELD_NAMES) == 10
    assert len(LINE_ITEM_FIELD_NAMES) == 5
    assert CRITICAL_HEADER_FIELD_NAMES == (
        "vendor_tax_id",
        "invoice_number",
        "invoice_date",
        "total_amount",
    )

    parsed = InvoiceExtractionSchema.model_validate(_sample_payload())
    assert parsed.header.vendor_name.value == "Mediterraneo Quimica SA"
    assert parsed.header.vendor_tax_id.value == "ESA98765432"
    assert parsed.header.currency.value == "EUR"  # normalized uppercase ISO 4217
    assert parsed.header.total_amount.value == Decimal("3449.71")
    assert parsed.header.total_amount.confidence == Decimal("99.50")
    assert len(parsed.line_items) == 2
    assert parsed.line_items[0].quantity.value == Decimal("4")
    assert parsed.line_items[0].tax_rate.value == Decimal("0.21")
    assert parsed.detected_language == "es"

    # Nullable optional header fields (due_date, po_number) accepted cleanly
    nullable_payload = _sample_payload()
    nullable_payload["header"]["due_date"] = {"value": None, "confidence": "100.00"}
    nullable_payload["header"]["po_number"] = {"value": None, "confidence": "100.00"}
    parsed_null = InvoiceExtractionSchema.model_validate(nullable_payload)
    assert parsed_null.header.due_date.value is None
    assert parsed_null.header.po_number.value is None

    # Models are immutable (frozen=True) so downstream cannot mutate raw extracted evidence
    with pytest.raises(ValidationError):
        parsed.header.total_amount = ExtractedField(  # type: ignore[misc]
            value=Decimal("0.00"), confidence=Decimal("100.00")
        )

    # JSON schema export works for P6-4 system prompt generation
    json_schema = InvoiceExtractionSchema.json_schema_for_prompt()
    assert "properties" in json_schema
    assert "header" in json_schema["properties"]
    assert "line_items" in json_schema["properties"]


def test_confidence_aggregations_macro_average_min_and_line_confidence() -> None:
    """Verify deterministic macro-average header confidence, critical floor, line confidence, and flat map."""
    payload = _sample_payload()
    # Set one line field low (78.25%) to verify overall_min_confidence tracks line items too
    payload["line_items"][1]["unit_price"]["confidence"] = "78.25"
    parsed = InvoiceExtractionSchema.model_validate(payload)

    # Header sum: 98.5 + 96 + 99 + 95 + 92 + 94 + 97.5 + 97 + 99.5 + 100 = 968.5 -> /10 = 96.85
    assert parsed.header.macro_avg_confidence() == Decimal("96.85")
    assert parsed.header_macro_avg_confidence() == Decimal("96.85")
    assert parsed.header.min_confidence() == Decimal("92.00")
    assert parsed.header.min_critical_confidence() == Decimal("95.00")

    # Line 0 sum: 94 + 98 + 96 + 97 + 95 = 480 -> /5 = 96.00
    assert parsed.line_items[0].line_confidence() == Decimal("96.00")
    # Line 1 sum: 91 + 99 + 78.25 + 96 + 94 = 458.25 -> /5 = 91.65
    assert parsed.line_items[1].line_confidence() == Decimal("91.65")
    assert parsed.overall_min_confidence() == Decimal("78.25")

    all_conf = parsed.all_field_confidences()
    assert len(all_conf) == 10 + (2 * 5)
    assert all_conf["header.vendor_tax_id"] == Decimal("96.00")
    assert all_conf["line_items[1].unit_price"] == Decimal("78.25")


def test_confidence_bounds_reject_out_of_range_non_finite_bool_and_no_silent_rescaling() -> None:
    """Verify confidence enforces finite [0.00, 100.00], blocks bool/NaN/Inf, and never rescales 0.85 -> 85."""
    # Very low percentage 0.85% must NOT be silently rescaled to 85% (prevents bypassing <80% review)
    low_field = ExtractedField[str](value="INV-1", confidence=Decimal("0.85"))
    assert low_field.confidence == Decimal("0.85")

    for bad_conf in (
        Decimal("-0.01"),
        Decimal("100.01"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        True,
        False,
        "NaN",
        "inf",
    ):
        with pytest.raises(ValidationError):
            ExtractedField[str].model_validate({"value": "INV-1", "confidence": bad_conf})


def test_supports_negative_credit_note_amounts_and_rejects_invalid_numbers_and_tax_rates() -> None:
    """Verify FR-11 credit note negative numbers pass while NaN/Inf/bool/overflow/bad tax_rate fail closed."""
    credit_payload = _sample_payload()
    credit_payload["header"]["subtotal"]["value"] = "-301.00"
    credit_payload["header"]["tax_amount"]["value"] = "-63.21"
    credit_payload["header"]["total_amount"]["value"] = "-364.21"
    credit_payload["line_items"][0]["quantity"]["value"] = "-4"
    credit_payload["line_items"][0]["line_total"]["value"] = "-301.00"

    parsed = InvoiceExtractionSchema.model_validate(credit_payload)
    assert parsed.header.total_amount.value == Decimal("-364.21")
    assert parsed.line_items[0].quantity.value == Decimal("-4")
    assert parsed.line_items[0].line_total.value == Decimal("-301.00")

    # Reject NaN, Infinity, bool, and SQL DECIMAL(18,2) overflow in monetary fields
    for bad_amt in ("NaN", "Infinity", True, False, str(MAX_MONETARY_AMOUNT + Decimal("1.00"))):
        bad = _sample_payload()
        bad["header"]["total_amount"]["value"] = bad_amt
        with pytest.raises(ValidationError):
            InvoiceExtractionSchema.model_validate(bad)

    # Reject out-of-range tax_rate (< 0 or > 1.0000) and invalid ISO 4217 currency
    for bad_rate in ("-0.01", "1.05", "21.00", "NaN", True):
        bad = _sample_payload()
        bad["line_items"][0]["tax_rate"]["value"] = bad_rate
        with pytest.raises(ValidationError):
            InvoiceExtractionSchema.model_validate(bad)

    for bad_ccy in ("US", "EURO", "12$", ""):
        bad = _sample_payload()
        bad["header"]["currency"]["value"] = bad_ccy
        with pytest.raises(ValidationError):
            InvoiceExtractionSchema.model_validate(bad)


def test_forbids_extra_prompt_injected_fields_across_all_schema_levels() -> None:
    """Verify extra='forbid' blocks LLM prompt-injected status/approval/rule-bypass fields (CWE-915)."""
    # 1. Top-level injected approval bypass
    top_inject = _sample_payload()
    top_inject["status"] = "APPROVED_CLERK"
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(top_inject)

    # 2. Header-level injected field
    hdr_inject = _sample_payload()
    hdr_inject["header"]["skip_validation"] = True
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(hdr_inject)

    # 3. Line-item-level injected field
    line_inject = _sample_payload()
    line_inject["line_items"][0]["approved_by"] = "dave.admin"
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(line_inject)

    # 4. ExtractedField-level injected field
    field_inject = _sample_payload()
    field_inject["header"]["total_amount"]["override"] = True
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(field_inject)

    # 5. Excessive line_items (> MAX_LINE_ITEMS) blocked against DoS (CWE-400)
    dos_payload = _sample_payload()
    dos_payload["line_items"] = [dos_payload["line_items"][0]] * (MAX_LINE_ITEMS + 1)
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(dos_payload)


def test_ground_truth_round_trip_validates_against_real_pilot_dataset() -> None:
    """Verify from_ground_truth_dict() and to_ground_truth_dict() match real sample_data/ground_truth/ files."""
    gt_dir = Path("sample_data/ground_truth")
    gt_files = sorted(gt_dir.glob("*.json"))[:15]
    assert len(gt_files) > 0

    for gt_file in gt_files:
        raw = json.loads(gt_file.read_text(encoding="utf-8"))
        extracted = InvoiceExtractionSchema.from_ground_truth_dict(
            raw, default_confidence=Decimal("97.50")
        )
        assert extracted.header_macro_avg_confidence() == Decimal("97.50")
        round_tripped = extracted.to_ground_truth_dict()
        assert round_tripped["header"]["invoice_number"] == raw["header"]["invoice_number"]
        assert round_tripped["header"]["currency"] == raw["header"]["currency"]
        assert Decimal(str(round_tripped["header"]["total_amount"])) == Decimal(
            str(raw["header"]["total_amount"])
        )
        assert len(round_tripped["line_items"]) == len(raw["line_items"])


def test_pii_masking_in_repr_and_layer_isolation_zero_db_or_validation_imports() -> None:
    """Verify vendor_tax_id is masked in repr() (CWE-532) and schemas.py obeys CLAUDE.md §4.2 layer rules."""
    parsed = InvoiceExtractionSchema.model_validate(_sample_payload())
    assert "ESA98765432" not in repr(parsed)
    assert "ESA98765432" not in repr(parsed.header)
    assert "***-**-5432" in repr(parsed.header)

    # Sanity check class exports
    assert InvoiceHeaderExtraction is not None
    assert InvoiceLineItemExtraction is not None

    src_code = Path("src/extraction/schemas.py").read_text(encoding="utf-8")
    for forbidden in ("src.database", "src.validation", "sqlalchemy", "api_key=", "sk-"):
        assert forbidden not in src_code


def test_blocks_decimal_exponent_bombs_and_direct_extracted_field_bool_coercion() -> None:
    """Verify FiniteDecimal defeats 1E-5000000 DoS bombs, sub-micro precision, and direct bool coercion (CWE-400/20)."""
    for bomb in (
        "1E-5000000",
        "1E+5000000",
        "0.00000001",
        "1" + ("0" * 40),
        True,
        False,
    ):
        with pytest.raises(ValidationError):
            ExtractedField[FiniteDecimal].model_validate({"value": bomb, "confidence": "95.00"})

    # Extreme zero exponent canonicalizes safely to Decimal("0")
    zero_field = ExtractedField[FiniteDecimal].model_validate(
        {"value": "0E-5000000", "confidence": "95.00"}
    )
    assert zero_field.value == Decimal("0")


def test_blocks_unicode_bidi_zero_width_hash_bypass_control_chars_and_xss_identifiers() -> None:
    """Verify bidi/ZWSP homograph blocking, control-char/XSS rejection, and DE/ES diacritic preservation."""
    # Valid German & Spanish diacritics MUST be accepted cleanly (FR-02)
    intl_payload = _sample_payload()
    intl_payload["header"]["vendor_name"]["value"] = "Münster Straße Analytics GmbH — España"
    intl_payload["line_items"][0]["description"]["value"] = "Calibración de precisión (5 < 10 mm)"
    parsed_intl = InvoiceExtractionSchema.model_validate(intl_payload)
    assert "Münster" in parsed_intl.header.vendor_name.value
    assert "Calibración" in parsed_intl.line_items[0].description.value

    # Invisible bidi override / zero-width space in identifiers would bypass SHA-256 duplicate detection
    for hostile_id in (
        "INV-2026-\u200b1001",
        "INV-2026-\u202e1001",
        "INV-2026-1001\r\nInjected",
        "INV-2026-1001\x00",
        "<script>alert(1)</script>",
        "</invoice_text>",
    ):
        bad = _sample_payload()
        bad["header"]["invoice_number"]["value"] = hostile_id
        with pytest.raises(ValidationError):
            InvoiceExtractionSchema.model_validate(bad)

    # Invisible bidi char in vendor_name and description also blocked
    bad_desc = _sample_payload()
    bad_desc["line_items"][0]["description"]["value"] = "Widget \u202e evil"
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(bad_desc)


def test_model_validate_json_strict_bool_flags_and_from_ground_truth_malformed_input_guards() -> (
    None
):
    """Verify model_validate_json, strict bool annotation flags, exact JSON dump, and malformed ground-truth guards."""
    raw_json = json.dumps(_sample_payload())
    parsed = InvoiceExtractionSchema.model_validate_json(raw_json)
    assert parsed.header.total_amount.value == Decimal("3449.71")

    # model_dump(mode="json") serializes Decimal cleanly without losing precision
    dumped = parsed.model_dump(mode="json")
    assert dumped["header"]["total_amount"]["value"] == "3449.71"
    assert dumped["header"]["total_amount"]["confidence"] == "99.50"

    # Non-boolean strings must NOT coerce to True on tax annotation flags
    bad_flag = _sample_payload()
    bad_flag["is_reverse_charge"] = "true"
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(bad_flag)

    bad_lang = _sample_payload()
    bad_lang["detected_language"] = "fr"
    with pytest.raises(ValidationError):
        InvoiceExtractionSchema.model_validate(bad_lang)

    # Malformed ground-truth dicts raise clean ValueError (not AttributeError)
    with pytest.raises(ValueError, match="header"):
        InvoiceExtractionSchema.from_ground_truth_dict({"only": "bad"})
    with pytest.raises(ValueError, match="must be a dict"):
        InvoiceExtractionSchema.from_ground_truth_dict({"header": {}, "line_items": ["not-a-dict"]})
    with pytest.raises(ValueError, match="exceeds maximum"):
        InvoiceExtractionSchema.from_ground_truth_dict(
            {"header": {}, "line_items": [{}] * (MAX_LINE_ITEMS + 1)}
        )
