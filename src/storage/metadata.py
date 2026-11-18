"""
Azure Blob Metadata Tagging & Integrity Verification (P4-4).

Enforces CLAUDE.md §4.2, §7.2, and §7.3 for immutable WORM invoice storage:
- Canonical mandatory tags on every uploaded blob:
  - ``VendorID``: Validated alphanumeric/hyphen/underscore vendor key (defaults to ``UNKNOWN``).
  - ``UploadTimestamp``: Timezone-aware UTC ISO-8601 timestamp (``YYYY-MM-DDTHH:MM:SSZ``).
  - ``FileHash``: Authoritative lowercase 64-char SHA-256 digest of the stored bytes.
- Case-insensitive parsing supports Azure Blob REST / Azurite lowercased ``x-ms-meta-*``
  headers while rejecting duplicate case-colliding keys (parser differentials).
- Defense-in-depth guards block hash spoofing (CWE-345/354), PII/secret leakage into blob
  headers (CWE-200/359), CRLF header injection (CWE-113), and Azure's 8 KB header cap (CWE-400).
"""

import hashlib
import hmac
import re
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

# Canonical Azure Blob metadata keys (CLAUDE.md §7.3, TASKS.md P4-4)
METADATA_KEY_VENDOR_ID = "VendorID"
METADATA_KEY_UPLOAD_TIMESTAMP = "UploadTimestamp"
METADATA_KEY_FILE_HASH = "FileHash"

RESERVED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        METADATA_KEY_VENDOR_ID,
        METADATA_KEY_UPLOAD_TIMESTAMP,
        METADATA_KEY_FILE_HASH,
    }
)
RESERVED_METADATA_KEYS_LOWER: frozenset[str] = frozenset(k.lower() for k in RESERVED_METADATA_KEYS)

DEFAULT_UNKNOWN_VENDOR_ID = "UNKNOWN"

# Azure Blob Storage metadata constraints (C# identifier keys, non-empty printable ASCII, <= 8 KB wire headers)
METADATA_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
METADATA_VALUE_PATTERN = re.compile(r"^[\x20-\x7e]{1,256}$")
VENDOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_METADATA_ENTRIES: int = 32
MAX_TOTAL_METADATA_BYTES: int = 8192
_AZURE_META_HEADER_OVERHEAD_BYTES: int = len("x-ms-meta-: \r\n")

# Forbidden sensitive / PII metadata key tokens (CLAUDE.md §7.2, CWE-200 / CWE-359)
_FORBIDDEN_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "taxid",
    "vatid",
    "ssn",
    "iban",
    "bankaccount",
    "routingnumber",
    "swiftcode",
    "password",
    "passwd",
    "secret",
    "apikey",
    "token",
    "accountkey",
    "connectionstring",
    "credential",
)

# Value-level PII / credential leak guards for free-form extra metadata (CWE-200 / CWE-359)
_FORBIDDEN_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),  # IBAN
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),  # JWT token
    re.compile(r"(?:AccountKey=|SharedAccessSignature|[?&]sig=)", re.IGNORECASE),  # Azure secrets
)


class BlobMetadataError(ValueError):
    """Raised when Azure Blob metadata keys, values, or canonical tags fail validation."""


class BlobMetadataIntegrityError(BlobMetadataError):
    """Raised when a blob's SHA-256 digest does not match its ``FileHash`` metadata tag."""


class InvoiceBlobMetadata(BaseModel):
    """Immutable canonical metadata tag set attached to every WORM invoice blob."""

    model_config = ConfigDict(frozen=True)

    vendor_id: str
    upload_timestamp: datetime
    file_hash: str

    def format_upload_timestamp(self) -> str:
        """Format UTC upload timestamp canonically as ISO-8601 with trailing ``Z``."""
        utc_ts = self.upload_timestamp.astimezone(UTC)
        if utc_ts.microsecond:
            return utc_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return utc_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_azure_metadata(self) -> dict[str, str]:
        """Return Azure Blob ``x-ms-meta-*`` compatible dictionary with canonical tag keys."""
        return {
            METADATA_KEY_VENDOR_ID: self.vendor_id,
            METADATA_KEY_UPLOAD_TIMESTAMP: self.format_upload_timestamp(),
            METADATA_KEY_FILE_HASH: self.file_hash,
        }


def validate_vendor_id(vendor_id: str) -> str:
    """Validate VendorID tag format (1-64 alphanumeric/hyphen/underscore chars, zero PII/CRLF)."""
    if not isinstance(vendor_id, str) or not VENDOR_ID_PATTERN.match(vendor_id):
        raise BlobMetadataError("Invalid metadata VendorID: expected 1-64 [A-Za-z0-9_-] characters")
    return vendor_id


def normalize_upload_timestamp(upload_timestamp: datetime | str | None) -> datetime:
    """Normalize UploadTimestamp to a timezone-aware UTC datetime, rejecting naive timestamps."""
    if upload_timestamp is None:
        return datetime.now(UTC)

    if isinstance(upload_timestamp, str):
        if "T" not in upload_timestamp and "t" not in upload_timestamp:
            raise BlobMetadataError(
                "Invalid metadata UploadTimestamp: must be ISO-8601 with 'T' separator and UTC timezone"
            )
        normalized_str = (
            f"{upload_timestamp[:-1]}+00:00"
            if upload_timestamp.endswith(("Z", "z"))
            else upload_timestamp
        )
        try:
            parsed = datetime.fromisoformat(normalized_str)
        except ValueError:
            raise BlobMetadataError(
                "Invalid metadata UploadTimestamp: malformed ISO-8601 timestamp"
            ) from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise BlobMetadataError(
                "Invalid metadata UploadTimestamp: explicit timezone offset required"
            )
        return parsed.astimezone(UTC)

    if isinstance(upload_timestamp, datetime):
        if upload_timestamp.tzinfo is None or upload_timestamp.utcoffset() is None:
            raise BlobMetadataError(
                "Invalid metadata UploadTimestamp: timezone-aware datetime required"
            )
        return upload_timestamp.astimezone(UTC)

    raise BlobMetadataError("Invalid metadata UploadTimestamp: expected datetime or ISO-8601 str")


def validate_file_hash(file_hash: str) -> str:
    """Validate and normalize a 64-character hexadecimal SHA-256 digest."""
    if not isinstance(file_hash, str):
        raise BlobMetadataError("Invalid metadata FileHash: expected 64-char SHA-256 hex string")
    lowered = file_hash.strip().lower()
    if not SHA256_HEX_PATTERN.match(lowered):
        raise BlobMetadataError("Invalid metadata FileHash: expected 64-char SHA-256 hex string")
    return lowered


def _reject_sensitive_key(key: str) -> None:
    """Block sensitive PII or credential fields from being written into Azure Blob headers."""
    normalized = key.lower().replace("_", "")
    for token in _FORBIDDEN_SENSITIVE_KEY_TOKENS:
        if token in normalized:
            raise BlobMetadataError(
                f"Invalid metadata key {key!r}: sensitive/PII fields are forbidden in blob metadata"
            )


def validate_metadata_entry(key: str, value: str) -> tuple[str, str]:
    """Validate a single Azure Blob metadata key/value pair (CWE-113 / CWE-200 / CWE-359)."""
    if not isinstance(key, str) or not METADATA_KEY_PATTERN.match(key):
        raise BlobMetadataError(f"Invalid metadata key: {key!r}")
    _reject_sensitive_key(key)
    if (
        not isinstance(value, str)
        or not METADATA_VALUE_PATTERN.match(value)
        or value != value.strip()
    ):
        raise BlobMetadataError(f"Invalid metadata value for key {key!r}")
    if key.lower() != METADATA_KEY_FILE_HASH.lower():
        for pattern in _FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                raise BlobMetadataError(
                    f"Invalid metadata value for key {key!r}: sensitive/PII pattern forbidden in blob metadata"
                )
    return key, value


def enforce_total_metadata_budget(metadata: dict[str, str]) -> None:
    """Enforce Azure Storage metadata entry count and 8 KB wire-header byte budget (CWE-400)."""
    if len(metadata) > MAX_METADATA_ENTRIES:
        raise BlobMetadataError(
            f"Invalid metadata: exceeds maximum of {MAX_METADATA_ENTRIES} entries"
        )
    total_bytes = sum(
        _AZURE_META_HEADER_OVERHEAD_BYTES + len(k.encode("ascii")) + len(v.encode("ascii"))
        for k, v in metadata.items()
    )
    if total_bytes > MAX_TOTAL_METADATA_BYTES:
        raise BlobMetadataError(
            f"Invalid metadata: total wire header size ({total_bytes} bytes) exceeds Azure 8192-byte header budget"
        )


def build_invoice_blob_metadata(
    data: bytes,
    *,
    vendor_id: str = DEFAULT_UNKNOWN_VENDOR_ID,
    upload_timestamp: datetime | None = None,
    expected_file_hash: str | None = None,
) -> InvoiceBlobMetadata:
    """
    Build authoritative canonical blob metadata (VendorID, UploadTimestamp, FileHash).

    Always computes ``FileHash`` directly from ``data`` bytes; if ``expected_file_hash`` is
    provided, verifies constant-time equality before returning.
    """
    if not isinstance(data, bytes) or len(data) == 0:
        raise BlobMetadataError("Cannot compute metadata FileHash for empty payload")

    clean_vendor = validate_vendor_id(vendor_id)
    utc_ts = normalize_upload_timestamp(upload_timestamp)
    computed_hash = hashlib.sha256(data).hexdigest()

    if expected_file_hash is not None:
        normalized_expected = validate_file_hash(expected_file_hash)
        if not hmac.compare_digest(computed_hash, normalized_expected):
            raise BlobMetadataIntegrityError(
                "Metadata FileHash mismatch: payload SHA-256 does not match expected digest"
            )

    return InvoiceBlobMetadata(
        vendor_id=clean_vendor,
        upload_timestamp=utc_ts,
        file_hash=computed_hash,
    )


def merge_invoice_blob_metadata(
    base: InvoiceBlobMetadata,
    extra_metadata: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Merge optional non-reserved caller metadata onto canonical tags.

    Blocks overrides of reserved tags (``VendorID``, ``UploadTimestamp``, ``FileHash``)
    across any casing, duplicate case-colliding keys, PII keys, CRLF values, and >8 KB totals.
    """
    merged = base.to_azure_metadata()
    if extra_metadata is None:
        enforce_total_metadata_budget(merged)
        return merged

    if not isinstance(extra_metadata, dict):
        raise BlobMetadataError("Invalid metadata: expected dict[str, str]")

    seen_lower: set[str] = set(RESERVED_METADATA_KEYS_LOWER)
    for key, value in extra_metadata.items():
        clean_key, clean_val = validate_metadata_entry(key, value)
        lower_key = clean_key.lower()
        if lower_key in RESERVED_METADATA_KEYS_LOWER:
            raise BlobMetadataError(
                f"Invalid metadata key {clean_key!r}: reserved canonical tag cannot be overridden"
            )
        if lower_key in seen_lower:
            raise BlobMetadataError(
                f"Invalid metadata key {clean_key!r}: duplicate case-colliding metadata key"
            )
        seen_lower.add(lower_key)
        merged[clean_key] = clean_val

    enforce_total_metadata_budget(merged)
    return merged


def prepare_upload_metadata(
    data: bytes,
    *,
    vendor_id: str | None = None,
    upload_timestamp: datetime | None = None,
    extra_metadata: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Resolve and harden upload metadata for WORM blob writes.

    Always populates canonical ``VendorID``, ``UploadTimestamp``, and authoritative
    ``FileHash``. If a caller supplies ``VendorID``/``UploadTimestamp`` inside
    ``extra_metadata``, validates them strictly and rejects conflicts with explicit arguments.
    Any ``FileHash`` inside ``extra_metadata`` is verified against ``sha256(data)``.
    """
    if extra_metadata is not None and not isinstance(extra_metadata, dict):
        raise BlobMetadataError("Invalid metadata: expected dict[str, str]")

    filtered_extra: dict[str, str] = {}
    seen_lower: set[str] = set()
    dict_vendor: str | None = None
    dict_ts_raw: str | None = None
    dict_hash: str | None = None

    if extra_metadata:
        for key, value in extra_metadata.items():
            clean_key, clean_val = validate_metadata_entry(key, value)
            lower_key = clean_key.lower()
            if lower_key in seen_lower:
                raise BlobMetadataError(
                    f"Invalid metadata key {clean_key!r}: duplicate case-colliding metadata key"
                )
            seen_lower.add(lower_key)

            if lower_key == METADATA_KEY_VENDOR_ID.lower():
                dict_vendor = validate_vendor_id(clean_val)
            elif lower_key == METADATA_KEY_UPLOAD_TIMESTAMP.lower():
                dict_ts_raw = clean_val
            elif lower_key == METADATA_KEY_FILE_HASH.lower():
                dict_hash = validate_file_hash(clean_val)
            else:
                filtered_extra[clean_key] = clean_val

    # Resolve VendorID (reject conflicting values if supplied via both kwarg and dict)
    if vendor_id is not None:
        resolved_vendor = validate_vendor_id(vendor_id)
        if dict_vendor is not None and dict_vendor != resolved_vendor:
            raise BlobMetadataError(
                "Invalid metadata VendorID: conflicting values between vendor_id argument and metadata dict"
            )
    elif dict_vendor is not None:
        resolved_vendor = dict_vendor
    else:
        resolved_vendor = DEFAULT_UNKNOWN_VENDOR_ID

    # Resolve UploadTimestamp (reject conflicting values if supplied via both kwarg and dict)
    if upload_timestamp is not None:
        resolved_ts = normalize_upload_timestamp(upload_timestamp)
        if dict_ts_raw is not None:
            parsed_dict_ts = normalize_upload_timestamp(dict_ts_raw)
            if parsed_dict_ts != resolved_ts:
                raise BlobMetadataError(
                    "Invalid metadata UploadTimestamp: conflicting values between upload_timestamp argument and metadata dict"
                )
    elif dict_ts_raw is not None:
        resolved_ts = normalize_upload_timestamp(dict_ts_raw)
    else:
        resolved_ts = datetime.now(UTC)

    canonical = build_invoice_blob_metadata(
        data,
        vendor_id=resolved_vendor,
        upload_timestamp=resolved_ts,
        expected_file_hash=dict_hash,
    )
    return merge_invoice_blob_metadata(canonical, filtered_extra or None)


def parse_invoice_blob_metadata(raw_metadata: dict[str, str] | None) -> InvoiceBlobMetadata:
    """
    Parse canonical ``InvoiceBlobMetadata`` from Azure Blob properties metadata.

    Handles both PascalCase (``VendorID``) and Azure REST lowercased (``vendorid``) keys,
    while rejecting missing canonical tags or duplicate case-colliding keys.
    """
    if not isinstance(raw_metadata, dict) or not raw_metadata:
        raise BlobMetadataError("Blob metadata is missing required canonical tags")

    normalized_map: dict[str, str] = {}
    for key, value in raw_metadata.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise BlobMetadataError("Invalid metadata entry types in blob properties")
        lower_key = key.lower()
        if lower_key in normalized_map:
            raise BlobMetadataError(
                f"Invalid metadata: duplicate case-colliding key {key!r} detected"
            )
        normalized_map[lower_key] = value

    missing = [
        canonical
        for canonical in (
            METADATA_KEY_VENDOR_ID,
            METADATA_KEY_UPLOAD_TIMESTAMP,
            METADATA_KEY_FILE_HASH,
        )
        if canonical.lower() not in normalized_map
    ]
    if missing:
        raise BlobMetadataError(
            f"Blob metadata missing required canonical tags: {', '.join(missing)}"
        )

    return InvoiceBlobMetadata(
        vendor_id=validate_vendor_id(normalized_map[METADATA_KEY_VENDOR_ID.lower()]),
        upload_timestamp=normalize_upload_timestamp(
            normalized_map[METADATA_KEY_UPLOAD_TIMESTAMP.lower()]
        ),
        file_hash=validate_file_hash(normalized_map[METADATA_KEY_FILE_HASH.lower()]),
    )


def verify_blob_metadata_integrity(
    data: bytes,
    raw_metadata: dict[str, str] | None,
) -> InvoiceBlobMetadata:
    """
    Verify downloaded blob bytes against stored ``FileHash`` metadata using constant-time digest check.
    """
    parsed = parse_invoice_blob_metadata(raw_metadata)
    computed_hash = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(computed_hash, parsed.file_hash):
        raise BlobMetadataIntegrityError(
            "Blob integrity check failed: computed SHA-256 does not match FileHash metadata"
        )
    return parsed
