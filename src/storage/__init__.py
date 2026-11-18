"""
Azure Blob WORM storage client wrapper: Managed Identity authentication and metadata tagging.
"""

from src.storage.azurite import (
    DEFAULT_AZURITE_BLOB_URL,
    check_azurite_reachable,
    create_azurite_worm_client,
    ensure_worm_container,
    is_azurite_enabled,
    validate_azurite_url,
)
from src.storage.blob_client import (
    DEFAULT_WORM_RETENTION_DAYS,
    MAX_BLOB_SIZE_BYTES,
    AzureBlobWORMClient,
    BlobAlreadyExistsError,
    BlobNotFoundError,
    BlobStorageConfigurationError,
    BlobStorageError,
    BlobUploadResult,
    BlobWORMClientProtocol,
    InMemoryWORMBlobClient,
    build_extraction_json_blob_name,
    build_raw_invoice_blob_name,
    get_blob_worm_client,
    reset_blob_client_cache,
    validate_blob_account_url,
    validate_blob_name,
    validate_container_name,
)

__all__ = [
    "AzureBlobWORMClient",
    "BlobAlreadyExistsError",
    "BlobNotFoundError",
    "BlobStorageConfigurationError",
    "BlobStorageError",
    "BlobUploadResult",
    "BlobWORMClientProtocol",
    "DEFAULT_AZURITE_BLOB_URL",
    "DEFAULT_WORM_RETENTION_DAYS",
    "InMemoryWORMBlobClient",
    "MAX_BLOB_SIZE_BYTES",
    "build_extraction_json_blob_name",
    "build_raw_invoice_blob_name",
    "check_azurite_reachable",
    "create_azurite_worm_client",
    "ensure_worm_container",
    "get_blob_worm_client",
    "is_azurite_enabled",
    "reset_blob_client_cache",
    "validate_azurite_url",
    "validate_blob_account_url",
    "validate_blob_name",
    "validate_container_name",
]
