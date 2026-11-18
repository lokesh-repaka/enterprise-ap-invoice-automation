"""
Core infrastructure layer: configuration, security, logging, Redis, and secrets.
MUST NOT import from extraction/ or validation/ (CLAUDE.md §4.2).
"""

from src.core.config import Settings, get_settings
from src.core.logging import get_logger, request_id_ctx, setup_logging
from src.core.redis_client import (
    DEFAULT_DEAD_LETTER_QUEUE_KEY,
    DEFAULT_INVOICE_QUEUE_KEY,
    IdempotencyRecord,
    InvoiceQueueJob,
    RedisJobPayloadError,
    RedisJobQueueClient,
    RedisQueueConfigurationError,
    RedisQueueError,
    compute_idempotency_key,
    get_redis_queue_client,
    hash_client_idempotency_key,
    reset_redis_queue_client_cache,
)

__all__ = [
    "DEFAULT_DEAD_LETTER_QUEUE_KEY",
    "DEFAULT_INVOICE_QUEUE_KEY",
    "IdempotencyRecord",
    "InvoiceQueueJob",
    "RedisJobPayloadError",
    "RedisJobQueueClient",
    "RedisQueueConfigurationError",
    "RedisQueueError",
    "Settings",
    "compute_idempotency_key",
    "get_logger",
    "get_redis_queue_client",
    "get_settings",
    "hash_client_idempotency_key",
    "request_id_ctx",
    "reset_redis_queue_client_cache",
    "setup_logging",
]
