"""
Pydantic schemas for Invoice Upload, Read Detail, Exception Queue, and Async Job Payloads (P5-1, P5-4).
"""

from datetime import date, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict


class InvoiceUploadResponse(BaseModel):
    """HTTP 202 Accepted (or HTTP 200 OK on idempotent replay) invoice upload receipt."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    status: str = "UPLOADED"
    queued: bool = True
    deduplicated: bool = False
    idempotency_key: str | None = None
    filename: str
    detected_mime: str
    size_bytes: int
    file_hash: str
    blob_url: str
    vendor_id: str
    uploaded_at: datetime
    request_id: str | None = None


class InvoiceJobPayload(BaseModel):
    """Structured JSON job message pushed onto the Redis invoice processing queue."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    blob_name: str
    blob_url: str
    file_hash: str
    filename: str
    detected_mime: str
    vendor_id: str
    uploaded_by: str
    request_id: str | None = None
    enqueued_at: str


class InvoiceLineResponse(BaseModel):
    """Immutable line-item representation returned in ``GET /api/v1/invoices/{id}``."""

    model_config = ConfigDict(frozen=True)

    line_id: str
    line_number: int
    description: str
    quantity: Decimal
    unit_price: Decimal
    line_total: Decimal
    line_tax_rate: Decimal
    confidence_score: Decimal | None = None


class InvoiceDetailResponse(BaseModel):
    """Full invoice header, extracted line items, and audit summary for clerk/manager review."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    vendor_id: str | None = None
    vendor_tax_id: str
    vendor_name: str | None = None
    invoice_number: str
    invoice_date: date | None = None
    due_date: date | None = None
    po_number: str | None = None
    subtotal: Decimal | None = None
    total_tax_amount: Decimal | None = None
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal | None = None
    confidence_macro_avg: Decimal
    status: str
    blob_raw_url: str | None = None
    blob_json_url: str | None = None
    created_at: datetime
    updated_at: datetime
    lines: list[InvoiceLineResponse]
    audit_event_count: int = 0


class ExceptionQueueItem(BaseModel):
    """Data-minimized exception queue row (omits raw Tax ID and composite hash: CWE-200)."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    invoice_number: str
    vendor_id: str | None = None
    vendor_name: str | None = None
    total_amount: Decimal
    currency: str
    total_amount_usd: Decimal | None = None
    confidence_macro_avg: Decimal
    status: str
    invoice_date: date | None = None
    created_at: datetime


class ExceptionQueueResponse(BaseModel):
    """Paginated response for ``GET /api/v1/invoices/exceptions``."""

    model_config = ConfigDict(frozen=True)

    items: list[ExceptionQueueItem]
    total: int
    limit: int
    offset: int
    filters_applied: dict[str, Any]
