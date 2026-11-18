"""
Pydantic schemas for Invoice Upload API and Async Redis Job Payloads (P5-1).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class InvoiceUploadResponse(BaseModel):
    """HTTP 202 Accepted receipt returned after validation, WORM write, SQL insert, and enqueue."""

    model_config = ConfigDict(frozen=True)

    invoice_id: str
    status: str = "UPLOADED"
    queued: bool = True
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
