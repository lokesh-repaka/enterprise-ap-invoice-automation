"""Initial baseline migration: Vendors, Invoices, InvoiceLines, AuditLogs, ExchangeRates

Revision ID: 0001
Revises: None
Create Date: 2026-02-15 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Vendors Master Table
    op.create_table(
        "vendors",
        sa.Column("vendor_tax_id", sa.String(length=50), nullable=False),
        sa.Column("vendor_id", sa.String(length=50), nullable=True),
        sa.Column("vendor_name", sa.String(length=200), nullable=False),
        sa.Column("country_code", sa.String(length=10), nullable=False),
        sa.Column(
            "date_format_locale", sa.String(length=20), server_default="MM/DD/YYYY", nullable=False
        ),
        sa.Column(
            "number_format_preference",
            sa.String(length=20),
            server_default="PERIOD",
            nullable=False,
        ),
        sa.Column("default_currency", sa.String(length=10), server_default="USD", nullable=False),
        sa.Column("tax_scheme", sa.String(length=100), nullable=True),
        sa.Column(
            "standard_tax_rate",
            sa.Numeric(precision=5, scale=4),
            server_default="0.0000",
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("vendor_tax_id"),
    )
    op.create_index("IX_vendors_vendor_id", "vendors", ["vendor_id"], unique=False)
    op.create_index("IX_vendors_country", "vendors", ["country_code"], unique=False)
    op.create_index("IX_vendors_name", "vendors", ["vendor_name"], unique=False)

    # 2. Invoices Table
    op.create_table(
        "invoices",
        sa.Column("invoice_id", sa.String(length=36), nullable=False),
        sa.Column("vendor_tax_id", sa.String(length=50), nullable=False),
        sa.Column("vendor_name", sa.String(length=200), nullable=True),
        sa.Column("invoice_number", sa.String(length=100), nullable=False),
        sa.Column("invoice_date", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("po_number", sa.String(length=100), nullable=True),
        sa.Column("subtotal", sa.Numeric(precision=18, scale=2), nullable=True),
        sa.Column("total_tax_amount", sa.Numeric(precision=18, scale=2), nullable=True),
        sa.Column("total_amount", sa.Numeric(precision=18, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=10), server_default="USD", nullable=False),
        sa.Column("total_amount_usd", sa.Numeric(precision=18, scale=2), nullable=True),
        sa.Column(
            "confidence_macro_avg",
            sa.Numeric(precision=5, scale=2),
            server_default="0.00",
            nullable=False,
        ),
        sa.Column("status", sa.String(length=50), server_default="UPLOADED", nullable=False),
        sa.Column("composite_hash", sa.String(length=64), nullable=False),
        sa.Column("blob_raw_url", sa.String(length=500), nullable=True),
        sa.Column("blob_json_url", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["vendor_tax_id"], ["vendors.vendor_tax_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("invoice_id"),
    )
    op.create_index("IX_invoices_composite_hash", "invoices", ["composite_hash"], unique=False)
    op.create_index("IX_invoices_status_date", "invoices", ["status", "invoice_date"], unique=False)
    op.create_index(
        "IX_invoices_vendor_number", "invoices", ["vendor_tax_id", "invoice_number"], unique=False
    )
    op.create_index("IX_invoices_po_number", "invoices", ["po_number"], unique=False)

    # 3. Invoice Lines Table
    op.create_table(
        "invoice_lines",
        sa.Column("line_id", sa.String(length=36), nullable=False),
        sa.Column("invoice_id", sa.String(length=36), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("quantity", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("unit_price", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.Column("line_total", sa.Numeric(precision=18, scale=2), nullable=False),
        sa.Column(
            "line_tax_rate",
            sa.Numeric(precision=5, scale=4),
            server_default="0.0000",
            nullable=False,
        ),
        sa.Column(
            "confidence_score",
            sa.Numeric(precision=5, scale=2),
            server_default="100.00",
            nullable=True,
        ),
        sa.ForeignKeyConstraint(["invoice_id"], ["invoices.invoice_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("line_id"),
    )
    op.create_index(
        "IX_invoice_lines_invoice_num", "invoice_lines", ["invoice_id", "line_number"], unique=False
    )

    # 4. Audit Logs Table
    op.create_table(
        "audit_logs",
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("invoice_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=100), nullable=False),
        sa.Column("action_type", sa.String(length=50), nullable=False),
        sa.Column("field_name", sa.String(length=100), nullable=True),
        sa.Column("previous_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("reason_code", sa.String(length=100), nullable=True),
        sa.Column("comment", sa.String(length=1000), nullable=True),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["invoice_id"], ["invoices.invoice_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("audit_id"),
    )
    op.create_index(
        "IX_audit_logs_invoice_timestamp", "audit_logs", ["invoice_id", "timestamp"], unique=False
    )
    op.create_index("IX_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)

    # 5. Exchange Rates Table
    op.create_table(
        "exchange_rates",
        sa.Column("rate_id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rate_date", sa.Date(), nullable=False),
        sa.Column("from_currency", sa.String(length=10), nullable=False),
        sa.Column("to_currency", sa.String(length=10), server_default="USD", nullable=False),
        sa.Column("exchange_rate", sa.Numeric(precision=18, scale=6), nullable=False),
        sa.PrimaryKeyConstraint("rate_id"),
        sa.UniqueConstraint("rate_date", "from_currency", "to_currency", name="UQ_exchange_rates"),
    )
    op.create_index(
        "IX_exchange_rates_lookup", "exchange_rates", ["rate_date", "from_currency"], unique=False
    )


def downgrade() -> None:
    op.drop_table("exchange_rates")
    op.drop_table("audit_logs")
    op.drop_table("invoice_lines")
    op.drop_table("invoices")
    op.drop_table("vendors")
