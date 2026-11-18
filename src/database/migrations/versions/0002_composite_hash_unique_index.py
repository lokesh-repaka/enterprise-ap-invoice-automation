"""Enforce partial unique index on invoices.composite_hash excluding VOID & REJECTED_DUPLICATE

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-16 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("IX_invoices_composite_hash", table_name="invoices")
    op.create_index(
        "UX_invoices_composite_hash",
        "invoices",
        ["composite_hash"],
        unique=True,
        sqlite_where=sa.text("status NOT IN ('REJECTED_DUPLICATE', 'VOID')"),
        mssql_where=sa.text("status NOT IN ('REJECTED_DUPLICATE', 'VOID')"),
    )


def downgrade() -> None:
    op.drop_index("UX_invoices_composite_hash", table_name="invoices")
    op.create_index("IX_invoices_composite_hash", "invoices", ["composite_hash"], unique=False)
