"""Add customclaw_definitions table.

Revision ID: 0002
Revises:     0001
Create Date: 2024-02-01 00:00:00.000000

The CustomClawDefinition model lives at app/models/customclaw.py.
This migration creates its backing table so that Alembic tracks it explicitly
rather than relying solely on SQLAlchemy's create_all() at startup.

Usage:
    alembic upgrade 0002      # apply this migration
    alembic downgrade 0001    # drop the table and revert to baseline
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers — used by Alembic
revision:       str                             = "0002"
down_revision:  Union[str, None]               = "0001"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the customclaw_definitions table."""
    op.create_table(
        "customclaw_definitions",
        # Primary key — UUID so IDs are globally unique across tenants
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        # Core identity fields
        sa.Column("name",        sa.String(256),  nullable=False),
        sa.Column("description", sa.Text(),        nullable=True),
        sa.Column("base_url",    sa.String(512),   nullable=False),

        # Authentication configuration
        sa.Column("auth_type",   sa.String(32),  server_default="none", nullable=False),
        sa.Column("auth_value",  sa.Text(),       nullable=True),
        sa.Column("auth_header", sa.String(128),  nullable=True),

        # Display metadata
        sa.Column("icon", sa.String(32), nullable=True),

        # JSON-serialised fields stored as text (SQLite-compatible)
        sa.Column("tags",      sa.Text(), nullable=True),   # JSON array string
        sa.Column("endpoints", sa.Text(), nullable=True),   # JSON array string

        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Drop the customclaw_definitions table."""
    op.drop_table("customclaw_definitions")
