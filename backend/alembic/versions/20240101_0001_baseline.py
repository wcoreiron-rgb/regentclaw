"""Baseline — captures existing schema created by create_all on startup.

Run this ONCE on a fresh DB to bring Alembic into sync with the running schema:

    # If the DB was already created by FastAPI's create_all at startup:
    alembic stamp 0001

    # If you want Alembic to create a fresh DB from scratch:
    alembic upgrade head

After this, use `alembic revision --autogenerate -m "description"` for all
future schema changes. Never manually edit the DB schema after this point.

Revision ID: 0001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision:       str                         = "0001"
down_revision:  Union[str, None]            = None
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    This is a baseline migration — it represents all tables already created
    by SQLAlchemy's create_all() on first startup.

    If running against an empty database, this will create all tables.
    If the tables already exist (typical dev scenario), Alembic will skip
    existing tables automatically when using --autogenerate for future changes.

    For an already-running database, stamp instead of upgrading:
        alembic stamp 0001
    """
    # All tables are already managed by SQLAlchemy create_all() at startup.
    # This migration is intentionally a no-op so that `alembic stamp 0001`
    # can mark the existing DB as being at this baseline.
    #
    # Future migrations generated with --autogenerate will build on top of
    # this revision and contain real DDL changes.
    pass


def downgrade() -> None:
    """
    Downgrading past the baseline drops all managed tables.
    WARNING: This is destructive on a production database.
    """
    pass
