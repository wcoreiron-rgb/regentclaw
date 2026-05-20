"""Add remediation_actions and remediation_playbooks tables.

Revision ID: 0003
Revises:     0002
Create Date: 2024-03-01 00:00:00.000000

The RemediationAction and RemediationPlaybook models live at
app/models/remediation.py.  This migration creates their backing tables so
that Alembic tracks them explicitly rather than relying solely on
SQLAlchemy's create_all() at startup.

Usage:
    alembic upgrade 0003      # apply this migration
    alembic downgrade 0002    # drop the tables and revert to 0002
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers — used by Alembic
revision:       str                             = "0003"
down_revision:  Union[str, None]               = "0002"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the remediation_actions and remediation_playbooks tables."""

    # ── remediation_actions ───────────────────────────────────────────────────
    op.create_table(
        "remediation_actions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        # Linkage
        sa.Column("finding_id",      postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("workflow_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("playbook_id",     sa.String(128),  nullable=True),

        # What to do
        sa.Column("provider",     sa.String(64),  nullable=False),
        sa.Column("action_type",  sa.String(64),  nullable=False),
        sa.Column("target_type",  sa.String(64),  nullable=False),
        sa.Column("target_id",    sa.String(512), nullable=False),
        sa.Column("target_label", sa.String(512), nullable=True),
        sa.Column("parameters",   sa.Text(),      nullable=True),

        # Governance
        sa.Column(
            "status",
            sa.Enum(
                "pending_approval",
                "approved",
                "rejected",
                "executing",
                "completed",
                "failed",
                "rolled_back",
                "timed_out",
                name="remediationstatus",
            ),
            nullable=False,
            server_default="pending_approval",
        ),
        sa.Column("risk_level",        sa.String(16),  nullable=False, server_default="high"),
        sa.Column("requires_approval", sa.Boolean(),   nullable=False, server_default="true"),

        # Accountability
        sa.Column("triggered_by",       sa.String(128), nullable=False, server_default="auto"),
        sa.Column("approved_by",        sa.String(128), nullable=True),
        sa.Column("rejected_reason",    sa.Text(),      nullable=True),
        sa.Column("approval_expires_at", sa.DateTime(timezone=True), nullable=True),

        # Execution tracking
        sa.Column("executed_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),

        # Rollback
        sa.Column("rollback_data", sa.Text(), nullable=True),

        # Output
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error",  sa.Text(), nullable=True),

        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # ── remediation_playbooks ─────────────────────────────────────────────────
    op.create_table(
        "remediation_playbooks",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("slug",        sa.String(128), nullable=True, unique=True),
        sa.Column("name",        sa.String(256), nullable=False),
        sa.Column("description", sa.Text(),      nullable=True),

        # Trigger conditions
        sa.Column("trigger_claw",     sa.String(64),  nullable=True),
        sa.Column("trigger_severity", sa.String(16),  nullable=True),
        sa.Column("trigger_category", sa.String(128), nullable=True),
        sa.Column("trigger_keywords", sa.Text(),      nullable=True),

        # Playbook definition
        sa.Column("actions_json", sa.Text(), nullable=False),

        # Settings
        sa.Column("is_active",               sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("requires_approval",       sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("auto_rollback_on_failure", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("run_count",               sa.Integer(), nullable=False, server_default="0"),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    """Drop the remediation tables."""
    op.drop_table("remediation_actions")
    op.drop_table("remediation_playbooks")
    # Drop the enum type (PostgreSQL only)
    op.execute("DROP TYPE IF EXISTS remediationstatus")
