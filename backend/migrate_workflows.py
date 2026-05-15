"""
RegentClaw — Workflow Migration
Creates the workflows and workflow_runs tables.

Usage:
  docker compose exec backend python migrate_workflows.py
"""
import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal


async def migrate():
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS workflows (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name            VARCHAR(255) NOT NULL,
                description     TEXT,
                trigger_type    VARCHAR(32) NOT NULL DEFAULT 'manual',
                status          VARCHAR(32) NOT NULL DEFAULT 'active',
                is_active       BOOLEAN NOT NULL DEFAULT TRUE,
                steps_json      TEXT NOT NULL DEFAULT '[]',
                step_count      INTEGER NOT NULL DEFAULT 0,
                category        VARCHAR(64),
                tags            VARCHAR(255),
                created_by      VARCHAR(255),
                owner_name      VARCHAR(255),
                run_count       INTEGER NOT NULL DEFAULT 0,
                last_run_at     TIMESTAMPTZ,
                last_run_status VARCHAR(32),
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        print("  ✅ workflows table created (or already present)")

        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workflow_id      UUID NOT NULL,
                status           VARCHAR(32) NOT NULL DEFAULT 'pending',
                triggered_by     VARCHAR(255) NOT NULL DEFAULT 'manual',
                steps_log        TEXT,
                summary          TEXT,
                error_message    TEXT,
                steps_completed  INTEGER NOT NULL DEFAULT 0,
                steps_failed     INTEGER NOT NULL DEFAULT 0,
                started_at       TIMESTAMPTZ,
                completed_at     TIMESTAMPTZ,
                duration_sec     FLOAT,
                created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        print("  ✅ workflow_runs table created (or already present)")

        await db.commit()
        print("\nNext: docker compose exec backend python seed_workflows.py --reset")


if __name__ == "__main__":
    asyncio.run(migrate())
