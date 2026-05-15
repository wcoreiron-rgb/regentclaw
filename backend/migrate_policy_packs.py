"""
RegentClaw — Policy Pack Migration
Creates the policy_packs table.

Usage:
  docker compose exec backend python migrate_policy_packs.py
"""
import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal


async def migrate():
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS policy_packs (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name        VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                framework   VARCHAR(64) NOT NULL,
                version     VARCHAR(32) NOT NULL DEFAULT '1.0',
                policy_count INTEGER NOT NULL DEFAULT 0,
                policies_json TEXT NOT NULL DEFAULT '[]',
                is_applied  BOOLEAN NOT NULL DEFAULT FALSE,
                applied_at  TIMESTAMPTZ,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        await db.commit()
        print("✅ policy_packs table created (or already present)")
        print("\nNext: docker compose exec backend python seed_policy_packs.py --reset")


if __name__ == "__main__":
    asyncio.run(migrate())
