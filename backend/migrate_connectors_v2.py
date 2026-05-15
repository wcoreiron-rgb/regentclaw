"""
RegentClaw — Connector Model Migration v2
Adds: category (VARCHAR 64), trust_score (FLOAT)

Usage:
  docker compose exec backend python migrate_connectors_v2.py
"""

import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal


async def migrate():
    async with AsyncSessionLocal() as db:
        # Add category column if missing
        try:
            await db.execute(text(
                "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS category VARCHAR(64)"
            ))
            print("  ✅ category column added (or already present)")
        except Exception as e:
            print(f"  ⚠ category: {e}")

        # Add trust_score column if missing
        try:
            await db.execute(text(
                "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS trust_score FLOAT DEFAULT 70.0"
            ))
            print("  ✅ trust_score column added (or already present)")
        except Exception as e:
            print(f"  ⚠ trust_score: {e}")

        await db.commit()
        print("\nMigration complete. Run seed_connectors.py --reset to populate new fields.")


if __name__ == "__main__":
    asyncio.run(migrate())
