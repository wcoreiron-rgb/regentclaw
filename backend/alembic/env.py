"""
RegentClaw — Alembic env.py
Supports both synchronous (alembic CLI) and async SQLAlchemy engines.

Running migrations:
  # Inside docker:
  docker compose exec backend alembic upgrade head

  # Locally (with DB accessible on localhost:5432):
  cd backend && alembic upgrade head
"""
import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ── Alembic config ────────────────────────────────────────────────────────────
config = context.config

# Set up loggers from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Import all models so Alembic sees every table ─────────────────────────────
# This must happen BEFORE target_metadata is set.
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.core.database import Base  # noqa: E402

# Load every model module so SQLAlchemy registers all tables
import app.models  # noqa: F401, E402
from app.claws.arcclaw.models      import AIEvent              # noqa: F401, E402
from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction  # noqa: F401, E402
from app.models.agent          import Agent, Schedule, AgentRun, PlatformSettings  # noqa: F401, E402
from app.models.policy_pack    import PolicyPack               # noqa: F401, E402
from app.models.workflow       import Workflow, WorkflowRun    # noqa: F401, E402
from app.models.finding        import Finding                  # noqa: F401, E402
from app.models.trigger        import EventTrigger             # noqa: F401, E402
from app.models.memory         import IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot  # noqa: F401, E402
from app.models.skill_pack     import SkillPack                # noqa: F401, E402
from app.models.exchange       import ExchangePublisher, ExchangePackage, ExchangeInstallRecord  # noqa: F401, E402
from app.models.channel_gateway import ChannelMessage, ChannelIdentity, ChannelConfig  # noqa: F401, E402
from app.models.exec_channels  import ExecRequest, CredentialBrokerEntry, ProductionGate  # noqa: F401, E402
from app.models.entity_profile import EntityProfile, BehaviorEvent  # noqa: F401, E402

target_metadata = Base.metadata

# ── Database URL ──────────────────────────────────────────────────────────────
# Use sync URL for Alembic (psycopg2 / asyncpg both OK but Alembic CLI needs sync)
_db_url = (
    os.getenv("DATABASE_URL_SYNC")
    or os.getenv("DATABASE_URL", "postgresql://regentclaw:regentclaw@db:5432/regentclaw")
)

# If using asyncpg URL, convert to sync for Alembic CLI
if "+asyncpg" in _db_url:
    _db_url = _db_url.replace("+asyncpg", "")

config.set_main_option("sqlalchemy.url", _db_url)


# ── Offline migration (generates SQL, no live DB connection) ──────────────────

def run_migrations_offline() -> None:
    """Generate SQL without a live DB connection (useful for review/audit)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online migration (runs against a live DB) ─────────────────────────────────

def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations via a sync connection wrapper."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ── Entry point ───────────────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
