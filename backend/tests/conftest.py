"""Shared pytest fixtures for RegentClaw backend tests."""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Use the app's core Base so all models are registered
from app.core.database import Base, get_db
from main import app

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_session():
    """
    Provide an in-memory SQLite session for each test.
    All tables are created fresh and dropped after the test.
    """
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Import all models so they are registered with Base.metadata
    import app.models  # noqa: F401 — registers models without core.database Base
    from app.models.agent import Agent, Schedule, AgentRun, PlatformSettings  # noqa
    from app.models.policy_pack import PolicyPack  # noqa
    from app.models.workflow import Workflow, WorkflowRun  # noqa
    from app.models.finding import Finding  # noqa
    from app.models.trigger import EventTrigger  # noqa
    from app.models.memory import IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot  # noqa
    from app.models.skill_pack import SkillPack  # noqa
    from app.models.exchange import ExchangePublisher, ExchangePackage, ExchangeInstallRecord  # noqa
    from app.models.channel_gateway import ChannelMessage, ChannelIdentity, ChannelConfig  # noqa
    from app.models.exec_channels import ExecRequest, CredentialBrokerEntry, ProductionGate  # noqa
    from app.models.entity_profile import EntityProfile, BehaviorEvent  # noqa
    from app.models.customclaw import CustomClawDefinition  # noqa
    from app.models.audit import AuditLog  # noqa
    from app.claws.arcclaw.models import AIEvent  # noqa
    from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction  # noqa

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncTestSession = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncTestSession() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    """
    Provide an httpx AsyncClient wired to the FastAPI app with:
      - DB dependency overridden to the in-memory test session.
      - Auth dependency overridden to bypass JWT validation.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    # Bypass JWT authentication for tests
    try:
        from app.core.deps import get_current_user
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "test-user",
            "sub": "test-user",
            "email": "test@test.com",
            "role": "admin",
        }
    except ImportError:
        pass

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
