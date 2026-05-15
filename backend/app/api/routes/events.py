"""CoreOS — Events & Telemetry Bus routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.core.database import get_db
from app.models.event import Event, EventSeverity, EventOutcome
from app.schemas.event import EventRead

router = APIRouter(prefix="/events", tags=["CoreOS — Events"])


@router.get("", response_model=list[EventRead])
async def list_events(
    limit: int = 100,
    offset: int = 0,
    module: str | None = None,
    severity: str | None = None,
    outcome: str | None = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Event).order_by(desc(Event.timestamp)).limit(limit).offset(offset)
    if module:
        stmt = stmt.where(Event.source_module == module)
    if severity:
        stmt = stmt.where(Event.severity == EventSeverity(severity))
    if outcome:
        stmt = stmt.where(Event.outcome == EventOutcome(outcome))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/anomalies", response_model=list[EventRead])
async def list_anomalies(limit: int = 50, db: AsyncSession = Depends(get_db)):
    stmt = select(Event).where(Event.is_anomaly == True).order_by(desc(Event.risk_score)).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()
