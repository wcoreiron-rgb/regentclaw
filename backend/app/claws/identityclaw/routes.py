"""IdentityClaw — API Routes."""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel, ConfigDict
from uuid import UUID
from typing import Optional

from app.core.database import get_db
from app.models.identity import Identity, IdentityType, IdentityStatus
from app.schemas.identity import IdentityCreate, IdentityRead, IdentityUpdate
from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction, IdentityRiskLevel
from app.services.risk_scoring import calculate_event_risk
from app.services.audit_service import log_action

router = APIRouter(prefix="/identityclaw", tags=["IdentityClaw — Identity Security"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class RiskEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    timestamp: datetime
    identity_id: str
    identity_name: Optional[str]
    identity_type: Optional[str]
    risk_type: str
    risk_level: IdentityRiskLevel
    risk_score: float
    description: Optional[str]
    is_resolved: bool


class PrivilegedActionCreate(BaseModel):
    requestor_id: str
    requestor_name: Optional[str] = None
    action: str
    target_identity_id: Optional[str] = None
    justification: Optional[str] = None


class PrivilegedActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    timestamp: datetime
    requestor_id: str
    requestor_name: Optional[str]
    action: str
    target_identity_id: Optional[str]
    justification: Optional[str]
    status: str
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]


class IdentityClawStats(BaseModel):
    total_identities: int
    human_identities: int
    non_human_identities: int
    orphaned_identities: int
    high_risk_identities: int
    pending_approvals: int


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/identities", response_model=list[IdentityRead], summary="Identity inventory")
async def list_identities(
    identity_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Identity).order_by(desc(Identity.risk_score)).limit(limit)
    if identity_type:
        stmt = stmt.where(Identity.type == IdentityType(identity_type))
    if status:
        stmt = stmt.where(Identity.status == IdentityStatus(status))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/identities", response_model=IdentityRead, summary="Register identity")
async def register_identity(payload: IdentityCreate, db: AsyncSession = Depends(get_db)):
    identity = Identity(**payload.model_dump())
    db.add(identity)
    await log_action(
        db=db, actor="system", actor_type="system",
        action="register_identity", outcome="allowed",
        resource_type="identity", resource_name=payload.name,
        module="identityclaw",
    )
    await db.commit()
    await db.refresh(identity)
    return identity


@router.get("/identities/{identity_id}", response_model=IdentityRead, summary="Get identity detail")
async def get_identity(identity_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Identity).where(Identity.id == UUID(identity_id))
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


@router.patch("/identities/{identity_id}", response_model=IdentityRead, summary="Update identity")
async def update_identity(identity_id: str, payload: IdentityUpdate, db: AsyncSession = Depends(get_db)):
    stmt = select(Identity).where(Identity.id == UUID(identity_id))
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(identity, field, value)
    await db.commit()
    await db.refresh(identity)
    return identity


@router.get("/orphaned", response_model=list[IdentityRead], summary="Orphaned identities")
async def get_orphaned_identities(db: AsyncSession = Depends(get_db)):
    """Identities with no owner that are agents/connectors — high risk."""
    stmt = (
        select(Identity)
        .where(Identity.owner_id.is_(None))
        .where(Identity.type.in_([IdentityType.AGENT, IdentityType.CONNECTOR, IdentityType.SERVICE]))
        .where(Identity.status == IdentityStatus.ACTIVE)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/risk-events", response_model=list[RiskEventRead], summary="Identity risk events")
async def list_risk_events(
    limit: int = 50,
    unresolved_only: bool = False,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(IdentityRiskEvent).order_by(desc(IdentityRiskEvent.timestamp)).limit(limit)
    if unresolved_only:
        stmt = stmt.where(IdentityRiskEvent.is_resolved == False)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/approvals", response_model=PrivilegedActionRead, summary="Request privileged action approval")
async def request_approval(payload: PrivilegedActionCreate, db: AsyncSession = Depends(get_db)):
    action = PrivilegedAction(**payload.model_dump())
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/approvals", response_model=list[PrivilegedActionRead], summary="List approval requests")
async def list_approvals(status: Optional[str] = "pending", db: AsyncSession = Depends(get_db)):
    stmt = select(PrivilegedAction).where(PrivilegedAction.status == status).order_by(desc(PrivilegedAction.timestamp))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/approvals/{action_id}/review", response_model=PrivilegedActionRead, summary="Approve or deny")
async def review_approval(
    action_id: str,
    decision: str,      # "approved" or "denied"
    reviewed_by: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(PrivilegedAction).where(PrivilegedAction.id == UUID(action_id))
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Approval request not found")
    action.status = decision
    action.reviewed_by = reviewed_by
    action.reviewed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/stats", response_model=IdentityClawStats, summary="IdentityClaw summary")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = await db.execute(select(func.count(Identity.id)))
    humans = await db.execute(select(func.count(Identity.id)).where(Identity.type == IdentityType.HUMAN))
    non_humans = await db.execute(
        select(func.count(Identity.id)).where(
            Identity.type.in_([IdentityType.AGENT, IdentityType.CONNECTOR, IdentityType.SERVICE, IdentityType.MODULE])
        )
    )
    orphaned = await db.execute(
        select(func.count(Identity.id))
        .where(Identity.owner_id.is_(None))
        .where(Identity.type != IdentityType.HUMAN)
    )
    high_risk = await db.execute(select(func.count(Identity.id)).where(Identity.risk_score >= 50))
    pending = await db.execute(select(func.count(PrivilegedAction.id)).where(PrivilegedAction.status == "pending"))

    return IdentityClawStats(
        total_identities=total.scalar() or 0,
        human_identities=humans.scalar() or 0,
        non_human_identities=non_humans.scalar() or 0,
        orphaned_identities=orphaned.scalar() or 0,
        high_risk_identities=high_risk.scalar() or 0,
        pending_approvals=pending.scalar() or 0,
    )
