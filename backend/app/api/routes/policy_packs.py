"""CoreOS — Policy Pack routes."""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from uuid import UUID

from app.core.database import get_db
from app.models.policy_pack import PolicyPack
from app.models.policy import Policy
from app.schemas.policy_pack import PolicyPackCreate, PolicyPackRead

router = APIRouter(prefix="/policy-packs", tags=["CoreOS — Policy Packs"])


@router.get("", response_model=list[PolicyPackRead])
async def list_policy_packs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PolicyPack).order_by(PolicyPack.created_at.asc()))
    return result.scalars().all()


@router.get("/{pack_id}", response_model=PolicyPackRead)
async def get_policy_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PolicyPack).where(PolicyPack.id == UUID(pack_id)))
    pack = result.scalar_one_or_none()
    if not pack:
        raise HTTPException(status_code=404, detail="Policy pack not found")
    return pack


@router.post("", response_model=PolicyPackRead, status_code=201)
async def create_policy_pack(payload: PolicyPackCreate, db: AsyncSession = Depends(get_db)):
    pack = PolicyPack(**payload.model_dump())
    db.add(pack)
    await db.commit()
    await db.refresh(pack)
    return pack


@router.post("/{pack_id}/apply", response_model=PolicyPackRead)
async def apply_policy_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    """Deploy all policies from this pack into the active policies table."""
    result = await db.execute(select(PolicyPack).where(PolicyPack.id == UUID(pack_id)))
    pack = result.scalar_one_or_none()
    if not pack:
        raise HTTPException(status_code=404, detail="Policy pack not found")

    if pack.is_applied:
        raise HTTPException(status_code=409, detail="Pack is already applied. Remove it first.")

    try:
        policy_defs = json.loads(pack.policies_json)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid policies_json in pack")

    pack_tag = f"policy_pack:{pack.id}"
    for pd in policy_defs:
        policy = Policy(
            name=pd.get("name", "Unnamed"),
            description=pd.get("description"),
            priority=pd.get("priority", 100),
            scope=pd.get("scope", "global"),
            scope_target=pd.get("scope_target"),
            condition_json=pd.get("condition_json", "{}"),
            action=pd.get("action", "monitor"),
            is_active=pd.get("is_active", True),
            version=pd.get("version", "1.0"),
            created_by=pack_tag,
        )
        db.add(policy)

    pack.is_applied = True
    pack.applied_at = datetime.utcnow()
    await db.commit()
    await db.refresh(pack)
    return pack


@router.post("/{pack_id}/unapply", response_model=PolicyPackRead)
async def unapply_policy_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    """Remove all policies deployed by this pack."""
    result = await db.execute(select(PolicyPack).where(PolicyPack.id == UUID(pack_id)))
    pack = result.scalar_one_or_none()
    if not pack:
        raise HTTPException(status_code=404, detail="Policy pack not found")

    pack_tag = f"policy_pack:{pack.id}"
    await db.execute(delete(Policy).where(Policy.created_by == pack_tag))

    pack.is_applied = False
    pack.applied_at = None
    await db.commit()
    await db.refresh(pack)
    return pack


@router.delete("/{pack_id}", status_code=204)
async def delete_policy_pack(pack_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PolicyPack).where(PolicyPack.id == UUID(pack_id)))
    pack = result.scalar_one_or_none()
    if not pack:
        raise HTTPException(status_code=404, detail="Policy pack not found")
    # Remove associated policies first
    pack_tag = f"policy_pack:{pack.id}"
    await db.execute(delete(Policy).where(Policy.created_by == pack_tag))
    await db.delete(pack)
    await db.commit()
