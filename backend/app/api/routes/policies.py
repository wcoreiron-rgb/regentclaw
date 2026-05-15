"""CoreOS — Policy CRUD routes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from uuid import UUID

from app.core.database import get_db
from app.models.policy import Policy
from app.schemas.policy import PolicyCreate, PolicyRead, PolicyUpdate

router = APIRouter(prefix="/policies", tags=["CoreOS — Policies"])


@router.get("", response_model=list[PolicyRead])
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).order_by(Policy.priority.asc()))
    return result.scalars().all()


@router.post("", response_model=PolicyRead, status_code=201)
async def create_policy(payload: PolicyCreate, db: AsyncSession = Depends(get_db)):
    policy = Policy(**payload.model_dump())
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/{policy_id}", response_model=PolicyRead)
async def get_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == UUID(policy_id)))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.patch("/{policy_id}", response_model=PolicyRead)
async def update_policy(policy_id: str, payload: PolicyUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == UUID(policy_id)))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == UUID(policy_id)))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(policy)
    await db.commit()
