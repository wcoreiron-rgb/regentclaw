from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.models.identity import IdentityType, IdentityStatus


class IdentityBase(BaseModel):
    name: str
    type: IdentityType
    description: Optional[str] = None
    is_privileged: bool = False
    external_id: Optional[str] = None
    source: Optional[str] = None


class IdentityCreate(IdentityBase):
    owner_id: Optional[UUID] = None


class IdentityUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[IdentityStatus] = None
    description: Optional[str] = None
    is_privileged: Optional[bool] = None
    owner_id: Optional[UUID] = None


class IdentityRead(IdentityBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: IdentityStatus
    trust_score: float
    risk_score: float
    owner_id: Optional[UUID] = None
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
