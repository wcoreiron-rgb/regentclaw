from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional


class PolicyPackRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    framework: str
    version: str
    policy_count: int
    policies_json: str
    is_applied: bool
    applied_at: Optional[datetime] = None
    created_at: datetime


class PolicyPackCreate(BaseModel):
    name: str
    description: Optional[str] = None
    framework: str
    version: str = "1.0"
    policy_count: int = 0
    policies_json: str = "[]"
