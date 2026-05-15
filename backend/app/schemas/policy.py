from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional, Any
from app.models.policy import PolicyAction, PolicyScope


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    priority: int = 100
    scope: PolicyScope = PolicyScope.GLOBAL
    scope_target: Optional[str] = None
    condition_json: str        # JSON string: {"field": "...", "op": "...", "value": ...}
    action: PolicyAction
    created_by: Optional[str] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = None
    condition_json: Optional[str] = None
    action: Optional[PolicyAction] = None


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    version: str
    is_active: bool
    priority: int
    scope: PolicyScope
    scope_target: Optional[str] = None
    condition_json: str
    action: PolicyAction
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
