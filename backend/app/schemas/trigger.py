"""Pydantic schemas for Event Triggers."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from uuid import UUID
from pydantic import BaseModel, field_validator
import json


class TriggerCondition(BaseModel):
    field: str
    op: str   # eq, neq, gt, gte, lt, lte, contains, not_contains, in, not_in
    value: Any


class TriggerCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str          # finding_created | finding_escalated | event_created | webhook_inbound
    source_filter: Optional[str] = None
    severity_min: Optional[str] = None
    conditions_json: str = "[]"
    action_type: str = "fire_workflow"
    workflow_id: Optional[UUID] = None
    target_claw: Optional[str] = None
    alert_config_json: Optional[str] = None
    cooldown_seconds: int = 300
    is_active: bool = True
    created_by: Optional[str] = None
    category: Optional[str] = None

    @field_validator("conditions_json")
    @classmethod
    def validate_conditions(cls, v: str) -> str:
        try:
            parsed = json.loads(v)
            assert isinstance(parsed, list)
        except Exception:
            raise ValueError("conditions_json must be a JSON array")
        return v


class TriggerUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    source_filter: Optional[str] = None
    severity_min: Optional[str] = None
    conditions_json: Optional[str] = None
    action_type: Optional[str] = None
    workflow_id: Optional[UUID] = None
    target_claw: Optional[str] = None
    alert_config_json: Optional[str] = None
    cooldown_seconds: Optional[int] = None
    is_active: Optional[bool] = None
    category: Optional[str] = None


class TriggerRead(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    trigger_type: str
    source_filter: Optional[str]
    severity_min: Optional[str]
    conditions_json: str
    action_type: str
    workflow_id: Optional[UUID]
    target_claw: Optional[str]
    cooldown_seconds: int
    is_active: bool
    last_triggered_at: Optional[datetime]
    trigger_count: int
    created_by: Optional[str]
    category: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
