from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.models.event import EventSeverity, EventOutcome


class EventCreate(BaseModel):
    source_module: str
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_type: Optional[str] = None
    action: str
    target: Optional[str] = None
    target_type: Optional[str] = None
    severity: EventSeverity = EventSeverity.INFO
    description: Optional[str] = None
    metadata_json: Optional[str] = None


class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    source_module: str
    actor_id: Optional[str] = None
    actor_name: Optional[str] = None
    actor_type: Optional[str] = None
    action: str
    target: Optional[str] = None
    outcome: EventOutcome
    severity: EventSeverity
    risk_score: float
    policy_name: Optional[str] = None
    policy_reason: Optional[str] = None
    description: Optional[str] = None
    is_anomaly: bool
    requires_review: bool
