from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.claws.arcclaw.models import AIEventType, AIEventOutcome


class AIEventSubmit(BaseModel):
    """Submit an AI interaction for inspection."""
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    tool_name: Optional[str] = None
    session_id: Optional[str] = None
    event_type: AIEventType = AIEventType.PROMPT_SUBMITTED
    prompt_text: str


class AIEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    tool_name: Optional[str] = None
    event_type: AIEventType
    is_sensitive: bool
    risk_score: float
    outcome: AIEventOutcome
    policy_applied: Optional[str] = None
    block_reason: Optional[str] = None
    findings_json: Optional[str] = None
    categories_json: Optional[str] = None
    redacted_text: Optional[str] = None


class ArcClawStats(BaseModel):
    total_events: int
    blocked_events: int
    flagged_events: int
    sensitive_events: int
    avg_risk_score: float
    top_tools: list[dict]
