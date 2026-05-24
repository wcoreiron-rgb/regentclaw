from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.swarm import SwarmJobStatus, SwarmTaskStatus


class SwarmJobCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    profile: str = Field(default="FAST_TRIAGE", max_length=64)
    requested_by: str = Field(default="manual", max_length=255)
    trigger_type: str = Field(default="manual", max_length=32)
    classification: str = Field(default="internal", max_length=64)
    participants: list[str] = Field(default_factory=list)
    task_type: str = Field(default="analyze", max_length=128)
    input: dict[str, Any] = Field(default_factory=dict)
    parallelism: int = Field(default=3, ge=1, le=24)
    model_profile: Optional[str] = Field(default=None, max_length=128)


class SwarmTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    swarm_job_id: UUID
    claw: str
    task_type: str
    status: SwarmTaskStatus
    model_profile: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    risk_score: Optional[float] = None
    input_json: str
    output_json: Optional[str] = None
    execution_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SwarmJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    profile: str
    status: SwarmJobStatus
    requested_by: str
    trigger_type: str
    input_json: str
    classification: str
    participants_json: str
    parallelism: int
    overall_severity: Optional[str] = None
    confidence: Optional[float] = None
    final_summary: Optional[str] = None
    result_json: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SwarmActionResponse(BaseModel):
    job_id: UUID
    status: SwarmJobStatus
    message: str
