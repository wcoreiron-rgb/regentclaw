from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from app.models.workflow import TriggerType, WorkflowStatus, WorkflowRunStatus


class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: TriggerType = TriggerType.MANUAL
    status: WorkflowStatus = WorkflowStatus.ACTIVE
    is_active: bool = True
    steps_json: str = "[]"
    step_count: int = 0
    category: Optional[str] = None
    tags: Optional[str] = None
    created_by: Optional[str] = None
    owner_name: Optional[str] = None


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_type: Optional[TriggerType] = None
    status: Optional[WorkflowStatus] = None
    is_active: Optional[bool] = None
    steps_json: Optional[str] = None
    step_count: Optional[int] = None
    category: Optional[str] = None
    tags: Optional[str] = None
    owner_name: Optional[str] = None


class WorkflowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    trigger_type: TriggerType
    status: WorkflowStatus
    is_active: bool
    steps_json: str
    step_count: int
    category: Optional[str] = None
    tags: Optional[str] = None
    created_by: Optional[str] = None
    owner_name: Optional[str] = None
    run_count: int
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class WorkflowRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workflow_id: UUID
    status: WorkflowRunStatus
    triggered_by: str
    steps_log: Optional[str] = None
    summary: Optional[str] = None
    error_message: Optional[str] = None
    steps_completed: int
    steps_failed: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_sec: Optional[float] = None
    created_at: datetime


class WorkflowTriggerResponse(BaseModel):
    run_id: UUID
    workflow_id: UUID
    status: WorkflowRunStatus
    message: str
