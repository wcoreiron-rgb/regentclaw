from __future__ import annotations

import os
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job, run_swarm_job_in_session
from app.core.swarm.schemas import SwarmActionResponse, SwarmJobCreate, SwarmJobRead, SwarmTaskRead
from app.models.swarm import SwarmJob, SwarmJobStatus, SwarmTask, SwarmTaskStatus

router = APIRouter(prefix="/swarm/jobs", tags=["Swarm"])


@router.post("", response_model=SwarmJobRead, status_code=201)
async def create_job(
    payload: SwarmJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    job = await create_swarm_job(db, payload)
    # Tests use an isolated in-memory DB session. Running inline avoids spawning
    # a separate session that cannot see test tables.
    if os.getenv("PYTEST_CURRENT_TEST"):
        await run_swarm_job_in_session(db, job.id)
    else:
        background_tasks.add_task(run_swarm_job, job.id)
    return job


@router.get("", response_model=list[SwarmJobRead])
async def list_jobs(
    status: Optional[SwarmJobStatus] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(SwarmJob).order_by(desc(SwarmJob.created_at)).limit(limit)
    if status:
        q = q.where(SwarmJob.status == status)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{job_id}", response_model=SwarmJobRead)
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SwarmJob).where(SwarmJob.id == UUID(job_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Swarm job not found")
    return job


@router.get("/{job_id}/tasks", response_model=list[SwarmTaskRead])
async def get_job_tasks(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SwarmTask)
        .where(SwarmTask.swarm_job_id == UUID(job_id))
        .order_by(SwarmTask.created_at.asc())
    )
    return result.scalars().all()


@router.post("/{job_id}/cancel", response_model=SwarmActionResponse)
async def cancel_job(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SwarmJob).where(SwarmJob.id == UUID(job_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Swarm job not found")
    if job.status in {SwarmJobStatus.COMPLETED, SwarmJobStatus.FAILED, SwarmJobStatus.CANCELLED}:
        return SwarmActionResponse(job_id=job.id, status=job.status, message="Job already finalized")

    job.status = SwarmJobStatus.CANCELLED
    task_result = await db.execute(select(SwarmTask).where(SwarmTask.swarm_job_id == job.id))
    for task in task_result.scalars().all():
        if task.status in {SwarmTaskStatus.PENDING, SwarmTaskStatus.RUNNING}:
            task.status = SwarmTaskStatus.CANCELLED
    await db.commit()
    return SwarmActionResponse(job_id=job.id, status=job.status, message="Job cancelled")


@router.post("/{job_id}/approve", response_model=SwarmActionResponse)
async def approve_job(job_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SwarmJob).where(SwarmJob.id == UUID(job_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Swarm job not found")
    if job.status != SwarmJobStatus.REQUIRES_APPROVAL:
        return SwarmActionResponse(job_id=job.id, status=job.status, message="No approval required")

    job.status = SwarmJobStatus.COMPLETED
    await db.commit()
    return SwarmActionResponse(job_id=job.id, status=job.status, message="Job approved")
