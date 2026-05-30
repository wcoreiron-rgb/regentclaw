from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.fabric.providers.agt import get_agt_adapter
from app.models.swarm import SwarmTask, SwarmTaskStatus


def _severity_from_risk(risk_score: float) -> str:
    if risk_score >= 70:
        return "critical"
    if risk_score >= 50:
        return "high"
    if risk_score >= 25:
        return "medium"
    if risk_score > 0:
        return "low"
    return "info"


async def execute_task(db: AsyncSession, task: SwarmTask) -> dict[str, Any]:
    """
    Sprint 1 dispatcher.
    Uses deterministic local execution so swarm flows are testable before
    connector-backed task execution is fully implemented.
    """
    started = datetime.utcnow()
    task.status = SwarmTaskStatus.RUNNING
    task.started_at = started
    await db.commit()

    # Simulate bounded async work per claw for parallel orchestration.
    base = (sum(ord(c) for c in task.claw) % 30) + 40
    simulated_ms = base * 10
    await asyncio.sleep(min(simulated_ms / 1000.0, 0.45))

    risk_score = float(base)
    severity = _severity_from_risk(risk_score)
    confidence = round(min(0.99, 0.60 + (risk_score / 200.0)), 2)
    output = {
        "task_id": str(task.id),
        "swarm_job_id": str(task.swarm_job_id),
        "claw": task.claw,
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "findings": [
            {
                "title": f"{task.claw} simulated analysis",
                "detail": f"Deterministic Sprint 1 task result for {task.task_type}.",
            }
        ],
        "evidence": [],
        "recommended_actions": [],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": [],
        "execution_time_ms": simulated_ms,
    }

    adapter = get_agt_adapter()
    secure_channel = adapter.send_secure_message(
        sender=task.claw,
        recipient="swarm_judge",
        message_type="TASK_RESULT",
        payload={
            "task_id": str(task.id),
            "swarm_job_id": str(task.swarm_job_id),
            "severity": severity,
            "risk_score": risk_score,
        },
    )
    if secure_channel.get("enabled"):
        output["secure_channel"] = secure_channel
        output["policy_decisions"].append(
            {
                "action": "E2E_MESSAGE",
                "outcome": secure_channel.get("status"),
                "provider": secure_channel.get("provider"),
            }
        )

    task.status = SwarmTaskStatus.COMPLETED
    task.severity = severity
    task.confidence = confidence
    task.risk_score = risk_score
    task.execution_time_ms = simulated_ms
    task.output_json = json.dumps(output)
    task.completed_at = datetime.utcnow()
    await db.commit()
    return output


async def execute_task_by_id(task_id: UUID) -> dict[str, Any] | None:
    """
    Execute a task in an isolated DB session.
    Used by background swarm execution for real parallelism.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(SwarmTask).where(SwarmTask.id == task_id))
        task = result.scalar_one_or_none()
        if not task:
            return None
        return await execute_task(db, task)
