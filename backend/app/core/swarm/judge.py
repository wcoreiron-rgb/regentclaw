from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.modelclaw.routes import route_model_call
from app.core.modelclaw.schemas import ModelRouteRequest

def judge_swarm_result(job_name: str, aggregate: dict[str, Any], task_count: int) -> dict[str, Any]:
    severity = aggregate.get("overall_severity", "info")
    confidence = float(aggregate.get("confidence", 0.0))
    risk_score = float(aggregate.get("risk_score", 0.0))
    requires_approval = severity in {"high", "critical"} or risk_score >= 60

    summary = (
        f"Swarm job '{job_name}' completed with {task_count} tasks. "
        f"Overall severity: {severity}. Confidence: {confidence:.2f}. "
        f"Average risk score: {risk_score:.1f}."
    )

    return {
        "overall_severity": severity,
        "confidence": confidence,
        "executive_summary": summary,
        "timeline": [],
        "root_cause": "Deterministic Sprint 1 execution baseline.",
        "blast_radius": "Limited to analyzed entities in the job input.",
        "top_findings": aggregate.get("top_findings", []),
        "recommended_actions": aggregate.get("recommended_actions", []),
        "requires_human_approval": requires_approval,
        "compliance_impact": [],
        "next_steps": [],
    }


async def judge_swarm_result_with_modelclaw(
    db: AsyncSession,
    job_name: str,
    aggregate: dict[str, Any],
    task_count: int,
    *,
    classification: str = "internal",
    swarm_job_id: str | None = None,
) -> dict[str, Any]:
    """
    Swarm Judge with ModelClaw synthesis.
    Falls back to deterministic judge when ModelClaw route is denied/unavailable.
    """
    judged = judge_swarm_result(job_name, aggregate, task_count)

    prompt = (
        "Summarize this swarm result for security operators as executive summary, root cause, "
        "blast radius, and next steps.\n"
        f"job_name={job_name}\n"
        f"aggregate={json.dumps(aggregate)}\n"
        f"task_count={task_count}\n"
    )
    try:
        routed = await route_model_call(
            ModelRouteRequest(
                claw="swarm_judge",
                action_type="MODEL_CALL",
                prompt=prompt,
                data_classification=classification,
                model_profile="swarm_judge_profile",
                swarm_job_id=swarm_job_id,
                context={"purpose": "swarm_summary_synthesis"},
            ),
            db=db,
        )
        if routed.allowed and routed.response:
            judged["executive_summary"] = routed.response
            judged["next_steps"] = [
                "Review ModelClaw-generated synthesis",
                "Validate top findings and recommended actions",
            ]
            judged["judge_model"] = {
                "provider": routed.provider,
                "model": routed.model,
                "profile": routed.model_profile,
            }
        else:
            judged["judge_model"] = {"blocked": True, "policy_name": routed.policy_name, "reason": routed.reason}
    except HTTPException as exc:
        judged["judge_model"] = {
            "blocked": True,
            "policy_name": "modelclaw_profile_guard",
            "reason": str(exc.detail),
        }
    except Exception as exc:  # pragma: no cover - defensive fallback
        judged["judge_model"] = {"error": str(exc)}
    return judged
