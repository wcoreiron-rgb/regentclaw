from __future__ import annotations

from typing import Any


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

