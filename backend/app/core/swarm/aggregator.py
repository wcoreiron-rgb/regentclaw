from __future__ import annotations

from typing import Any


def aggregate_task_outputs(task_outputs: list[dict[str, Any]]) -> dict[str, Any]:
    if not task_outputs:
        return {
            "overall_severity": "info",
            "confidence": 0.0,
            "top_findings": [],
            "recommended_actions": [],
            "risk_score": 0.0,
        }

    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max(task_outputs, key=lambda o: severity_rank.get((o.get("severity") or "info").lower(), 0))
    overall = (top.get("severity") or "info").lower()

    confidences = [float(o.get("confidence", 0.0)) for o in task_outputs]
    risks = [float(o.get("risk_score", 0.0)) for o in task_outputs]
    findings = [f for out in task_outputs for f in out.get("findings", [])][:10]
    recommendations = [r for out in task_outputs for r in out.get("recommended_actions", [])][:10]

    return {
        "overall_severity": overall,
        "confidence": round(sum(confidences) / max(len(confidences), 1), 2),
        "top_findings": findings,
        "recommended_actions": recommendations,
        "risk_score": round(sum(risks) / max(len(risks), 1), 2),
    }

