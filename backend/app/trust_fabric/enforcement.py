"""
Trust Fabric — Enforcement Layer
The core zero-trust action mediation for RegentClaw.
Every action is verified before execution. No anonymous execution.
"""
import json
from datetime import datetime
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.policy_engine import evaluate_action, PolicyResult
from app.services.risk_scoring import calculate_event_risk, severity_from_score
from app.services.audit_service import log_action
from app.models.event import Event, EventOutcome, EventSeverity
from app.trust_fabric.anomaly import detect_anomalies


class ActionRequest:
    """Represents a request for an action by a module/agent."""

    def __init__(
        self,
        module: str,
        actor_id: str,
        actor_name: str,
        actor_type: str,
        action: str,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ):
        self.module = module
        self.actor_id = actor_id
        self.actor_name = actor_name
        self.actor_type = actor_type
        self.action = action
        self.target = target
        self.target_type = target_type
        self.context = context or {}
        self.timestamp = datetime.utcnow()


class EnforcementDecision:
    """The Trust Fabric decision for an ActionRequest."""

    def __init__(
        self,
        allowed: bool,
        outcome: EventOutcome,
        risk_score: float,
        severity: EventSeverity,
        policy_name: str,
        reason: str,
        anomalies: list[str],
    ):
        self.allowed = allowed
        self.outcome = outcome
        self.risk_score = risk_score
        self.severity = severity
        self.policy_name = policy_name
        self.reason = reason
        self.anomalies = anomalies


async def enforce(
    db: AsyncSession,
    request: ActionRequest,
    ip_address: Optional[str] = None,
) -> EnforcementDecision:
    """
    Main enforcement entrypoint.
    1. Detect anomalies
    2. Evaluate policy
    3. Calculate risk
    4. Log event + audit
    5. Return decision
    """
    # Build full evaluation context
    eval_context = {
        "module": request.module,
        "actor_id": request.actor_id,
        "actor_type": request.actor_type,
        "action": request.action,
        "target": request.target,
        "target_type": request.target_type,
        **request.context,
    }

    # 1. Anomaly detection
    anomalies = await detect_anomalies(db, request)

    # 2. Policy evaluation
    policy_result: PolicyResult = await evaluate_action(db, eval_context, module=request.module)

    # 3. Risk scoring
    signals = list(anomalies)
    if not policy_result.allowed:
        signals.append("blocked_policy")
    if request.actor_type == "agent":
        signals.append("identity_anomaly") if anomalies else None

    risk_score = calculate_event_risk(signals)
    sev_str = severity_from_score(risk_score)
    severity = EventSeverity(sev_str)

    # 4. Map outcome
    from app.models.policy import PolicyAction
    outcome_map = {
        PolicyAction.ALLOW: EventOutcome.ALLOWED,
        PolicyAction.DENY: EventOutcome.BLOCKED,
        PolicyAction.REQUIRE_APPROVAL: EventOutcome.REQUIRES_APPROVAL,
        PolicyAction.MONITOR: EventOutcome.ALLOWED,
        PolicyAction.ISOLATE: EventOutcome.BLOCKED,
    }
    outcome = outcome_map.get(policy_result.action, EventOutcome.FLAGGED)

    # 5. Persist event
    event = Event(
        timestamp=request.timestamp,
        source_module=request.module,
        actor_id=request.actor_id,
        actor_name=request.actor_name,
        actor_type=request.actor_type,
        action=request.action,
        target=request.target,
        target_type=request.target_type,
        outcome=outcome,
        severity=severity,
        risk_score=risk_score,
        policy_name=policy_result.policy_name,
        policy_reason=policy_result.reason,
        description=f"[{request.module}] {request.actor_name} → {request.action}",
        metadata_json=json.dumps({"anomalies": anomalies, "context": request.context}),
        is_anomaly=bool(anomalies),
        requires_review=risk_score >= 50 or outcome == EventOutcome.REQUIRES_APPROVAL,
    )
    db.add(event)

    # 6. Audit log
    await log_action(
        db=db,
        actor=request.actor_name,
        actor_type=request.actor_type,
        action=request.action,
        outcome=outcome.value,
        resource_type=request.target_type,
        resource_id=request.target,
        policy_applied=policy_result.policy_name,
        reason=policy_result.reason,
        module=request.module,
        ip_address=ip_address,
        detail_json=json.dumps({"risk_score": risk_score, "anomalies": anomalies}),
        compliance_relevant=risk_score >= 25,
    )

    await db.commit()

    return EnforcementDecision(
        allowed=policy_result.allowed,
        outcome=outcome,
        risk_score=risk_score,
        severity=severity,
        policy_name=policy_result.policy_name,
        reason=policy_result.reason,
        anomalies=anomalies,
    )
