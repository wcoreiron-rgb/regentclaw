"""
CoreOS — Policy Engine
Deterministic policy evaluation. Every action is checked before execution.
"""
import json
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.policy import Policy, PolicyAction, PolicyScope


class PolicyResult:
    def __init__(self, action: PolicyAction, policy_name: str, reason: str):
        self.action = action
        self.policy_name = policy_name
        self.reason = reason
        self.allowed = action in (PolicyAction.ALLOW, PolicyAction.MONITOR)

    def __repr__(self):
        return f"<PolicyResult action={self.action} policy={self.policy_name}>"


OPERATORS = {
    "eq": lambda field_val, val: field_val == val,
    "neq": lambda field_val, val: field_val != val,
    "in": lambda field_val, val: field_val in val,
    "not_in": lambda field_val, val: field_val not in val,
    "contains": lambda field_val, val: val in str(field_val),
    "startswith": lambda field_val, val: str(field_val).startswith(val),
    "gt": lambda field_val, val: float(field_val) > float(val),
    "lt": lambda field_val, val: float(field_val) < float(val),
    "gte": lambda field_val, val: float(field_val) >= float(val),
    "lte": lambda field_val, val: float(field_val) <= float(val),
}


def _evaluate_condition(condition: dict, context: dict[str, Any]) -> bool:
    """Evaluate a single condition against context. Returns True if condition matches."""
    field = condition.get("field", "")
    operator = condition.get("op", "eq")
    value = condition.get("value")

    field_val = context.get(field)
    if field_val is None:
        return False

    evaluator = OPERATORS.get(operator)
    if evaluator is None:
        return False

    try:
        return evaluator(field_val, value)
    except Exception:
        return False


async def evaluate_action(
    db: AsyncSession,
    context: dict[str, Any],
    module: Optional[str] = None,
) -> PolicyResult:
    """
    Evaluate all active policies in priority order against the given context.
    Returns the first matching policy result.
    Default: ALLOW if no policy matches.
    """
    stmt = (
        select(Policy)
        .where(Policy.is_active == True)
        .order_by(Policy.priority.asc())
    )
    result = await db.execute(stmt)
    policies = result.scalars().all()

    for policy in policies:
        # Scope filtering
        if policy.scope == PolicyScope.MODULE and policy.scope_target != module:
            continue

        try:
            condition = json.loads(policy.condition_json)
        except (json.JSONDecodeError, TypeError):
            continue

        if _evaluate_condition(condition, context):
            return PolicyResult(
                action=policy.action,
                policy_name=policy.name,
                reason=f"Matched policy '{policy.name}' (priority {policy.priority})"
            )

    # Default: allow
    return PolicyResult(
        action=PolicyAction.ALLOW,
        policy_name="default",
        reason="No matching policy — default allow"
    )
