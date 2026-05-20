"""
Base classes and shared data structures for remediation action modules.

Every action module must expose:
  SUPPORTED_ACTIONS: list[str]
  async def execute(action_type, target_id, params, credentials) -> ActionResult
  async def rollback(action_type, target_id, rollback_data, credentials) -> ActionResult
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActionResult:
    """Result returned from every action execute/rollback call."""
    success: bool
    message: str
    rollback_data: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    error: str | None = None


def simulated(action_type: str, target_id: str, extra: dict | None = None) -> ActionResult:
    """Return a simulated success when credentials are not configured."""
    return ActionResult(
        success=True,
        message=f"Simulated: would have executed '{action_type}' on target '{target_id}' — credentials not configured",
        rollback_data=extra or {},
        output={"simulated": True, "action_type": action_type, "target_id": target_id},
    )
