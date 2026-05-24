from __future__ import annotations

from app.core.swarm.schemas import SwarmJobCreate

DEFAULT_PARTICIPANTS = [
    "identityclaw",
    "cloudclaw",
    "threatclaw",
]


def select_participants(payload: SwarmJobCreate) -> list[str]:
    """Pick participants for a swarm run."""
    if payload.participants:
        return list(dict.fromkeys([p.strip().lower() for p in payload.participants if p.strip()]))
    return DEFAULT_PARTICIPANTS

