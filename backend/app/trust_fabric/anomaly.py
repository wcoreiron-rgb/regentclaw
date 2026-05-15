"""
Trust Fabric — Anomaly Detection
Statistical anomaly detection using z-score against per-entity baselines.

Baseline data is stored in EntityProfile.baseline_json with the shape:
    {
        "metric_name": {
            "mean":   float,
            "std":    float,
            "count":  int,
            "sum":    float,
            "sum_sq": float
        },
        ...
    }

Online Welford algorithm is used so we never have to store raw historical
values — only the running statistics above are required.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.entity_profile import EntityProfile
from app.models.event import Event, EventOutcome

if TYPE_CHECKING:
    from app.trust_fabric.enforcement import ActionRequest

# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum observations required before we issue a non-zero anomaly score.
_COLD_START_THRESHOLD = 10

# Z-score → anomaly score bands
# (z_min, z_max, score_min, score_max)
_ZSCORE_BANDS = [
    (0.0, 2.0, 0.0,  20.0),   # normal
    (2.0, 3.0, 20.0, 50.0),   # elevated
    (3.0, 4.0, 50.0, 80.0),   # high
    (4.0, None, 80.0, 100.0), # critical
]

# High-risk action keywords (preserved from previous version)
SENSITIVE_ACTIONS = {
    "delete", "drop", "truncate", "wipe", "purge",
    "exfiltrate", "export_bulk", "shell_exec", "execute_code",
    "read_secret", "access_credential", "bypass_auth",
}

SENSITIVE_TARGETS = {
    "credentials", "secrets", "api_key", "password", "token",
    "ssh_key", "private_key", "database", "backup", "production",
}

RISKY_ACTOR_TYPES = {"agent", "service", "connector"}


# ── Core z-score functions ────────────────────────────────────────────────────

def _zscore_to_anomaly_score(z: float) -> float:
    """
    Map an absolute z-score value to a 0-100 anomaly score using linear
    interpolation within the configured bands.
    """
    z = abs(z)
    for z_min, z_max, s_min, s_max in _ZSCORE_BANDS:
        if z_max is None or z < z_max:
            if z_max is None:
                # Critical band — clamp at 100
                return min(100.0, s_min + (z - z_min) * 5.0)
            # Linear interpolation within band
            band_width = z_max - z_min
            position   = (z - z_min) / band_width
            return s_min + position * (s_max - s_min)
    return 100.0


def compute_anomaly_score(
    entity_id:      str,
    entity_type:    str,
    metric:         str,
    observed_value: float,
    baseline:       dict,
) -> float:
    """
    Compute a 0-100 anomaly score for a single metric observation.

    Args:
        entity_id:      Identifier of the entity being scored (for logging).
        entity_type:    Type of entity (user, agent, etc.).
        metric:         Name of the metric (e.g. "events_per_hour").
        observed_value: The value observed right now.
        baseline:       The baseline_json dict from EntityProfile, which must
                        contain a key for `metric` with count/mean/std fields.

    Returns:
        float in [0, 100].  Returns 0.0 if there are fewer than
        _COLD_START_THRESHOLD observations (cold-start protection).
    """
    metric_stats = baseline.get(metric)
    if not metric_stats:
        return 0.0  # No baseline data yet

    count = metric_stats.get("count", 0)
    if count < _COLD_START_THRESHOLD:
        return 0.0  # Cold-start: not enough data to judge

    mean = metric_stats.get("mean", 0.0)
    std  = metric_stats.get("std",  0.0)

    if std == 0.0:
        # No variance — any deviation from the mean is maximally anomalous,
        # but if observed == mean it is perfectly normal.
        if observed_value == mean:
            return 0.0
        return 80.0  # treat as high (no reference variance)

    z = (observed_value - mean) / std
    return _zscore_to_anomaly_score(z)


def update_baseline(baseline: dict, metric: str, new_value: float) -> dict:
    """
    Update the running statistics for `metric` in `baseline` using the
    online Welford algorithm.  Returns the mutated baseline dict.

    Welford's method — numerically stable single-pass variance:
        count  += 1
        delta   = value - mean
        mean   += delta / count
        delta2  = value - mean          # updated mean
        M2     += delta * delta2
        var     = M2 / (count - 1)      # sample variance (count > 1)
        std     = sqrt(var)

    We also track sum / sum_sq for compatibility with any future consumers.
    """
    if baseline is None:
        baseline = {}

    stats = baseline.get(metric, {"mean": 0.0, "std": 0.0, "count": 0,
                                   "sum": 0.0, "sum_sq": 0.0, "M2": 0.0})

    count  = stats.get("count", 0) + 1
    mean   = stats.get("mean", 0.0)
    M2     = stats.get("M2", 0.0)

    delta  = new_value - mean
    mean  += delta / count
    delta2 = new_value - mean
    M2    += delta * delta2

    if count > 1:
        std = math.sqrt(M2 / (count - 1))
    else:
        std = 0.0

    baseline[metric] = {
        "count":  count,
        "mean":   mean,
        "std":    std,
        "sum":    stats.get("sum", 0.0) + new_value,
        "sum_sq": stats.get("sum_sq", 0.0) + new_value ** 2,
        "M2":     M2,
    }
    return baseline


# ── Main detection entrypoint ─────────────────────────────────────────────────

async def detect_anomalies(db: AsyncSession, request: "ActionRequest") -> list[str]:
    """
    Detect anomalies for an action request.
    Returns a deduplicated list of anomaly signal keys.

    Combines:
      - Rule-based heuristics (fast, always run)
      - Z-score baseline checks (if EntityProfile baseline is available)
    """
    anomalies: list[str] = []

    action_lower = request.action.lower()
    target_lower = (request.target or "").lower()

    # ── Rule-based checks ────────────────────────────────────────────────────

    if any(s in action_lower for s in SENSITIVE_ACTIONS):
        anomalies.append("sensitive_action")

    if any(s in target_lower for s in SENSITIVE_TARGETS):
        anomalies.append("credential_access_attempt")

    if "shell" in action_lower or "exec" in action_lower or "bash" in action_lower:
        anomalies.append("shell_access_attempt")

    if "bulk" in action_lower or "export" in action_lower:
        if "external" in target_lower or "upload" in action_lower:
            anomalies.append("exfiltration_pattern")

    hour = datetime.utcnow().hour
    if hour < 7 or hour > 19:
        if request.actor_type in RISKY_ACTOR_TYPES:
            anomalies.append("off_hours_access")

    if request.actor_type in RISKY_ACTOR_TYPES:
        failures = await _recent_failures(db, request.actor_id)
        if failures >= 3:
            anomalies.append("identity_anomaly")

    # ── Z-score volume check ─────────────────────────────────────────────────

    recent_volume = await _recent_event_count(db, request.actor_id, minutes=60)

    profile = await _load_entity_profile(db, request.actor_id, request.actor_type)
    if profile is not None:
        baseline = profile.baseline_json or {}
        volume_score = compute_anomaly_score(
            entity_id=request.actor_id,
            entity_type=request.actor_type,
            metric="events_per_hour",
            observed_value=float(recent_volume),
            baseline=baseline,
        )
        if volume_score >= 50.0:
            anomalies.append("unusual_volume")

        # Update the baseline for next time (async write-through)
        updated_baseline = update_baseline(baseline, "events_per_hour", float(recent_volume))
        profile.baseline_json = updated_baseline
        profile.updated_at = datetime.utcnow()
        await db.commit()
    else:
        # Fallback to simple threshold when no profile exists
        if recent_volume > 20:
            anomalies.append("unusual_volume")

    return list(set(anomalies))


# ── DB helpers ────────────────────────────────────────────────────────────────

async def _load_entity_profile(
    db: AsyncSession, entity_id: str, entity_type: str
) -> EntityProfile | None:
    """Load (or return None) the EntityProfile for this entity."""
    try:
        stmt = select(EntityProfile).where(EntityProfile.entity_id == entity_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception:
        return None


async def _recent_failures(db: AsyncSession, actor_id: str, minutes: int = 15) -> int:
    """Count blocked events for actor in last N minutes."""
    since = datetime.utcnow() - timedelta(minutes=minutes)
    stmt = (
        select(func.count(Event.id))
        .where(Event.actor_id == actor_id)
        .where(Event.outcome == EventOutcome.BLOCKED)
        .where(Event.timestamp >= since)
    )
    result = await db.execute(stmt)
    return result.scalar() or 0


async def _recent_event_count(db: AsyncSession, actor_id: str, minutes: int = 60) -> int:
    """Count all events for actor in last N minutes."""
    since = datetime.utcnow() - timedelta(minutes=minutes)
    stmt = (
        select(func.count(Event.id))
        .where(Event.actor_id == actor_id)
        .where(Event.timestamp >= since)
    )
    result = await db.execute(stmt)
    return result.scalar() or 0
