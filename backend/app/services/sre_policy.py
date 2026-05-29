from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from threading import Lock
from typing import Deque

from app.core.config import settings
from redis import Redis


@dataclass
class SREModuleState:
    module: str
    total: int
    failures: int
    error_rate: float
    budget_remaining: float
    circuit_open: bool
    circuit_open_until: str | None
    window_minutes: int


class SREPolicyEngine:
    def __init__(self) -> None:
        self._lock = Lock()
        self._events: dict[str, Deque[tuple[datetime, bool]]] = {}
        self._open_until: dict[str, datetime] = {}
        self._redis = self._build_redis()
        self._loaded = False

    def _build_redis(self) -> Redis | None:
        try:
            client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
            client.ping()
            return client
        except Exception:
            return None

    def _load_from_redis_unlocked(self) -> None:
        if self._loaded or self._redis is None:
            return
        raw = self._redis.get("trust_fabric:sre_state")
        if not raw:
            self._loaded = True
            return
        try:
            payload = json.loads(raw)
            events = payload.get("events", {})
            open_until = payload.get("open_until", {})

            def _as_bool(val: object) -> bool:
                if isinstance(val, bool):
                    return val
                if isinstance(val, (int, float)):
                    return bool(val)
                if isinstance(val, str):
                    return val.strip().lower() in {"1", "true", "yes", "y", "t"}
                return False

            self._events = {
                module: deque((datetime.fromisoformat(ts), _as_bool(ok)) for ts, ok in pairs)
                for module, pairs in events.items()
            }
            self._open_until = {
                module: datetime.fromisoformat(ts)
                for module, ts in open_until.items()
            }
        except Exception:
            self._events = {}
            self._open_until = {}
        self._loaded = True

    def _persist_to_redis_unlocked(self) -> None:
        if self._redis is None:
            return
        payload = {
            "events": {
                module: [[ts.isoformat(), ok] for ts, ok in q]
                for module, q in self._events.items()
            },
            "open_until": {
                module: ts.isoformat() for module, ts in self._open_until.items()
            },
        }
        try:
            ttl_seconds = max(300, settings.SRE_WINDOW_MINUTES * 120)
            self._redis.set("trust_fabric:sre_state", json.dumps(payload), ex=ttl_seconds)
        except Exception:
            # Keep serving from memory even if Redis is temporarily unavailable.
            pass

    def _window_start(self) -> datetime:
        return datetime.utcnow() - timedelta(minutes=settings.SRE_WINDOW_MINUTES)

    def _trim(self, module: str) -> None:
        q = self._events.setdefault(module, deque())
        cutoff = self._window_start()
        while q and q[0][0] < cutoff:
            q.popleft()
        # Clean up empty module queues and expired open states to keep persisted state lean.
        if not q:
            self._events.pop(module, None)
        open_until = self._open_until.get(module)
        if open_until and open_until <= datetime.utcnow():
            self._open_until.pop(module, None)

    def _compute_state_unlocked(self, module: str) -> SREModuleState:
        self._trim(module)
        q = self._events.get(module, deque())
        total = len(q)
        failures = sum(1 for _, ok in q if not ok)
        error_rate = (failures / total) if total else 0.0
        budget_remaining = max(0.0, settings.SRE_ERROR_BUDGET - error_rate)
        open_until = self._open_until.get(module)
        now = datetime.utcnow()
        is_open = bool(open_until and open_until > now)
        return SREModuleState(
            module=module,
            total=total,
            failures=failures,
            error_rate=round(error_rate, 4),
            budget_remaining=round(budget_remaining, 4),
            circuit_open=is_open,
            circuit_open_until=open_until.isoformat() if is_open else None,
            window_minutes=settings.SRE_WINDOW_MINUTES,
        )

    def check_circuit(self, module: str) -> tuple[bool, str | None]:
        with self._lock:
            self._load_from_redis_unlocked()
            state = self._compute_state_unlocked(module)
            self._persist_to_redis_unlocked()
            if state.circuit_open:
                return False, "SRE circuit breaker open for module"
            return True, None

    def record_outcome(self, module: str, success: bool) -> SREModuleState:
        with self._lock:
            self._load_from_redis_unlocked()
            q = self._events.setdefault(module, deque())
            q.append((datetime.utcnow(), success))
            state = self._compute_state_unlocked(module)

            if (
                state.total >= settings.SRE_MIN_SAMPLES
                and state.error_rate >= settings.SRE_CIRCUIT_BREAKER_THRESHOLD
            ):
                self._open_until[module] = datetime.utcnow() + timedelta(
                    seconds=settings.SRE_CIRCUIT_BREAKER_OPEN_SECONDS
                )
                state = self._compute_state_unlocked(module)

            self._persist_to_redis_unlocked()
            return state

    def get_state(self, module: str) -> SREModuleState:
        with self._lock:
            self._load_from_redis_unlocked()
            state = self._compute_state_unlocked(module)
            self._persist_to_redis_unlocked()
            return state

    def get_overview(self) -> dict:
        with self._lock:
            self._load_from_redis_unlocked()
            modules = sorted(set(self._events.keys()) | set(self._open_until.keys()))
            overview = {
                "enabled": settings.SRE_POLICY_ENABLED,
                "window_minutes": settings.SRE_WINDOW_MINUTES,
                "error_budget": settings.SRE_ERROR_BUDGET,
                "circuit_breaker_threshold": settings.SRE_CIRCUIT_BREAKER_THRESHOLD,
                "circuit_breaker_open_seconds": settings.SRE_CIRCUIT_BREAKER_OPEN_SECONDS,
                "min_samples": settings.SRE_MIN_SAMPLES,
                "backend": "redis" if self._redis is not None else "memory",
                "modules": [self._compute_state_unlocked(m).__dict__ for m in modules],
            }
            self._persist_to_redis_unlocked()
            return overview

    def reset(self, module: str | None = None) -> dict:
        with self._lock:
            self._load_from_redis_unlocked()
            if module:
                self._events.pop(module, None)
                self._open_until.pop(module, None)
                self._persist_to_redis_unlocked()
                return {"reset": True, "module": module}
            self._events.clear()
            self._open_until.clear()
            self._persist_to_redis_unlocked()
            return {"reset": True, "module": None}


_engine: SREPolicyEngine | None = None


def get_sre_engine() -> SREPolicyEngine:
    global _engine
    if _engine is None:
        _engine = SREPolicyEngine()
    return _engine
