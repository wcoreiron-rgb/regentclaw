import asyncio
from uuid import uuid4

import pytest

from app.core.swarm.orchestrator import _run_bounded_parallel_tasks


@pytest.mark.asyncio
async def test_bounded_parallel_tasks_respects_parallelism_limit():
    active = 0
    max_active = 0
    lock = asyncio.Lock()

    async def runner(_task_id):
        nonlocal active, max_active
        async with lock:
            active += 1
            max_active = max(max_active, active)
        await asyncio.sleep(0.05)
        async with lock:
            active -= 1
        return {"ok": True}

    task_ids = [uuid4() for _ in range(8)]
    outputs, failures = await _run_bounded_parallel_tasks(task_ids, parallelism=3, runner=runner)

    assert not failures
    assert len(outputs) == 8
    assert 1 < max_active <= 3
