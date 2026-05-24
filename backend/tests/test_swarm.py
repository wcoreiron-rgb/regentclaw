import pytest


BASE = "/api/v1/swarm/jobs"


def _payload(**overrides):
    body = {
        "name": "Test Incident Swarm",
        "profile": "INCIDENT_RESPONSE",
        "participants": ["identityclaw", "cloudclaw", "threatclaw"],
        "task_type": "investigate",
        "input": {"entity": "user@company.com", "time_range": "24h"},
        "classification": "confidential",
        "parallelism": 3,
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_create_swarm_job(client):
    response = await client.post(BASE, json=_payload())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "Test Incident Swarm"
    assert body["status"] in {"pending", "running", "requires_approval", "completed"}
    assert "id" in body


@pytest.mark.asyncio
async def test_get_swarm_job_and_tasks(client):
    create = await client.post(BASE, json=_payload())
    assert create.status_code == 201, create.text
    job_id = create.json()["id"]

    get_job = await client.get(f"{BASE}/{job_id}")
    assert get_job.status_code == 200
    assert get_job.json()["id"] == job_id

    get_tasks = await client.get(f"{BASE}/{job_id}/tasks")
    assert get_tasks.status_code == 200
    tasks = get_tasks.json()
    assert isinstance(tasks, list)
    assert len(tasks) == 3
    assert set(t["claw"] for t in tasks) == {"identityclaw", "cloudclaw", "threatclaw"}


@pytest.mark.asyncio
async def test_cancel_swarm_job(client):
    create = await client.post(BASE, json=_payload())
    job_id = create.json()["id"]
    response = await client.post(f"{BASE}/{job_id}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["job_id"] == job_id
    assert body["status"] in {"cancelled", "completed", "requires_approval"}


@pytest.mark.asyncio
async def test_list_swarm_jobs(client):
    await client.post(BASE, json=_payload(name="Swarm A"))
    await client.post(BASE, json=_payload(name="Swarm B"))
    response = await client.get(BASE)
    assert response.status_code == 200
    jobs = response.json()
    assert isinstance(jobs, list)
    assert len(jobs) >= 2

