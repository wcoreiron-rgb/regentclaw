import pytest


BASE = "/api/v1/modelclaw"


@pytest.mark.asyncio
async def test_modelclaw_providers_and_profiles(client):
    providers = await client.get(f"{BASE}/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)
    assert any(p["provider"] == "nvidia_nim" for p in providers.json())

    profiles = await client.get(f"{BASE}/profiles")
    assert profiles.status_code == 200, profiles.text
    assert isinstance(profiles.json(), list)
    assert any(p["name"] == "nim_fast_reasoning" for p in profiles.json())


@pytest.mark.asyncio
async def test_modelclaw_route_and_calls_audit(client):
    routed = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "Summarize this IOC campaign in 5 bullets.",
            "data_classification": "internal",
            "model_profile": "nim_fast_reasoning",
            "swarm_job_id": "job_001",
        },
    )
    assert routed.status_code == 200, routed.text
    body = routed.json()
    assert body["allowed"] is True
    assert body["provider"] == "nvidia_nim"
    assert body["model_profile"] == "nim_fast_reasoning"
    assert body["response"]

    calls = await client.get(f"{BASE}/calls")
    assert calls.status_code == 200, calls.text
    rows = calls.json()
    assert isinstance(rows, list)
    assert rows
    assert rows[0]["provider"] == "nvidia_nim"


@pytest.mark.asyncio
async def test_modelclaw_denies_disallowed_classification(client):
    denied = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "Top secret prompt",
            "data_classification": "top_secret",
            "model_profile": "nim_fast_reasoning",
        },
    )
    assert denied.status_code == 403
