import json

import pytest


@pytest.mark.asyncio
async def test_policy_packs_stats_route_not_shadowed(client):
    resp = await client.get("/api/v1/policy-packs/stats")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "total_packs" in body
    assert "applied_packs" in body
    assert "total_policies" in body


@pytest.mark.asyncio
async def test_schedule_delete_with_linked_runs(client):
    agent_resp = await client.post(
        "/api/v1/agents",
        json={
            "name": "Schedule Test Agent",
            "description": "Regression test agent",
            "claw": "identityclaw",
            "execution_mode": "monitor",
            "risk_level": "low",
            "status": "active",
        },
    )
    assert agent_resp.status_code == 201, agent_resp.text
    agent_id = agent_resp.json()["id"]

    sched_resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Regression Schedule",
            "agent_id": agent_id,
            "frequency": "hourly",
            "status": "active",
            "approval_required": False,
        },
    )
    assert sched_resp.status_code == 201, sched_resp.text
    schedule_id = sched_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/schedules/{schedule_id}/run")
    assert run_resp.status_code == 202, run_resp.text

    delete_resp = await client.delete(f"/api/v1/schedules/{schedule_id}")
    assert delete_resp.status_code == 204, delete_resp.text


@pytest.mark.asyncio
async def test_autonomy_emergency_json_payload_shape(client):
    on_resp = await client.post(
        "/api/v1/autonomy/emergency/activate",
        json={"reason": "regression test", "activated_by": "tester"},
    )
    assert on_resp.status_code == 200, on_resp.text
    assert on_resp.json()["status"] == "emergency_mode_activated"

    off_resp = await client.post(
        "/api/v1/autonomy/emergency/deactivate",
        json={"deactivated_by": "tester"},
    )
    assert off_resp.status_code == 200, off_resp.text
    assert off_resp.json()["status"] == "emergency_mode_deactivated"


@pytest.mark.asyncio
async def test_orchestration_replay_alias_by_run_id(client):
    create_resp = await client.post(
        "/api/v1/orchestrations",
        json={
            "name": "Replay Alias Workflow",
            "description": "Regression workflow",
            "trigger_type": "manual",
            "is_active": True,
            "steps_json": json.dumps(
                [
                    {"id": "s1", "name": "notify", "type": "notify", "config": {"message": "hi"}, "on_failure": "continue"},
                    {"id": "s2", "name": "wait", "type": "wait", "config": {"seconds": 1}, "on_failure": "stop"},
                ]
            ),
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    workflow_id = create_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/orchestrations/{workflow_id}/run")
    assert run_resp.status_code == 200, run_resp.text
    run_id = run_resp.json()["run_id"]

    replay_resp = await client.get(f"/api/v1/orchestrations/run-replay/{run_id}")
    assert replay_resp.status_code == 200, replay_resp.text
    replay = replay_resp.json()
    assert replay["run"]["id"] == run_id
    assert "timeline" in replay


@pytest.mark.asyncio
async def test_trust_fabric_multi_agent_status(client):
    resp = await client.get("/api/v1/trust-fabric/multi-agent/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "agt"
    assert "agent_mesh_enabled" in body
    assert "encrypted_messaging_enabled" in body
    assert "cryptographic_identity_enabled" in body
    assert "signature_algorithm" in body
    assert "compatibility_mode" in body


@pytest.mark.asyncio
async def test_trust_fabric_mcp_scan_route(client):
    resp = await client.post(
        "/api/v1/trust-fabric/mcp/scan",
        json={"target_type": "skill", "path": "/app/app"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target_type"] == "skill"
    assert "mcp_gateway_enabled" in body
    assert "risk_score" in body


@pytest.mark.asyncio
async def test_trust_fabric_multi_agent_verify_route(client):
    from app.core.config import settings
    from app.fabric.providers.agt import adapter as agt_adapter_module
    from app.fabric.providers.agt import get_agt_adapter

    settings.AGT_ENABLE_E2E_MESSAGING = True
    agt_adapter_module._adapter = None
    try:
        adapter = get_agt_adapter()
        secure = adapter.send_secure_message(
            sender="identityclaw",
            recipient="swarm_judge",
            message_type="TASK_RESULT",
            payload={"task_id": "t-1", "risk_score": 55},
        )

        resp = await client.post(
            "/api/v1/trust-fabric/multi-agent/verify",
            json={
                "envelope": secure["envelope"],
                "signature": secure["signature"],
                "key_id": secure["key_id"],
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["verified"] is True
        assert body["algorithm"] == "ed25519"
    finally:
        settings.AGT_ENABLE_E2E_MESSAGING = False
        agt_adapter_module._adapter = None
