"""Policy harness regressions: allow/deny packs and replay-style checks."""

import json

import pytest


def _pack_payload(name: str, policies: list[dict]) -> dict:
    return {
        "name": name,
        "description": "Policy harness test pack",
        "framework": "regression",
        "version": "1.0",
        "policy_count": len(policies),
        "policies_json": json.dumps(policies),
    }


async def _create_pack(client, name: str, policies: list[dict]) -> str:
    resp = await client.post("/api/v1/policy-packs", json=_pack_payload(name, policies))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_policy_pack_apply_and_unapply_controls_trust_fabric_decision(client):
    pack_id = await _create_pack(
        client,
        "regression-deny-shell",
        [
            {
                "name": "deny shell exec",
                "priority": 2,
                "scope": "global",
                "condition_json": json.dumps({"field": "action", "op": "eq", "value": "shell_exec"}),
                "action": "deny",
                "is_active": True,
            }
        ],
    )

    apply_resp = await client.post(f"/api/v1/policy-packs/{pack_id}/apply")
    assert apply_resp.status_code == 200, apply_resp.text
    assert apply_resp.json()["is_applied"] is True

    denied = await client.post(
        "/api/v1/trust-fabric/evaluate",
        json={
            "module": "trust_fabric",
            "actor_id": "policy-harness-user",
            "actor_name": "Policy Harness User",
            "actor_type": "human",
            "action": "shell_exec",
            "target": "critical-node",
            "target_type": "host",
            "context": {},
        },
    )
    assert denied.status_code == 200, denied.text
    denied_body = denied.json()
    assert denied_body["allowed"] is False
    assert denied_body["policy_name"] == "deny shell exec"

    unapply_resp = await client.post(f"/api/v1/policy-packs/{pack_id}/unapply")
    assert unapply_resp.status_code == 200, unapply_resp.text
    assert unapply_resp.json()["is_applied"] is False

    allowed = await client.post(
        "/api/v1/trust-fabric/evaluate",
        json={
            "module": "trust_fabric",
            "actor_id": "policy-harness-user",
            "actor_name": "Policy Harness User",
            "actor_type": "human",
            "action": "shell_exec",
            "target": "critical-node",
            "target_type": "host",
            "context": {},
        },
    )
    assert allowed.status_code == 200, allowed.text
    allowed_body = allowed.json()
    assert allowed_body["allowed"] is True
    assert allowed_body["policy_name"] == "default"


@pytest.mark.asyncio
async def test_policy_harness_priority_prefers_deny_when_allow_and_deny_match(client):
    pack_id = await _create_pack(
        client,
        "regression-priority",
        [
            {
                "name": "deny risky action",
                "priority": 5,
                "scope": "global",
                "condition_json": json.dumps({"field": "action", "op": "eq", "value": "risky_action"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "allow risky action later",
                "priority": 15,
                "scope": "global",
                "condition_json": json.dumps({"field": "action", "op": "eq", "value": "risky_action"}),
                "action": "allow",
                "is_active": True,
            },
        ],
    )

    apply_resp = await client.post(f"/api/v1/policy-packs/{pack_id}/apply")
    assert apply_resp.status_code == 200, apply_resp.text

    resp = await client.post(
        "/api/v1/trust-fabric/evaluate",
        json={
            "module": "trust_fabric",
            "actor_id": "priority-user",
            "actor_name": "Priority User",
            "actor_type": "human",
            "action": "risky_action",
            "target": "resource-1",
            "target_type": "resource",
            "context": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allowed"] is False
    assert body["policy_name"] == "deny risky action"


@pytest.mark.asyncio
async def test_policy_harness_replay_is_deterministic_for_same_request(client):
    pack_id = await _create_pack(
        client,
        "regression-replay",
        [
            {
                "name": "require approval for parallelism gt 2",
                "priority": 7,
                "scope": "global",
                "condition_json": json.dumps({"field": "parallelism", "op": "gt", "value": 2}),
                "action": "require_approval",
                "is_active": True,
            }
        ],
    )
    apply_resp = await client.post(f"/api/v1/policy-packs/{pack_id}/apply")
    assert apply_resp.status_code == 200, apply_resp.text

    payload = {
        "module": "swarm",
        "actor_id": "replay-user",
        "actor_name": "Replay User",
        "actor_type": "human",
        "action": "start_swarm",
        "target": "daily-triage",
        "target_type": "swarm_job",
        "context": {"parallelism": 4},
    }

    first = await client.post("/api/v1/trust-fabric/evaluate", json=payload)
    second = await client.post("/api/v1/trust-fabric/evaluate", json=payload)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text

    body_1 = first.json()
    body_2 = second.json()
    assert body_1["allowed"] is False
    assert body_1["outcome"] == "requires_approval"
    assert body_1["policy_name"] == "require approval for parallelism gt 2"
    assert body_2["allowed"] == body_1["allowed"]
    assert body_2["outcome"] == body_1["outcome"]
    assert body_2["policy_name"] == body_1["policy_name"]
