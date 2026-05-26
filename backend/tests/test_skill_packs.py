import json

import pytest


BASE = "/api/v1/skill-packs"


def _pack_payload(slug: str, name: str) -> dict:
    manifest = {
        "skills": [{"id": "s1", "name": "Investigate", "claw": "identityclaw", "action": "investigate"}],
        "scope_permissions": ["read:findings"],
    }
    return {
        "name": name,
        "slug": slug,
        "version": "1.0.0",
        "description": "test pack",
        "manifest_json": json.dumps(manifest),
        "risk_level": "medium",
        "requires_approval": False,
    }


@pytest.mark.asyncio
async def test_install_skill_pack_blocked_by_policy(client):
    create_resp = await client.post(f"{BASE}", json=_pack_payload("deny-install-pack", "Deny Install Pack"))
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]

    deny_policy = {
        "name": "Block skill pack installs",
        "description": "test deny",
        "priority": 1,
        "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "install_skill_pack"}),
        "action": "deny",
        "created_by": "test",
    }
    policy_resp = await client.post("/api/v1/policies", json=deny_policy)
    assert policy_resp.status_code == 201, policy_resp.text

    install_resp = await client.post(f"{BASE}/{pack_id}/install", json={"installed_by": "tester"})
    assert install_resp.status_code == 403, install_resp.text
    detail = install_resp.json()["detail"]
    assert "blocked by Trust Fabric policy" in detail["message"]
    assert detail["outcome"] == "blocked"


@pytest.mark.asyncio
async def test_install_skill_pack_blocked_by_gateway_scan(client, monkeypatch):
    create_resp = await client.post(f"{BASE}", json=_pack_payload("gateway-fail-pack", "Gateway Fail Pack"))
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]

    class _FakeFlags:
        enable_mcp_gateway = True

    class _FakeAdapter:
        flags = _FakeFlags()

        def scan_path(self, path: str):
            return {
                "is_safe": False,
                "risk_score": 90.0,
                "critical_count": 1,
                "high_count": 2,
                "findings": [{"severity": "critical", "message": "hidden instruction payload"}],
                "path": path,
            }

    from app.api.routes import skill_packs_v2 as skill_pack_routes

    monkeypatch.setattr(skill_pack_routes, "get_agt_adapter", lambda: _FakeAdapter())

    install_resp = await client.post(
        f"{BASE}/{pack_id}/install",
        json={"installed_by": "tester", "scan_path": "backend/app/claws/identityclaw"},
    )
    assert install_resp.status_code == 400, install_resp.text
    detail = install_resp.json()["detail"]
    assert "blocked by MCP Security Gateway scan" in detail["message"]
    assert detail["scan"]["critical_count"] == 1

