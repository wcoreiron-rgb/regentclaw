"""
Tests for Policy CRUD and evaluation endpoints.

Endpoints under test:
  POST /api/v1/policies          — create policy
  GET  /api/v1/policies          — list policies
  POST /api/v1/policies/evaluate — evaluate a policy (if implemented)
"""
import pytest
import pytest_asyncio


BASE = "/api/v1/policies"


@pytest.mark.asyncio
async def test_create_policy(client):
    """POST /api/v1/policies should create and return a policy."""
    payload = {
        "name":           "Test Block Policy",
        "description":    "Blocks test actions",
        "action":         "deny",
        "priority":       10,
        "condition_json": '{"field": "action", "op": "eq", "value": "delete"}',
    }
    resp = await client.post(BASE, json=payload)
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    assert data["name"] == payload["name"]
    assert data["action"] == "deny"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_policies(client):
    """GET /api/v1/policies should return a list (possibly empty)."""
    await client.post(BASE, json={
        "name":           "List Test Policy",
        "action":         "allow",
        "priority":       5,
        "condition_json": "{}",
    })
    resp = await client.get(BASE)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    for item in data:
        assert "id" in item
        assert "name" in item


@pytest.mark.asyncio
async def test_create_policy_roundtrip(client):
    """Creating and then fetching a policy by ID should return matching data."""
    create_resp = await client.post(BASE, json={
        "name":           "Roundtrip Policy",
        "action":         "allow",
        "priority":       1,
        "condition_json": '{"field": "resource", "op": "eq", "value": "s3://bucket"}',
    })
    assert create_resp.status_code in (200, 201)
    created = create_resp.json()
    policy_id = created["id"]

    get_resp = await client.get(f"{BASE}/{policy_id}")
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["id"] == policy_id
    assert fetched["name"] == "Roundtrip Policy"


@pytest.mark.asyncio
async def test_policy_evaluation(client):
    """
    POST /api/v1/policies/evaluate — evaluate an action against loaded policies.

    If the endpoint does not exist (404) we mark the test as expected-skip
    rather than failing, since evaluation is a future endpoint.
    """
    payload = {
        "actor_id":   "user-1",
        "actor_type": "user",
        "action":     "read",
        "target":     "s3://my-bucket/file.txt",
        "context":    {},
    }
    resp = await client.post(f"{BASE}/evaluate", json=payload)

    if resp.status_code in (404, 405):
        pytest.skip("Policy evaluate endpoint not yet implemented — skipping")

    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    assert "decision" in data or "action" in data or "result" in data
