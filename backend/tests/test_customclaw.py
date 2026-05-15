"""
Tests for CustomClaw definition persistence via the API.

Endpoints under test:
  POST   /api/v1/customclaw/definitions          — create definition
  GET    /api/v1/customclaw/definitions           — list definitions
  DELETE /api/v1/customclaw/definitions/{id}      — delete definition
"""
import pytest

BASE = "/api/v1/customclaw/definitions"


def _sample_definition(**overrides) -> dict:
    """Return a valid CustomClaw definition payload."""
    payload = {
        "name":        "Test REST Integration",
        "description": "A test custom claw pointing at httpbin",
        "base_url":    "https://httpbin.org",
        "auth_type":   "none",
        "icon":        "🔌",
        "tags":        ["test", "http"],
        "endpoints": [
            {
                "name":   "Get IP",
                "path":   "/ip",
                "method": "GET",
            }
        ],
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_create_definition_persists(client):
    """
    POST /api/v1/customclaw/definitions should create the definition and
    return it with an assigned ID.
    """
    payload = _sample_definition(name="Persist Test")
    resp = await client.post(BASE, json=payload)
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()
    assert "id" in data
    assert data["name"] == "Persist Test"
    assert data["base_url"] == "https://httpbin.org"


@pytest.mark.asyncio
async def test_list_definitions(client):
    """
    GET /api/v1/customclaw/definitions should include previously created items.
    """
    # Create two definitions
    for i in range(2):
        await client.post(BASE, json=_sample_definition(name=f"Definition {i}"))

    resp = await client.get(BASE)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Response may be a list or a dict with a nested list
    if isinstance(data, list):
        definitions = data
    elif isinstance(data, dict):
        definitions = data.get("definitions", data.get("items", data.get("results", [])))
    else:
        definitions = []

    assert len(definitions) >= 2
    names = [d.get("name", "") for d in definitions]
    assert "Definition 0" in names
    assert "Definition 1" in names


@pytest.mark.asyncio
async def test_delete_definition(client):
    """
    DELETE /api/v1/customclaw/definitions/{id} should remove the definition
    so it no longer appears in the list.
    """
    # Create a definition to delete
    create_resp = await client.post(BASE, json=_sample_definition(name="To Be Deleted"))
    assert create_resp.status_code in (200, 201), create_resp.text
    def_id = create_resp.json()["id"]

    # Delete it
    del_resp = await client.delete(f"{BASE}/{def_id}")
    assert del_resp.status_code in (200, 204), del_resp.text

    # Confirm it's gone
    get_resp = await client.get(f"{BASE}/{def_id}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_create_definition_requires_name_and_base_url(client):
    """
    POST /api/v1/customclaw/definitions without required fields should fail.
    """
    resp = await client.post(BASE, json={"description": "missing required fields"})
    # Should return a 4xx validation error
    assert resp.status_code >= 400


@pytest.mark.asyncio
async def test_get_definition_not_found(client):
    """GET /api/v1/customclaw/definitions/{id} with unknown ID should 404."""
    resp = await client.get(f"{BASE}/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
