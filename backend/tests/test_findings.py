"""
Tests for Finding endpoints and CloudClaw scan integration.

Endpoints under test:
  GET  /api/v1/findings                  — list findings (filterable)
  POST /api/v1/cloudclaw/scan            — trigger CloudClaw scan
  GET  /api/v1/findings?claw=cloudclaw   — filter findings by claw
"""
import pytest


FINDINGS_BASE  = "/api/v1/findings"
CLOUDCLAW_SCAN = "/api/v1/cloudclaw/scan"


@pytest.mark.asyncio
async def test_list_findings_empty(client):
    """GET /api/v1/findings on an empty DB should return an empty list."""
    resp = await client.get(FINDINGS_BASE)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # The endpoint may return a list or a dict with a 'findings' key
    if isinstance(data, list):
        assert data == []
    elif isinstance(data, dict):
        items = data.get("findings", data.get("items", data.get("results", [])))
        assert isinstance(items, list)
        assert len(items) == 0


@pytest.mark.asyncio
async def test_cloudclaw_scan_returns_findings(client):
    """
    POST /api/v1/cloudclaw/scan should trigger a scan and return a result dict.
    In the test environment no real connectors are configured so we accept
    a scan that returns 0 new findings — we just assert the response shape.
    """
    resp = await client.post(CLOUDCLAW_SCAN)
    # Scan may return 200 OK or 202 Accepted
    assert resp.status_code in (200, 201, 202), resp.text
    data = resp.json()
    # Should include some indication of scan results
    assert isinstance(data, dict), "Scan response should be a JSON object"
    # Accept any of these common response keys
    has_result_key = any(k in data for k in (
        "message", "findings", "total_created", "status",
        "scan_id", "results", "summary",
    ))
    assert has_result_key, f"Unexpected scan response shape: {data}"


@pytest.mark.asyncio
async def test_findings_by_claw(client):
    """GET /api/v1/findings?claw=cloudclaw should accept the filter without error."""
    resp = await client.get(FINDINGS_BASE, params={"claw": "cloudclaw"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    if isinstance(data, list):
        # Every returned finding should belong to cloudclaw
        for finding in data:
            if "claw" in finding:
                assert finding["claw"].lower() == "cloudclaw"
    elif isinstance(data, dict):
        items = data.get("findings", data.get("items", []))
        for finding in items:
            if "claw" in finding:
                assert finding["claw"].lower() == "cloudclaw"


@pytest.mark.asyncio
async def test_findings_filter_by_severity(client):
    """GET /api/v1/findings with severity filter should not error."""
    resp = await client.get(FINDINGS_BASE, params={"severity": "high"})
    assert resp.status_code == 200, resp.text
