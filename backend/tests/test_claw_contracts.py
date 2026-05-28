import pytest


@pytest.mark.asyncio
async def test_arcclaw_contract_endpoints(client):
    stats = await client.get("/api/v1/arcclaw/stats")
    assert stats.status_code == 200, stats.text

    findings = await client.get("/api/v1/arcclaw/findings")
    assert findings.status_code == 200, findings.text
    assert isinstance(findings.json(), list)

    providers = await client.get("/api/v1/arcclaw/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)


@pytest.mark.asyncio
async def test_identityclaw_contract_endpoints(client):
    stats = await client.get("/api/v1/identityclaw/stats")
    assert stats.status_code == 200, stats.text

    findings = await client.get("/api/v1/identityclaw/findings")
    assert findings.status_code == 200, findings.text
    assert isinstance(findings.json(), list)

    providers = await client.get("/api/v1/identityclaw/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)
