"""
RegentClaw — Connector Test Service
=====================================
Tests real connectivity for each connector type.
Uses stored (decrypted) credentials to make a minimal API call.
Returns success/failure + a human-readable message.

Every test is read-only — no writes, no side effects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional
import httpx

logger = logging.getLogger(__name__)
TIMEOUT = 10.0


@dataclass
class TestResult:
    success: bool
    message: str
    detail: Optional[str] = None


# ── Per-connector test implementations ────────────────────────────────────────

async def _test_openai(creds: dict) -> TestResult:
    api_key = creds.get("api_key", "")
    if not api_key:
        return TestResult(False, "API key not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code == 200:
                models = resp.json().get("data", [])
                return TestResult(True, f"Connected — {len(models)} models available")
            elif resp.status_code == 401:
                return TestResult(False, "Invalid API key — check your OpenAI key")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.ConnectError:
            return TestResult(False, "Cannot reach api.openai.com — check network")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_anthropic(creds: dict) -> TestResult:
    api_key = creds.get("api_key", "")
    if not api_key:
        return TestResult(False, "API key not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            if resp.status_code == 200:
                return TestResult(True, "Connected — Anthropic API responding")
            elif resp.status_code == 401:
                return TestResult(False, "Invalid API key — check your Anthropic key")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.ConnectError:
            return TestResult(False, "Cannot reach api.anthropic.com — check network")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_ollama(creds: dict) -> TestResult:
    base_url = creds.get("base_url", "http://host.docker.internal:11434").rstrip("/")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                names = [m["name"] for m in models[:5]]
                return TestResult(True, f"Connected — {len(models)} models: {', '.join(names) or 'none pulled yet'}")
            else:
                return TestResult(False, f"Ollama responded HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(False, f"Cannot reach Ollama at {base_url} — is it running?")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_slack(creds: dict) -> TestResult:
    token = creds.get("bot_token", "")
    if not token:
        return TestResult(False, "Bot token not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            data = resp.json()
            if data.get("ok"):
                return TestResult(True, f"Connected as @{data.get('user', 'unknown')} in {data.get('team', 'unknown')}")
            else:
                return TestResult(False, f"Slack error: {data.get('error', 'unknown')}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_github(creds: dict) -> TestResult:
    token = creds.get("personal_access_token", "")
    if not token:
        return TestResult(False, "Personal access token not provided")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            )
            if resp.status_code == 200:
                user = resp.json()
                return TestResult(True, f"Connected as @{user.get('login')} — {user.get('public_repos', 0)} repos")
            elif resp.status_code == 401:
                return TestResult(False, "Invalid token — check your GitHub PAT")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_crowdstrike(creds: dict) -> TestResult:
    client_id     = creds.get("client_id", "")
    client_secret = creds.get("client_secret", "")
    if not client_id or not client_secret:
        return TestResult(False, "Client ID and Client Secret are required")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.crowdstrike.com/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
            )
            if resp.status_code == 201:
                return TestResult(True, "Connected — OAuth token obtained successfully")
            elif resp.status_code == 401:
                return TestResult(False, "Invalid credentials — check Client ID and Secret")
            else:
                return TestResult(False, f"HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            return TestResult(False, str(e))


async def _test_pagerduty(creds: dict) -> TestResult:
    routing_key = creds.get("routing_key", "")
    if not routing_key:
        return TestResult(False, "Routing key not provided")
    # PagerDuty doesn't have a ping endpoint — validate format
    if len(routing_key) < 20:
        return TestResult(False, "Routing key appears invalid (too short)")
    return TestResult(True, "Routing key format valid — send a test event to fully verify")


async def _test_generic(creds: dict, endpoint: str) -> TestResult:
    """Fallback: just check if the endpoint is reachable."""
    if not endpoint or not endpoint.startswith("http"):
        return TestResult(False, "No valid endpoint configured")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(endpoint)
            return TestResult(
                resp.status_code < 500,
                f"Endpoint reachable — HTTP {resp.status_code}",
            )
        except httpx.ConnectError:
            return TestResult(False, f"Cannot reach {endpoint}")
        except Exception as e:
            return TestResult(False, str(e))


# ── Router ─────────────────────────────────────────────────────────────────────

TEST_MAP = {
    "openai":      _test_openai,
    "anthropic":   _test_anthropic,
    "ollama":      _test_ollama,
    "slack":       _test_slack,
    "github":      _test_github,
    "crowdstrike": _test_crowdstrike,
    "pagerduty":   _test_pagerduty,
}


async def test_connector(connector_type: str, creds: dict, endpoint: str = "") -> TestResult:
    """Run the appropriate connectivity test for this connector type."""
    handler = TEST_MAP.get(connector_type)
    if handler:
        return await handler(creds)
    return await _test_generic(creds, endpoint)
