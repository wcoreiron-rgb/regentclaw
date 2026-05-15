"""
RegentClaw CLI — HTTP client
All API calls go through here. Reads REGENTCLAW_API_URL from env (default: localhost:8000).
"""
import os
import json
import sys
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

BASE_URL = os.environ.get("REGENTCLAW_API_URL", "http://localhost:8000").rstrip("/")
PREFIX = "/api/v1"


def _client() -> "httpx.Client":
    if httpx is None:
        print("Error: httpx is not installed. Run: pip install httpx")
        sys.exit(1)
    timeout = float(os.environ.get("REGENTCLAW_TIMEOUT", "30"))
    return httpx.Client(base_url=BASE_URL, timeout=timeout)


def get(path: str, params: dict | None = None) -> Any:
    with _client() as c:
        r = c.get(PREFIX + path, params=params)
        r.raise_for_status()
        return r.json()


def post(path: str, body: dict | None = None) -> Any:
    with _client() as c:
        r = c.post(PREFIX + path, json=body or {})
        r.raise_for_status()
        return r.json()


def patch(path: str, body: dict) -> Any:
    with _client() as c:
        r = c.patch(PREFIX + path, json=body)
        r.raise_for_status()
        return r.json()


def delete(path: str) -> Any:
    with _client() as c:
        r = c.delete(PREFIX + path)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {}
