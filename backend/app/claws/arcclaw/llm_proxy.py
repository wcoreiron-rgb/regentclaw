"""
ArcClaw — LLM Proxy Service
==============================
ArcClaw sits between the user and the LLM.
Every prompt is inspected BEFORE it reaches the model.

Flow:
  User prompt
      ↓
  ArcClaw scan (patterns + AGT injection audit)
      ↓
  Trust Fabric policy check
      ↓
  BLOCKED  → return decision, never call LLM
  ALLOWED  → forward to LLM, return response
  REDACTED → strip secrets, forward clean version

Supported providers:
  - OpenAI  (GPT-4o, GPT-4, GPT-3.5)  → needs OPENAI_API_KEY
  - Anthropic (Claude)                  → needs ANTHROPIC_API_KEY
  - Ollama  (any local model)           → free, no key, runs locally
"""

from __future__ import annotations

import os
import json
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_BASE_URL   = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

TIMEOUT = 60.0  # seconds


# ── Response model ─────────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    provider: str
    model: str
    content: str
    tokens_used: int = 0
    error: Optional[str] = None
    success: bool = True


# ── OpenAI ────────────────────────────────────────────────────────────────────

async def call_openai(
    prompt: str,
    model: str = "gpt-4o-mini",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    resolved_key = api_key or OPENAI_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="openai", model=model, content="",
            error="OpenAI API key not configured. Add it via the Connector Marketplace or set OPENAI_API_KEY in backend/.env.",
            success=False,
        )

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {resolved_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
            return LLMResponse(provider="openai", model=model, content=choice, tokens_used=tokens)

        except httpx.HTTPStatusError as e:
            err = f"OpenAI API error {e.response.status_code}: {e.response.text[:200]}"
            logger.error(err)
            return LLMResponse(provider="openai", model=model, content="", error=err, success=False)
        except Exception as e:
            return LLMResponse(provider="openai", model=model, content="", error=str(e), success=False)


# ── Anthropic (Claude) ────────────────────────────────────────────────────────

async def call_anthropic(
    prompt: str,
    model: str = "claude-3-haiku-20240307",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    resolved_key = api_key or ANTHROPIC_API_KEY
    if not resolved_key:
        return LLMResponse(
            provider="anthropic", model=model, content="",
            error="Anthropic API key not configured. Add it via the Connector Marketplace or set ANTHROPIC_API_KEY in backend/.env.",
            success=False,
        )

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": resolved_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1024,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["content"][0]["text"]
            tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
            return LLMResponse(provider="anthropic", model=model, content=content, tokens_used=tokens)

        except httpx.HTTPStatusError as e:
            err = f"Anthropic API error {e.response.status_code}: {e.response.text[:200]}"
            logger.error(err)
            return LLMResponse(provider="anthropic", model=model, content="", error=err, success=False)
        except Exception as e:
            return LLMResponse(provider="anthropic", model=model, content="", error=str(e), success=False)


# ── Ollama (local — free, no API key) ────────────────────────────────────────

async def call_ollama(
    prompt: str,
    model: str = "llama3.2",
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,   # unused for Ollama — accepted for uniform signature
) -> LLMResponse:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            tokens = data.get("eval_count", 0)
            return LLMResponse(provider="ollama", model=model, content=content, tokens_used=tokens)

        except httpx.ConnectError:
            return LLMResponse(
                provider="ollama", model=model, content="",
                error=(
                    f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
                    "Install Ollama from https://ollama.com and run: ollama pull llama3.2"
                ),
                success=False,
            )
        except httpx.HTTPStatusError as e:
            # Model not found → suggest pull
            if e.response.status_code == 404:
                return LLMResponse(
                    provider="ollama", model=model, content="",
                    error=f"Model '{model}' not found. Run: ollama pull {model}",
                    success=False,
                )
            return LLMResponse(provider="ollama", model=model, content="", error=str(e), success=False)
        except Exception as e:
            return LLMResponse(provider="ollama", model=model, content="", error=str(e), success=False)


# ── Router ────────────────────────────────────────────────────────────────────

PROVIDER_MAP = {
    "openai":    call_openai,
    "anthropic": call_anthropic,
    "ollama":    call_ollama,
}

MODEL_DEFAULTS = {
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-3-haiku-20240307",
    "ollama":    "llama3.2",
}


async def call_llm(
    provider: str,
    prompt: str,
    model: Optional[str] = None,
    system: str = "You are a helpful assistant.",
    api_key: Optional[str] = None,
) -> LLMResponse:
    """Route a prompt to the specified LLM provider."""
    handler = PROVIDER_MAP.get(provider)
    if not handler:
        return LLMResponse(
            provider=provider, model=model or "unknown", content="",
            error=f"Unknown provider '{provider}'. Use: openai, anthropic, ollama",
            success=False,
        )
    resolved_model = model or MODEL_DEFAULTS.get(provider, "")
    return await handler(prompt, model=resolved_model, system=system, api_key=api_key)


async def fetch_ollama_models() -> tuple[list[str], bool]:
    """
    Query Ollama's /api/tags endpoint to get all locally installed models.
    Returns (model_list, is_reachable).
    Falls back to an empty list if Ollama isn't running.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            # Each entry has a "name" field like "llama3.2:latest"
            models = [m["name"] for m in data.get("models", [])]
            return (models if models else ["llama3.2"]), True
    except Exception:
        return [], False


async def available_providers(
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
) -> list[dict]:
    """
    Return which providers are configured and ready, with live Ollama model list.
    Accepts pre-resolved keys from the connector store so callers don't need to
    re-read the secrets file — env vars are always checked as a fallback.
    """
    ollama_models, ollama_reachable = await fetch_ollama_models()
    fallback_models = ["llama3.2", "llama3.1", "mistral", "phi3", "gemma2"]

    has_openai    = bool(openai_key    or OPENAI_API_KEY)
    has_anthropic = bool(anthropic_key or ANTHROPIC_API_KEY)

    return [
        {
            "provider": "openai",
            "label": "OpenAI (GPT-4o)",
            "models": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "ready": has_openai,
            "setup": (
                "Connected via Connector Marketplace" if has_openai
                else "Add your OpenAI API key via Connector Marketplace → OpenAI API"
            ),
            "cost": "paid",
        },
        {
            "provider": "anthropic",
            "label": "Anthropic (Claude)",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229"],
            "ready": has_anthropic,
            "setup": (
                "Connected via Connector Marketplace" if has_anthropic
                else "Add your Anthropic API key via Connector Marketplace → Anthropic Claude"
            ),
            "cost": "paid",
        },
        {
            "provider": "ollama",
            "label": "Ollama (Local — Free)",
            "models": ollama_models if ollama_reachable else fallback_models,
            "ready": ollama_reachable,
            "setup": (
                "Ollama is running — models listed above are installed on your machine."
                if ollama_reachable
                else "Install from https://ollama.com then run: ollama pull llama3.2"
            ),
            "cost": "free",
        },
    ]
