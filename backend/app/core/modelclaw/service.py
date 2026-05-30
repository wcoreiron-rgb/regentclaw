from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from app.core.modelclaw.schemas import ModelProfileCreate

_PROVIDERS: dict[str, dict[str, Any]] = {
    "nvidia_nim": {"enabled": True, "default_model": "meta/llama-3.3-70b-instruct", "supports_tool_calling": True},
    "ollama": {"enabled": True, "default_model": "qwen2.5:14b-instruct", "supports_tool_calling": True},
    "azure_openai": {"enabled": True, "default_model": "gpt-4o-mini", "supports_tool_calling": True},
    "openai": {"enabled": True, "default_model": "gpt-4.1-mini", "supports_tool_calling": True},
    "anthropic": {"enabled": True, "default_model": "claude-3-5-sonnet", "supports_tool_calling": True},
    "gemini": {"enabled": False, "default_model": "gemini-2.5-pro", "supports_tool_calling": True},
    "vllm_local": {"enabled": False, "default_model": "local/default", "supports_tool_calling": False},
}

_PROFILES: dict[str, dict[str, Any]] = {
    "nim_fast_reasoning": {
        "name": "nim_fast_reasoning",
        "provider": "nvidia_nim",
        "model": "meta/llama-3.3-70b-instruct",
        "allowed_claws": ["threatclaw", "identityclaw", "cloudclaw", "arcclaw"],
        "allowed_data_classes": ["public", "internal", "confidential"],
        "temperature": 0.2,
        "max_tokens": 4000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": "ollama_local_fallback",
        "created_at": datetime.utcnow(),
    },
    "ollama_local_fallback": {
        "name": "ollama_local_fallback",
        "provider": "ollama",
        "model": "qwen2.5:14b-instruct",
        "allowed_claws": ["arcclaw", "threatclaw"],
        "allowed_data_classes": ["public", "internal"],
        "temperature": 0.2,
        "max_tokens": 3000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": None,
        "created_at": datetime.utcnow(),
    },
}

_MODEL_CALLS: list[dict[str, Any]] = []


def list_providers() -> list[dict[str, Any]]:
    return [{"provider": k, **v} for k, v in sorted(_PROVIDERS.items())]


def list_profiles() -> list[dict[str, Any]]:
    return list(_PROFILES.values())


def get_profile(name: str | None) -> dict[str, Any] | None:
    if not name:
        return _PROFILES.get("nim_fast_reasoning")
    return _PROFILES.get(name)


def upsert_profile(payload: ModelProfileCreate) -> dict[str, Any]:
    row = payload.model_dump()
    row["created_at"] = datetime.utcnow()
    _PROFILES[payload.name] = row
    return row


def record_model_call(row: dict[str, Any]) -> dict[str, Any]:
    entry = {"id": f"mc_{uuid4().hex[:12]}", "timestamp": datetime.utcnow(), **row}
    _MODEL_CALLS.insert(0, entry)
    if len(_MODEL_CALLS) > 500:
        del _MODEL_CALLS[500:]
    return entry


def list_model_calls(limit: int = 50) -> list[dict[str, Any]]:
    return _MODEL_CALLS[: max(1, min(limit, 500))]
