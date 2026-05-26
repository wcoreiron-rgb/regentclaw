"""Regent Fabric -> AGT adapter.

Keeps AGT wiring in one place so Claws do not import AGT directly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.trust_fabric.agt_bridge import (
    AGT_AVAILABLE,
    agt_status,
    scan_module_directory,
    scan_package_json,
    scan_requirements,
)
from app.fabric.providers.agt.version import AGTVersionInfo


@dataclass(frozen=True)
class AGTFeatureFlags:
    version_mode: str
    enable_agent_mesh: bool
    enable_e2e_messaging: bool
    enable_mcp_gateway: bool
    enable_shadow_discovery: bool


class AGTAdapter:
    def __init__(self) -> None:
        self.version = AGTVersionInfo(compatibility_mode=settings.AGT_VERSION_MODE)
        self.flags = AGTFeatureFlags(
            version_mode=settings.AGT_VERSION_MODE,
            enable_agent_mesh=settings.AGT_ENABLE_AGENT_MESH,
            enable_e2e_messaging=settings.AGT_ENABLE_E2E_MESSAGING,
            enable_mcp_gateway=settings.AGT_ENABLE_MCP_GATEWAY,
            enable_shadow_discovery=settings.AGT_ENABLE_SHADOW_DISCOVERY,
        )

    def status(self) -> dict[str, Any]:
        return {
            "provider": self.version.provider,
            "sdk_target": self.version.sdk_target,
            "agt_available": AGT_AVAILABLE,
            "features": asdict(self.flags),
            "bridge": agt_status(),
        }

    def scan_backend_deps(self, requirements_path: str) -> dict[str, Any]:
        result = scan_requirements(requirements_path)
        return asdict(result)

    def scan_frontend_deps(self, package_json_path: str) -> dict[str, Any]:
        result = scan_package_json(package_json_path)
        return asdict(result)

    def scan_path(self, path: str) -> dict[str, Any]:
        result = scan_module_directory(path)
        payload = asdict(result)
        payload["path"] = str(Path(path).resolve())
        return payload


_adapter: AGTAdapter | None = None


def get_agt_adapter() -> AGTAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AGTAdapter()
    return _adapter

