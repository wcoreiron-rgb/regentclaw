"""Static AGT provider metadata and compatibility mode."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AGTVersionInfo:
    provider: str = "agt"
    sdk_target: str = "3.2.x"
    compatibility_mode: str = "v1_compat"

