"""
CoreOS — Policy Engine
Centralized policy definitions enforced cross-module.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Enum as SAEnum, Integer, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class PolicyAction(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    MONITOR = "monitor"
    ISOLATE = "isolate"


class PolicyScope(str, enum.Enum):
    GLOBAL = "global"
    MODULE = "module"
    CONNECTOR = "connector"
    IDENTITY = "identity"


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # Lower = higher priority

    # Scope
    scope: Mapped[PolicyScope] = mapped_column(SAEnum(PolicyScope), default=PolicyScope.GLOBAL)
    scope_target: Mapped[str | None] = mapped_column(String(256), nullable=True)  # module name, etc.

    # Condition (JSON)
    condition_json: Mapped[str] = mapped_column(Text, nullable=False)  # e.g., {"field":"tool_name","op":"in","value":["delete_file"]}

    # Action
    action: Mapped[PolicyAction] = mapped_column(SAEnum(PolicyAction), nullable=False)

    # Metadata
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
