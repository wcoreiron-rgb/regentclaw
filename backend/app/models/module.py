"""
CoreOS — Module Registry
Every Claw module is a registered, governed entity with its own identity and scope.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Boolean, Text, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class ModuleStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    QUARANTINED = "quarantined"
    SUSPENDED = "suspended"


class Module(Base):
    __tablename__ = "modules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    status: Mapped[ModuleStatus] = mapped_column(SAEnum(ModuleStatus), default=ModuleStatus.ACTIVE)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Permissions the module has requested & been granted
    permissions: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON list

    # Owner identity
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # Module identity in the identity registry
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("identities.id"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    identity: Mapped["object"] = relationship("Identity", foreign_keys=[identity_id])
