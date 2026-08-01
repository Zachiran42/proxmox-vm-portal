from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

db = SQLAlchemy()

ROLES = ("admin", "operator", "user")
ACTIVE_VM_STATUSES = ("provisioning", "accepted", "running")


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'operator', 'user')", name="ck_users_role"),
        CheckConstraint("quota_vms >= 0", name="ck_users_quota_vms"),
        CheckConstraint("quota_cpu >= 0", name="ck_users_quota_cpu"),
        CheckConstraint("quota_ram_mb >= 0", name="ck_users_quota_ram"),
        CheckConstraint("quota_disk_gb >= 0", name="ck_users_quota_disk"),
        CheckConstraint(
            "auth_provider IN ('local', 'oidc')", name="ck_users_auth_provider"
        ),
        CheckConstraint(
            "(auth_provider = 'local' AND password_hash IS NOT NULL "
            "AND external_issuer IS NULL AND external_subject IS NULL) OR "
            "(auth_provider = 'oidc' AND password_hash IS NULL "
            "AND external_issuer IS NOT NULL AND external_subject IS NOT NULL)",
            name="ck_users_auth_identity",
        ),
        UniqueConstraint(
            "external_issuer", "external_subject", name="uq_users_external_identity"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(db.String(128), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(db.String(512))
    auth_provider: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="local"
    )
    external_issuer: Mapped[str | None] = mapped_column(db.String(255))
    external_subject: Mapped[str | None] = mapped_column(db.String(255))
    role: Mapped[str] = mapped_column(db.String(16), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    quota_vms: Mapped[int] = mapped_column(nullable=False, default=3)
    quota_cpu: Mapped[int] = mapped_column(nullable=False, default=8)
    quota_ram_mb: Mapped[int] = mapped_column(nullable=False, default=16384)
    quota_disk_gb: Mapped[int] = mapped_column(nullable=False, default=200)
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    allocations: Mapped[list[VMAllocation]] = relationship(back_populates="owner")

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "authentication": self.auth_provider,
            "is_active": self.is_active,
            "quota": {
                "vms": self.quota_vms,
                "cpu": self.quota_cpu,
                "ram_mb": self.quota_ram_mb,
                "disk_gb": self.quota_disk_gb,
            },
        }


class VMAllocation(db.Model):
    __tablename__ = "vm_allocations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('provisioning', 'accepted', 'running', 'failed', 'deleted')",
            name="ck_vm_allocations_status",
        ),
        UniqueConstraint("owner_id", "name", name="uq_vm_allocations_owner_name"),
        Index("ix_vm_allocations_owner_status", "owner_id", "status"),
    )

    id: Mapped[str] = mapped_column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    owner_id: Mapped[int] = mapped_column(
        db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(db.String(63), nullable=False)
    node: Mapped[str] = mapped_column(db.String(63), nullable=False)
    iso: Mapped[str] = mapped_column(db.String(255), nullable=False)
    cpu: Mapped[int] = mapped_column(nullable=False)
    ram_mb: Mapped[int] = mapped_column(nullable=False)
    disk_gb: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="provisioning"
    )
    upstream_request_id: Mapped[str | None] = mapped_column(db.String(255))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    owner: Mapped[User] = relationship(back_populates="allocations")


class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')",
            name="ck_audit_events_outcome",
        ),
        Index("ix_audit_events_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(db.String(80), nullable=False)
    target_type: Mapped[str] = mapped_column(db.String(40), nullable=False)
    target_id: Mapped[str | None] = mapped_column(db.String(255))
    outcome: Mapped[str] = mapped_column(db.String(16), nullable=False)
    request_id: Mapped[str] = mapped_column(db.String(36), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(db.JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "actor_user_id": self.actor_user_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }
