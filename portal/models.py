from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

db = SQLAlchemy()

ROLES = ("admin", "operator", "user")
ACTIVE_VM_STATUSES = ("queued", "provisioning", "accepted", "running", "stopped")


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


class ImageProfile(db.Model):
    __tablename__ = "image_profiles"
    __table_args__ = (
        CheckConstraint(
            "(source_type = 'iso' AND iso IS NOT NULL AND template_node IS NULL "
            "AND template_vmid IS NULL) OR (source_type = 'cloud_init' AND "
            "iso IS NULL AND template_node IS NOT NULL AND template_vmid IS NOT NULL)",
            name="ck_image_profiles_source",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(db.String(63), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(db.String(100), nullable=False)
    description: Mapped[str] = mapped_column(db.String(500), nullable=False, default="")
    source_type: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="iso"
    )
    iso: Mapped[str | None] = mapped_column(db.String(255))
    template_node: Mapped[str | None] = mapped_column(db.String(63))
    template_vmid: Mapped[int | None] = mapped_column()
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    def public_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "label": self.label,
            "description": self.description,
            "source_type": self.source_type,
            "iso": self.iso,
            "template_node": self.template_node,
            "template_vmid": self.template_vmid,
            "enabled": self.enabled,
            "automatic_guest_access": self.source_type == "cloud_init",
        }


class VMAllocation(db.Model):
    __tablename__ = "vm_allocations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'provisioning', 'accepted', 'running', 'stopped', 'failed', 'deleted')",
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
    profile_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("image_profiles.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(db.String(63), nullable=False)
    node: Mapped[str] = mapped_column(db.String(63), nullable=False)
    iso: Mapped[str | None] = mapped_column(db.String(255))
    vmid: Mapped[int | None] = mapped_column()
    guest_username: Mapped[str | None] = mapped_column(db.String(32))
    credential_url: Mapped[str | None] = mapped_column(db.String(1024))
    credential_created_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    credential_expire_days: Mapped[int | None] = mapped_column()
    credential_expire_views: Mapped[int | None] = mapped_column()
    cpu: Mapped[int] = mapped_column(nullable=False)
    ram_mb: Mapped[int] = mapped_column(nullable=False)
    disk_gb: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(db.String(16), nullable=False, default="queued")
    upstream_request_id: Mapped[str | None] = mapped_column(db.String(255))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    owner: Mapped[User] = relationship(back_populates="allocations")
    profile: Mapped[ImageProfile | None] = relationship()
    job: Mapped[ProvisioningJob | None] = relationship(
        back_populates="allocation", uselist=False
    )
    operations: Mapped[list[VMOperation]] = relationship(
        back_populates="allocation",
        cascade="all, delete-orphan",
        order_by="VMOperation.created_at",
    )


class ProvisioningJob(db.Model):
    __tablename__ = "provisioning_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'validating', 'submitting', 'submitted', 'polling', 'succeeded', 'failed', 'attention')",
            name="ck_provisioning_jobs_status",
        ),
        CheckConstraint(
            "stage IN ('create', 'start')", name="ck_provisioning_jobs_stage"
        ),
        Index("ix_provisioning_jobs_status_available", "status", "available_at"),
    )

    id: Mapped[str] = mapped_column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    allocation_id: Mapped[str] = mapped_column(
        db.ForeignKey("vm_allocations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(db.String(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    stage: Mapped[str] = mapped_column(db.String(16), nullable=False, default="create")
    upstream_node: Mapped[str | None] = mapped_column(db.String(63))
    credential_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    locked_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    locked_by: Mapped[str | None] = mapped_column(db.String(128))
    error_code: Mapped[str | None] = mapped_column(db.String(80))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))

    allocation: Mapped[VMAllocation] = relationship(back_populates="job")

    def public_dict(self, *, include_credentials: bool = False) -> dict[str, Any]:
        latest_operation = (
            self.allocation.operations[-1] if self.allocation.operations else None
        )
        result: dict[str, Any] = {
            "id": self.id,
            "vm_id": self.allocation_id,
            "status": self.status,
            "stage": self.stage,
            "error_code": self.error_code,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "vm": {
                "name": self.allocation.name,
                "node": self.allocation.node,
                "vmid": self.allocation.vmid,
                "profile": self.allocation.profile.slug
                if self.allocation.profile is not None
                else None,
                "cpu": self.allocation.cpu,
                "ram_mb": self.allocation.ram_mb,
                "disk_gb": self.allocation.disk_gb,
                "guest_username": self.allocation.guest_username,
                "status": self.allocation.status,
            },
        }
        if latest_operation is not None:
            result["operation"] = latest_operation.public_dict()
        if include_credentials and self.allocation.credential_url:
            result["guest_access"] = {
                "username": self.allocation.guest_username,
                "password_url": self.allocation.credential_url,
                "expire_after_days": self.allocation.credential_expire_days,
                "expire_after_views": self.allocation.credential_expire_views,
            }
        return result


class VMOperation(db.Model):
    __tablename__ = "vm_operations"
    __table_args__ = (
        CheckConstraint(
            "action IN ('start', 'stop', 'reboot', 'delete')",
            name="ck_vm_operations_action",
        ),
        CheckConstraint(
            "status IN ('queued', 'submitting', 'submitted', 'polling', "
            "'succeeded', 'failed', 'attention')",
            name="ck_vm_operations_status",
        ),
        Index("ix_vm_operations_status_available", "status", "available_at"),
        Index(
            "uq_vm_operations_active_allocation",
            "allocation_id",
            unique=True,
            postgresql_where=text(
                "status IN ('queued', 'submitting', 'submitted', 'polling')"
            ),
            sqlite_where=text(
                "status IN ('queued', 'submitting', 'submitted', 'polling')"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    allocation_id: Mapped[str] = mapped_column(
        db.ForeignKey("vm_allocations.id", ondelete="CASCADE"), nullable=False
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(db.String(16), nullable=False)
    status: Mapped[str] = mapped_column(db.String(16), nullable=False, default="queued")
    upstream_node: Mapped[str | None] = mapped_column(db.String(63))
    upstream_request_id: Mapped[str | None] = mapped_column(db.String(255))
    available_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    locked_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    locked_by: Mapped[str | None] = mapped_column(db.String(128))
    error_code: Mapped[str | None] = mapped_column(db.String(80))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))

    allocation: Mapped[VMAllocation] = relationship(back_populates="operations")

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "error_code": self.error_code,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class WorkerHeartbeat(db.Model):
    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(db.String(128), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )


class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')",
            name="ck_audit_events_outcome",
        ),
        Index("ix_audit_events_created_at", "created_at"),
        Index(
            "ix_audit_events_login_throttle",
            "action",
            "target_id",
            "outcome",
            "created_at",
        ),
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
