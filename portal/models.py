from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

db = SQLAlchemy()

ROLES = ("admin", "operator", "user")
ACTIVE_VM_STATUSES = (
    "pending_approval",
    "queued",
    "provisioning",
    "accepted",
    "running",
    "stopped",
)


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
            "auth_provider IN ('local', 'oidc', 'ldap')",
            name="ck_users_auth_provider",
        ),
        CheckConstraint(
            "(auth_provider = 'local' AND password_hash IS NOT NULL "
            "AND external_issuer IS NULL AND external_subject IS NULL) OR "
            "(auth_provider IN ('oidc', 'ldap') AND password_hash IS NULL "
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
    must_change_password: Mapped[bool] = mapped_column(nullable=False, default=False)
    quota_vms: Mapped[int] = mapped_column(nullable=False, default=3)
    quota_cpu: Mapped[int] = mapped_column(nullable=False, default=8)
    quota_ram_mb: Mapped[int] = mapped_column(nullable=False, default=16384)
    quota_disk_gb: Mapped[int] = mapped_column(nullable=False, default=200)
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )

    allocations: Mapped[list[VMAllocation]] = relationship(
        back_populates="owner", foreign_keys="VMAllocation.owner_id"
    )
    notifications: Mapped[list[UserNotification]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "authentication": self.auth_provider,
            "is_active": self.is_active,
            "must_rotate_credentials": self.must_change_password,
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
        CheckConstraint(
            "lifecycle_status IN ('active', 'deprecated', 'retired')",
            name="ck_image_profiles_lifecycle_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(db.String(63), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(db.String(100), nullable=False)
    description: Mapped[str] = mapped_column(db.String(500), nullable=False, default="")
    version: Mapped[str] = mapped_column(db.String(64), nullable=False, default="1.0.0")
    lifecycle_status: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="active"
    )
    supported_until: Mapped[date | None] = mapped_column(db.Date())
    replacement_slug: Mapped[str | None] = mapped_column(db.String(63))
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
            "version": self.version,
            "lifecycle_status": self.lifecycle_status,
            "supported_until": self.supported_until.isoformat()
            if self.supported_until is not None
            else None,
            "replacement_slug": self.replacement_slug,
            "source_type": self.source_type,
            "iso": self.iso,
            "template_node": self.template_node,
            "template_vmid": self.template_vmid,
            "enabled": self.enabled,
            "automatic_guest_access": self.source_type == "cloud_init",
        }


class NetworkProfile(db.Model):
    __tablename__ = "network_profiles"
    __table_args__ = (
        CheckConstraint("vlan_tag IS NULL OR (vlan_tag >= 1 AND vlan_tag <= 4094)", name="ck_network_profiles_vlan_tag"),
        CheckConstraint("netbox_prefix_id IS NULL OR netbox_prefix_id > 0", name="ck_network_profiles_netbox_prefix"),
        CheckConstraint(
            "allow_manual_ip = true OR allow_automatic_ip = true",
            name="ck_network_profiles_ip_assignment",
        ),
        CheckConstraint(
            "connectivity_mode IN ('sandbox', 'isolated', 'internal', 'internet', 'ticket_required')",
            name="ck_network_profiles_connectivity_mode",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(db.String(63), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(db.String(100), nullable=False)
    cidr: Mapped[str] = mapped_column(db.String(18), nullable=False)
    gateway: Mapped[str] = mapped_column(db.String(15), nullable=False)
    dns_servers: Mapped[str] = mapped_column(db.String(64), nullable=False)
    bridge: Mapped[str] = mapped_column(db.String(32), nullable=False, default="vmbr0")
    vlan_tag: Mapped[int | None] = mapped_column()
    netbox_prefix_id: Mapped[int | None] = mapped_column()
    netbox_vrf_id: Mapped[int | None] = mapped_column()
    pool_start: Mapped[str | None] = mapped_column(db.String(15))
    pool_end: Mapped[str | None] = mapped_column(db.String(15))
    excluded_ips: Mapped[str] = mapped_column(db.String(1024), nullable=False, default="")
    allow_manual_ip: Mapped[bool] = mapped_column(nullable=False, default=True)
    allow_automatic_ip: Mapped[bool] = mapped_column(nullable=False, default=False)
    connectivity_mode: Mapped[str] = mapped_column(
        db.String(32), nullable=False, default="sandbox"
    )
    connectivity_description: Mapped[str] = mapped_column(
        db.String(300), nullable=False, default=""
    )
    sandbox_ssh_sources: Mapped[str] = mapped_column(db.Text, nullable=False, default="")
    sandbox_ntp_servers: Mapped[str] = mapped_column(db.String(512), nullable=False, default="")
    sandbox_apt_endpoints: Mapped[str] = mapped_column(db.String(512), nullable=False, default="")
    sandbox_registry_endpoints: Mapped[str] = mapped_column(db.String(512), nullable=False, default="")
    sandbox_monitoring_endpoints: Mapped[str] = mapped_column(db.String(512), nullable=False, default="")
    sandbox_policy_revision: Mapped[int] = mapped_column(nullable=False, default=1)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    allocations: Mapped[list[VMAllocation]] = relationship(back_populates="network_profile")

    def public_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "label": self.label,
            "cidr": self.cidr,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers.split(","),
            "bridge": self.bridge,
            "vlan_tag": self.vlan_tag,
            "netbox_managed": self.netbox_prefix_id is not None,
            "netbox_prefix_id": self.netbox_prefix_id,
            "netbox_vrf_id": self.netbox_vrf_id,
            "pool_start": self.pool_start,
            "pool_end": self.pool_end,
            "excluded_ips": [
                value for value in self.excluded_ips.split(",") if value
            ],
            "allow_manual_ip": self.allow_manual_ip,
            "allow_automatic_ip": self.allow_automatic_ip,
            "connectivity_mode": self.connectivity_mode,
            "connectivity_description": self.connectivity_description,
            "sandbox_ssh_sources": [value for value in self.sandbox_ssh_sources.split(",") if value],
            "sandbox_ntp_servers": [value for value in self.sandbox_ntp_servers.split(",") if value],
            "sandbox_apt_endpoints": [value for value in self.sandbox_apt_endpoints.split(",") if value],
            "sandbox_registry_endpoints": [value for value in self.sandbox_registry_endpoints.split(",") if value],
            "sandbox_monitoring_endpoints": [value for value in self.sandbox_monitoring_endpoints.split(",") if value],
            "sandbox_policy_revision": self.sandbox_policy_revision,
            "flow_request_required": self.connectivity_mode == "ticket_required",
            "initially_isolated": True,
            "enabled": self.enabled,
        }


class SoftwareModule(db.Model):
    __tablename__ = "software_modules"
    __table_args__ = (
        CheckConstraint(
            "install_mode IN ('preinstalled', 'apt', 'container')",
            name="ck_software_modules_install_mode",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(db.String(63), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(db.String(100), nullable=False)
    description: Mapped[str] = mapped_column(db.String(500), nullable=False, default="")
    install_mode: Mapped[str] = mapped_column(db.String(16), nullable=False)
    artifacts: Mapped[str] = mapped_column(db.Text, nullable=False, default="")
    required: Mapped[bool] = mapped_column(nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    def public_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "label": self.label,
            "description": self.description,
            "install_mode": self.install_mode,
            "artifacts": [value for value in self.artifacts.split("\n") if value],
            "required": self.required,
            "enabled": self.enabled,
        }


class NetBoxConfiguration(db.Model):
    __tablename__ = "netbox_configuration"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_netbox_configuration_singleton"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    base_url: Mapped[str] = mapped_column(db.String(512), nullable=False)
    api_token_ciphertext: Mapped[str] = mapped_column(db.Text, nullable=False)
    ca_certificate: Mapped[str | None] = mapped_column(db.Text)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    updated_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ProxmoxConfiguration(db.Model):
    __tablename__ = "proxmox_configuration"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_proxmox_configuration_singleton"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    api_url: Mapped[str] = mapped_column(db.String(512), nullable=False)
    token_id: Mapped[str] = mapped_column(db.String(255), nullable=False)
    token_secret_ciphertext: Mapped[str] = mapped_column(db.Text, nullable=False)
    ca_certificate: Mapped[str | None] = mapped_column(db.Text)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    updated_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class SiemConfiguration(db.Model):
    __tablename__ = "siem_configuration"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_siem_configuration_singleton"),
        CheckConstraint(
            "minimum_outcome IN ('all', 'failure', 'denied')",
            name="ck_siem_configuration_minimum_outcome",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    pull_token_ciphertext: Mapped[str] = mapped_column(db.Text, nullable=False)
    minimum_outcome: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="all"
    )
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    updated_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class VMAllocation(db.Model):
    __tablename__ = "vm_allocations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_approval', 'queued', 'provisioning', 'accepted', "
            "'running', 'stopped', 'rejected', 'failed', 'deleted')",
            name="ck_vm_allocations_status",
        ),
        CheckConstraint(
            "approval_status IN ('not_required', 'pending', 'approved', 'rejected')",
            name="ck_vm_allocations_approval_status",
        ),
        CheckConstraint(
            "network_mode IN ('dhcp', 'static')",
            name="ck_vm_allocations_network_mode",
        ),
        CheckConstraint(
            "network_policy IN ('normal', 'sandbox', 'isolated')",
            name="ck_vm_allocations_network_policy",
        ),
        CheckConstraint(
            "sandbox_release_status IN ('not_requested', 'pending', 'approved', 'rejected')",
            name="ck_vm_allocations_sandbox_release_status",
        ),
        CheckConstraint(
            "usage_purpose IN ('technical_test', 'functional_test', 'training', 'security_test')",
            name="ck_vm_allocations_usage_purpose",
        ),
        CheckConstraint(
            "(network_mode = 'dhcp' AND ipv4_cidr IS NULL AND gateway IS NULL "
            "AND dns_servers IS NULL) OR "
            "(network_mode = 'static' AND ipv4_cidr IS NOT NULL "
            "AND gateway IS NOT NULL AND dns_servers IS NOT NULL)",
            name="ck_vm_allocations_network_fields",
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
    network_profile_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("network_profiles.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(db.String(63), nullable=False)
    image_profile_slug: Mapped[str | None] = mapped_column(db.String(63))
    image_version: Mapped[str | None] = mapped_column(db.String(64))
    usage_purpose: Mapped[str] = mapped_column(
        db.String(32), nullable=False, default="technical_test"
    )
    data_policy_version: Mapped[str] = mapped_column(
        db.String(40), nullable=False, default="no-real-patient-data-v1"
    )
    data_policy_acknowledged_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    node: Mapped[str] = mapped_column(db.String(63), nullable=False)
    iso: Mapped[str | None] = mapped_column(db.String(255))
    vmid: Mapped[int | None] = mapped_column()
    guest_username: Mapped[str | None] = mapped_column(db.String(32))
    network_mode: Mapped[str] = mapped_column(
        db.String(8), nullable=False, default="dhcp"
    )
    automatic_ip: Mapped[bool] = mapped_column(nullable=False, default=False)
    ipv4_cidr: Mapped[str | None] = mapped_column(db.String(18))
    gateway: Mapped[str | None] = mapped_column(db.String(15))
    dns_servers: Mapped[str | None] = mapped_column(db.String(64))
    network_bridge: Mapped[str | None] = mapped_column(db.String(32))
    vlan_tag: Mapped[int | None] = mapped_column()
    network_policy: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="sandbox"
    )
    network_policy_revision: Mapped[int | None] = mapped_column()
    network_policy_updated_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    sandbox_release_status: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="not_requested"
    )
    sandbox_release_requested_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    sandbox_release_decided_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    sandbox_release_decided_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    sandbox_release_reason: Mapped[str | None] = mapped_column(db.String(500))
    sandbox_release_ticket: Mapped[str | None] = mapped_column(db.String(100))
    sandbox_release_duration_hours: Mapped[int | None] = mapped_column()
    sandbox_release_expires_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    software_modules: Mapped[list[str]] = mapped_column(db.JSON, nullable=False, default=list)
    netbox_ip_id: Mapped[int | None] = mapped_column()
    netbox_prefix_id: Mapped[int | None] = mapped_column()
    netbox_vrf_id: Mapped[int | None] = mapped_column()
    credential_url: Mapped[str | None] = mapped_column(db.String(1024))
    credential_created_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    credential_expire_days: Mapped[int | None] = mapped_column()
    credential_expire_views: Mapped[int | None] = mapped_column()
    last_ipv4: Mapped[str | None] = mapped_column(db.String(15))
    network_observed_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    guest_password_reset_requested_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    archived_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    lifecycle_quarantined_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    lifecycle_delete_after: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    lifecycle_enforcement_error: Mapped[str | None] = mapped_column(
        db.String(80)
    )
    approval_status: Mapped[str] = mapped_column(
        db.String(16), nullable=False, default="not_required"
    )
    approval_requested_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    approval_decided_at: Mapped[datetime | None] = mapped_column(
        db.DateTime(timezone=True)
    )
    approval_decided_by_id: Mapped[int | None] = mapped_column(
        db.ForeignKey("users.id", ondelete="SET NULL")
    )
    approval_reason: Mapped[str | None] = mapped_column(db.String(500))
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

    owner: Mapped[User] = relationship(
        back_populates="allocations", foreign_keys=[owner_id]
    )
    approval_decided_by: Mapped[User | None] = relationship(
        foreign_keys=[approval_decided_by_id]
    )
    profile: Mapped[ImageProfile | None] = relationship()
    network_profile: Mapped[NetworkProfile | None] = relationship(back_populates="allocations")
    job: Mapped[ProvisioningJob | None] = relationship(
        back_populates="allocation", uselist=False
    )
    operations: Mapped[list[VMOperation]] = relationship(
        back_populates="allocation",
        cascade="all, delete-orphan",
        order_by="VMOperation.created_at",
    )
    maintenance_jobs: Mapped[list[VMMaintenanceJob]] = relationship(
        back_populates="allocation",
        cascade="all, delete-orphan",
        order_by="VMMaintenanceJob.created_at",
    )

    def lifecycle_dict(
        self, *, warning_days: int = 14, now: datetime | None = None
    ) -> dict[str, Any]:
        if self.expires_at is None:
            return {"state": "unmanaged", "expires_at": None, "days_remaining": None}
        current = now or datetime.now(UTC)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        seconds_remaining = (expires_at - current).total_seconds()
        days_remaining = max(0, int((seconds_remaining + 86399) // 86400))
        if seconds_remaining <= 0:
            state = "expired"
        elif seconds_remaining <= warning_days * 86400:
            state = "warning"
        else:
            state = "active"
        return {
            "state": state,
            "expires_at": expires_at.isoformat(),
            "days_remaining": days_remaining,
            "quarantined_at": (
                self.lifecycle_quarantined_at.isoformat()
                if self.lifecycle_quarantined_at is not None
                else None
            ),
            "delete_after": (
                self.lifecycle_delete_after.isoformat()
                if self.lifecycle_delete_after is not None
                else None
            ),
            "enforcement_error": self.lifecycle_enforcement_error,
        }

    def image_lifecycle_dict(self, *, today: date | None = None) -> dict[str, Any]:
        current_date = today or datetime.now(UTC).date()
        profile = self.profile
        if self.image_profile_slug is None or self.image_version is None:
            return {
                "state": "legacy",
                "profile_slug": self.image_profile_slug,
                "version": self.image_version,
                "current_version": profile.version if profile is not None else None,
                "supported_until": None,
                "replacement_slug": None,
            }
        if profile is None:
            state = "profile_removed"
        elif profile.lifecycle_status == "retired":
            state = "retired"
        elif profile.supported_until is not None and profile.supported_until < current_date:
            state = "unsupported"
        elif profile.lifecycle_status == "deprecated":
            state = "deprecated"
        elif profile.version != self.image_version:
            state = "superseded"
        else:
            state = "supported"
        return {
            "state": state,
            "profile_slug": self.image_profile_slug,
            "version": self.image_version,
            "current_version": profile.version if profile is not None else None,
            "supported_until": (
                profile.supported_until.isoformat()
                if profile is not None and profile.supported_until is not None
                else None
            ),
            "replacement_slug": profile.replacement_slug if profile is not None else None,
        }


class ProvisioningJob(db.Model):
    __tablename__ = "provisioning_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('approval_pending', 'queued', 'validating', 'submitting', "
            "'submitted', 'polling', 'succeeded', 'failed', 'attention')",
            name="ck_provisioning_jobs_status",
        ),
        CheckConstraint(
            "stage IN ('create', 'start', 'modules')", name="ck_provisioning_jobs_stage"
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
    module_attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    guest_pid: Mapped[int | None] = mapped_column()
    guest_password_ciphertext: Mapped[str | None] = mapped_column(db.Text())
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

    def public_dict(
        self, *, include_credentials: bool = False, expiration_warning_days: int = 14
    ) -> dict[str, Any]:
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
            "archived_at": self.allocation.archived_at.isoformat()
            if self.allocation.archived_at is not None
            else None,
            "vm": {
                "name": self.allocation.name,
                "node": self.allocation.node,
                "vmid": self.allocation.vmid,
                "profile": self.allocation.profile.slug
                if self.allocation.profile is not None
                else None,
                "image_lifecycle": self.allocation.image_lifecycle_dict(),
                "cpu": self.allocation.cpu,
                "ram_mb": self.allocation.ram_mb,
                "disk_gb": self.allocation.disk_gb,
                "guest_username": self.allocation.guest_username,
                "network_mode": self.allocation.network_mode,
                "automatic_ip": self.allocation.automatic_ip,
                "network_profile": self.allocation.network_profile.slug
                if self.allocation.network_profile is not None
                else None,
                "network_policy": self.allocation.network_policy,
                "network_policy_revision": self.allocation.network_policy_revision,
                "sandbox_release": {
                    "status": self.allocation.sandbox_release_status,
                    "requested_at": (
                        self.allocation.sandbox_release_requested_at.isoformat()
                        if self.allocation.sandbox_release_requested_at is not None
                        else None
                    ),
                    "reason": self.allocation.sandbox_release_reason,
                    "ticket_reference": self.allocation.sandbox_release_ticket,
                    "duration_hours": self.allocation.sandbox_release_duration_hours,
                    "expires_at": (
                        self.allocation.sandbox_release_expires_at.isoformat()
                        if self.allocation.sandbox_release_expires_at is not None
                        else None
                    ),
                },
                "software_modules": list(self.allocation.software_modules or []),
                "usage_purpose": self.allocation.usage_purpose,
                "data_policy": {
                    "version": self.allocation.data_policy_version,
                    "acknowledged_at": (
                        self.allocation.data_policy_acknowledged_at.isoformat()
                        if self.allocation.data_policy_acknowledged_at is not None
                        else None
                    ),
                },
                "ipv4_cidr": self.allocation.ipv4_cidr,
                "gateway": self.allocation.gateway,
                "dns_servers": self.allocation.dns_servers.split(",")
                if self.allocation.dns_servers
                else [],
                "last_ipv4": self.allocation.last_ipv4,
                "network_observed_at": self.allocation.network_observed_at.isoformat()
                if self.allocation.network_observed_at is not None
                else None,
                "status": self.allocation.status,
                "approval": {
                    "status": self.allocation.approval_status,
                    "requested_at": self.allocation.approval_requested_at.isoformat()
                    if self.allocation.approval_requested_at is not None
                    else None,
                    "decided_at": self.allocation.approval_decided_at.isoformat()
                    if self.allocation.approval_decided_at is not None
                    else None,
                    "reason": self.allocation.approval_reason,
                },
                "lifecycle": self.allocation.lifecycle_dict(
                    warning_days=expiration_warning_days
                ),
            },
        }
        if self.allocation.guest_password_reset_requested_at is not None:
            result["vm"]["ssh_password_change"] = {
                "requested": True,
                "requested_at": (
                    self.allocation.guest_password_reset_requested_at.isoformat()
                ),
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


class VMMaintenanceJob(db.Model):
    """Inventaire APT ou mise à jour lancée depuis l'administration."""

    __tablename__ = "vm_maintenance_jobs"
    __table_args__ = (
        CheckConstraint(
            "action IN ('scan', 'update')",
            name="ck_vm_maintenance_jobs_action",
        ),
        CheckConstraint(
            "status IN ('queued', 'submitting', 'submitted', 'succeeded', "
            "'failed', 'attention')",
            name="ck_vm_maintenance_jobs_status",
        ),
        Index(
            "ix_vm_maintenance_jobs_status_available",
            "status",
            "available_at",
        ),
        Index(
            "uq_vm_maintenance_jobs_active_allocation",
            "allocation_id",
            unique=True,
            postgresql_where=text(
                "status IN ('queued', 'submitting', 'submitted')"
            ),
            sqlite_where=text(
                "status IN ('queued', 'submitting', 'submitted')"
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
    guest_pid: Mapped[int | None] = mapped_column()
    report: Mapped[dict[str, Any] | None] = mapped_column(db.JSON())
    output_excerpt: Mapped[str | None] = mapped_column(db.Text())
    error_code: Mapped[str | None] = mapped_column(db.String(80))
    available_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    locked_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))
    locked_by: Mapped[str | None] = mapped_column(db.String(128))
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))

    allocation: Mapped[VMAllocation] = relationship(back_populates="maintenance_jobs")

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "report": self.report,
            "error_code": self.error_code,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at is not None
            else None,
        }


class WorkerHeartbeat(db.Model):
    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[str] = mapped_column(db.String(128), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )


class PortalSetting(db.Model):
    __tablename__ = "portal_settings"

    key: Mapped[str] = mapped_column(db.String(80), primary_key=True)
    value: Mapped[str] = mapped_column(db.String(512), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class UserNotification(db.Model):
    __tablename__ = "user_notifications"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('approval_requested', 'approval_approved', "
            "'approval_rejected', 'provisioning_succeeded', "
            "'provisioning_failed', 'provisioning_attention', "
            "'lifecycle_warning', 'lifecycle_expired', "
            "'lifecycle_quarantined', 'lifecycle_deletion_scheduled', "
            "'lifecycle_deleted', 'lifecycle_enforcement_failed', "
            "'guest_password_reset_requested', "
            "'guest_password_reset_completed', "
            "'sandbox_release_requested', 'sandbox_release_decided', "
            "'sandbox_release_expired')",
            name="ck_user_notifications_kind",
        ),
        UniqueConstraint(
            "user_id", "dedup_key", name="uq_user_notifications_user_dedup"
        ),
        Index(
            "ix_user_notifications_user_read_created",
            "user_id",
            "read_at",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[int] = mapped_column(
        db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(db.String(32), nullable=False)
    title: Mapped[str] = mapped_column(db.String(160), nullable=False)
    message: Mapped[str] = mapped_column(db.String(1000), nullable=False)
    target_type: Mapped[str | None] = mapped_column(db.String(32))
    target_id: Mapped[str | None] = mapped_column(db.String(64))
    dedup_key: Mapped[str] = mapped_column(db.String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    read_at: Mapped[datetime | None] = mapped_column(db.DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="notifications")

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "message": self.message,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "created_at": self.created_at.isoformat(),
            "read_at": self.read_at.isoformat() if self.read_at is not None else None,
        }


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
