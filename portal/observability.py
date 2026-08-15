from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from .models import (
    PortalSetting,
    ProvisioningJob,
    User,
    VMAllocation,
    VMOperation,
    WorkerHeartbeat,
    db,
)
from .pve import PVEHTTPError, PVEProtocolError, PVETransportError

PROVISIONING_STATUSES = (
    "queued",
    "validating",
    "submitting",
    "submitted",
    "polling",
    "succeeded",
    "failed",
    "attention",
)
OPERATION_STATUSES = (
    "queued",
    "submitting",
    "submitted",
    "polling",
    "succeeded",
    "failed",
    "attention",
)
ALLOCATION_STATUSES = (
    "queued",
    "provisioning",
    "accepted",
    "running",
    "stopped",
    "failed",
    "deleted",
)


def _labels(**labels: str) -> str:
    encoded = ",".join(
        f'{name}="{_label_escape(value)}"'
        for name, value in labels.items()
    )
    return "{" + encoded + "}"


def _label_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _counts(model: Any, field: Any) -> dict[str, int]:
    rows = db.session.execute(select(field, func.count(model.id)).group_by(field))
    return {str(status): int(count) for status, count in rows}


def render_prometheus_metrics(pve_client, *, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    lines = [
        "# HELP portal_up Portal process and database availability.",
        "# TYPE portal_up gauge",
        "portal_up 1",
    ]

    heartbeat = db.session.scalar(
        select(WorkerHeartbeat)
        .order_by(WorkerHeartbeat.last_seen_at.desc())
        .limit(1)
    )
    worker_age = -1
    if heartbeat is not None:
        last_seen = heartbeat.last_seen_at
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        worker_age = max(0, int((now - last_seen).total_seconds()))
    lines.extend(
        (
            "# HELP portal_worker_last_seen_seconds Seconds since the latest worker heartbeat; -1 means never seen.",
            "# TYPE portal_worker_last_seen_seconds gauge",
            f"portal_worker_last_seen_seconds {worker_age}",
        )
    )

    try:
        online_nodes = len(pve_client.list_nodes())
        pve_reachable = 1
    except (PVETransportError, PVEHTTPError, PVEProtocolError):
        online_nodes = 0
        pve_reachable = 0
    lines.extend(
        (
            "# HELP portal_proxmox_reachable Whether the Proxmox API inventory is reachable.",
            "# TYPE portal_proxmox_reachable gauge",
            f"portal_proxmox_reachable {pve_reachable}",
            "# HELP portal_proxmox_online_nodes Number of online Proxmox nodes.",
            "# TYPE portal_proxmox_online_nodes gauge",
            f"portal_proxmox_online_nodes {online_nodes}",
        )
    )

    provisioning = _counts(ProvisioningJob, ProvisioningJob.status)
    operations = _counts(VMOperation, VMOperation.status)
    allocations = _counts(VMAllocation, VMAllocation.status)
    lines.extend(
        (
            "# HELP portal_jobs Provisioning jobs by status.",
            "# TYPE portal_jobs gauge",
        )
    )
    lines.extend(
        f"portal_jobs{_labels(status=status)} {provisioning.get(status, 0)}"
        for status in PROVISIONING_STATUSES
    )
    lines.extend(
        (
            "# HELP portal_vm_operations Lifecycle operations by status.",
            "# TYPE portal_vm_operations gauge",
        )
    )
    lines.extend(
        f"portal_vm_operations{_labels(status=status)} {operations.get(status, 0)}"
        for status in OPERATION_STATUSES
    )
    lines.extend(
        (
            "# HELP portal_vm_allocations VM allocations by status.",
            "# TYPE portal_vm_allocations gauge",
        )
    )
    lines.extend(
        f"portal_vm_allocations{_labels(status=status)} {allocations.get(status, 0)}"
        for status in ALLOCATION_STATUSES
    )
    warning_setting = db.session.get(PortalSetting, "expiration_warning_days")
    try:
        warning_days = int(warning_setting.value) if warning_setting else 14
    except ValueError:
        warning_days = 14
    active_filter = VMAllocation.status.not_in(("deleted", "failed"))
    expired = db.session.scalar(
        select(func.count(VMAllocation.id)).where(
            active_filter,
            VMAllocation.expires_at.is_not(None),
            VMAllocation.expires_at <= now,
        )
    )
    warning = db.session.scalar(
        select(func.count(VMAllocation.id)).where(
            active_filter,
            VMAllocation.expires_at > now,
            VMAllocation.expires_at <= now + timedelta(days=warning_days),
        )
    )
    unmanaged = db.session.scalar(
        select(func.count(VMAllocation.id)).where(
            active_filter, VMAllocation.expires_at.is_(None)
        )
    )
    lines.extend(
        (
            "# HELP portal_vm_lifecycle VM allocations by lifecycle deadline state.",
            "# TYPE portal_vm_lifecycle gauge",
            f'portal_vm_lifecycle{{state="expired"}} {int(expired or 0)}',
            f'portal_vm_lifecycle{{state="warning"}} {int(warning or 0)}',
            f'portal_vm_lifecycle{{state="unmanaged"}} {int(unmanaged or 0)}',
        )
    )

    user_rows = db.session.execute(
        select(User.role, User.is_active, func.count(User.id)).group_by(
            User.role, User.is_active
        )
    )
    users = {(str(role), bool(active)): int(count) for role, active, count in user_rows}
    lines.extend(("# HELP portal_users Portal users by role and state.", "# TYPE portal_users gauge"))
    for role in ("admin", "operator", "user"):
        for active in (True, False):
            lines.append(
                f"portal_users{_labels(role=role, active=str(active).lower())} "
                f"{users.get((role, active), 0)}"
            )
    return "\n".join(lines) + "\n"
