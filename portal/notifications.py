from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from .models import (
    AuditEvent,
    User,
    UserNotification,
    VMAllocation,
    VMOperation,
    db,
)
from .pve import PVEHTTPError, PVEProtocolError, PVETransportError


def create_notification(
    *,
    user_id: int,
    kind: str,
    title: str,
    message: str,
    dedup_key: str,
    target_type: str | None = None,
    target_id: str | None = None,
) -> UserNotification:
    existing = db.session.scalar(
        select(UserNotification).where(
            UserNotification.user_id == user_id,
            UserNotification.dedup_key == dedup_key,
        )
    )
    if existing is not None:
        return existing
    notification = UserNotification(
        user_id=user_id,
        kind=kind,
        title=title[:160],
        message=message[:1000],
        target_type=target_type,
        target_id=target_id,
        dedup_key=dedup_key[:160],
    )
    db.session.add(notification)
    return notification


def notify_active_admins(
    *,
    kind: str,
    title: str,
    message: str,
    dedup_key: str,
    target_type: str | None = None,
    target_id: str | None = None,
) -> list[UserNotification]:
    admin_ids = db.session.scalars(
        select(User.id).where(User.role == "admin", User.is_active.is_(True))
    ).all()
    return [
        create_notification(
            user_id=admin_id,
            kind=kind,
            title=title,
            message=message,
            dedup_key=dedup_key,
            target_type=target_type,
            target_id=target_id,
        )
        for admin_id in admin_ids
    ]


def process_lifecycle_notifications(
    *, warning_days: int, now: datetime | None = None
) -> int:
    """Crée les rappels d'échéance dus, sans modifier ni arrêter les VM."""
    current = now or datetime.now(UTC)
    cutoff = current + timedelta(days=warning_days)
    allocations = db.session.scalars(
        select(VMAllocation)
        .where(
            VMAllocation.expires_at.is_not(None),
            VMAllocation.expires_at <= cutoff,
            VMAllocation.status.not_in(("deleted", "rejected", "failed")),
        )
        .order_by(VMAllocation.expires_at)
        .with_for_update(skip_locked=True)
    ).all()
    if not allocations:
        return 0

    due = []
    for allocation in allocations:
        lifecycle = allocation.lifecycle_dict(warning_days=warning_days, now=current)
        expires_at = lifecycle["expires_at"]
        state = lifecycle["state"]
        if state not in {"warning", "expired"} or expires_at is None:
            continue
        kind = "lifecycle_expired" if state == "expired" else "lifecycle_warning"
        dedup_key = f"{kind}:{allocation.id}:{expires_at}"
        due.append((allocation, lifecycle, kind, dedup_key))
    if not due:
        return 0

    due_keys = [item[3] for item in due]
    existing_keys = set(
        db.session.scalars(
            select(UserNotification.dedup_key).where(
                UserNotification.dedup_key.in_(due_keys)
            )
        ).all()
    )
    created = 0
    for allocation, lifecycle, kind, dedup_key in due:
        if dedup_key in existing_keys:
            continue
        state = lifecycle["state"]
        if state == "expired":
            title = "Machine arrivée à échéance"
            message = (
                f"La machine {allocation.name} est arrivée à échéance. "
                "Son démarrage reste bloqué jusqu'à sa prolongation par un administrateur."
            )
        else:
            days = lifecycle["days_remaining"]
            title = "Échéance de machine proche"
            message = (
                f"La machine {allocation.name} arrive à échéance dans {days} jour(s). "
                "Contactez un administrateur si elle doit être prolongée."
            )
        create_notification(
            user_id=allocation.owner_id,
            kind=kind,
            title=title,
            message=message,
            dedup_key=dedup_key,
            target_type="vm",
            target_id=allocation.id,
        )
        existing_keys.add(dedup_key)
        created += 1
    return created


def process_lifecycle_enforcement(
    pve_client,
    *,
    action: str,
    grace_days: int,
    now: datetime | None = None,
) -> int:
    """Met en quarantaine les VM expirées puis programme leur suppression."""
    if action not in {"notify_only", "quarantine", "delete"}:
        raise ValueError("Action d'expiration invalide.")
    if type(grace_days) is not int or not 1 <= grace_days <= 365:
        raise ValueError("Délai de grâce invalide.")
    if action == "notify_only":
        return 0

    current = now or datetime.now(UTC)
    allocations = db.session.scalars(
        select(VMAllocation)
        .where(
            VMAllocation.expires_at.is_not(None),
            VMAllocation.expires_at <= current,
            VMAllocation.status.not_in(("deleted", "rejected", "failed")),
        )
        .order_by(VMAllocation.expires_at)
        .limit(50)
        .with_for_update(skip_locked=True)
    ).all()
    processed = 0
    for allocation in allocations:
        if allocation.vmid is None:
            _record_lifecycle_failure(allocation, "lifecycle_vmid_missing")
            continue
        if allocation.lifecycle_quarantined_at is None:
            try:
                pve_client.set_vm_network_policy(
                    allocation.node, allocation.vmid, "isolated"
                )
            except PVEHTTPError as error:
                code = (
                    "lifecycle_enforcement_forbidden"
                    if error.status == 403
                    else "lifecycle_enforcement_rejected"
                )
                _record_lifecycle_failure(allocation, code)
                continue
            except (PVETransportError, PVEProtocolError):
                _record_lifecycle_failure(
                    allocation, "lifecycle_enforcement_unavailable"
                )
                continue
            allocation.network_policy = "isolated"
            allocation.network_policy_updated_at = current
            allocation.lifecycle_quarantined_at = current
            allocation.lifecycle_enforcement_error = None
            if action == "delete":
                allocation.lifecycle_delete_after = current + timedelta(
                    days=grace_days
                )
            _record_lifecycle_quarantine(allocation, current)
            processed += 1
            db.session.commit()
        elif action == "delete" and allocation.lifecycle_delete_after is None:
            allocation.lifecycle_delete_after = current + timedelta(days=grace_days)
            _notify_lifecycle_deletion(allocation)
            db.session.commit()
        elif action == "quarantine" and allocation.lifecycle_delete_after is not None:
            allocation.lifecycle_delete_after = None
            db.session.commit()

        try:
            actual_status = pve_client.get_vm_status(
                allocation.node, allocation.vmid
            )
        except (PVETransportError, PVEHTTPError, PVEProtocolError):
            _record_lifecycle_failure(allocation, "lifecycle_status_unknown")
            continue
        allocation.status = actual_status
        allocation.lifecycle_enforcement_error = None
        if actual_status == "running":
            _queue_lifecycle_operation(allocation, "stop")
        elif (
            action == "delete"
            and allocation.lifecycle_delete_after is not None
            and _as_utc(allocation.lifecycle_delete_after) <= current
        ):
            _queue_lifecycle_operation(allocation, "delete")
        db.session.commit()
    return processed


def process_sandbox_release_expirations(
    pve_client, *, now: datetime | None = None
) -> int:
    """Referme automatiquement les ouvertures temporaires arrivées à échéance."""
    current = now or datetime.now(UTC)
    allocations = db.session.scalars(
        select(VMAllocation)
        .where(
            VMAllocation.network_policy == "normal",
            VMAllocation.sandbox_release_status == "approved",
            VMAllocation.sandbox_release_expires_at.is_not(None),
            VMAllocation.sandbox_release_expires_at <= current,
            VMAllocation.status.not_in(("deleted", "rejected", "failed")),
        )
        .order_by(VMAllocation.sandbox_release_expires_at)
        .limit(50)
        .with_for_update(skip_locked=True)
    ).all()
    processed = 0
    for allocation in allocations:
        if allocation.vmid is None:
            continue
        # Import local pour éviter une dépendance circulaire avec le worker.
        from .jobs import build_sandbox_firewall_rules

        try:
            pve_client.set_vm_network_policy(
                allocation.node,
                allocation.vmid,
                "sandbox",
                rules=build_sandbox_firewall_rules(allocation),
            )
        except (PVETransportError, PVEHTTPError, PVEProtocolError):
            continue
        allocation.network_policy = "sandbox"
        allocation.network_policy_revision = (
            allocation.network_profile.sandbox_policy_revision
            if allocation.network_profile is not None
            else 1
        )
        allocation.network_policy_updated_at = current
        allocation.sandbox_release_status = "not_requested"
        allocation.sandbox_release_expires_at = None
        create_notification(
            user_id=allocation.owner_id,
            kind="sandbox_release_expired",
            title="Ouverture réseau temporaire terminée",
            message=(
                f"La machine {allocation.name} est automatiquement revenue "
                "dans le bac à sable."
            ),
            dedup_key=f"sandbox-release-expired:{allocation.id}:{current.isoformat()}",
            target_type="vm",
            target_id=allocation.id,
        )
        db.session.add(
            AuditEvent(
                actor_user_id=None,
                action="vm.sandbox_release.expire",
                target_type="vm",
                target_id=allocation.id,
                outcome="success",
                request_id=str(uuid.uuid4()),
                details={"ticket_reference": allocation.sandbox_release_ticket},
            )
        )
        db.session.commit()
        processed += 1
    return processed


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _queue_lifecycle_operation(
    allocation: VMAllocation, action: str
) -> bool:
    active = db.session.scalar(
        select(VMOperation.id).where(
            VMOperation.allocation_id == allocation.id,
            VMOperation.status.in_(("queued", "submitting", "submitted", "polling")),
        )
    )
    if active is not None:
        return False
    quarantine_at = allocation.lifecycle_quarantined_at
    previous = db.session.scalar(
        select(VMOperation.id).where(
            VMOperation.allocation_id == allocation.id,
            VMOperation.action == action,
            VMOperation.created_at >= quarantine_at,
        )
    )
    if previous is not None:
        return False
    db.session.add(
        VMOperation(
            allocation_id=allocation.id,
            actor_user_id=None,
            action=action,
            status="queued",
        )
    )
    return True


def _record_lifecycle_quarantine(
    allocation: VMAllocation, current: datetime
) -> None:
    create_notification(
        user_id=allocation.owner_id,
        kind="lifecycle_quarantined",
        title="Machine expirée et isolée",
        message=(
            f"La machine {allocation.name} a été isolée du réseau à son échéance. "
            "Contactez un administrateur pour la prolonger et la reconnecter."
        ),
        dedup_key=f"lifecycle-quarantine:{allocation.id}:{current.isoformat()}",
        target_type="vm",
        target_id=allocation.id,
    )
    db.session.add(
        AuditEvent(
            actor_user_id=None,
            action="vm.lifecycle.quarantine",
            target_type="vm",
            target_id=allocation.id,
            outcome="success",
            request_id=str(uuid.uuid4()),
            details={
                "expires_at": allocation.expires_at.isoformat()
                if allocation.expires_at is not None
                else None,
                "delete_after": allocation.lifecycle_delete_after.isoformat()
                if allocation.lifecycle_delete_after is not None
                else None,
            },
        )
    )
    if allocation.lifecycle_delete_after is not None:
        _notify_lifecycle_deletion(allocation)


def _notify_lifecycle_deletion(allocation: VMAllocation) -> None:
    delete_after = allocation.lifecycle_delete_after
    if delete_after is None:
        return
    create_notification(
        user_id=allocation.owner_id,
        kind="lifecycle_deletion_scheduled",
        title="Suppression automatique planifiée",
        message=(
            f"La machine {allocation.name} sera supprimée après le délai de grâce, "
            f"à partir du {_as_utc(delete_after).isoformat()}."
        ),
        dedup_key=f"lifecycle-delete:{allocation.id}:{_as_utc(delete_after).isoformat()}",
        target_type="vm",
        target_id=allocation.id,
    )


def _record_lifecycle_failure(
    allocation: VMAllocation, error_code: str
) -> None:
    if allocation.lifecycle_enforcement_error == error_code:
        db.session.rollback()
        return
    allocation.lifecycle_enforcement_error = error_code
    db.session.add(
        AuditEvent(
            actor_user_id=None,
            action="vm.lifecycle.enforce",
            target_type="vm",
            target_id=allocation.id,
            outcome="failure",
            request_id=str(uuid.uuid4()),
            details={"error_code": error_code, "manual_review": True},
        )
    )
    notify_active_admins(
        kind="lifecycle_enforcement_failed",
        title="Cycle de vie à vérifier",
        message=(
            f"L'automatisation de la machine {allocation.name} a échoué "
            f"({error_code})."
        ),
        dedup_key=f"lifecycle-enforcement:{allocation.id}:{error_code}",
        target_type="vm",
        target_id=allocation.id,
    )
    db.session.commit()
