from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from .models import User, UserNotification, VMAllocation, db


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
