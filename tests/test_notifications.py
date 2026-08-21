from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import _attention, _complete, _fail
from portal.models import ProvisioningJob, User, UserNotification, VMAllocation, db
from portal.notifications import create_notification, process_lifecycle_notifications
from portal.pve import FakePVEClient

ADMIN_PASSWORD = "correct-horse-battery-staple"


def make_app():
    return create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(ADMIN_PASSWORD),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
    )


def login_admin(client):
    response = client.post(
        "/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def user_client(app, user_id):
    client = app.test_client()
    with client.session_transaction() as portal_session:
        portal_session["user_id"] = user_id
        portal_session["authentication"] = "local"
        portal_session["csrf_token"] = "user-notification-csrf"
    client.environ_base["HTTP_X_CSRF_TOKEN"] = "user-notification-csrf"
    return client


def test_notifications_are_private_and_can_be_marked_read():
    app = make_app()
    with app.app_context():
        user = User(
            username="alice",
            password_hash=generate_password_hash("alice-password"),
            role="user",
        )
        db.session.add(user)
        db.session.flush()
        notification = create_notification(
            user_id=user.id,
            kind="provisioning_succeeded",
            title="Machine prête",
            message="La machine web-01 est prête.",
            dedup_key="test:web-01:ready",
            target_type="vm",
            target_id="vm-private-id",
        )
        db.session.commit()
        user_id = user.id
        notification_id = notification.id

    anonymous = app.test_client()
    assert anonymous.get("/api/notifications").status_code == 401

    admin = app.test_client()
    login_admin(admin)
    assert admin.get("/api/notifications").get_json()["notifications"] == []
    assert admin.post(
        f"/api/notifications/{notification_id}/read"
    ).status_code == 404

    client = user_client(app, user_id)
    listed = client.get("/api/notifications?limit=10&unread=true")
    assert listed.status_code == 200
    assert listed.get_json()["unread_count"] == 1
    assert listed.get_json()["notifications"][0]["target_id"] == "vm-private-id"

    marked = client.post(f"/api/notifications/{notification_id}/read")
    assert marked.status_code == 200
    assert marked.get_json()["notification"]["read_at"] is not None
    assert client.get("/api/notifications?unread=true").get_json()[
        "notifications"
    ] == []
    assert client.post("/api/notifications/read-all").get_json()["updated"] == 0


def test_notification_query_is_strict_and_read_all_is_scoped():
    app = make_app()
    client = app.test_client()
    login_admin(client)
    with app.app_context():
        admin = db.session.scalar(select(User).where(User.username == "admin"))
        for index in range(2):
            create_notification(
                user_id=admin.id,
                kind="approval_requested",
                title="Demande à approuver",
                message=f"Demande {index}",
                dedup_key=f"approval:{index}",
            )
        db.session.commit()

    for query, field in (
        ("?extra=x", "query"),
        ("?limit=x", "limit"),
        ("?limit=0", "limit"),
        ("?limit=101", "limit"),
        ("?unread=yes", "unread"),
    ):
        response = client.get(f"/api/notifications{query}")
        assert response.status_code == 400
        assert field in response.get_json()["errors"]

    assert client.post("/api/notifications/read-all").get_json()["updated"] == 2
    assert len(client.get("/api/notifications?unread=false").get_json()["notifications"]) == 2


def test_provisioning_terminal_states_create_deduplicated_notifications():
    app = make_app()
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        jobs = []
        for name in ("ready-vm", "failed-vm", "attention-vm"):
            allocation = VMAllocation(
                owner_id=owner.id,
                name=name,
                node="pve-a",
                cpu=2,
                ram_mb=4096,
                disk_gb=40,
                status="queued",
            )
            job = ProvisioningJob(allocation=allocation)
            db.session.add_all((allocation, job))
            jobs.append(job)
        db.session.commit()

        _complete(jobs[0])
        _fail(jobs[1], "pve_task_failed")
        _fail(jobs[1], "pve_task_failed")
        _attention(jobs[2], "pve_task_status_unknown")

        kinds = db.session.scalars(
            select(UserNotification.kind).order_by(UserNotification.kind)
        ).all()
        assert kinds == [
            "provisioning_attention",
            "provisioning_failed",
            "provisioning_succeeded",
        ]
        assert db.session.scalar(select(func.count(UserNotification.id))) == 3
        assert all(item.created_at is not None for item in owner.notifications)


def test_lifecycle_notifications_warn_expire_and_follow_extensions():
    app = make_app()
    now = datetime(2026, 8, 21, 10, tzinfo=UTC)
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        allocation = VMAllocation(
            owner_id=owner.id,
            name="clinical-app",
            node="pve-a",
            vmid=120,
            cpu=2,
            ram_mb=4096,
            disk_gb=40,
            status="running",
            expires_at=now + timedelta(days=5),
        )
        ignored = VMAllocation(
            owner_id=owner.id,
            name="failed-build",
            node="pve-a",
            cpu=2,
            ram_mb=2048,
            disk_gb=20,
            status="failed",
            expires_at=now - timedelta(days=1),
        )
        db.session.add_all((allocation, ignored))
        db.session.commit()

        assert process_lifecycle_notifications(warning_days=14, now=now) == 1
        assert process_lifecycle_notifications(warning_days=14, now=now) == 0
        db.session.commit()
        first = db.session.scalar(select(UserNotification))
        assert first.kind == "lifecycle_warning"
        assert first.target_id == allocation.id
        assert "5 jour(s)" in first.message

        allocation.expires_at = now + timedelta(days=30)
        db.session.commit()
        assert process_lifecycle_notifications(warning_days=14, now=now) == 0
        assert (
            process_lifecycle_notifications(
                warning_days=14, now=now + timedelta(days=20)
            )
            == 1
        )
        assert (
            process_lifecycle_notifications(
                warning_days=14, now=now + timedelta(days=31)
            )
            == 1
        )
        db.session.commit()

        kinds = db.session.scalars(
            select(UserNotification.kind).order_by(UserNotification.created_at)
        ).all()
        assert kinds.count("lifecycle_warning") == 2
        assert kinds.count("lifecycle_expired") == 1
        assert db.session.scalar(select(func.count(UserNotification.id))) == 3
