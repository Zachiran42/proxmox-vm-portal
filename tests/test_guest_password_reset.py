from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import (
    AuditEvent,
    ImageProfile,
    ProvisioningJob,
    User,
    UserNotification,
    VMAllocation,
    db,
)
from portal.pve import FakePVEClient, PVEHTTPError


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": set()})


@pytest.fixture
def app(pve_client):
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(
                "correct-horse-battery-staple"
            ),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


def login(client, username, password):
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def seed_cloud_vm(app, *, status="running"):
    with app.app_context():
        owner = User(
            username="hugo",
            password_hash=generate_password_hash("owner-password"),
            role="user",
        )
        outsider = User(
            username="outsider",
            password_hash=generate_password_hash("outsider-password"),
            role="user",
        )
        profile = ImageProfile(
            slug="debian-13-cloud",
            label="Debian 13 Cloud",
            source_type="cloud_init",
            template_node="pve-a",
            template_vmid=9130,
        )
        allocation = VMAllocation(
            owner=owner,
            profile=profile,
            name="clinical-app",
            node="pve-a",
            vmid=107,
            guest_username="hugo",
            cpu=2,
            ram_mb=4096,
            disk_gb=40,
            status=status,
        )
        job = ProvisioningJob(
            allocation=allocation,
            status="succeeded",
            completed_at=datetime.now(UTC),
        )
        db.session.add_all((owner, outsider, profile, allocation, job))
        db.session.commit()
        return allocation.id


def test_admin_requests_reset_and_owner_applies_password_without_persistence(
    app, pve_client
):
    vm_id = seed_cloud_vm(app)
    admin = app.test_client()
    login(admin, "admin", "correct-horse-battery-staple")

    requested = admin.post(f"/api/admin/vms/{vm_id}/guest-password-reset", json={})
    duplicate = admin.post(f"/api/admin/vms/{vm_id}/guest-password-reset", json={})

    assert requested.status_code == 202
    assert requested.get_json()["status"] == "pending"
    assert duplicate.status_code == 200
    assert duplicate.get_json()["status"] == "already_pending"

    owner = app.test_client()
    login(owner, "hugo", "owner-password")
    pending_job = owner.get("/api/jobs").get_json()["jobs"][0]
    assert pending_job["vm"]["ssh_password_change"]["requested"] is True
    changed = owner.post(
        f"/api/vms/{vm_id}/guest-password",
        json={"password": "new guest password"},
    )

    assert changed.status_code == 200
    assert pve_client.guest_password_resets == [
        ("pve-a", 107, "hugo", "new guest password")
    ]
    assert "ssh_password_change" not in owner.get("/api/jobs").get_json()["jobs"][0]["vm"]
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.guest_password_reset_requested_at is None
        kinds = db.session.scalars(
            select(UserNotification.kind).order_by(UserNotification.created_at)
        ).all()
        assert kinds == [
            "guest_password_reset_requested",
            "guest_password_reset_completed",
        ]
        events = db.session.scalars(
            select(AuditEvent)
            .where(AuditEvent.target_id == vm_id)
            .order_by(AuditEvent.created_at)
        ).all()
        assert [event.action for event in events] == [
            "vm.guest_password_reset.request",
            "vm.guest_password_reset.apply",
        ]
        assert "new guest password" not in repr([event.details for event in events])


def test_only_admin_can_request_and_only_owner_can_apply(app):
    vm_id = seed_cloud_vm(app)
    outsider = app.test_client()
    login(outsider, "outsider", "outsider-password")

    assert (
        outsider.post(f"/api/admin/vms/{vm_id}/guest-password-reset", json={}).status_code
        == 403
    )
    assert (
        outsider.post(
            f"/api/vms/{vm_id}/guest-password", json={"password": "valid password"}
        ).status_code
        == 404
    )


def test_reset_requires_running_vm_and_configured_minimum(app, pve_client):
    vm_id = seed_cloud_vm(app, status="stopped")
    owner = app.test_client()
    login(owner, "hugo", "owner-password")

    short = owner.post(
        f"/api/vms/{vm_id}/guest-password", json={"password": "four"}
    )
    stopped = owner.post(
        f"/api/vms/{vm_id}/guest-password", json={"password": "valid password"}
    )

    assert short.status_code == 400
    assert "8" in short.get_json()["errors"]["password"]
    assert stopped.status_code == 409
    assert stopped.get_json()["error"] == "guest_password_reset_requires_running_vm"
    assert pve_client.guest_password_resets == []


def test_proxmox_permission_failure_is_audited_without_clearing_request(
    app, pve_client
):
    vm_id = seed_cloud_vm(app)
    admin = app.test_client()
    login(admin, "admin", "correct-horse-battery-staple")
    assert admin.post(
        f"/api/admin/vms/{vm_id}/guest-password-reset", json={}
    ).status_code == 202

    def denied(**_kwargs):
        raise PVEHTTPError(403, "permission denied")

    pve_client.set_guest_password = denied
    owner = app.test_client()
    login(owner, "hugo", "owner-password")
    response = owner.post(
        f"/api/vms/{vm_id}/guest-password", json={"password": "valid password"}
    )

    assert response.status_code == 503
    assert response.get_json()["error"] == "guest_password_reset_permission_denied"
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.guest_password_reset_requested_at is not None
        event = db.session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "vm.guest_password_reset.apply")
            .order_by(AuditEvent.created_at.desc())
        )
        assert event.outcome == "failure"
        assert event.details["error_code"] == "guest_password_reset_permission_denied"
