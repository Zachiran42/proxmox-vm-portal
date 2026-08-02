from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import (
    AuditEvent,
    ProvisioningJob,
    User,
    VMAllocation,
    VMOperation,
    WorkerHeartbeat,
    db,
)
from portal.pve import FakePVEClient, PVETransportError


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


def login(client):
    response = client.post(
        "/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    )
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def seed_incidents(app):
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        provisioning_vm = VMAllocation(
            owner_id=owner.id,
            name="ambiguous-build",
            node="pve-a",
            vmid=101,
            cpu=2,
            ram_mb=4096,
            disk_gb=40,
            status="provisioning",
            upstream_request_id="UPID:provisioning",
        )
        provisioning = ProvisioningJob(
            allocation=provisioning_vm,
            status="attention",
            upstream_node="pve-a",
            error_code="pve_task_status_unknown",
            completed_at=datetime.now(UTC),
        )
        lifecycle_vm = VMAllocation(
            owner_id=owner.id,
            name="ambiguous-stop",
            node="pve-a",
            vmid=102,
            cpu=2,
            ram_mb=2048,
            disk_gb=20,
            status="running",
        )
        lifecycle_job = ProvisioningJob(
            allocation=lifecycle_vm,
            status="succeeded",
            completed_at=datetime.now(UTC),
        )
        lifecycle = VMOperation(
            allocation=lifecycle_vm,
            actor_user_id=owner.id,
            action="stop",
            status="attention",
            upstream_node="pve-a",
            upstream_request_id="UPID:stop",
            error_code="pve_task_status_unknown",
            completed_at=datetime.now(UTC),
        )
        db.session.add_all(
            (provisioning_vm, provisioning, lifecycle_vm, lifecycle_job, lifecycle)
        )
        db.session.commit()
        return provisioning.id, lifecycle.id


def incident_action(client, kind, incident_id, action, **extra):
    return client.post(
        f"/api/admin/incidents/{kind}/{incident_id}/actions",
        json={"action": action, **extra},
    )


def test_admin_overview_reports_services_queue_and_safe_incidents(app, pve_client):
    provisioning_id, lifecycle_id = seed_incidents(app)
    with app.app_context():
        assert process_next_job(pve_client, worker_id="worker-a") is False
    client = app.test_client()
    login(client)

    response = client.get("/api/admin/operations")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["services"]["database"]["status"] == "healthy"
    assert payload["services"]["worker"]["status"] == "healthy"
    assert payload["services"]["proxmox"]["status"] == "healthy"
    assert payload["services"]["password_pusher"]["status"] == "disabled"
    assert payload["queue"] == {"active": 0, "attention": 2}
    assert {incident["id"] for incident in payload["incidents"]} == {
        provisioning_id,
        lifecycle_id,
    }
    assert all(incident["can_resume"] for incident in payload["incidents"])
    assert all("upstream_request_id" not in incident for incident in payload["incidents"])


def test_overview_classifies_stale_worker_and_unavailable_proxmox(app, pve_client):
    with app.app_context():
        db.session.add(
            WorkerHeartbeat(
                worker_id="stale-worker",
                last_seen_at=datetime.now(UTC) - timedelta(minutes=10),
            )
        )
        db.session.commit()
    pve_client.list_nodes = lambda: (_ for _ in ()).throw(
        PVETransportError("offline")
    )
    client = app.test_client()
    login(client)

    services = client.get("/api/admin/operations").get_json()["services"]

    assert services["worker"]["status"] == "degraded"
    assert services["proxmox"]["status"] == "unavailable"


def test_admin_can_resume_existing_upid_without_replaying_submission(app):
    provisioning_id, _ = seed_incidents(app)
    client = app.test_client()
    login(client)

    response = incident_action(
        client, "provisioning", provisioning_id, "resume_tracking"
    )

    assert response.status_code == 200
    assert response.get_json() == {"status": "submitted"}
    with app.app_context():
        job = db.session.get(ProvisioningJob, provisioning_id)
        assert job.status == "submitted"
        assert job.error_code is None
        assert job.completed_at is None
        event = db.session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "incident.resume_tracking"
            )
        )
        assert event.details["previous_error"] == "pve_task_status_unknown"
    assert incident_action(
        client, "provisioning", provisioning_id, "resume_tracking"
    ).get_json()["error"] == "incident_not_open"


def test_close_failed_requires_exact_name_and_preserves_lifecycle_vm_state(app):
    _, lifecycle_id = seed_incidents(app)
    client = app.test_client()
    login(client)

    mismatch = incident_action(
        client,
        "lifecycle",
        lifecycle_id,
        "close_failed",
        confirm_name="wrong-name",
    )
    assert mismatch.get_json()["error"] == "confirmation_mismatch"
    resolved = incident_action(
        client,
        "lifecycle",
        lifecycle_id,
        "close_failed",
        confirm_name="ambiguous-stop",
    )
    assert resolved.get_json() == {"status": "failed"}
    with app.app_context():
        operation = db.session.get(VMOperation, lifecycle_id)
        assert operation.status == "failed"
        assert operation.allocation.status == "running"


def test_close_failed_provisioning_releases_reserved_quota(app):
    provisioning_id, _ = seed_incidents(app)
    client = app.test_client()
    login(client)

    response = incident_action(
        client,
        "provisioning",
        provisioning_id,
        "close_failed",
        confirm_name="ambiguous-build",
    )

    assert response.get_json() == {"status": "failed"}
    assert client.get("/api/me").get_json()["usage"] == {
        "vms": 1,
        "cpu": 2,
        "ram_mb": 2048,
        "disk_gb": 20,
    }


def test_non_resumable_unknown_and_forbidden_incidents_are_rejected(app):
    provisioning_id, _ = seed_incidents(app)
    with app.app_context():
        job = db.session.get(ProvisioningJob, provisioning_id)
        job.upstream_node = None
        job.allocation.upstream_request_id = None
        user = User(
            username="regular-user",
            password_hash=generate_password_hash("regular-user-strong-password"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    client = app.test_client()
    login(client)
    assert incident_action(
        client, "provisioning", provisioning_id, "resume_tracking"
    ).get_json()["error"] == "incident_not_resumable"
    assert incident_action(
        client, "unknown", provisioning_id, "resume_tracking"
    ).status_code == 404

    regular = app.test_client()
    with regular.session_transaction() as portal_session:
        portal_session["user_id"] = user_id
        portal_session["authentication"] = "local"
        portal_session["csrf_token"] = "regular-csrf"
    regular.environ_base["HTTP_X_CSRF_TOKEN"] = "regular-csrf"
    assert regular.get("/api/admin/operations").status_code == 403
    assert incident_action(
        regular, "provisioning", provisioning_id, "resume_tracking"
    ).status_code == 403


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "action"),
        ({"action": "retry"}, "action"),
        ({"action": "close_failed"}, "confirm_name"),
        ({"action": "resume_tracking", "confirm_name": "vm"}, "confirm_name"),
        ({"action": "resume_tracking", "extra": True}, "body"),
    ],
)
def test_incident_actions_use_strict_validation(app, payload, field):
    provisioning_id, _ = seed_incidents(app)
    client = app.test_client()
    login(client)
    response = client.post(
        f"/api/admin/incidents/provisioning/{provisioning_id}/actions",
        json=payload,
    )
    assert response.status_code == 400
    assert field in response.get_json()["errors"]
