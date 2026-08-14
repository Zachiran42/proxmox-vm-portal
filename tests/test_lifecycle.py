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
    db,
)
from portal.pve import FakePVEClient, PVEHTTPError, PVETransportError


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


def seed_vm(app, *, status="accepted"):
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        allocation = VMAllocation(
            owner_id=owner.id,
            name="lifecycle-vm",
            node="pve-a",
            vmid=101,
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
        db.session.add_all((allocation, job))
        db.session.commit()
        return allocation.id


def run_step(app, pve_client):
    with app.app_context():
        return process_next_job(
            pve_client,
            worker_id="lifecycle-worker",
            poll_seconds=0,
            lease_seconds=60,
        )


def request_action(client, vm_id, action, **extra):
    return client.post(
        f"/api/vms/{vm_id}/actions", json={"action": action, **extra}
    )


def test_owner_can_run_full_lifecycle_and_delete_releases_quota(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)

    assert request_action(client, vm_id, "start").status_code == 202
    assert request_action(client, vm_id, "start").get_json()["error"] == "operation_in_progress"
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True

    assert request_action(client, vm_id, "reboot").status_code == 202
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True

    assert request_action(client, vm_id, "stop").status_code == 202
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True

    deleted = request_action(
        client, vm_id, "delete", confirm_name="lifecycle-vm"
    )
    assert deleted.status_code == 202
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True

    assert pve_client.starts == [("pve-a", 101)]
    assert pve_client.reboots == [("pve-a", 101)]
    assert pve_client.stops == [("pve-a", 101)]
    assert pve_client.deletions == [("pve-a", 101)]
    assert client.get("/api/me").get_json()["usage"] == {
        "vms": 0,
        "cpu": 0,
        "ram_mb": 0,
        "disk_gb": 0,
    }
    history = client.get("/api/jobs").get_json()["jobs"][0]
    assert history["vm"]["status"] == "deleted"
    assert history["operation"]["action"] == "delete"
    assert history["operation"]["status"] == "succeeded"
    with app.app_context():
        assert [event.action for event in db.session.scalars(
            select(AuditEvent).where(AuditEvent.target_id == vm_id).order_by(AuditEvent.created_at)
        )] == ["vm.start", "vm.reboot", "vm.stop", "vm.delete"]


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "action"),
        ({"action": "pause"}, "action"),
        ({"action": "start", "confirm_name": "x"}, "confirm_name"),
        ({"action": "delete"}, "confirm_name"),
        ({"action": "start", "extra": True}, "body"),
    ],
)
def test_action_payload_is_strictly_validated(app, payload, field):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    response = client.post(f"/api/vms/{vm_id}/actions", json=payload)
    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_action_requires_login_csrf_ownership_state_and_exact_delete_name(app):
    vm_id = seed_vm(app)
    anonymous = app.test_client()
    assert request_action(anonymous, vm_id, "start").status_code == 401

    client = app.test_client()
    login(client)
    del client.environ_base["HTTP_X_CSRF_TOKEN"]
    assert request_action(client, vm_id, "start").status_code == 403
    login(client)
    assert request_action(client, vm_id, "delete", confirm_name="wrong").get_json()["error"] == "confirmation_mismatch"
    assert request_action(client, vm_id, "reboot").get_json()["error"] == "lifecycle_invalid_state"

    with app.app_context():
        other = User(
            username="other-user",
            password_hash=generate_password_hash("other-user-secure-password"),
            role="user",
        )
        db.session.add(other)
        db.session.commit()
        other_id = other.id
    other_client = app.test_client()
    with other_client.session_transaction() as portal_session:
        portal_session["user_id"] = other_id
        portal_session["authentication"] = "local"
        portal_session["csrf_token"] = "other-csrf"
    other_client.environ_base["HTTP_X_CSRF_TOKEN"] = "other-csrf"
    assert request_action(other_client, vm_id, "start").status_code == 404


def test_action_rejects_non_json_and_vm_without_upstream_id(app):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    assert client.post(f"/api/vms/{vm_id}/actions").status_code == 400
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        allocation.vmid = None
        db.session.commit()
    assert request_action(client, vm_id, "start").get_json()["error"] == "vm_not_ready"


def test_failed_or_deleted_vm_can_be_archived_and_restored(app):
    vm_id = seed_vm(app, status="failed")
    client = app.test_client()
    login(client)

    archived = client.post(f"/api/vms/{vm_id}/archive", json={"archived": True})

    assert archived.status_code == 200
    assert archived.get_json() == {"status": "archived"}
    assert client.get("/api/jobs").get_json() == {"jobs": []}
    history = client.get("/api/jobs?archived=only").get_json()["jobs"]
    assert len(history) == 1
    assert history[0]["vm_id"] == vm_id
    assert history[0]["archived_at"] is not None

    restored = client.post(f"/api/vms/{vm_id}/archive", json={"archived": False})

    assert restored.status_code == 200
    assert restored.get_json() == {"status": "visible"}
    assert len(client.get("/api/jobs").get_json()["jobs"]) == 1
    with app.app_context():
        actions = db.session.scalars(
            select(AuditEvent.action)
            .where(AuditEvent.target_id == vm_id)
            .order_by(AuditEvent.created_at)
        ).all()
        assert actions == ["vm.archive", "vm.unarchive"]


def test_archive_requires_valid_payload_ownership_and_terminal_state(app):
    vm_id = seed_vm(app, status="running")
    client = app.test_client()
    login(client)

    assert client.post(f"/api/vms/{vm_id}/archive").status_code == 400
    assert client.post(
        f"/api/vms/{vm_id}/archive", json={"archived": "yes"}
    ).status_code == 400
    assert client.post(
        f"/api/vms/{vm_id}/archive", json={"archived": True, "extra": True}
    ).status_code == 400
    rejected = client.post(
        f"/api/vms/{vm_id}/archive", json={"archived": True}
    )
    assert rejected.status_code == 409
    assert rejected.get_json()["error"] == "archive_invalid_state"

    with app.app_context():
        other = User(
            username="archive-other",
            password_hash=generate_password_hash("archive-other-password"),
            role="user",
        )
        db.session.add(other)
        db.session.commit()
        other_id = other.id
        allocation = db.session.get(VMAllocation, vm_id)
        allocation.status = "deleted"
        db.session.commit()
    other_client = app.test_client()
    with other_client.session_transaction() as portal_session:
        portal_session["user_id"] = other_id
        portal_session["authentication"] = "local"
        portal_session["csrf_token"] = "archive-csrf"
    other_client.environ_base["HTTP_X_CSRF_TOKEN"] = "archive-csrf"
    assert other_client.post(
        f"/api/vms/{vm_id}/archive", json={"archived": True}
    ).status_code == 404
    assert other_client.get(f"/api/vms/{vm_id}").status_code == 404


def test_worker_classifies_operation_failures_and_ambiguous_results(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    assert request_action(client, vm_id, "start").status_code == 202
    pve_client.start_vm = lambda _node, _vmid: (_ for _ in ()).throw(
        PVEHTTPError(403, "denied")
    )
    assert run_step(app, pve_client) is True
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        assert (operation.status, operation.error_code) == (
            "failed",
            "pve_operation_rejected",
        )

    assert request_action(client, vm_id, "start").status_code == 202
    pve_client.start_vm = lambda _node, _vmid: (_ for _ in ()).throw(
        PVETransportError("timeout")
    )
    assert run_step(app, pve_client) is True
    with app.app_context():
        latest = db.session.scalars(
            select(VMOperation).order_by(VMOperation.created_at.desc())
        ).first()
        assert (latest.status, latest.error_code) == (
            "attention",
            "pve_operation_unknown",
        )


def test_worker_reconciles_manual_start_and_requires_stop_before_delete(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    pve_client.vm_statuses[("pve-a", 101)] = "running"

    assert request_action(client, vm_id, "start").status_code == 202
    assert run_step(app, pve_client) is True
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        allocation = db.session.get(VMAllocation, vm_id)
        assert operation.status == "succeeded"
        assert allocation.status == "running"
    assert pve_client.starts == []

    assert request_action(client, vm_id, "stop").status_code == 202
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True
    assert request_action(
        client, vm_id, "delete", confirm_name="lifecycle-vm"
    ).status_code == 202
    pve_client.vm_statuses[("pve-a", 101)] = "running"
    assert run_step(app, pve_client) is True
    with app.app_context():
        latest = db.session.scalars(
            select(VMOperation).order_by(VMOperation.created_at.desc())
        ).first()
        allocation = db.session.get(VMAllocation, vm_id)
        assert latest.error_code == "vm_must_be_stopped"
        assert allocation.status == "running"


def test_worker_marks_unknown_state_for_reconciliation_failure(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    pve_client.get_vm_status = lambda _node, _vmid: (_ for _ in ()).throw(
        PVETransportError("timeout")
    )

    assert request_action(client, vm_id, "start").status_code == 202
    assert run_step(app, pve_client) is True
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        assert operation.status == "attention"
        assert operation.error_code == "pve_status_unknown"


def test_operation_polling_reschedules_running_and_transport_failures(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    assert request_action(client, vm_id, "start").status_code == 202
    assert run_step(app, pve_client) is True

    pve_client.task_statuses = [{"status": "running"}]
    assert run_step(app, pve_client) is True
    with app.app_context():
        assert db.session.scalar(select(VMOperation)).status == "submitted"

    pve_client.get_task_status = lambda _node, _upid: (_ for _ in ()).throw(
        PVETransportError("temporary")
    )
    assert run_step(app, pve_client) is True
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        assert operation.status == "submitted"
        assert operation.error_code == "pve_temporarily_unavailable"


def test_stale_operation_leases_recover_without_replaying_submission(app, pve_client):
    vm_id = seed_vm(app)
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        operation = VMOperation(
            allocation_id=vm_id,
            actor_user_id=owner.id,
            action="start",
            status="submitting",
            locked_at=datetime.now(UTC) - timedelta(minutes=10),
            locked_by="dead-worker",
        )
        db.session.add(operation)
        db.session.commit()
    assert run_step(app, pve_client) is False
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        assert operation.status == "attention"
        assert operation.error_code == "worker_crashed_during_operation"
        assert db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.start")
        ).details["manual_review"] is True


def test_stale_polling_operation_returns_to_task_tracking(app, pve_client):
    vm_id = seed_vm(app)
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        operation = VMOperation(
            allocation_id=vm_id,
            actor_user_id=owner.id,
            action="start",
            status="polling",
            upstream_node="pve-a",
            upstream_request_id="UPID:existing",
            available_at=datetime.now(UTC) + timedelta(hours=1),
            locked_at=datetime.now(UTC) - timedelta(minutes=10),
            locked_by="dead-worker",
        )
        db.session.add(operation)
        db.session.commit()
    assert run_step(app, pve_client) is False
    with app.app_context():
        operation = db.session.scalar(select(VMOperation))
        assert operation.status == "submitted"
        assert operation.locked_at is None
