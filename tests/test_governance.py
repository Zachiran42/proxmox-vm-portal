from __future__ import annotations

import json

import pytest
from sqlalchemy import inspect, select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import AuditEvent, ProvisioningJob, User, VMAllocation, db
from portal.pve import FakePVEClient

ADMIN_PASSWORD = "correct-horse-battery-staple"
USER_PASSWORD = "another-strong-password"


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": {"local:iso/debian-12.iso"}})


@pytest.fixture
def app(pve_client):
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(ADMIN_PASSWORD),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def login(client, username="admin", password=ADMIN_PASSWORD):
    response = client.post("/login", json={"username": username, "password": password})
    if response.status_code == 200:
        client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]
    return response


def user_payload(*, username="alice", role="user", vms=2, cpu=4, ram_mb=8192, disk_gb=100):
    return {
        "username": username,
        "password": USER_PASSWORD,
        "role": role,
        "quota": {"vms": vms, "cpu": cpu, "ram_mb": ram_mb, "disk_gb": disk_gb},
    }


def vm_payload(name="vm-alice-01"):
    return {
        "name": name,
        "node": "pve-a",
        "profile": "debian-12",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
    }


def create_user(client, **kwargs):
    return client.post("/api/admin/users", json=user_payload(**kwargs))


def test_admin_can_create_and_list_users_without_exposing_password(app):
    client = app.test_client()
    assert login(client).status_code == 200

    created = create_user(client)
    listed = client.get("/api/admin/users")

    assert created.status_code == 201
    assert created.get_json()["user"] == {
        "id": 2,
        "username": "alice",
        "role": "user",
        "authentication": "local",
        "is_active": True,
        "quota": {"vms": 2, "cpu": 4, "ram_mb": 8192, "disk_gb": 100},
    }
    assert [user["username"] for user in listed.get_json()["users"]] == ["admin", "alice"]
    assert "password" not in json.dumps(created.get_json())


def test_duplicate_username_is_rejected_and_audited(app):
    client = app.test_client()
    login(client)
    assert create_user(client).status_code == 201
    duplicate = create_user(client)

    assert duplicate.status_code == 409
    assert duplicate.get_json() == {"errors": {"username": "Identifiant déjà utilisé."}}
    with app.app_context():
        event = db.session.scalars(
            select(AuditEvent).where(AuditEvent.action == "user.create").order_by(AuditEvent.created_at.desc())
        ).first()
        assert event.outcome == "failure"
        assert event.details == {"reason": "username_conflict"}


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"username": "INVALID"}, "username"),
        ({"password": "too-short"}, "password"),
        ({"role": "root"}, "role"),
        ({"quota": {"vms": -1, "cpu": 4, "ram_mb": 8192, "disk_gb": 100}}, "quota.vms"),
        ({"extra": True}, "unknown"),
    ],
)
def test_user_creation_validation(app, change, field):
    client = app.test_client()
    login(client)
    payload = user_payload()
    payload.update(change)
    response = client.post("/api/admin/users", json=payload)
    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_non_admin_cannot_manage_users_or_read_audit(app):
    client = app.test_client()
    login(client)
    assert create_user(client).status_code == 201
    assert client.post("/logout").status_code == 200
    assert login(client, "alice", USER_PASSWORD).status_code == 200

    assert client.get("/api/admin/users").status_code == 403
    assert create_user(client, username="bob").status_code == 403
    assert client.get("/api/admin/audit-events").status_code == 403
    with app.app_context():
        denied = db.session.scalar(
            select(db.func.count(AuditEvent.id)).where(AuditEvent.action == "authorization.denied")
        )
        assert denied == 3


def test_quota_is_reserved_before_second_proxmox_request(app, pve_client):
    client = app.test_client()
    login(client)
    assert create_user(client, vms=1, cpu=2, ram_mb=4096, disk_gb=40).status_code == 201
    client.post("/logout")
    login(client, "alice", USER_PASSWORD)

    first = client.post("/api/vms", json=vm_payload())
    second = client.post("/api/vms", json=vm_payload(name="vm-alice-02"))

    assert first.status_code == 202
    assert second.status_code == 409
    assert second.get_json()["error"] == "quota_exceeded"
    assert set(second.get_json()["errors"]) == {"vms", "cpu", "ram_mb", "disk_gb"}
    assert len(pve_client.requests) == 0
    assert client.get("/api/me").get_json()["usage"] == {
        "vms": 1, "cpu": 2, "ram_mb": 4096, "disk_gb": 40
    }


def test_duplicate_vm_name_has_a_distinct_conflict_error(app, pve_client):
    client = app.test_client()
    login(client)
    assert client.post("/api/vms", json=vm_payload()).status_code == 202

    duplicate = client.post("/api/vms", json=vm_payload())

    assert duplicate.status_code == 409
    assert duplicate.get_json()["error"] == "name_conflict"
    assert len(pve_client.requests) == 0


def test_ambiguous_pve_submission_requires_attention_and_is_audited(app):
    from portal.pve import PVETransportError

    client = app.test_client()
    login(client)
    app.extensions["pve_client"].create_vm = lambda _request: (_ for _ in ()).throw(
        PVETransportError("secret upstream detail")
    )
    response = client.post("/api/vms", json=vm_payload())
    assert response.status_code == 202
    with app.app_context():
        assert process_next_job(
            app.extensions["pve_client"], worker_id="test-worker", poll_seconds=1
        ) is True

    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        job = db.session.scalar(select(ProvisioningJob))
        event = db.session.scalars(
            select(AuditEvent).where(AuditEvent.action == "vm.provision").order_by(AuditEvent.created_at.desc())
        ).first()
        assert allocation.status == "provisioning"
        assert job.status == "attention"
        assert job.error_code == "pve_submission_unknown"
        assert event.outcome == "failure"
        assert "secret" not in json.dumps(event.details)


def test_inactive_user_session_is_revoked(app):
    client = app.test_client()
    login(client)
    with app.app_context():
        user = db.session.scalar(select(User).where(User.username == "admin"))
        user.is_active = False
        db.session.commit()
    assert client.get("/api/me").status_code == 401


def test_admin_can_read_audit_log(app):
    client = app.test_client()
    login(client)
    create_user(client)
    response = client.get("/api/admin/audit-events")
    assert response.status_code == 200
    events = response.get_json()["events"]
    assert {event["action"] for event in events} >= {"authentication.login", "user.create"}
    assert all(event["request_id"] for event in events)
    assert USER_PASSWORD not in json.dumps(events)


def test_initial_migration_and_bootstrap_admin(tmp_path, pve_client):
    database_path = tmp_path / "migration.db"
    app = create_app(
        {
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(ADMIN_PASSWORD),
        },
        pve_client=pve_client,
    )
    runner = app.test_cli_runner()
    assert runner.invoke(args=["db", "upgrade"]).exit_code == 0
    with app.app_context():
        assert {"users", "vm_allocations", "audit_events", "alembic_version"} <= set(
            inspect(db.engine).get_table_names()
        )

    first = runner.invoke(args=["bootstrap-admin"])
    second = runner.invoke(args=["bootstrap-admin"])
    assert first.exit_code == 0
    assert "créé" in first.output
    assert second.exit_code != 0
    assert "déjà" in second.output
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
