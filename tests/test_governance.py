from __future__ import annotations

import json

import pytest
from sqlalchemy import inspect, select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import (
    AuditEvent,
    PortalSetting,
    ProvisioningJob,
    User,
    VMAllocation,
    db,
)
from portal.pve import (
    FakePVEClient,
    PVEHTTPError,
    PVEProtocolError,
    PVETransportError,
)

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


def test_reset_admin_password(app):
    runner = app.test_cli_runner()
    new_password = "eight888"
    result = runner.invoke(
        args=["reset-admin-password"],
        input=f"{new_password}\n{new_password}\n",
    )
    assert result.exit_code == 0
    assert "modifié" in result.output

    client = app.test_client()
    response = client.post(
        "/login",
        json={"username": "admin", "password": new_password},
    )
    assert response.status_code == 200


def test_reset_admin_password_rejects_non_admin(app):
    with app.app_context():
        db.session.add(
            User(
                username="regular-user",
                password_hash=generate_password_hash("regular-password-strong"),
                role="user",
            )
        )
        db.session.commit()

    runner = app.test_cli_runner()
    result = runner.invoke(
        args=["reset-admin-password", "--username", "regular-user"],
        input="new-regular-password\nnew-regular-password\n",
    )
    assert result.exit_code != 0
    assert "n'est pas administrateur" in result.output


def test_check_proxmox_cli_reports_visible_nodes(app):
    result = app.test_cli_runner().invoke(args=["check-proxmox"])

    assert result.exit_code == 0
    assert "pve-a" in result.output


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (PVEHTTPError(401, "upstream-sensitive"), "Token Proxmox refusé"),
        (PVEHTTPError(403, "upstream-sensitive"), "permission Sys.Audit absente"),
        (PVEHTTPError(500, "upstream-sensitive"), "erreur HTTP 500"),
        (PVETransportError("upstream-sensitive"), "Connexion TLS"),
        (PVEProtocolError("upstream-sensitive"), "Réponse Proxmox invalide"),
    ],
)
def test_check_proxmox_cli_explains_failures(app, pve_client, error, message):
    pve_client.list_nodes = lambda: (_ for _ in ()).throw(error)

    result = app.test_cli_runner().invoke(args=["check-proxmox"])

    assert result.exit_code != 0
    assert message in result.output
    assert "upstream-sensitive" not in result.output


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
        "must_rotate_credentials": False,
        "quota": {"vms": 2, "cpu": 4, "ram_mb": 8192, "disk_gb": 100},
    }
    assert [user["username"] for user in listed.get_json()["users"]] == ["admin", "alice"]
    assert "password" not in json.dumps(created.get_json())
    assert listed.get_json()["users"][1]["usage"] == {
        "vms": 0,
        "cpu": 0,
        "ram_mb": 0,
        "disk_gb": 0,
    }


def test_admin_can_update_local_role_quotas_status_and_password(app):
    client = app.test_client()
    login(client)
    created = create_user(client).get_json()["user"]

    response = client.patch(
        f"/api/admin/users/{created['id']}",
        json={
            "password": "a-new-strong-password",
            "role": "operator",
            "is_active": False,
            "quota": {"vms": 5, "cpu": 12, "ram_mb": 24576, "disk_gb": 400},
        },
    )

    assert response.status_code == 200
    assert response.get_json()["user"] == {
        "id": created["id"],
        "username": "alice",
        "role": "operator",
        "authentication": "local",
        "is_active": False,
        "must_rotate_credentials": False,
        "quota": {"vms": 5, "cpu": 12, "ram_mb": 24576, "disk_gb": 400},
    }
    assert "password" not in json.dumps(response.get_json())
    with app.app_context():
        event = db.session.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "user.update")
            .order_by(AuditEvent.created_at.desc())
        ).first()
        assert event.details == {
            "role_before": "user",
            "role_after": "operator",
            "active_before": True,
            "active_after": False,
            "password_rotated": True,
        }


def test_admin_cannot_demote_or_disable_own_account(app):
    client = app.test_client()
    login(client)
    admin = client.get("/api/me").get_json()["user"]
    base = {
        "role": "admin",
        "is_active": True,
        "quota": admin["quota"],
    }

    demoted = client.patch(
        f"/api/admin/users/{admin['id']}", json={**base, "role": "user"}
    )
    disabled = client.patch(
        f"/api/admin/users/{admin['id']}", json={**base, "is_active": False}
    )

    assert demoted.status_code == 409
    assert disabled.status_code == 409
    assert demoted.get_json() == {"error": "self_admin_protection"}


def test_oidc_role_and_password_remain_managed_by_identity_provider(app):
    client = app.test_client()
    login(client)
    with app.app_context():
        user = User(
            username="oidc-user",
            password_hash=None,
            auth_provider="oidc",
            external_issuer="https://id.example/realms/portal",
            external_subject="oidc-subject",
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    response = client.patch(
        f"/api/admin/users/{user_id}",
        json={
            "password": "must-not-be-applied",
            "role": "admin",
            "is_active": True,
            "quota": {"vms": 3, "cpu": 8, "ram_mb": 16384, "disk_gb": 200},
        },
    )

    assert response.status_code == 409
    assert response.get_json() == {"error": "external_identity_managed"}


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
        ({"password": ""}, "password"),
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


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"role": "root"}, "role"),
        ({"is_active": "yes"}, "is_active"),
        ({"password": ""}, "password"),
        ({"quota": {"vms": -1, "cpu": 4, "ram_mb": 8192, "disk_gb": 100}}, "quota.vms"),
        ({"unexpected": True}, "unknown"),
    ],
)
def test_user_update_validation(app, change, field):
    client = app.test_client()
    login(client)
    user = create_user(client).get_json()["user"]
    payload = {
        "role": "user",
        "is_active": True,
        "quota": {"vms": 2, "cpu": 4, "ram_mb": 8192, "disk_gb": 100},
    }
    payload.update(change)

    response = client.patch(f"/api/admin/users/{user['id']}", json=payload)

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
    assert client.patch("/api/admin/users/1", json={}).status_code == 403
    assert client.get("/api/admin/audit-events").status_code == 403
    assert client.get("/api/admin/settings").status_code == 403
    assert client.patch(
        "/api/admin/settings", json={"guest_password_min_length": 1}
    ).status_code == 403
    with app.app_context():
        denied = db.session.scalar(
            select(db.func.count(AuditEvent.id)).where(AuditEvent.action == "authorization.denied")
        )
        assert denied == 6


@pytest.mark.parametrize("value", [0, 257, "8", None])
def test_guest_password_minimum_rejects_invalid_admin_values(app, value):
    client = app.test_client()
    login(client)
    response = client.patch(
        "/api/admin/settings", json={"guest_password_min_length": value}
    )
    assert response.status_code == 400
    assert "guest_password_min_length" in response.get_json()["errors"]


def test_guest_password_settings_reject_unknown_payload(app):
    client = app.test_client()
    login(client)
    response = client.patch("/api/admin/settings", json={"unknown": 8})
    assert response.status_code == 400
    assert "body" in response.get_json()["errors"]


def test_invalid_stored_guest_password_policy_falls_back_safely(app):
    client = app.test_client()
    login(client)
    with app.app_context():
        db.session.add(PortalSetting(key="guest_password_min_length", value="invalid"))
        db.session.commit()
    assert client.get("/api/me").get_json()["settings"] == {
        "guest_password_min_length": 8,
        "static_ipv4_networks": "",
        "default_vm_lifetime_days": 90,
        "max_vm_lifetime_days": 365,
        "expiration_warning_days": 14,
        "vm_approval_required": False,
    }


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
        assert {
            "users",
            "vm_allocations",
            "vm_operations",
            "worker_heartbeats",
            "audit_events",
            "netbox_configuration",
            "proxmox_configuration",
            "alembic_version",
        } <= set(inspect(db.engine).get_table_names())
        assert "expires_at" in {
            column["name"]
            for column in inspect(db.engine).get_columns("vm_allocations")
        }

    first = runner.invoke(args=["bootstrap-admin"])
    second = runner.invoke(args=["bootstrap-admin"])
    assert first.exit_code == 0
    assert "créé" in first.output
    assert second.exit_code != 0
    assert "déjà" in second.output
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
