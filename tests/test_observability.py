import csv
from datetime import UTC, datetime, timedelta
from io import StringIO

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import (
    AuditEvent,
    ProvisioningJob,
    User,
    VMAllocation,
    WorkerHeartbeat,
    db,
)
from portal.pve import FakePVEClient, PVETransportError

ADMIN_PASSWORD = "correct-horse-battery-staple"
METRICS_TOKEN = "metrics-token-with-at-least-thirty-two-characters"


def make_app(pve_client, metrics_token=""):
    return create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(ADMIN_PASSWORD),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
            "PORTAL_METRICS_TOKEN": metrics_token,
        },
        pve_client=pve_client,
    )


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": set(), "pve-b": set()})


@pytest.fixture
def app(pve_client):
    application = make_app(pve_client, METRICS_TOKEN)
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


def login(client, username="admin", password=ADMIN_PASSWORD):
    response = client.post(
        "/login", json={"username": username, "password": password}
    )
    if response.status_code == 200:
        client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()[
            "csrf_token"
        ]
    return response


def seed_metrics(app):
    with app.app_context():
        admin = db.session.scalar(select(User).where(User.username == "admin"))
        operator = User(
            username="private-operator-name",
            password_hash=generate_password_hash("operator-strong-password"),
            role="operator",
            is_active=False,
        )
        allocation = VMAllocation(
            owner_id=admin.id,
            name="private-vm-name",
            node="pve-a",
            vmid=101,
            cpu=2,
            ram_mb=2048,
            disk_gb=20,
            status="provisioning",
            upstream_request_id="UPID:private-task-id",
        )
        job = ProvisioningJob(
            allocation=allocation,
            status="attention",
            upstream_node="pve-a",
            error_code="pve_task_status_unknown",
            completed_at=datetime.now(UTC),
        )
        heartbeat = WorkerHeartbeat(
            worker_id="private-worker-id",
            last_seen_at=datetime.now(UTC) - timedelta(seconds=4),
        )
        db.session.add_all((operator, allocation, job, heartbeat))
        db.session.commit()


def test_metrics_are_disabled_without_a_token(pve_client):
    application = make_app(pve_client)
    assert application.test_client().get("/metrics").status_code == 404


def test_short_metrics_token_is_rejected(pve_client):
    with pytest.raises(ValueError, match="32 caractères"):
        make_app(pve_client, "too-short")


def test_metrics_require_exact_bearer_token_and_expose_only_aggregates(
    app, pve_client
):
    seed_metrics(app)
    client = app.test_client()

    missing = client.get("/metrics")
    invalid = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    response = client.get(
        "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"}
    )

    assert missing.status_code == 401
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert response.status_code == 200
    assert response.content_type == "text/plain; version=0.0.4; charset=utf-8"
    metrics = response.get_data(as_text=True)
    assert "portal_up 1" in metrics
    worker_age = next(
        int(line.split()[1])
        for line in metrics.splitlines()
        if line.startswith("portal_worker_last_seen_seconds ")
    )
    assert 4 <= worker_age <= 10
    assert 'portal_jobs{status="attention"} 1' in metrics
    assert 'portal_vm_allocations{status="provisioning"} 1' in metrics
    assert 'portal_users{role="operator",active="false"} 1' in metrics
    assert "portal_proxmox_online_nodes 2" in metrics
    assert "private-vm-name" not in metrics
    assert "private-operator-name" not in metrics
    assert "private-worker-id" not in metrics
    assert "UPID:private-task-id" not in metrics


def test_metrics_report_proxmox_failure_without_leaking_error(app, pve_client):
    pve_client.list_nodes = lambda: (_ for _ in ()).throw(
        PVETransportError("secret upstream detail")
    )
    response = app.test_client().get(
        "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"}
    )
    metrics = response.get_data(as_text=True)
    assert "portal_proxmox_reachable 0" in metrics
    assert "portal_proxmox_online_nodes 0" in metrics
    assert "secret" not in metrics


def test_admin_audit_export_is_downloadable_and_neutralizes_csv_formulas(app):
    with app.app_context():
        admin = db.session.scalar(select(User).where(User.username == "admin"))
        db.session.add(
            AuditEvent(
                actor_user_id=admin.id,
                action="test.export",
                target_type="vm",
                target_id="=2+2",
                outcome="success",
                request_id="request-export",
                details={"safe": "value"},
            )
        )
        db.session.commit()
    client = app.test_client()
    login(client)

    response = client.get("/api/admin/audit-events.csv?limit=2")

    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == (
        'attachment; filename="portal-audit.csv"'
    )
    rows = list(csv.DictReader(StringIO(response.get_data(as_text=True))))
    exported = next(row for row in rows if row["action"] == "test.export")
    assert exported["target_id"] == "'=2+2"
    assert exported["details"] == '{"safe": "value"}'


@pytest.mark.parametrize("limit", ["nope", "0", "5001"])
def test_audit_export_validates_limit(app, limit):
    client = app.test_client()
    login(client)
    response = client.get(f"/api/admin/audit-events.csv?limit={limit}")
    assert response.status_code == 400
    assert "limit" in response.get_json()["errors"]


def test_audit_export_requires_admin_role(app):
    anonymous = app.test_client()
    assert anonymous.get("/api/admin/audit-events.csv").status_code == 401
    with app.app_context():
        user = User(
            username="regular-user",
            password_hash=generate_password_hash("regular-user-strong-password"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
    regular = app.test_client()
    assert login(
        regular, "regular-user", "regular-user-strong-password"
    ).status_code == 200
    assert regular.get("/api/admin/audit-events.csv").status_code == 403
