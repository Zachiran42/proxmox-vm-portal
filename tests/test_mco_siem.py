from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import (
    AuditEvent,
    SiemConfiguration,
    User,
    VMAllocation,
    VMMaintenanceJob,
    db,
)
from portal.pve import FakePVEClient


@pytest.fixture
def app():
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
        pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
    )
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


def login(client, username="admin", password="correct-horse-battery-staple"):
    response = client.post("/login", json={"username": username, "password": password})
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def seed_mco_data(app):
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        allocation = VMAllocation(
            owner_id=owner.id,
            name="mco-test-01",
            node="pve-a",
            vmid=301,
            cpu=2,
            ram_mb=4096,
            disk_gb=40,
            status="running",
            network_policy="isolated",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        maintenance = VMMaintenanceJob(
            allocation=allocation,
            actor_user_id=owner.id,
            action="scan",
            status="succeeded",
            report={
                "available_count": 3,
                "remaining_count": 3,
                "reboot_required": True,
            },
            completed_at=datetime.now(UTC),
        )
        db.session.add_all((allocation, maintenance))
        db.session.commit()
        return allocation.id


def test_mco_report_aggregates_actionable_state_and_exports_csv(app):
    vm_id = seed_mco_data(app)
    client = app.test_client()
    login(client)

    response = client.get("/api/admin/mco/report")

    assert response.status_code == 200
    report = response.get_json()["report"]
    assert report["summary"] == {
        "machines": 1,
        "updates_available": 1,
        "reboot_required": 1,
        "never_scanned": 0,
        "maintenance_failures": 0,
        "expired": 1,
        "lifecycle_warning": 0,
        "isolated": 1,
        "obsolete_images": 1,
        "sandbox_release_requests": 0,
    }
    assert {item["category"] for item in report["items"]} == {
        "updates_available",
        "reboot_required",
        "vm_expired",
        "image_lifecycle",
    }
    assert all(item["vm_id"] == vm_id for item in report["items"])

    exported = client.get("/api/admin/mco/report.csv")
    assert exported.status_code == 200
    assert exported.headers["Cache-Control"] == "no-store"
    assert "mco-test-01" in exported.get_data(as_text=True)
    assert "updates_available" in exported.get_data(as_text=True)


def test_siem_pull_is_disabled_by_default_and_token_is_never_returned(app):
    client = app.test_client()
    login(client)

    initial = client.get("/api/admin/integrations/siem").get_json()["integration"]
    assert initial == {
        "configured": False,
        "source": "none",
        "token_configured": False,
        "minimum_outcome": "all",
        "enabled": False,
        "pull_endpoint": "/api/siem/events",
    }
    assert client.get("/api/siem/events").status_code == 404

    token = "siem-collector-token-that-is-long-enough-2026"
    saved = client.put(
        "/api/admin/integrations/siem",
        json={"pull_token": token, "minimum_outcome": "failure", "enabled": True},
    )
    assert saved.status_code == 200
    assert "pull_token" not in saved.get_json()["integration"]
    with app.app_context():
        configuration = db.session.get(SiemConfiguration, 1)
        assert token not in configuration.pull_token_ciphertext
        event = db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "integration.siem.update")
        )
        assert token not in json.dumps(event.details)


def test_siem_pull_filters_events_and_uses_a_stable_cursor(app):
    client = app.test_client()
    login(client)
    token = "siem-collector-token-that-is-long-enough-2026"
    assert client.put(
        "/api/admin/integrations/siem",
        json={"pull_token": token, "minimum_outcome": "failure", "enabled": True},
    ).status_code == 200
    assert client.get(
        "/api/siem/events", headers={"Authorization": "Bearer wrong-token"}
    ).status_code == 401
    with app.app_context():
        db.session.add(
            AuditEvent(
                action="test.failure",
                target_type="test",
                target_id="safe-target",
                outcome="failure",
                request_id="00000000-0000-0000-0000-000000000001",
                details={"reason": "controlled"},
            )
        )
        db.session.commit()

    pulled = client.get(
        "/api/siem/events?limit=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert pulled.status_code == 200
    assert pulled.mimetype == "application/x-ndjson"
    events = [json.loads(line) for line in pulled.get_data(as_text=True).splitlines()]
    assert events
    assert {event["event"]["outcome"] for event in events} <= {"failure", "denied"}
    assert any(event["event"]["action"] == "test.failure" for event in events)
    assert token not in pulled.get_data(as_text=True)

    after = pulled.headers["X-Portal-SIEM-Next-After"]
    after_id = pulled.headers["X-Portal-SIEM-Next-After-ID"]
    second = client.get(
        f"/api/siem/events?after={after}&after_id={after_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert second.status_code == 200
    assert second.get_data(as_text=True) == ""


def test_siem_pull_rejects_bad_queries_and_throttles_invalid_tokens(app):
    client = app.test_client()
    login(client)
    token = "siem-collector-token-that-is-long-enough-2026"
    assert client.put(
        "/api/admin/integrations/siem",
        json={"pull_token": token, "minimum_outcome": "all", "enabled": True},
    ).status_code == 200
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/siem/events?unknown=1", headers=headers).status_code == 400
    assert client.get("/api/siem/events?limit=1001", headers=headers).status_code == 400
    assert client.get("/api/siem/events?after=2026-01-01", headers=headers).status_code == 400
    assert client.get(
        "/api/siem/events?after_id=not-a-uuid", headers=headers
    ).status_code == 400

    wrong = {"Authorization": "Bearer invalid-collector-token"}
    for _ in range(20):
        assert client.get("/api/siem/events", headers=wrong).status_code == 401
    throttled = client.get("/api/siem/events", headers=wrong)
    assert throttled.status_code == 429
    assert throttled.headers["Retry-After"] == "900"


@pytest.mark.parametrize(
    "payload,field",
    [
        ({"enabled": True, "minimum_outcome": "all"}, "pull_token"),
        ({"pull_token": "short", "enabled": True}, "pull_token"),
        (
            {
                "pull_token": "x" * 32,
                "minimum_outcome": "critical",
                "enabled": True,
            },
            "minimum_outcome",
        ),
    ],
)
def test_siem_configuration_validation(app, payload, field):
    client = app.test_client()
    login(client)

    response = client.put("/api/admin/integrations/siem", json=payload)

    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_operator_can_read_mco_but_cannot_configure_siem(app):
    with app.app_context():
        db.session.add(
            User(
                username="operator",
                password_hash=generate_password_hash("operator-password"),
                role="operator",
            )
        )
        db.session.commit()
    client = app.test_client()
    login(client, "operator", "operator-password")

    assert client.get("/api/admin/mco/report").status_code == 200
    assert client.get("/api/admin/mco/report.csv").status_code == 200
    assert client.get("/api/admin/integrations/siem").status_code == 403

    anonymous = app.test_client()
    assert anonymous.get("/api/admin/mco/report").status_code == 401
    assert anonymous.get("/api/admin/mco/report.csv").status_code == 401
