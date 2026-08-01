from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import AuditEvent, ImageProfile, ProvisioningJob, VMAllocation, db
from portal.pve import (
    FakePVEClient,
    PVEHTTPError,
    PVEProtocolError,
    PVETransportError,
)


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
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(
                "correct-horse-battery-staple"
            ),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def login(client):
    response = client.post(
        "/login",
        json={
            "username": "admin",
            "password": "correct-horse-battery-staple",
        },
    )
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def vm_payload(name="worker-vm-01"):
    return {
        "name": name,
        "node": "pve-a",
        "profile": "debian-12",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
    }


def enqueue(app):
    client = app.test_client()
    login(client)
    response = client.post("/api/vms", json=vm_payload())
    assert response.status_code == 202
    return client, response.get_json()["job_id"]


def run_step(app, pve_client):
    with app.app_context():
        return process_next_job(
            pve_client, worker_id="test-worker", poll_seconds=0, lease_seconds=60
        )


def test_worker_submits_and_reconciles_successful_proxmox_task(app, pve_client):
    client, job_id = enqueue(app)

    assert run_step(app, pve_client) is True
    with app.app_context():
        job = db.session.get(ProvisioningJob, job_id)
        assert job.status == "submitted"
        assert job.allocation.status == "provisioning"
        assert job.allocation.upstream_request_id == "UPID:fake:1"
    assert pve_client.requests == [
        {
            "name": "worker-vm-01",
            "node": "pve-a",
            "iso": "local:iso/debian-12.iso",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        }
    ]

    assert run_step(app, pve_client) is True
    response = client.get(f"/api/jobs/{job_id}")
    assert response.get_json()["job"]["status"] == "succeeded"
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        assert allocation.status == "accepted"
        event = db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.provision")
        )
        assert event.outcome == "success"


def test_running_task_is_rescheduled_before_success(app, pve_client):
    pve_client.task_statuses = [
        {"status": "running"},
        {"status": "stopped", "exitstatus": "OK"},
    ]
    enqueue(app)
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True
    with app.app_context():
        assert db.session.scalar(select(ProvisioningJob)).status == "submitted"
    assert run_step(app, pve_client) is True
    with app.app_context():
        assert db.session.scalar(select(ProvisioningJob)).status == "succeeded"


def test_missing_iso_fails_job_and_releases_quota(app, pve_client):
    pve_client.accessible_isos.clear()
    client, job_id = enqueue(app)

    assert run_step(app, pve_client) is True

    response = client.get(f"/api/jobs/{job_id}")
    assert response.get_json()["job"]["error_code"] == "iso_unavailable"
    assert client.get("/api/me").get_json()["usage"] == {
        "vms": 0,
        "cpu": 0,
        "ram_mb": 0,
        "disk_gb": 0,
    }


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (PVETransportError("temporary"), "queued", "pve_inventory_unavailable"),
        (PVEHTTPError(503, "temporary"), "queued", "pve_inventory_unavailable"),
        (PVEProtocolError("invalid"), "failed", "pve_inventory_invalid"),
    ],
)
def test_inventory_errors_are_classified(app, pve_client, error, expected_status, expected_code):
    enqueue(app)
    pve_client.is_iso_available = lambda _node, _iso: (_ for _ in ()).throw(error)

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == expected_status
        assert job.error_code == expected_code


def test_disabled_profile_stops_queued_job(app, pve_client):
    enqueue(app)
    with app.app_context():
        db.session.scalar(select(ImageProfile)).enabled = False
        db.session.commit()

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "failed"
        assert job.error_code == "image_profile_unavailable"
    assert pve_client.requests == []


def test_rejected_submission_is_terminal_but_transport_ambiguity_is_not(app, pve_client):
    enqueue(app)
    pve_client.create_vm = lambda _payload: (_ for _ in ()).throw(
        PVEHTTPError(403, "secret upstream rejection")
    )
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "failed"
        assert job.error_code == "pve_submission_rejected"


@pytest.mark.parametrize(
    "error",
    [PVEHTTPError(500, "uncertain"), PVEHTTPError(429, "uncertain")],
)
def test_ambiguous_http_submission_requires_attention(app, pve_client, error):
    enqueue(app)
    pve_client.create_vm = lambda _payload: (_ for _ in ()).throw(error)

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "pve_submission_unknown"


def test_poll_transport_error_retries_without_duplicate_creation(app, pve_client):
    enqueue(app)
    run_step(app, pve_client)
    original = pve_client.get_task_status
    pve_client.get_task_status = lambda _node, _upid: (_ for _ in ()).throw(
        PVETransportError("temporary")
    )
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "submitted"
        assert job.error_code == "pve_temporarily_unavailable"
    pve_client.get_task_status = original
    run_step(app, pve_client)
    assert len(pve_client.requests) == 1


@pytest.mark.parametrize(
    "error",
    [PVEHTTPError(404, "missing"), PVEProtocolError("invalid")],
)
def test_unknown_task_status_requires_manual_attention(app, pve_client, error):
    enqueue(app)
    run_step(app, pve_client)
    pve_client.get_task_status = lambda _node, _upid: (_ for _ in ()).throw(error)

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "pve_task_status_unknown"
        assert job.allocation.status == "provisioning"


def test_failed_proxmox_task_is_terminal(app, pve_client):
    pve_client.task_statuses = [{"status": "stopped", "exitstatus": "ERROR"}]
    enqueue(app)
    run_step(app, pve_client)
    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "failed"
        assert job.error_code == "pve_task_failed"


def test_missing_upid_requires_manual_attention(app, pve_client):
    enqueue(app)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.status = "submitted"
        db.session.commit()

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "missing_upstream_task"


def test_stale_worker_leases_are_recovered_safely(app, pve_client):
    enqueue(app)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.status = "submitting"
        job.locked_at = datetime.now(UTC) - timedelta(minutes=10)
        job.locked_by = "dead-worker"
        db.session.commit()

    assert run_step(app, pve_client) is False

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "worker_crashed_during_submission"
        event = db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.provision")
        )
        assert event.details == {"reason": "worker_crashed_during_submission"}


@pytest.mark.parametrize(
    ("stale_status", "recovered_status"),
    [("validating", "queued"), ("polling", "submitted")],
)
def test_stale_retryable_leases_return_to_queue(app, pve_client, stale_status, recovered_status):
    enqueue(app)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.status = stale_status
        job.available_at = datetime.now(UTC) + timedelta(hours=1)
        job.locked_at = datetime.now(UTC) - timedelta(minutes=10)
        job.locked_by = "dead-worker"
        if stale_status == "polling":
            job.allocation.upstream_request_id = "UPID:fake:existing"
        db.session.commit()

    assert run_step(app, pve_client) is False

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == recovered_status
        assert job.locked_at is None


def test_admin_manages_approved_image_profiles(app):
    client = app.test_client()
    login(client)
    created = client.post(
        "/api/admin/image-profiles",
        json={
            "slug": "ubuntu-2404",
            "label": "Ubuntu 24.04",
            "description": "Installation approuvée",
            "iso": "local:iso/ubuntu-24.04.iso",
        },
    )
    assert created.status_code == 201
    assert len(client.get("/api/image-profiles").get_json()["profiles"]) == 2

    disabled = client.patch(
        "/api/admin/image-profiles/ubuntu-2404", json={"enabled": False}
    )
    assert disabled.status_code == 200
    assert disabled.get_json()["profile"]["enabled"] is False
    assert len(client.get("/api/image-profiles").get_json()["profiles"]) == 1
    assert len(client.get("/api/admin/image-profiles").get_json()["profiles"]) == 2
