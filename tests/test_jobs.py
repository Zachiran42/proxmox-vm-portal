from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import (
    AuditEvent,
    ImageProfile,
    ProvisioningJob,
    User,
    VMAllocation,
    db,
)
from portal.password_pusher import FakePasswordPusherClient
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
def password_pusher():
    return FakePasswordPusherClient(pushes=[])


@pytest.fixture
def app(pve_client, password_pusher):
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
        password_pusher_client=password_pusher,
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
            pve_client,
            app.extensions["password_pusher_client"],
            worker_id="test-worker",
            poll_seconds=0,
            lease_seconds=60,
        )


def create_cloud_profile(client):
    response = client.post(
        "/api/admin/image-profiles",
        json={
            "slug": "debian-cloud",
            "label": "Debian Cloud",
            "description": "Template cloud-init validé",
            "source_type": "cloud_init",
            "template_node": "pve-a",
            "template_vmid": 9000,
        },
    )
    assert response.status_code == 201


def enqueue_cloud(app, pve_client):
    pve_client.templates.add(("pve-a", 9000))
    client = app.test_client()
    login(client)
    create_cloud_profile(client)
    response = client.post(
        "/api/vms",
        json={
            **vm_payload("cloud-vm-01"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "mot de passe choisi !",
        },
    )
    assert response.status_code == 202
    return client, response.get_json()["job_id"]


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
            "source_type": "iso",
            "template_node": None,
            "template_vmid": None,
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


def test_owner_can_list_recent_jobs_with_safe_vm_details(app, pve_client):
    client, job_id = enqueue(app)

    response = client.get("/api/jobs")

    assert response.status_code == 200
    assert response.get_json()["jobs"] == [
        {
            "id": job_id,
            "vm_id": response.get_json()["jobs"][0]["vm_id"],
            "status": "queued",
            "stage": "create",
            "error_code": None,
            "created_at": response.get_json()["jobs"][0]["created_at"],
            "updated_at": response.get_json()["jobs"][0]["updated_at"],
            "vm": {
                "name": "worker-vm-01",
                "node": "pve-a",
                "vmid": None,
                "profile": "debian-12",
                "cpu": 2,
                "ram_mb": 4096,
                "disk_gb": 40,
                "guest_username": None,
                "status": "queued",
            },
        }
    ]


def test_job_history_never_lists_another_owners_jobs(app):
    enqueue(app)
    with app.app_context():
        user = User(
            username="history-user",
            password_hash=generate_password_hash("history-user-strong-password"),
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    client = app.test_client()
    with client.session_transaction() as portal_session:
        portal_session["user_id"] = user_id
        portal_session["authentication"] = "local"

    assert client.get("/api/jobs").get_json() == {"jobs": []}


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
            "source_type": "iso",
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


def test_admin_cannot_publish_an_unavailable_cloud_init_template(app):
    client = app.test_client()
    login(client)

    response = client.post(
        "/api/admin/image-profiles",
        json={
            "slug": "unverified-template",
            "label": "Unverified template",
            "description": "Must be rejected",
            "source_type": "cloud_init",
            "template_node": "pve-a",
            "template_vmid": 9130,
        },
    )

    assert response.status_code == 422
    assert response.get_json() == {
        "errors": {"template": "Template Proxmox indisponible ou non converti."}
    }
    assert len(client.get("/api/admin/image-profiles").get_json()["profiles"]) == 1


def test_cloud_init_profile_uses_selected_password_and_starts_vm(app, pve_client):
    client, job_id = enqueue_cloud(app, pve_client)

    assert run_step(app, pve_client) is True  # clone
    assert run_step(app, pve_client) is True  # configuration et démarrage
    with app.app_context():
        job = db.session.get(ProvisioningJob, job_id)
        assert job.stage == "start"
        assert job.status == "submitted"
        assert job.guest_password_ciphertext is None
        assert job.allocation.vmid == 100
    assert run_step(app, pve_client) is True  # suivi du démarrage

    result = client.get(f"/api/jobs/{job_id}").get_json()["job"]
    assert result["status"] == "succeeded"
    assert "guest_access" not in result
    assert pve_client.configurations[0]["username"] == "hugo"
    assert pve_client.configurations[0]["password"] == "mot de passe choisi !"
    assert pve_client.starts == [("pve-a", 100)]
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        assert not hasattr(allocation, "password")
        events = db.session.scalars(select(AuditEvent)).all()
        assert "mot de passe choisi !" not in str([event.details for event in events])


def test_operator_can_monitor_without_receiving_guest_password(app, pve_client):
    owner_client, job_id = enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    owner_job = owner_client.get(f"/api/jobs/{job_id}").get_json()["job"]
    assert "guest_password" not in str(owner_job)

    with app.app_context():
        operator = User(
            username="operator",
            password_hash=generate_password_hash("operator-password-strong"),
            role="operator",
        )
        db.session.add(operator)
        db.session.commit()
        operator_id = operator.id
    operator_client = app.test_client()
    with operator_client.session_transaction() as portal_session:
        portal_session["user_id"] = operator_id
        portal_session["authentication"] = "local"
    result = operator_client.get(f"/api/jobs/{job_id}").get_json()["job"]
    assert "guest_access" not in result


def test_cloud_init_requires_non_root_username_and_selected_password(app, pve_client):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)

    missing = client.post(
        "/api/vms", json={**vm_payload(), "profile": "debian-cloud"}
    )
    root = client.post(
        "/api/vms",
        json={
            **vm_payload(), "profile": "debian-cloud",
            "guest_username": "root", "guest_password": "password",
        },
    )
    iso_with_user = client.post(
        "/api/vms", json={**vm_payload(), "guest_username": "hugo"}
    )
    assert missing.status_code == 400
    assert root.status_code == 400
    assert iso_with_user.status_code == 400


def test_admin_controls_guest_password_minimum_without_complexity_rules(
    app, pve_client
):
    client = app.test_client()
    login(client)
    changed = client.patch(
        "/api/admin/settings", json={"guest_password_min_length": 12}
    )
    assert changed.status_code == 200
    assert client.get("/api/admin/settings").get_json()["settings"] == {
        "guest_password_min_length": 12
    }
    changed_again = client.patch(
        "/api/admin/settings", json={"guest_password_min_length": 10}
    )
    assert changed_again.status_code == 200
    assert client.get("/api/me").get_json()["settings"] == {
        "guest_password_min_length": 10
    }
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)

    short = client.post(
        "/api/vms",
        json={
            **vm_payload("short-password"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "123456789",
        },
    )
    selected = " douze mots ! "
    accepted = client.post(
        "/api/vms",
        json={
            **vm_payload("chosen-password"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": selected,
        },
    )

    assert short.status_code == 400
    assert "guest_password" in short.get_json()["errors"]
    assert accepted.status_code == 202
    assert selected not in accepted.get_data(as_text=True)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.guest_password_ciphertext
        assert selected not in job.guest_password_ciphertext
        assert selected not in str(
            [event.details for event in db.session.scalars(select(AuditEvent)).all()]
        )


def test_cloud_profile_distinguishes_missing_password_and_iso_password(app, pve_client):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)

    missing_password = client.post(
        "/api/vms",
        json={
            **vm_payload("missing-password"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
        },
    )
    iso_password = client.post(
        "/api/vms",
        json={**vm_payload("iso-password"), "guest_password": "anything"},
    )

    assert missing_password.status_code == 400
    assert "guest_password" in missing_password.get_json()["errors"]
    assert iso_password.status_code == 400
    assert "guest_username" in iso_password.get_json()["errors"]


def test_guest_configuration_retry_keeps_selected_password(app, pve_client):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    original_configure = pve_client.configure_cloud_init_vm
    pve_client.configure_cloud_init_vm = lambda **_kwargs: (_ for _ in ()).throw(
        PVETransportError("temporary")
    )

    run_step(app, pve_client)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "submitted"
        assert job.error_code == "pve_guest_config_unavailable"
        assert job.guest_password_ciphertext is not None

    pve_client.configure_cloud_init_vm = original_configure
    run_step(app, pve_client)
    assert pve_client.configurations[0]["password"] == "mot de passe choisi !"


def test_cloud_init_start_ambiguity_does_not_retain_password(
    app, pve_client
):
    client, job_id = enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    pve_client.start_vm = lambda _node, _vmid: (_ for _ in ()).throw(
        PVETransportError("uncertain")
    )

    run_step(app, pve_client)

    result = client.get(f"/api/jobs/{job_id}").get_json()["job"]
    assert result["status"] == "attention"
    assert result["error_code"] == "pve_start_unknown"
    assert "guest_access" not in result
    with app.app_context():
        assert db.session.get(ProvisioningJob, job_id).guest_password_ciphertext is None


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (
            PVETransportError("temporary"),
            "submitted",
            "pve_guest_config_unavailable",
        ),
        (PVEProtocolError("invalid"), "attention", "pve_guest_config_failed"),
    ],
)
def test_cloud_init_configuration_errors_are_classified(
    app, pve_client, error, expected_status, expected_code
):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    pve_client.configure_cloud_init_vm = lambda **_kwargs: (_ for _ in ()).throw(
        error
    )

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == expected_status
        assert job.error_code == expected_code


def test_guest_configuration_stops_after_five_attempts(app, pve_client):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        db.session.scalar(select(ProvisioningJob)).credential_attempts = 4
        db.session.commit()
    pve_client.configure_cloud_init_vm = lambda **_kwargs: (_ for _ in ()).throw(
        PVETransportError("temporary")
    )

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.credential_attempts == 5


def test_failed_start_task_requires_manual_review(app, pve_client):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    pve_client.task_statuses = [{"status": "stopped", "exitstatus": "ERROR"}]

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "pve_start_failed"


def test_invalid_or_unconfigured_guest_bootstrap_requires_attention(
    app, pve_client
):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.allocation.guest_username = None
        db.session.commit()
    run_step(app, pve_client)
    with app.app_context():
        assert db.session.scalar(select(ProvisioningJob)).error_code == "guest_bootstrap_invalid"

    # Même clone, remis en suivi pour simuler la perte du secret chiffré.
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.status = "submitted"
        job.error_code = None
        job.completed_at = None
        job.allocation.guest_username = "hugo"
        job.guest_password_ciphertext = None
        db.session.commit()
        process_next_job(
            pve_client,
            None,
            worker_id="test-worker",
            poll_seconds=0,
            lease_seconds=60,
        )
        assert db.session.scalar(select(ProvisioningJob)).error_code == "guest_password_unavailable"


def test_corrupted_encrypted_guest_password_requires_attention(app, pve_client):
    enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        job.guest_password_ciphertext = "not-a-valid-fernet-token"
        db.session.commit()

    run_step(app, pve_client)

    with app.app_context():
        job = db.session.scalar(select(ProvisioningJob))
        assert job.status == "attention"
        assert job.error_code == "guest_password_unavailable"
