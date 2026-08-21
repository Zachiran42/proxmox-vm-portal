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
    NetBoxConfiguration,
    ProvisioningJob,
    ProxmoxConfiguration,
    User,
    VMAllocation,
    db,
)
from portal.netbox import FakeNetBoxClient, NetBoxUnavailable
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
def netbox_client():
    return FakeNetBoxClient(reservations={}, prefixes={42: "10.10.12.0/24"})


@pytest.fixture
def app(pve_client, password_pusher, netbox_client):
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
        netbox_client=netbox_client,
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
            app.extensions["netbox_client"],
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
    lifecycle = response.get_json()["jobs"][0]["vm"]["lifecycle"]

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
            "archived_at": None,
            "vm": {
                "name": "worker-vm-01",
                "node": "pve-a",
                "vmid": None,
                "profile": "debian-12",
                "cpu": 2,
                "ram_mb": 4096,
                "disk_gb": 40,
                "guest_username": None,
                "network_mode": "dhcp",
                "automatic_ip": False,
                "network_profile": None,
                "ipv4_cidr": None,
                "gateway": None,
                "dns_servers": [],
                "last_ipv4": None,
                "network_observed_at": None,
                "status": "queued",
                "approval": {
                    "status": "not_required",
                    "requested_at": None,
                    "decided_at": None,
                    "reason": None,
                },
                "lifecycle": {
                    "state": "active",
                    "expires_at": lifecycle["expires_at"],
                    "days_remaining": 90,
                },
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


def test_cloud_init_static_ipv4_is_allowlisted_reserved_and_sent_to_pve(
    app, pve_client
):
    client = app.test_client()
    login(client)
    assert client.patch(
        "/api/admin/settings",
        json={
            "guest_password_min_length": 8,
            "static_ipv4_networks": "192.168.10.0/24\n192.168.10.0/24",
        },
    ).get_json()["settings"]["static_ipv4_networks"] == "192.168.10.0/24"
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    payload = {
        **vm_payload("fixed-vm"),
        "profile": "debian-cloud",
        "guest_username": "hugo",
        "guest_password": "password",
        "network_mode": "static",
        "ipv4_cidr": "192.168.10.50/24",
        "gateway": "192.168.10.254",
        "dns_servers": ["192.168.10.10", "192.168.10.11"],
    }

    created = client.post("/api/vms", json=payload)
    assert created.status_code == 202
    run_step(app, pve_client)
    run_step(app, pve_client)
    assert pve_client.configurations[0]["network_mode"] == "static"
    assert pve_client.configurations[0]["ipv4_cidr"] == "192.168.10.50/24"
    assert pve_client.configurations[0]["gateway"] == "192.168.10.254"
    assert pve_client.configurations[0]["dns_servers"] == [
        "192.168.10.10",
        "192.168.10.11",
    ]

    duplicate = client.post("/api/vms", json={**payload, "name": "fixed-vm-2"})
    assert duplicate.status_code == 400
    assert "déjà réservée" in duplicate.get_json()["errors"]["ipv4_cidr"]


def test_vlan_profile_reserves_configures_and_releases_netbox(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    profile_payload = {
        "slug": "chu-vlan-12",
        "label": "CHU VLAN 12",
        "cidr": "10.10.12.0/24",
        "gateway": "10.10.12.254",
        "dns_servers": ["10.10.1.10", "10.10.1.11"],
        "bridge": "vmbr0",
        "vlan_tag": 12,
        "netbox_prefix_id": 42,
        "enabled": True,
    }
    assert client.post("/api/admin/network-profiles", json=profile_payload).status_code == 201
    assert client.get("/api/network-profiles").get_json()["profiles"][0]["netbox_managed"] is True
    response = client.post(
        "/api/vms",
        json={
            **vm_payload("chu-vm-01"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "password",
            "network_profile": "chu-vlan-12",
            "network_mode": "static",
            "ipv4_cidr": "10.10.12.50/24",
            "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10", "10.10.1.11"],
        },
    )
    assert response.status_code == 202
    vm_id = response.get_json()["vm_id"]
    assert run_step(app, pve_client) is True
    assert netbox_client.reservations == {1: "10.10.12.50/24"}
    assert run_step(app, pve_client) is True
    assert pve_client.configurations[0]["bridge"] == "vmbr0"
    assert pve_client.configurations[0]["vlan_tag"] == 12
    assert run_step(app, pve_client) is True

    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        allocation.status = "stopped"
        pve_client.vm_statuses[(allocation.node, allocation.vmid)] = "stopped"
        db.session.commit()
    assert client.post(
        f"/api/vms/{vm_id}/actions",
        json={"action": "delete", "confirm_name": "chu-vm-01"},
    ).status_code == 202
    assert run_step(app, pve_client) is True
    assert run_step(app, pve_client) is True
    assert netbox_client.reservations == {}


def test_vlan_profile_enforces_values_and_netbox_conflicts(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    assert client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "chu-vlan-12",
            "label": "CHU VLAN 12",
            "cidr": "10.10.12.0/24",
            "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"],
            "bridge": "vmbr0",
            "vlan_tag": 12,
            "netbox_prefix_id": 42,
            "enabled": True,
        },
    ).status_code == 201
    payload = {
        **vm_payload("chu-vm-conflict"),
        "profile": "debian-cloud",
        "guest_username": "hugo",
        "guest_password": "password",
        "network_profile": "chu-vlan-12",
        "network_mode": "static",
        "ipv4_cidr": "10.10.12.51/24",
        "gateway": "10.10.12.254",
        "dns_servers": ["10.10.1.10"],
    }
    assert client.post("/api/vms", json={**payload, "gateway": "10.10.12.1"}).status_code == 400
    netbox_client.reservations[99] = "10.10.12.51/24"
    created = client.post("/api/vms", json=payload)
    assert created.status_code == 202
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.get(ProvisioningJob, created.get_json()["job_id"])
        assert job.status == "failed"
        assert job.error_code == "netbox_ip_conflict"


def test_admin_network_profile_crud_and_validation(app, netbox_client):
    client = app.test_client()
    login(client)
    assert app.test_cli_runner().invoke(args=["check-netbox"]).exit_code == 0
    assert client.post("/api/admin/network-profiles", data="bad").status_code == 400
    assert client.post("/api/admin/network-profiles", json={}).status_code == 400
    invalid = client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "BAD",
            "label": "",
            "cidr": "0.0.0.0/2",
            "gateway": "invalid",
            "dns_servers": ["invalid"],
            "bridge": "?",
            "vlan_tag": 4095,
            "netbox_prefix_id": 0,
            "enabled": "yes",
            "unexpected": True,
        },
    )
    assert invalid.status_code == 400
    assert set(invalid.get_json()["errors"]) == {
        "unknown", "slug", "label", "cidr", "gateway", "dns_servers",
        "bridge", "vlan_tag", "netbox_prefix_id", "enabled",
    }
    gateway_on_network = {
        "slug": "bad-gateway", "label": "Bad gateway",
        "cidr": "10.10.12.0/24", "gateway": "10.10.12.0",
        "dns_servers": ["10.10.1.10"], "bridge": "vmbr0",
        "vlan_tag": None, "netbox_prefix_id": None, "enabled": True,
    }
    assert client.post(
        "/api/admin/network-profiles", json=gateway_on_network
    ).status_code == 400
    payload = {
        "slug": "chu-vlan-12",
        "label": "CHU VLAN 12",
        "cidr": "10.10.12.0/24",
        "gateway": "10.10.12.254",
        "dns_servers": ["10.10.1.10"],
        "bridge": "vmbr0",
        "vlan_tag": 12,
        "netbox_prefix_id": 42,
        "enabled": True,
    }
    assert client.post("/api/admin/network-profiles", json=payload).status_code == 201
    assert client.post("/api/admin/network-profiles", json=payload).status_code == 409
    listed = client.get("/api/admin/network-profiles").get_json()
    assert listed["netbox_enabled"] is True
    assert listed["profiles"][0]["netbox_prefix_id"] == 42
    assert client.patch("/api/admin/network-profiles/missing", json={}).status_code == 404
    assert client.patch(
        "/api/admin/network-profiles/chu-vlan-12", data="bad"
    ).status_code == 400
    assert client.patch(
        "/api/admin/network-profiles/chu-vlan-12", json={"bridge": "?"}
    ).status_code == 400
    updated = client.patch(
        "/api/admin/network-profiles/chu-vlan-12",
        json={"label": "VLAN production", "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.get_json()["profile"]["label"] == "VLAN production"
    netbox_client.unavailable = True
    assert client.patch(
        "/api/admin/network-profiles/chu-vlan-12", json={"enabled": True}
    ).status_code == 502


def test_netbox_outages_retry_without_replaying_proxmox(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    assert client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "chu-vlan-12", "label": "CHU VLAN 12",
            "cidr": "10.10.12.0/24", "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"], "bridge": "vmbr0",
            "vlan_tag": 12, "netbox_prefix_id": 42, "enabled": True,
        },
    ).status_code == 201
    created = client.post(
        "/api/vms",
        json={
            **vm_payload("chu-retry"), "profile": "debian-cloud",
            "guest_username": "hugo", "guest_password": "password",
            "network_profile": "chu-vlan-12", "network_mode": "static",
            "ipv4_cidr": "10.10.12.60/24", "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"],
        },
    )
    job_id = created.get_json()["job_id"]
    netbox_client.unavailable = True
    run_step(app, pve_client)
    with app.app_context():
        assert db.session.get(ProvisioningJob, job_id).error_code == "netbox_unavailable"
    assert pve_client.requests == []
    netbox_client.unavailable = False
    run_step(app, pve_client)
    run_step(app, pve_client)
    netbox_client.unavailable = True
    run_step(app, pve_client)
    with app.app_context():
        assert db.session.get(ProvisioningJob, job_id).error_code == "netbox_activation_failed"
    assert len(pve_client.requests) == 1
    netbox_client.unavailable = False
    run_step(app, pve_client)
    with app.app_context():
        assert db.session.get(ProvisioningJob, job_id).status == "succeeded"


@pytest.mark.parametrize("release_fails", [False, True])
def test_rejected_proxmox_clone_releases_netbox_reservation(
    app, pve_client, netbox_client, release_fails
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    assert client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "chu-vlan-12", "label": "CHU VLAN 12",
            "cidr": "10.10.12.0/24", "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"], "bridge": "vmbr0",
            "vlan_tag": 12, "netbox_prefix_id": 42, "enabled": True,
        },
    ).status_code == 201
    created = client.post(
        "/api/vms",
        json={
            **vm_payload("chu-rejected"), "profile": "debian-cloud",
            "guest_username": "hugo", "guest_password": "password",
            "network_profile": "chu-vlan-12", "network_mode": "static",
            "ipv4_cidr": "10.10.12.70/24", "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"],
        },
    )
    pve_client.create_vm = lambda _request: (_ for _ in ()).throw(
        PVEHTTPError(403, "denied")
    )
    if release_fails:
        netbox_client.release_ip = lambda _ip_id: (_ for _ in ()).throw(
            NetBoxUnavailable("offline")
        )
    run_step(app, pve_client)
    with app.app_context():
        job = db.session.get(ProvisioningJob, created.get_json()["job_id"])
        assert job.status == ("attention" if release_fails else "failed")
        assert job.error_code == (
            "netbox_release_failed" if release_fails else "pve_submission_rejected"
        )
    if not release_fails:
        assert netbox_client.reservations == {}


def test_admin_configures_proxmox_and_netbox_without_exposing_secrets(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)

    proxmox = client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.chu.example:8006/api2/json",
            "token_id": "portal@pve!provisioning",
            "token_secret": "pve-secret-value",
            "enabled": True,
        },
    )
    assert proxmox.status_code == 200
    assert proxmox.get_json()["integration"]["nodes"] == ["pve-a"]
    assert "pve-secret-value" not in proxmox.get_data(as_text=True)

    netbox = client.put(
        "/api/admin/integrations/netbox",
        json={
            "base_url": "https://netbox.chu.example",
            "api_token": "netbox-secret-value",
            "enabled": True,
        },
    )
    assert netbox.status_code == 200
    assert "netbox-secret-value" not in netbox.get_data(as_text=True)

    with app.app_context():
        pve_configuration = db.session.get(ProxmoxConfiguration, 1)
        netbox_configuration = db.session.get(NetBoxConfiguration, 1)
        assert "pve-secret-value" not in pve_configuration.token_secret_ciphertext
        assert "netbox-secret-value" not in netbox_configuration.api_token_ciphertext

    assert client.get("/api/admin/integrations/proxmox").get_json()["integration"] == {
        "api_url": "https://pve.chu.example:8006/api2/json",
        "ca_configured": False,
        "configured": True,
        "enabled": True,
        "source": "portal",
        "token_configured": True,
        "token_id": "portal@pve!provisioning",
    }
    assert client.get("/api/admin/integrations/netbox").get_json()["integration"] == {
        "base_url": "https://netbox.chu.example",
        "ca_configured": False,
        "configured": True,
        "enabled": True,
        "source": "portal",
        "token_configured": True,
    }


def test_integration_configuration_validates_secrets_and_ca(app):
    client = app.test_client()
    login(client)
    assert client.put(
        "/api/admin/integrations/netbox",
        json={"base_url": "http://netbox.example", "enabled": True},
    ).status_code == 400
    invalid_ca = client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.example:8006/api2/json",
            "token_id": "portal@pve!token",
            "token_secret": "secret",
            "ca_certificate": "-----BEGIN PRIVATE KEY-----",
            "enabled": True,
        },
    )
    assert invalid_ca.status_code == 400
    assert "privée" in invalid_ca.get_json()["errors"]["ca_certificate"]


def test_integration_configuration_handles_missing_and_unavailable_credentials(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)

    for endpoint in ("netbox", "proxmox"):
        response = client.put(
            f"/api/admin/integrations/{endpoint}",
            data="[]",
            content_type="application/json",
        )
        assert response.status_code == 400
        assert "body" in response.get_json()["errors"]

    assert client.put(
        "/api/admin/integrations/netbox",
        json={"base_url": "https://netbox.example", "enabled": False},
    ).status_code == 400
    assert client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.example:8006/api2/json",
            "token_id": "portal@pve!token",
            "enabled": False,
        },
    ).status_code == 400

    netbox_client.unavailable = True
    assert client.put(
        "/api/admin/integrations/netbox",
        json={
            "base_url": "https://netbox.example",
            "api_token": "secret",
            "enabled": True,
        },
    ).status_code == 502
    netbox_client.unavailable = False

    original_list_nodes = pve_client.list_nodes
    pve_client.list_nodes = lambda: []
    assert client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.example:8006/api2/json",
            "token_id": "portal@pve!token",
            "token_secret": "secret",
            "enabled": True,
        },
    ).status_code == 422
    pve_client.list_nodes = lambda: (_ for _ in ()).throw(PVETransportError("offline"))
    assert client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.example:8006/api2/json",
            "token_id": "portal@pve!token",
            "token_secret": "secret",
            "enabled": True,
        },
    ).status_code == 502
    pve_client.list_nodes = original_list_nodes


def test_integration_configuration_retains_and_detects_corrupt_secrets(app):
    client = app.test_client()
    login(client)
    proxmox_payload = {
        "api_url": "https://pve.example:8006/api2/json",
        "token_id": "portal@pve!token",
        "token_secret": "first-secret",
        "enabled": False,
    }
    netbox_payload = {
        "base_url": "https://netbox.example",
        "api_token": "first-token",
        "enabled": False,
    }
    assert client.put(
        "/api/admin/integrations/proxmox", json=proxmox_payload
    ).status_code == 200
    assert client.put(
        "/api/admin/integrations/netbox", json=netbox_payload
    ).status_code == 200

    proxmox_payload.pop("token_secret")
    netbox_payload.pop("api_token")
    assert client.put(
        "/api/admin/integrations/proxmox", json=proxmox_payload
    ).status_code == 200
    assert client.put(
        "/api/admin/integrations/netbox", json=netbox_payload
    ).status_code == 200

    with app.app_context():
        db.session.get(ProxmoxConfiguration, 1).token_secret_ciphertext = "corrupt"
        db.session.get(NetBoxConfiguration, 1).api_token_ciphertext = "corrupt"
        db.session.commit()
    assert client.put(
        "/api/admin/integrations/proxmox", json=proxmox_payload
    ).status_code == 409
    assert client.put(
        "/api/admin/integrations/netbox", json=netbox_payload
    ).status_code == 409


def test_integration_configuration_rejects_malformed_public_ca(app):
    client = app.test_client()
    login(client)
    assert client.put(
        "/api/admin/integrations/netbox",
        json={
            "base_url": "https://netbox.example",
            "api_token": "secret",
            "ca_certificate": "not a certificate",
            "enabled": False,
        },
    ).status_code == 400
    assert client.put(
        "/api/admin/integrations/proxmox",
        json={
            "api_url": "https://pve.example:8006/api2/json",
            "token_id": "portal@pve!token",
            "token_secret": "secret",
            "ca_certificate": "not a certificate",
            "enabled": False,
        },
    ).status_code == 400


def test_automatic_ipam_skips_exclusions_and_netbox_conflicts(
    app, pve_client, netbox_client
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    profile = client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "chu-auto",
            "label": "CHU automatique",
            "cidr": "10.10.12.0/24",
            "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"],
            "bridge": "vmbr0",
            "vlan_tag": 12,
            "netbox_prefix_id": 42,
            "pool_start": "10.10.12.50",
            "pool_end": "10.10.12.52",
            "excluded_ips": ["10.10.12.51"],
            "allow_manual_ip": False,
            "allow_automatic_ip": True,
            "enabled": True,
        },
    )
    assert profile.status_code == 201
    assert profile.get_json()["profile"]["pool_start"] == "10.10.12.50"

    manual = client.post(
        "/api/vms",
        json={
            **vm_payload("manual-forbidden"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "password",
            "network_profile": "chu-auto",
            "network_mode": "static",
            "ipv4_cidr": "10.10.12.50/24",
            "gateway": "10.10.12.254",
            "dns_servers": ["10.10.1.10"],
        },
    )
    assert manual.status_code == 400

    netbox_client.reservations[99] = "10.10.12.50/24"
    created = client.post(
        "/api/vms",
        json={
            **vm_payload("auto-vm"),
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "password",
            "network_profile": "chu-auto",
            "network_mode": "automatic",
        },
    )
    assert created.status_code == 202
    run_step(app, pve_client)
    with app.app_context():
        allocation = db.session.get(VMAllocation, created.get_json()["vm_id"])
        assert allocation.automatic_ip is True
        assert allocation.ipv4_cidr == "10.10.12.52/24"
        assert allocation.job.status == "queued"
    run_step(app, pve_client)
    assert "10.10.12.52/24" in netbox_client.reservations.values()


def test_static_ipv4_rejects_invalid_policy_and_iso_profiles(app, pve_client):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    fixed = {
        **vm_payload("fixed-invalid"),
        "profile": "debian-cloud",
        "guest_username": "hugo",
        "guest_password": "password",
        "network_mode": "static",
        "ipv4_cidr": "192.168.10.50/24",
        "gateway": "192.168.10.254",
        "dns_servers": ["192.168.10.10"],
    }
    assert client.post("/api/vms", json=fixed).status_code == 400
    assert client.patch(
        "/api/admin/settings", json={"static_ipv4_networks": "0.0.0.0/0"}
    ).status_code == 400
    assert client.patch(
        "/api/admin/settings", json={"static_ipv4_networks": "10.0.0.0/24"}
    ).status_code == 200
    assert client.post("/api/vms", json=fixed).status_code == 400
    iso_fixed = {**vm_payload("iso-fixed"), **{
        key: fixed[key]
        for key in ("network_mode", "ipv4_cidr", "gateway", "dns_servers")
    }}
    assert client.post("/api/vms", json=iso_fixed).status_code == 400


@pytest.mark.parametrize(
    ("updates", "field"),
    [
        ({"network_mode": "manual"}, "network_mode"),
        (
            {
                "network_mode": "dhcp",
                "ipv4_cidr": "10.0.0.5/24",
            },
            "network_mode",
        ),
        (
            {
                "network_mode": "static",
                "ipv4_cidr": "10.0.0.0/24",
                "gateway": "10.0.0.1",
                "dns_servers": ["10.0.0.2"],
            },
            "ipv4_cidr",
        ),
        (
            {
                "network_mode": "static",
                "ipv4_cidr": "10.0.0.5/24",
                "gateway": "10.0.1.1",
                "dns_servers": ["10.0.0.2"],
            },
            "gateway",
        ),
        (
            {
                "network_mode": "static",
                "ipv4_cidr": "10.0.0.5/24",
                "gateway": "10.0.0.1",
                "dns_servers": ["invalid"],
            },
            "dns_servers",
        ),
    ],
)
def test_cloud_init_network_validation_rejects_invalid_values(
    app, pve_client, updates, field
):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)
    payload = {
        **vm_payload("invalid-network"),
        "profile": "debian-cloud",
        "guest_username": "hugo",
        "guest_password": "password",
        **updates,
    }
    response = client.post("/api/vms", json=payload)
    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_owner_receives_vm_ipv4_and_ssh_identity_from_guest_agent(app, pve_client):
    client, _job_id = enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        vm_id = allocation.id
        assert allocation.vmid == 100
    pve_client.vm_ipv4_addresses[("pve-a", 100)] = ["192.168.1.51"]

    response = client.get(f"/api/vms/{vm_id}/network")

    assert response.status_code == 200
    network = response.get_json()
    assert network["status"] == "ready"
    assert network["ipv4"] == "192.168.1.51"
    assert network["ipv4_addresses"] == ["192.168.1.51"]
    assert network["last_ipv4"] == "192.168.1.51"
    assert network["observed_at"] is not None
    assert network["ssh_username"] == "hugo"
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.last_ipv4 == "192.168.1.51"
        assert allocation.network_observed_at is not None


def test_owner_receives_vm_details_and_operation_history(app, pve_client):
    client, _job_id = enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        vm_id = allocation.id
        allocation.last_ipv4 = "192.168.1.52"
        allocation.network_observed_at = datetime.now(UTC)
        db.session.commit()

    response = client.get(f"/api/vms/{vm_id}")

    assert response.status_code == 200
    details = response.get_json()["details"]
    assert details["vm_id"] == vm_id
    assert details["profile_label"] == "Debian Cloud"
    assert details["network"]["last_ipv4"] == "192.168.1.52"
    assert details["network"]["observed_at"] is not None
    assert details["vm"]["guest_username"] == "hugo"
    assert details["operations"] == []


def test_vm_network_is_hidden_from_another_user(app, pve_client):
    _owner_client, _job_id = enqueue_cloud(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    run_step(app, pve_client)
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        vm_id = allocation.id
        other = User(
            username="other-user",
            password_hash=generate_password_hash("other-user-strong-password"),
            role="user",
        )
        db.session.add(other)
        db.session.commit()
        other_id = other.id
    other_client = app.test_client()
    with other_client.session_transaction() as portal_session:
        portal_session["user_id"] = other_id
        portal_session["authentication"] = "local"

    assert other_client.get(f"/api/vms/{vm_id}/network").status_code == 404


def test_vm_network_reports_lifecycle_and_guest_agent_states(app, pve_client):
    client, _job_id = enqueue_cloud(app, pve_client)
    with app.app_context():
        allocation = db.session.scalar(select(VMAllocation))
        vm_id = allocation.id

    assert client.get("/api/vms/unknown/network").status_code == 404
    assert client.get(f"/api/vms/{vm_id}/network").get_json() == {
        "status": "unavailable",
        "ipv4": None,
        "ipv4_addresses": [],
        "last_ipv4": None,
        "observed_at": None,
        "ssh_username": "hugo",
    }

    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        allocation.vmid = 100
        allocation.status = "stopped"
        allocation.last_ipv4 = "192.168.1.50"
        allocation.network_observed_at = datetime.now(UTC)
        db.session.commit()
    stopped = client.get(f"/api/vms/{vm_id}/network").get_json()
    assert stopped["status"] == "stopped"
    assert stopped["ipv4"] == "192.168.1.50"
    assert stopped["ipv4_addresses"] == ["192.168.1.50"]
    assert stopped["last_ipv4"] == "192.168.1.50"
    assert stopped["observed_at"] is not None
    assert stopped["ssh_username"] == "hugo"

    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        allocation.status = "running"
        db.session.commit()
    assert client.get(f"/api/vms/{vm_id}/network").get_json()["status"] == "pending"

    pve_client.get_vm_ipv4_addresses = lambda _node, _vmid: (_ for _ in ()).throw(
        PVETransportError("offline")
    )
    unavailable = client.get(f"/api/vms/{vm_id}/network").get_json()
    assert unavailable["status"] == "temporarily_unavailable"
    assert unavailable["ipv4"] == "192.168.1.50"
    assert unavailable["ipv4_addresses"] == []
    assert unavailable["last_ipv4"] == "192.168.1.50"


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


def test_cloud_init_template_is_restricted_to_its_node(app, pve_client):
    client = app.test_client()
    login(client)
    pve_client.templates.add(("pve-a", 9000))
    create_cloud_profile(client)

    response = client.post(
        "/api/vms",
        json={
            **vm_payload("wrong-node-cloud-vm"),
            "node": "pve-b",
            "profile": "debian-cloud",
            "guest_username": "hugo",
            "guest_password": "mot de passe choisi !",
        },
    )

    assert response.status_code == 400
    assert "node" in response.get_json()["errors"]
    assert pve_client.requests == []


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
        "guest_password_min_length": 12,
        "static_ipv4_networks": "",
        "default_vm_lifetime_days": 90,
        "max_vm_lifetime_days": 365,
        "expiration_warning_days": 14,
        "vm_approval_required": False,
    }
    changed_again = client.patch(
        "/api/admin/settings", json={"guest_password_min_length": 10}
    )
    assert changed_again.status_code == 200
    assert client.get("/api/me").get_json()["settings"] == {
        "guest_password_min_length": 10,
        "static_ipv4_networks": "",
        "default_vm_lifetime_days": 90,
        "max_vm_lifetime_days": 365,
        "expiration_warning_days": 14,
        "vm_approval_required": False,
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
