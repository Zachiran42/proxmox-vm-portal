from datetime import UTC, datetime, timedelta
from unittest.mock import call, patch

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal import jobs as maintenance_worker
from portal.jobs import process_next_job
from portal.models import (
    AuditEvent,
    ImageProfile,
    ProvisioningJob,
    User,
    VMAllocation,
    VMMaintenanceJob,
    db,
)
from portal.pve import (
    FakePVEClient,
    PVEClient,
    PVEHTTPError,
    PVEProtocolError,
    PVETransportError,
)


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
        json={
            "username": "admin",
            "password": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def seed_vm(app):
    with app.app_context():
        owner = User(
            username="hugo",
            password_hash=generate_password_hash("owner-password"),
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
            name="test-maintenance",
            node="pve-a",
            vmid=107,
            guest_username="hugo",
            cpu=2,
            ram_mb=4096,
            disk_gb=40,
            status="running",
        )
        provisioning = ProvisioningJob(
            allocation=allocation,
            status="succeeded",
            completed_at=datetime.now(UTC),
        )
        db.session.add_all((owner, profile, allocation, provisioning))
        db.session.commit()
        return allocation.id


def test_admin_scans_updates_and_report_is_persisted(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    queued = client.post(
        f"/api/admin/vms/{vm_id}/maintenance", json={"action": "scan"}
    )
    assert queued.status_code == 202

    pve_client.guest_exec_results = [
        {
            "exited": True,
            "exitcode": 0,
            "out-data": (
                "__PORTAL_PENDING_BEGIN__\n"
                "Listing...\nopenssl/stable 3.0 amd64 [upgradable]\n"
                "curl/stable 8.0 amd64 [upgradable]\n"
                "__PORTAL_PENDING_END__\n"
                "__PORTAL_REBOOT_REQUIRED__\n"
            ),
        }
    ]
    with app.app_context():
        assert process_next_job(pve_client, worker_id="test", poll_seconds=0)
        assert process_next_job(pve_client, worker_id="test", poll_seconds=0)
        maintenance = db.session.scalar(select(VMMaintenanceJob))
        assert maintenance.status == "succeeded"
        assert maintenance.report == {
            "available_count": 2,
            "available_packages": ["openssl", "curl"],
            "updated_count": 0,
            "remaining_count": 2,
            "remaining_packages": ["openssl", "curl"],
            "reboot_required": True,
        }
        event = db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.maintenance.scan")
        )
        assert event.outcome == "success"
        assert event.details["available_count"] == 2

    inventory = client.get("/api/operations/vms").get_json()["items"][0]
    assert inventory["maintenance"]["report"]["available_count"] == 2
    assert pve_client.guest_exec_requests[0][:2] == ("pve-a", 107)
    assert "apt-get" in pve_client.guest_exec_requests[0][2][2]


def test_isolation_is_applied_by_proxmox_and_blocks_maintenance(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)

    isolated = client.post(
        f"/api/admin/vms/{vm_id}/network-policy", json={"policy": "isolated"}
    )
    maintenance = client.post(
        f"/api/admin/vms/{vm_id}/maintenance", json={"action": "update"}
    )

    assert isolated.status_code == 200
    assert pve_client.network_policies[("pve-a", 107)] == "isolated"
    assert maintenance.status_code == 409
    assert maintenance.get_json()["error"] == "maintenance_network_isolated"
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.network_policy == "isolated"
        event = db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.network_policy.update")
        )
        assert event.details == {"previous": "sandbox", "policy": "isolated"}


def test_firewall_log_is_exposed_without_guest_inspection(app, pve_client):
    vm_id = seed_vm(app)
    pve_client.firewall_logs[("pve-a", 107)] = [
        {"line": 17, "message": "107 6 tap107i0-OUT policy DROP: DST=10.0.0.2"}
    ]
    client = app.test_client()
    login(client)

    response = client.get(f"/api/admin/vms/{vm_id}/network-log")

    assert response.status_code == 200
    assert response.get_json()["source"] == "proxmox_firewall"
    assert response.get_json()["entries"][0]["message"].endswith("DST=10.0.0.2")


def test_pve_network_policy_checks_both_firewall_levels():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    with patch.object(
        client,
        "_request",
        side_effect=[
            {"enable": 1},
            {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1"},
            None,
            {"enable": 1, "policy_in": "DROP", "policy_out": "DROP"},
            None,
            {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=1"},
        ],
    ) as request:
        client.set_vm_network_policy("pve-a", 107, "isolated")

    assert request.call_args_list == [
        call("/cluster/firewall/options"),
        call("/nodes/pve-a/qemu/107/config"),
        call(
            "/nodes/pve-a/qemu/107/firewall/options",
            method="PUT",
            payload={
                "enable": 1,
                "policy_in": "DROP",
                "policy_out": "DROP",
                "log_level_in": "info",
                "log_level_out": "info",
            },
        ),
        call("/nodes/pve-a/qemu/107/firewall/options"),
        call(
            "/nodes/pve-a/qemu/107/config",
            method="PUT",
            payload={
                "net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=1"
            },
        ),
        call("/nodes/pve-a/qemu/107/config"),
    ]


def test_pve_network_policy_fails_closed_when_datacenter_firewall_is_off():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    with patch.object(client, "_request", return_value={"enable": 0}):
        with pytest.raises(PVEProtocolError, match="Datacenter"):
            client.set_vm_network_policy("pve-a", 107, "isolated")


def test_update_report_counts_installed_and_remaining_packages(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    assert client.post(
        f"/api/admin/vms/{vm_id}/maintenance", json={"action": "update"}
    ).status_code == 202
    pve_client.guest_exec_results = [
        {"exited": False},
        {
            "exited": True,
            "exitcode": 0,
            "out-data": (
                "__PORTAL_PENDING_BEGIN__\nopenssl/stable 3 amd64\n"
                "curl/stable 8 amd64\n__PORTAL_PENDING_END__\n"
                "__PORTAL_REMAINING_BEGIN__\ncurl/stable 8 amd64\n"
                "__PORTAL_REMAINING_END__\n"
            ),
        },
    ]
    with app.app_context():
        assert process_next_job(pve_client, worker_id="test", poll_seconds=0)
        assert process_next_job(pve_client, worker_id="test", poll_seconds=0)
        assert process_next_job(pve_client, worker_id="test", poll_seconds=0)
        job = db.session.scalar(select(VMMaintenanceJob))
        assert job.report["updated_count"] == 1
        assert job.report["remaining_packages"] == ["curl"]
        assert job.output_excerpt is None
        assert "upgrade" in pve_client.guest_exec_requests[0][2][2]


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (PVEHTTPError(403, "denied"), "failed", "maintenance_agent_rejected"),
        (PVEHTTPError(500, "failed"), "attention", "maintenance_submission_unknown"),
        (PVETransportError("offline"), "attention", "maintenance_submission_unknown"),
    ],
)
def test_maintenance_submission_failures_are_normalized(
    app, pve_client, error, expected_status, expected_code
):
    vm_id = seed_vm(app)
    with app.app_context():
        job = VMMaintenanceJob(allocation_id=vm_id, action="scan", status="queued")
        db.session.add(job)
        db.session.commit()
        pve_client.guest_exec = lambda *_args: (_ for _ in ()).throw(error)
        maintenance_worker._submit_maintenance(pve_client, job.id, 0)
        assert job.status == expected_status
        assert job.error_code == expected_code


@pytest.mark.parametrize(
    ("result_or_error", "expected_status", "expected_code"),
    [
        (PVETransportError("offline"), "submitted", None),
        (PVEProtocolError("bad"), "attention", "maintenance_status_unknown"),
        (
            {"exited": True, "exitcode": 1, "err-data": "apt failed"},
            "failed",
            "maintenance_command_failed",
        ),
    ],
)
def test_maintenance_poll_failures_are_normalized(
    app, pve_client, result_or_error, expected_status, expected_code
):
    vm_id = seed_vm(app)
    with app.app_context():
        job = VMMaintenanceJob(
            allocation_id=vm_id,
            action="scan",
            status="submitted",
            guest_pid=42,
        )
        db.session.add(job)
        db.session.commit()
        if isinstance(result_or_error, Exception):
            pve_client.guest_exec_status = lambda *_args: (
                (_ for _ in ()).throw(result_or_error)
            )
        else:
            pve_client.guest_exec_status = lambda *_args: result_or_error
        maintenance_worker._poll_maintenance(pve_client, job.id, 0)
        assert job.status == expected_status
        assert job.error_code == expected_code
        if expected_code == "maintenance_command_failed":
            assert job.output_excerpt == "apt failed"


def test_maintenance_recovery_and_invalid_states(app, pve_client):
    vm_id = seed_vm(app)
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        stopped = VMMaintenanceJob(
            allocation_id=vm_id, action="scan", status="queued"
        )
        db.session.add(stopped)
        allocation.status = "stopped"
        db.session.commit()
        maintenance_worker._submit_maintenance(pve_client, stopped.id, 0)
        assert stopped.error_code == "maintenance_vm_not_running"

        allocation.status = "running"
        isolated = VMMaintenanceJob(
            allocation_id=vm_id, action="scan", status="queued"
        )
        db.session.add(isolated)
        allocation.network_policy = "isolated"
        db.session.commit()
        maintenance_worker._submit_maintenance(pve_client, isolated.id, 0)
        assert isolated.error_code == "maintenance_network_isolated"

        stale = VMMaintenanceJob(
            allocation_id=vm_id,
            action="scan",
            status="submitting",
            locked_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        db.session.add(stale)
        db.session.commit()
        maintenance_worker._recover_stale_maintenance(60)
        assert stale.status == "attention"
        assert stale.error_code == "worker_crashed_during_maintenance"


def test_maintenance_api_validation_and_history(app):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    endpoint = f"/api/admin/vms/{vm_id}/maintenance"
    assert client.post(endpoint, json={}).status_code == 400
    assert client.post(endpoint, json={"action": "shell"}).status_code == 400
    assert client.post("/api/admin/vms/missing/maintenance", json={"action": "scan"}).status_code == 404
    assert client.post(endpoint, json={"action": "scan"}).status_code == 202
    assert client.post(endpoint, json={"action": "scan"}).status_code == 409
    assert len(client.get(endpoint).get_json()["items"]) == 1
    assert client.get("/api/admin/vms/missing/maintenance").status_code == 404


def test_network_api_validation_and_proxmox_failures(app, pve_client):
    vm_id = seed_vm(app)
    client = app.test_client()
    login(client)
    endpoint = f"/api/admin/vms/{vm_id}/network-policy"
    assert client.post(endpoint, json={}).status_code == 400
    assert client.post(endpoint, json={"policy": "open"}).status_code == 400
    assert client.post("/api/admin/vms/missing/network-policy", json={"policy": "isolated"}).status_code == 404
    assert client.post(endpoint, json={"policy": "normal"}).status_code == 400
    assert client.post(endpoint, json={"policy": "sandbox"}).status_code == 200

    pve_client.set_vm_network_policy = lambda *_args: (
        (_ for _ in ()).throw(PVEProtocolError("firewall off"))
    )
    assert client.post(endpoint, json={"policy": "isolated"}).status_code == 409
    pve_client.set_vm_network_policy = lambda *_args: (
        (_ for _ in ()).throw(PVEHTTPError(403, "denied"))
    )
    assert client.post(endpoint, json={"policy": "isolated"}).status_code == 403

    pve_client.get_vm_firewall_log = lambda *_args, **_kwargs: (
        (_ for _ in ()).throw(PVETransportError("offline"))
    )
    assert client.get(f"/api/admin/vms/{vm_id}/network-log").status_code == 503
    assert client.get("/api/admin/vms/missing/network-log").status_code == 404


def test_pve_guest_exec_and_firewall_log_validation():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    with patch.object(client, "_request", return_value={"pid": 42}) as request:
        assert client.guest_exec("pve-a", 107, ["/bin/true"]) == 42
        request.assert_called_once()
    with pytest.raises(ValueError):
        client.guest_exec("pve-a", 107, [])
    with patch.object(client, "_request", return_value={"pid": False}):
        with pytest.raises(PVEProtocolError):
            client.guest_exec("pve-a", 107, ["/bin/true"])

    with patch.object(
        client,
        "_request",
        return_value={"exited": 1, "exitcode": 0, "out-data": "ok"},
    ):
        assert client.guest_exec_status("pve-a", 107, 42) == {
            "exited": True,
            "exitcode": 0,
            "out-data": "ok",
        }
    with pytest.raises(ValueError):
        client.guest_exec_status("pve-a", 107, 0)
    with patch.object(client, "_request", return_value=[]):
        with pytest.raises(PVEProtocolError):
            client.guest_exec_status("pve-a", 107, 42)

    with patch.object(
        client,
        "_request",
        return_value=[{"n": 1, "t": "drop"}, {"n": "bad"}, "bad"],
    ):
        assert client.get_vm_firewall_log("pve-a", 107) == [
            {"line": 1, "message": "drop"}
        ]
    with pytest.raises(ValueError):
        client.get_vm_firewall_log("pve-a", 107, limit=0)
    with patch.object(client, "_request", return_value={}):
        with pytest.raises(PVEProtocolError):
            client.get_vm_firewall_log("pve-a", 107)


def test_pve_network_policy_rejects_unprotected_interface_and_unconfirmed_result():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    with patch.object(
        client,
        "_request",
        side_effect=[{"enable": 1}, {"net0": "virtio=AA:BB,bridge=vmbr0"}],
    ):
        with pytest.raises(PVEProtocolError, match="net0"):
            client.set_vm_network_policy("pve-a", 107, "isolated")
    with patch.object(
        client,
        "_request",
        side_effect=[
            {"enable": 1},
            {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1"},
            None,
            {"enable": 1, "policy_in": "ACCEPT", "policy_out": "DROP"},
        ],
    ):
        with pytest.raises(PVEProtocolError, match="confirmée"):
            client.set_vm_network_policy("pve-a", 107, "isolated")
    with patch.object(
        client,
        "_request",
        side_effect=[
            {"enable": 1},
            {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=1"},
            None,
            {"enable": 1, "policy_in": "ACCEPT", "policy_out": "ACCEPT"},
            None,
            {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=1"},
        ],
    ):
        with pytest.raises(PVEProtocolError, match="lien réseau"):
            client.set_vm_network_policy("pve-a", 107, "normal")
    with pytest.raises(ValueError):
        client.set_vm_network_policy("pve-a", 107, "unknown")
