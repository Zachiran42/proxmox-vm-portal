from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import (
    _module_command,
    _poll_modules,
    _submit_modules,
    build_sandbox_firewall_rules,
    process_next_job,
)
from portal.models import (
    AuditEvent,
    ImageProfile,
    NetworkProfile,
    ProvisioningJob,
    SoftwareModule,
    User,
    VMAllocation,
    db,
)
from portal.notifications import process_sandbox_release_expirations
from portal.pve import (
    FakePVEClient,
    PVEClient,
    PVEHTTPError,
    PVEProtocolError,
    PVETransportError,
)
from portal.validation import SoftwareModuleRequest, ValidationError


def login(client, username="admin", password="correct-horse-battery-staple"):
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def test_sandbox_rules_keep_link_up_and_allow_only_approved_services():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    rules = [
        {
            "type": "out",
            "action": "ACCEPT",
            "dest": "10.10.1.10",
            "proto": "udp",
            "dport": "53",
            "comment": "portal-sandbox:dns:1",
        }
    ]
    responses = [
        {"enable": 1},
        {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=1"},
        None,
        {"enable": 1, "policy_in": "DROP", "policy_out": "DROP"},
        [],
        None,
        [{"pos": 0, "enable": 1, "comment": "portal-sandbox:dns:1"}],
        None,
        {"net0": "virtio=AA:BB,bridge=vmbr0,firewall=1,link_down=0"},
    ]
    with patch.object(client, "_request", side_effect=responses) as request:
        client.set_vm_network_policy("pve-a", 107, "sandbox", rules=rules)
    assert request.call_args_list[-2].kwargs["payload"]["net0"].endswith("link_down=0")
    posted = [
        call.kwargs["payload"]
        for call in request.call_args_list
        if call.kwargs.get("method") == "POST"
    ]
    assert posted == [{**rules[0], "enable": 1, "log": "nolog"}]


def test_rule_builder_has_default_drop_exceptions_without_production_access():
    profile = NetworkProfile(
        slug="sandbox",
        label="Sandbox",
        cidr="10.10.12.0/24",
        gateway="10.10.12.254",
        dns_servers="10.10.1.10",
        bridge="vmbr0",
        sandbox_ssh_sources="10.20.0.0/24",
        sandbox_ntp_servers="10.10.1.20",
        sandbox_apt_endpoints="10.10.1.30",
        sandbox_registry_endpoints="10.10.1.40",
        sandbox_monitoring_endpoints="10.10.1.50",
    )
    allocation = VMAllocation(
        owner_id=1,
        network_profile=profile,
        name="sandbox-vm",
        node="pve-a",
        network_mode="dhcp",
        cpu=2,
        ram_mb=2048,
        disk_gb=20,
    )
    rules = build_sandbox_firewall_rules(allocation)
    assert all(rule["action"] == "ACCEPT" for rule in rules)
    assert {rule.get("dport") for rule in rules} >= {
        "22", "53", "67", "68", "123", "443", "10050", "10051"
    }
    assert not any(rule.get("dest") == "0.0.0.0/0" and rule.get("dport") == "443" for rule in rules)


def test_module_catalog_and_provisioning_from_internal_sources():
    pve = FakePVEClient(accessible_isos={"pve-a": set()})
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
        pve_client=pve,
    )
    client = app.test_client()
    login(client)
    pve.templates.add(("pve-a", 9130))
    assert client.post(
        "/api/admin/image-profiles",
        json={
            "slug": "debian-cloud", "label": "Debian Cloud", "description": "",
            "version": "13.6", "source_type": "cloud_init", "template_node": "pve-a",
            "template_vmid": 9130,
        },
    ).status_code == 201
    assert client.post(
        "/api/admin/software-modules",
        json={
            "slug": "docker", "label": "Docker", "description": "Préinstallé",
            "install_mode": "preinstalled", "artifacts": ["docker-ce"],
            "required": False, "enabled": True,
        },
    ).status_code == 201
    assert client.post(
        "/api/admin/network-profiles",
        json={
            "slug": "sandbox", "label": "Sandbox", "cidr": "10.10.12.0/24",
            "gateway": "10.10.12.254", "dns_servers": ["10.10.1.10"],
            "bridge": "vmbr0", "connectivity_mode": "sandbox",
            "sandbox_ssh_sources": ["10.20.0.0/24"],
            "sandbox_ntp_servers": ["10.10.1.20"],
            "sandbox_apt_endpoints": ["10.10.1.30"],
            "sandbox_registry_endpoints": ["10.10.1.40"],
            "sandbox_monitoring_endpoints": [], "enabled": True,
        },
    ).status_code == 201
    created = client.post(
        "/api/vms",
        json={
            "name": "docker-test", "node": "pve-a", "profile": "debian-cloud",
            "cpu": 2, "ram_mb": 2048, "disk_gb": 20,
            "usage_purpose": "technical_test", "no_patient_data_ack": True,
            "guest_username": "hugo", "guest_password": "password",
            "network_mode": "dhcp", "network_profile": "sandbox",
            "software_modules": ["docker"],
        },
    )
    assert created.status_code == 202
    with app.app_context():
        for _ in range(4):
            assert process_next_job(pve, worker_id="test", poll_seconds=0)
        allocation = db.session.get(VMAllocation, created.get_json()["vm_id"])
        assert allocation.status == "running"
        assert allocation.network_policy == "sandbox"
        assert allocation.software_modules == ["docker"]
        assert "dpkg-query" in pve.guest_exec_requests[0][2][2]
        assert pve.network_policy_rules[("pve-a", 100)]
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def test_owner_requests_release_and_only_admin_can_decide():
    pve = FakePVEClient(accessible_isos={"pve-a": set()})
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve,
    )
    with app.app_context():
        owner = User(username="hugo", password_hash=generate_password_hash("owner-password"))
        profile = ImageProfile(slug="debian", label="Debian", source_type="cloud_init", template_node="pve-a", template_vmid=9130)
        allocation = VMAllocation(owner=owner, profile=profile, name="sandbox-vm", node="pve-a", vmid=107, cpu=2, ram_mb=2048, disk_gb=20, status="running", network_policy="sandbox")
        db.session.add_all((owner, profile, allocation, ProvisioningJob(allocation=allocation, status="succeeded", completed_at=datetime.now(UTC))))
        db.session.commit()
        vm_id = allocation.id
    user = app.test_client()
    admin = app.test_client()
    login(admin, "admin", "admin-password")
    request_payload = {
        "reason": "Demande réseau correctement justifiée",
        "ticket_reference": "INC-4",
        "duration_hours": 24,
    }
    assert admin.post(
        "/api/vms/missing/sandbox-release-request", json=request_payload
    ).status_code == 409
    assert admin.patch(
        "/api/admin/settings",
        json={"flow_request_url": "https://glpi.chu.test/front/helpdesk.public.php"},
    ).status_code == 200
    login(user, "hugo", "owner-password")
    requested = user.post(
        f"/api/vms/{vm_id}/sandbox-release-request",
        json={
            "reason": "Accès HTTPS temporaire à la recette",
            "ticket_reference": "INC-2026-0042",
            "duration_hours": 24,
        },
    )
    assert requested.status_code == 202
    assert user.post(
        f"/api/admin/vms/{vm_id}/sandbox-release-decision",
        json={"action": "approve", "reason": "Validé"},
    ).status_code == 403
    approved = admin.post(
        f"/api/admin/vms/{vm_id}/sandbox-release-decision",
        json={"action": "approve", "reason": "Ticket validé par le réseau"},
    )
    assert approved.status_code == 200
    assert approved.get_json()["expires_at"] is not None
    assert pve.network_policies[("pve-a", 107)] == "normal"
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.sandbox_release_status == "approved"
        assert db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "vm.sandbox_release.decide")
        ) is not None
        assert process_sandbox_release_expirations(
            pve, now=datetime.now(UTC).replace(microsecond=0) + timedelta(hours=25)
        ) == 1
        assert allocation.network_policy == "sandbox"
        assert allocation.sandbox_release_status == "not_requested"
        expired_at = datetime.now(UTC) - timedelta(hours=1)
        without_vmid = VMAllocation(
            owner=allocation.owner, name="expired-without-vmid", node="pve-a",
            cpu=1, ram_mb=1024, disk_gb=10, status="running",
            network_policy="normal", sandbox_release_status="approved",
            sandbox_release_expires_at=expired_at,
        )
        unavailable = VMAllocation(
            owner=allocation.owner, name="expired-unavailable", node="pve-a", vmid=108,
            cpu=1, ram_mb=1024, disk_gb=10, status="running",
            network_policy="normal", sandbox_release_status="approved",
            sandbox_release_expires_at=expired_at,
        )
        db.session.add_all((without_vmid, unavailable))
        db.session.commit()
        pve.set_vm_network_policy = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PVETransportError("offline")
        )
        assert process_sandbox_release_expirations(pve) == 0
        db.session.remove()
        db.engine.dispose()


def test_software_module_validation_and_catalog_management():
    invalid_payloads = [
        {"unexpected": True},
        {"slug": "BAD", "label": "", "description": 1, "install_mode": "web", "artifacts": [], "required": "yes", "enabled": 1},
        {"slug": "apt", "label": "APT", "install_mode": "apt", "artifacts": ["bad package"]},
        {"slug": "oci", "label": "OCI", "install_mode": "container", "artifacts": ["docker:latest"]},
    ]
    for payload in invalid_payloads:
        try:
            SoftwareModuleRequest.from_dict(payload)
        except ValidationError:
            pass
        else:
            raise AssertionError("Une configuration dangereuse a été acceptée")

    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
    )
    client = app.test_client()
    login(client, "admin", "admin-password")
    endpoint = "/api/admin/software-modules"
    assert client.post(endpoint, json=[]).status_code == 400
    assert client.post(endpoint, json={}).status_code == 400
    payload = {
        "slug": "docker", "label": "Docker", "description": "Interne",
        "install_mode": "apt", "artifacts": ["docker-ce"],
        "required": False, "enabled": True,
    }
    assert client.post(endpoint, json=payload).status_code == 201
    assert client.post(endpoint, json=payload).status_code == 409
    assert len(client.get(endpoint).get_json()["modules"]) == 1
    assert len(client.get("/api/software-modules").get_json()["modules"]) == 1
    assert client.patch(f"{endpoint}/missing", json={}).status_code == 404
    assert client.patch(f"{endpoint}/docker", json=[]).status_code == 400
    assert client.patch(f"{endpoint}/docker", json={"install_mode": "web"}).status_code == 400
    updated = client.patch(
        f"{endpoint}/docker", json={"label": "Docker validé", "enabled": False}
    )
    assert updated.status_code == 200
    assert updated.get_json()["module"]["enabled"] is False
    assert client.get("/api/software-modules").get_json()["modules"] == []
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def test_module_commands_and_fail_closed_worker_paths():
    modules = [
        SoftwareModule(slug="base", label="Base", install_mode="preinstalled", artifacts="curl"),
        SoftwareModule(slug="apt", label="APT", install_mode="apt", artifacts="docker-ce\ndocker-ce-cli"),
        SoftwareModule(slug="oci", label="OCI", install_mode="container", artifacts="registry.test/chu/app:1"),
    ]
    command = _module_command(modules)
    assert command is not None
    assert "dpkg-query" in command[2]
    assert "apt-get update" in command[2]
    assert "docker pull registry.test/chu/app:1" in command[2]
    assert _module_command([]) is None

    pve = FakePVEClient(accessible_isos={"pve-a": set()})
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve,
    )
    with app.app_context():
        owner = db.session.scalar(select(User).where(User.username == "admin"))
        module = SoftwareModule(slug="required", label="Required", install_mode="apt", artifacts="curl", required=True)
        allocation = VMAllocation(owner=owner, name="worker-vm", node="pve-a", vmid=107, cpu=1, ram_mb=1024, disk_gb=10, status="running")
        job = ProvisioningJob(allocation=allocation, status="submitted", stage="start")
        db.session.add_all((module, allocation, job))
        db.session.commit()

        allocation.vmid = None
        assert _submit_modules(pve, job, 0) is False
        assert job.error_code == "module_install_invalid"
        allocation.vmid = 107
        for error, expected in [
            (PVETransportError("offline"), "guest_agent_not_ready"),
            (PVEProtocolError("invalid"), "module_install_submission_invalid"),
        ]:
            job.status, job.stage, job.module_attempts = "submitted", "start", 0
            pve.guest_exec = lambda *_args, _error=error: (_ for _ in ()).throw(_error)
            assert _submit_modules(pve, job, 0) is False
            assert job.error_code == expected
        job.status, job.stage, job.module_attempts = "submitted", "start", 29
        pve.guest_exec = lambda *_args: (_ for _ in ()).throw(PVEHTTPError(500, "failed"))
        assert _submit_modules(pve, job, 0) is False
        assert job.status == "attention"

        job.stage, job.status, job.guest_pid = "modules", "submitted", None
        _poll_modules(pve, None, job, 0)
        assert job.error_code == "module_install_invalid"
        job.guest_pid = 1
        for error, expected in [
            (PVETransportError("offline"), "guest_agent_unavailable"),
            (PVEProtocolError("invalid"), "module_install_status_unknown"),
        ]:
            job.status = "submitted"
            pve.guest_exec_status = lambda *_args, _error=error: (_ for _ in ()).throw(_error)
            _poll_modules(pve, None, job, 0)
            assert job.error_code == expected
        for result, expected_status in [
            ({"exited": False}, "submitted"),
            ({"exited": True, "exitcode": 1}, "attention"),
        ]:
            job.status = "submitted"
            pve.guest_exec_status = lambda *_args, _result=result: _result
            _poll_modules(pve, None, job, 0)
            assert job.status == expected_status
        db.session.remove()
        db.engine.dispose()


def test_pve_sandbox_rejects_unverifiable_firewall_states():
    client = PVEClient(
        api_url="https://pve.example/api2/json",
        token_id="portal@pve!provisioning",
        token_secret="secret",
    )
    try:
        client.set_vm_network_policy("pve-a", 107, "unknown")
    except ValueError:
        pass
    else:
        raise AssertionError("Politique inconnue acceptée")
    try:
        client.set_vm_network_policy("pve-a", 107, "sandbox")
    except ValueError:
        pass
    else:
        raise AssertionError("Sandbox vide accepté")

    rule = {"type": "out", "action": "ACCEPT", "dest": "10.0.0.1", "proto": "tcp", "dport": "443", "comment": "portal-sandbox:test:1"}
    scenarios = [
        ([{"enable": 0}], "Datacenter"),
        ([{"enable": 1}, {"net0": "virtio=AA:BB,bridge=vmbr0"}], "net0"),
        ([{"enable": 1}, {"net0": "virtio=AA,firewall=1"}, None, {"enable": 0}], "politique"),
        ([{"enable": 1}, {"net0": "virtio=AA,firewall=1"}, None, {"enable": 1, "policy_in": "DROP", "policy_out": "DROP"}, {}], "règles"),
    ]
    for responses, message in scenarios:
        with patch.object(client, "_request", side_effect=responses):
            try:
                client.set_vm_network_policy("pve-a", 107, "sandbox", rules=[rule])
            except PVEProtocolError as error:
                assert message.lower() in str(error).lower()
            else:
                raise AssertionError("État pare-feu non vérifiable accepté")

    existing = [
        {"pos": 2, "enable": 1, "comment": "manual-rule"},
        {"pos": 1, "enable": 1, "comment": "portal-sandbox:old:1"},
        "invalid",
    ]
    responses = [
        {"enable": 1},
        {"net0": "virtio=AA,firewall=1"},
        None,
        {"enable": 1, "policy_in": "DROP", "policy_out": "DROP"},
        existing,
        None,
    ]
    with patch.object(client, "_request", side_effect=responses):
        try:
            client.set_vm_network_policy(
                "pve-a", 107, "sandbox", rules=[{**rule, "comment": "invalid"}]
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Règle non gérée acceptée")


def test_sandbox_release_and_policy_endpoints_fail_closed():
    pve = FakePVEClient(accessible_isos={"pve-a": set()})
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve,
    )
    with app.app_context():
        owner = User(username="hugo", password_hash=generate_password_hash("owner-password"))
        stranger = User(username="alice", password_hash=generate_password_hash("alice-password"))
        profile = NetworkProfile(
            slug="sandbox", label="Sandbox", cidr="10.10.12.0/24",
            gateway="10.10.12.254", dns_servers="10.10.1.10", bridge="vmbr0",
        )
        allocation = VMAllocation(
            owner=owner, network_profile=profile, name="sandbox-vm", node="pve-a",
            vmid=107, cpu=2, ram_mb=2048, disk_gb=20, status="running",
            network_policy="isolated",
        )
        unavailable = VMAllocation(
            owner=owner, name="unavailable", node="pve-a", cpu=1,
            ram_mb=1024, disk_gb=10, status="failed", network_policy="sandbox",
        )
        db.session.add_all((owner, stranger, profile, allocation, unavailable))
        db.session.commit()
        vm_id, unavailable_id = allocation.id, unavailable.id

    admin = app.test_client()
    login(admin, "admin", "admin-password")
    assert admin.patch(
        "/api/admin/settings",
        json={"flow_request_url": "https://glpi.chu.test/front/helpdesk.public.php"},
    ).status_code == 200
    policy_endpoint = f"/api/admin/vms/{vm_id}/network-policy"
    assert admin.post(
        f"/api/admin/vms/{unavailable_id}/network-policy", json={"policy": "sandbox"}
    ).status_code == 409
    assert admin.post(policy_endpoint, json={"policy": "sandbox"}).status_code == 200
    assert pve.network_policy_rules[("pve-a", 107)]

    owner_client = app.test_client()
    login(owner_client, "hugo", "owner-password")
    release = f"/api/vms/{vm_id}/sandbox-release-request"
    request_payload = {
        "reason": "Demande réseau correctement justifiée",
        "ticket_reference": "INC-4",
        "duration_hours": 24,
    }
    assert owner_client.post(
        release, json={**request_payload, "ticket_reference": ""}
    ).status_code == 400
    assert owner_client.post(
        release, json={**request_payload, "duration_hours": 0}
    ).status_code == 400
    assert owner_client.post(
        release,
        json={"reason": "court", "ticket_reference": "INC-1", "duration_hours": 24},
    ).status_code == 400
    assert owner_client.post(
        f"/api/vms/{unavailable_id}/sandbox-release-request",
        json={"reason": "Demande suffisamment détaillée", "ticket_reference": "INC-2", "duration_hours": 24},
    ).status_code == 409
    stranger_client = app.test_client()
    login(stranger_client, "alice", "alice-password")
    assert stranger_client.post(
        release, json={"reason": "Demande suffisamment détaillée", "ticket_reference": "INC-3", "duration_hours": 24}
    ).status_code == 404
    assert owner_client.post(
        release, json=request_payload
    ).status_code == 202
    assert owner_client.post(
        release, json={"reason": "Nouvelle demande suffisamment détaillée", "ticket_reference": "INC-5", "duration_hours": 24}
    ).status_code == 409

    decision = f"/api/admin/vms/{vm_id}/sandbox-release-decision"
    assert admin.post(decision, json={"action": "open", "reason": "Valide"}).status_code == 400
    assert admin.post(decision, json={"action": "approve", "reason": "non"}).status_code == 400
    assert admin.post(
        "/api/admin/vms/missing/sandbox-release-decision",
        json={"action": "approve", "reason": "Ticket validé"},
    ).status_code == 404
    pve.set_vm_network_policy = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        PVETransportError("offline")
    )
    assert admin.post(
        decision, json={"action": "approve", "reason": "Ticket validé"}
    ).status_code == 503
    pve.set_vm_network_policy = FakePVEClient.set_vm_network_policy.__get__(pve)
    assert admin.post(
        decision, json={"action": "reject", "reason": "Flux non justifié"}
    ).status_code == 200
    assert admin.post(
        decision, json={"action": "reject", "reason": "Déjà traité"}
    ).status_code == 409
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
