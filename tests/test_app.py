from __future__ import annotations

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import VMAllocation, db
from portal.pve import FakePVEClient, PVEClient, PVEProtocolError


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": {"local:iso/debian-12.iso"}})


@pytest.fixture
def app(pve_client):
    app = create_app(
        {
            "TESTING": True,
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("correct-horse-battery-staple"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )
    yield app
    with app.app_context():
        from portal.models import db

        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def authenticated_client(app):
    client = app.test_client()
    response = client.post("/login", json={"username": "admin", "password": "correct-horse-battery-staple"})
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]
    return client


def test_healthz_returns_ok(app):
    response = app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_home_page_is_available(app):
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert "Portail Proxmox" in response.get_data(as_text=True)


def test_authenticated_user_can_list_nodes_and_isos(authenticated_client):
    nodes = authenticated_client.get("/api/nodes")
    isos = authenticated_client.get("/api/nodes/pve-a/isos")

    assert nodes.status_code == 200
    assert nodes.get_json() == {"nodes": ["pve-a"]}
    assert isos.status_code == 200
    assert isos.get_json() == {
        "node": "pve-a",
        "isos": ["local:iso/debian-12.iso"],
    }


def test_inventory_requires_authentication(app):
    client = app.test_client()

    assert client.get("/api/nodes").status_code == 401
    assert client.get("/api/nodes/pve-a/isos").status_code == 401


def test_inventory_rejects_invalid_node_name(authenticated_client):
    response = authenticated_client.get("/api/nodes/INVALID/isos")

    assert response.status_code == 400
    assert response.get_json() == {"errors": {"node": "Nœud invalide."}}


def test_valid_vm_request_is_accepted_and_sent_to_client(authenticated_client, pve_client):
    response = authenticated_client.post(
        "/api/vms",
        json={
            "name": "web-prod-01",
            "node": "pve-a",
            "profile": "debian-12",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        },
    )

    assert response.status_code == 202
    assert response.get_json()["status"] == "queued"
    assert response.get_json()["job_id"]
    assert response.get_json()["vm_id"]
    assert pve_client.requests == []


def test_vm_lifetime_policy_is_applied_to_new_requests(app, authenticated_client):
    changed = authenticated_client.patch(
        "/api/admin/settings",
        json={"default_vm_lifetime_days": 10, "max_vm_lifetime_days": 30},
    )
    assert changed.status_code == 200
    payload = {
        "name": "lifetime-vm",
        "node": "pve-a",
        "profile": "debian-12",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
    }
    rejected = authenticated_client.post(
        "/api/vms", json={**payload, "lifetime_days": 31}
    )
    created = authenticated_client.post(
        "/api/vms", json={**payload, "lifetime_days": 20}
    )
    assert rejected.status_code == 400
    assert "lifetime_days" in rejected.get_json()["errors"]
    assert created.status_code == 202
    with app.app_context():
        allocation = db.session.scalar(
            select(VMAllocation).where(VMAllocation.id == created.get_json()["vm_id"])
        )
        assert allocation.expires_at is not None
        assert 19 <= (allocation.expires_at - allocation.created_at).days <= 20


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"name": "UPPERCASE", "node": "pve-a", "profile": "debian-12", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "name"),
        ({"name": "web-01", "node": "PVE-A", "profile": "debian-12", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "node"),
        ({"name": "web-01", "node": "pve-a", "profile": "debian-12", "cpu": 0, "ram_mb": 4096, "disk_gb": 40}, "cpu"),
        ({"name": "web-01", "node": "pve-a", "profile": "debian-12", "cpu": 2, "ram_mb": 257, "disk_gb": 40}, "ram_mb"),
        ({"name": "web-01", "node": "pve-a", "profile": "debian-12", "cpu": 2, "ram_mb": 4096, "disk_gb": 0}, "disk_gb"),
        ({"name": "web-01", "node": "pve-a", "profile": "../debian", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "profile"),
    ],
)
def test_invalid_vm_request_is_rejected(authenticated_client, payload, field):
    response = authenticated_client.post("/api/vms", json=payload)

    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_unknown_fields_are_rejected(authenticated_client):
    payload = {
        "name": "web-01",
        "node": "pve-a",
        "profile": "debian-12",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
        "vmid": 100,
    }

    response = authenticated_client.post("/api/vms", json=payload)

    assert response.status_code == 400
    assert "unknown" in response.get_json()["errors"]


def test_profile_must_be_enabled(authenticated_client, pve_client):
    response = authenticated_client.post(
        "/api/vms",
        json={
            "name": "web-01",
            "node": "pve-a",
            "profile": "missing-profile",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        },
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == {"profile": "Profil indisponible."}
    assert pve_client.requests == []


def test_missing_json_is_rejected(authenticated_client):
    response = authenticated_client.post("/api/vms")

    assert response.status_code == 400
    assert response.get_json()["errors"] == {"body": "Un objet JSON est requis."}


def test_pve_client_uses_api_token_from_environment(monkeypatch):
    monkeypatch.setenv("PVE_API_URL", "https://pve.example:8006/api2/json")
    monkeypatch.setenv("PVE_TOKEN_ID", "portal@pve!provisioner")
    monkeypatch.setenv("PVE_TOKEN_SECRET", "test-secret")

    client = PVEClient.from_environment()

    assert client.api_url == "https://pve.example:8006/api2/json"
    assert client.authorization_header == "PVEAPIToken=portal@pve!provisioner=test-secret"


def test_pve_client_rejects_root_token(monkeypatch):
    monkeypatch.setenv("PVE_API_URL", "https://pve.example:8006/api2/json")
    monkeypatch.setenv("PVE_TOKEN_ID", "root@pam!dangerous")
    monkeypatch.setenv("PVE_TOKEN_SECRET", "test-secret")

    with pytest.raises(ValueError, match="root"):
        PVEClient.from_environment()


def test_pve_client_extracts_only_usable_ipv4_addresses(monkeypatch):
    client = PVEClient("https://pve.example/api2/json", "portal@pve!token", "secret")
    monkeypatch.setattr(
        client,
        "_request",
        lambda _path: {
            "result": [
                "invalid-interface",
                {"name": "broken", "ip-addresses": "invalid"},
                {
                    "name": "lo",
                    "ip-addresses": [
                        "invalid-address",
                        {"ip-address": "not-an-ip", "ip-address-type": "ipv4"},
                        {"ip-address": "127.0.0.1", "ip-address-type": "ipv4"},
                    ],
                },
                {
                    "name": "ens18",
                    "ip-addresses": [
                        {"ip-address": "192.168.1.51", "ip-address-type": "ipv4"},
                        {"ip-address": "169.254.1.2", "ip-address-type": "ipv4"},
                        {"ip-address": "fe80::1", "ip-address-type": "ipv6"},
                    ],
                },
            ]
        },
    )

    assert client.get_vm_ipv4_addresses("pve-a", 101) == ["192.168.1.51"]


def test_pve_client_rejects_invalid_guest_agent_response(monkeypatch):
    client = PVEClient("https://pve.example/api2/json", "portal@pve!token", "secret")
    monkeypatch.setattr(client, "_request", lambda _path: {"result": "invalid"})

    with pytest.raises(PVEProtocolError, match="interfaces"):
        client.get_vm_ipv4_addresses("pve-a", 101)
