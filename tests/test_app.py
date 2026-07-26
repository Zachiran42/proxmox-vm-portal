from __future__ import annotations

import pytest

from portal import create_app
from portal.pve import FakePVEClient, PVEClient


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": {"local:iso/debian-12.iso"}})


@pytest.fixture
def app(pve_client):
    app = create_app({"TESTING": True}, pve_client=pve_client)
    return app


def test_healthz_returns_ok(app):
    response = app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_home_page_is_available(app):
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert "Portail Proxmox" in response.get_data(as_text=True)


def test_valid_vm_request_is_accepted_and_sent_to_client(app, pve_client):
    response = app.test_client().post(
        "/api/vms",
        json={
            "name": "web-prod-01",
            "node": "pve-a",
            "iso": "local:iso/debian-12.iso",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        },
    )

    assert response.status_code == 202
    assert response.get_json() == {"status": "accepted", "request_id": "req-1"}
    assert pve_client.requests == [
        {
            "name": "web-prod-01",
            "node": "pve-a",
            "iso": "local:iso/debian-12.iso",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        }
    ]


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"name": "UPPERCASE", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "name"),
        ({"name": "web-01", "node": "PVE-A", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "node"),
        ({"name": "web-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 0, "ram_mb": 4096, "disk_gb": 40}, "cpu"),
        ({"name": "web-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 257, "disk_gb": 40}, "ram_mb"),
        ({"name": "web-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 0}, "disk_gb"),
        ({"name": "web-01", "node": "pve-a", "iso": "../debian.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}, "iso"),
    ],
)
def test_invalid_vm_request_is_rejected(app, payload, field):
    response = app.test_client().post("/api/vms", json=payload)

    assert response.status_code == 400
    assert field in response.get_json()["errors"]


def test_unknown_fields_are_rejected(app):
    payload = {
        "name": "web-01",
        "node": "pve-a",
        "iso": "local:iso/debian-12.iso",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
        "vmid": 100,
    }

    response = app.test_client().post("/api/vms", json=payload)

    assert response.status_code == 400
    assert "unknown" in response.get_json()["errors"]


def test_iso_must_be_available_on_selected_node(app, pve_client):
    response = app.test_client().post(
        "/api/vms",
        json={
            "name": "web-01",
            "node": "pve-b",
            "iso": "local:iso/debian-12.iso",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        },
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == {"iso": "ISO inaccessible sur le nœud sélectionné."}
    assert pve_client.requests == []


def test_missing_json_is_rejected(app):
    response = app.test_client().post("/api/vms")

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
