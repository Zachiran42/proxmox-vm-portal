from __future__ import annotations

import io
from urllib.error import HTTPError
from unittest.mock import patch

import pytest

from portal.pve import PVEClient, PVEHTTPError, PVEProtocolError


@pytest.fixture
def client():
    return PVEClient(
        api_url="https://pve.example:8006/api2/json",
        token_id="portal@pve!provisioner",
        token_secret="test-secret",
    )


def pve_response(data):
    response = io.BytesIO(("{\"data\": " + data + "}").encode())
    response.__enter__ = lambda: response
    response.__exit__ = lambda *args: None
    return response


def test_request_sends_token_auth_header_and_json_payload(client):
    with patch("portal.pve.urlopen", return_value=pve_response('"UPID:pve:0001"')) as urlopen:
        result = client._request("/cluster/nextid", method="POST", payload={"key": "value"})

    sent_request = urlopen.call_args.args[0]
    assert result == "UPID:pve:0001"
    assert sent_request.full_url == "https://pve.example:8006/api2/json/cluster/nextid"
    assert sent_request.method == "POST"
    assert sent_request.data == b'{"key": "value"}'
    assert sent_request.get_header("Authorization") == "PVEAPIToken=portal@pve!provisioner=test-secret"
    assert sent_request.get_header("Content-type") == "application/json"
    assert urlopen.call_args.kwargs == {"timeout": 10}


def test_request_wraps_http_errors_with_status_and_pve_message(client):
    error = HTTPError(
        "https://pve.example/api2/json/cluster/nextid",
        409,
        "Conflict",
        {},
        io.BytesIO(b'{"errors": {"vmid": "VMID 101 already exists"}}'),
    )

    with patch("portal.pve.urlopen", side_effect=error):
        with pytest.raises(PVEHTTPError, match="already exists") as caught:
            client._request("/cluster/nextid")

    assert caught.value.status == 409
    assert caught.value.message == "VMID 101 already exists"


def test_is_iso_available_uses_node_storage_content_endpoint(client):
    with patch.object(
        client,
        "_request",
        return_value=[{"volid": "local:iso/debian-12.iso"}, {"volid": "local:iso/other.iso"}],
    ) as request:
        assert client.is_iso_available("pve-a", "local:iso/debian-12.iso") is True

    request.assert_called_once_with("/nodes/pve-a/storage/local/content?content=iso")


def test_is_iso_available_returns_false_when_iso_is_missing(client):
    with patch.object(client, "_request", return_value=[]):
        assert client.is_iso_available("pve-a", "local:iso/debian-12.iso") is False


def test_list_nodes_returns_only_online_nodes_sorted(client):
    data = [
        {"node": "pve-b", "status": "online"},
        {"node": "pve-offline", "status": "offline"},
        {"node": "pve-a", "status": "online"},
        {"node": "pve-a", "status": "online"},
        {"status": "online"},
    ]
    with patch.object(client, "_request", return_value=data):
        assert client.list_nodes() == ["pve-a", "pve-b"]


def test_list_isos_discovers_enabled_iso_storages(client):
    with patch.object(
        client,
        "_request",
        side_effect=[
            [{"storage": "local"}, {"storage": "shared"}],
            [
                {"volid": "local:iso/debian-12.iso"},
                {"volid": "local:vztmpl/not-an-iso.tar.zst"},
            ],
            [{"volid": "shared:iso/ubuntu-24.04.iso"}],
        ],
    ) as request:
        assert client.list_isos("pve-a") == [
            "local:iso/debian-12.iso",
            "shared:iso/ubuntu-24.04.iso",
        ]

    assert [call.args[0] for call in request.call_args_list] == [
        "/nodes/pve-a/storage?content=iso&enabled=1",
        "/nodes/pve-a/storage/local/content?content=iso",
        "/nodes/pve-a/storage/shared/content?content=iso",
    ]


@pytest.mark.parametrize("method", ["list_nodes", "list_isos"])
def test_inventory_rejects_invalid_pve_shapes(client, method):
    with patch.object(client, "_request", return_value={"not": "a list"}):
        with pytest.raises(PVEProtocolError, match="invalide"):
            getattr(client, method)(*(["pve-a"] if method == "list_isos" else []))


def test_iso_check_rejects_invalid_pve_shape(client):
    with patch.object(client, "_request", return_value={"not": "a list"}):
        with pytest.raises(PVEProtocolError, match="invalide"):
            client.is_iso_available("pve-a", "local:iso/debian-12.iso")


def test_create_vm_allocates_valid_vmid_and_uses_exact_payload(client):
    vm_request = {
        "name": "web-prod-01",
        "node": "pve-a",
        "iso": "local:iso/debian-12.iso",
        "cpu": 2,
        "ram_mb": 4096,
        "disk_gb": 40,
    }
    expected_payload = {
        "vmid": 101,
        "name": "web-prod-01",
        "cores": 2,
        "memory": 4096,
        "scsihw": "virtio-scsi-pci",
        "scsi0": "local-lvm:40",
        "ide2": "local:iso/debian-12.iso,media=cdrom",
    }
    with patch.object(client, "_request", side_effect=["101", "UPID:pve:0001"]) as request:
        assert client.create_vm(vm_request) == "UPID:pve:0001"

    assert request.call_args_list[0].args == ("/cluster/nextid",)
    assert request.call_args_list[0].kwargs == {}
    assert request.call_args_list[1].args == ("/nodes/pve-a/qemu",)
    assert request.call_args_list[1].kwargs == {"method": "POST", "payload": expected_payload}


@pytest.mark.parametrize("status", [400, 409])
def test_create_vm_reallocates_vmid_after_a_specific_collision(client, status):
    vm_request = {"name": "web-prod-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}
    collision = PVEHTTPError(status, "VMID 101 already exists")

    with patch.object(client, "_request", side_effect=[101, collision, 102, "UPID:pve:0002"]) as request:
        assert client.create_vm(vm_request) == "UPID:pve:0002"

    assert request.call_args_list[0].args == ("/cluster/nextid",)
    assert request.call_args_list[1].kwargs["payload"]["vmid"] == 101
    assert request.call_args_list[2].args == ("/cluster/nextid",)
    assert request.call_args_list[3].kwargs["payload"]["vmid"] == 102
    assert request.call_count == 4


def test_create_vm_stops_after_three_vmid_collision_retries(client):
    vm_request = {"name": "web-prod-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}
    collision = PVEHTTPError(409, "VMID already used")

    with patch.object(client, "_request", side_effect=[101, collision, 102, collision, 103, collision, 104, collision]) as request:
        with pytest.raises(PVEHTTPError, match="already used"):
            client.create_vm(vm_request)

    assert [call.args[0] for call in request.call_args_list] == [
        "/cluster/nextid", "/nodes/pve-a/qemu", "/cluster/nextid", "/nodes/pve-a/qemu",
        "/cluster/nextid", "/nodes/pve-a/qemu", "/cluster/nextid", "/nodes/pve-a/qemu",
    ]


def test_create_vm_does_not_retry_non_collision_http_errors(client):
    vm_request = {"name": "web-prod-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}
    error = PVEHTTPError(409, "ISO storage is unavailable")

    with patch.object(client, "_request", side_effect=[101, error]) as request:
        with pytest.raises(PVEHTTPError, match="storage is unavailable"):
            client.create_vm(vm_request)

    assert request.call_count == 2


@pytest.mark.parametrize("vmid", [None, "", "abc", "100.5", 0, -1, True])
def test_create_vm_rejects_invalid_vmid(client, vmid):
    with patch.object(client, "_request", return_value=vmid) as request:
        with pytest.raises(ValueError, match="VMID"):
            client.create_vm({"name": "web-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 1, "ram_mb": 512, "disk_gb": 8})

    request.assert_called_once_with("/cluster/nextid")


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({}, "manquantes"),
        ({"PVE_API_URL": "http://pve.example/api2/json", "PVE_TOKEN_ID": "portal@pve!token", "PVE_TOKEN_SECRET": "test-secret"}, "HTTPS"),
        ({"PVE_API_URL": "https://pve.example/api2/json", "PVE_TOKEN_ID": "portal@pve", "PVE_TOKEN_SECRET": "test-secret"}, "identifiant de token"),
        ({"PVE_API_URL": "https://pve.example/api2/json", "PVE_TOKEN_ID": "root@pam!dangerous", "PVE_TOKEN_SECRET": "test-secret"}, "root"),
    ],
)
def test_from_environment_rejects_invalid_configuration(monkeypatch, environment, message):
    for name in ("PVE_API_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=message):
        PVEClient.from_environment()
