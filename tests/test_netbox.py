from unittest.mock import Mock, patch

import pytest
import requests

from portal.netbox import (
    FakeNetBoxClient,
    NetBoxClient,
    NetBoxConflict,
    NetBoxUnavailable,
)


def response(status, payload=None):
    result = Mock(status_code=status)
    result.json.return_value = payload
    return result


def test_netbox_reservation_activation_release_and_prefix_validation():
    client = NetBoxClient("https://netbox.example", "secret", "/ca.pem")
    with patch(
        "portal.netbox.requests.request",
        side_effect=[
            response(200, {"prefix": "10.10.12.0/24", "vrf": {"id": 7}}),
            response(201, {"id": 51}),
            response(200, {"id": 51, "status": {"value": "active"}}),
            response(204),
        ],
    ) as request:
        assert client.validate_prefix(42, "10.10.12.0/24") == 7
        assert client.reserve_ip(
            address="10.10.12.50/24", description="portal", dns_name="vm-01",
            vrf_id=7,
        ) == 51
        client.activate_ip(51)
        client.release_ip(51)
    assert request.call_args_list[1].kwargs["headers"]["Authorization"] == "Token secret"
    assert request.call_args_list[1].kwargs["verify"] == "/ca.pem"
    assert request.call_args_list[1].kwargs["json"]["status"] == "reserved"
    assert request.call_args_list[1].kwargs["json"]["vrf"] == 7
    assert request.call_args_list[3].args[:2] == (
        "DELETE",
        "https://netbox.example/api/ipam/ip-addresses/51/",
    )


def test_netbox_classifies_conflicts_transport_and_invalid_responses():
    client = NetBoxClient("https://netbox.example/", "secret")
    with patch("portal.netbox.requests.request", return_value=response(409, {})):
        with pytest.raises(NetBoxConflict):
            client.reserve_ip(address="10.0.0.2/24", description="vm")
    with patch(
        "portal.netbox.requests.request",
        side_effect=requests.ConnectionError("offline"),
    ):
        with pytest.raises(NetBoxUnavailable):
            client.check_connection()
    with patch("portal.netbox.requests.request", return_value=response(503, {})):
        with pytest.raises(NetBoxUnavailable):
            client.check_connection()
    invalid_json = response(200)
    invalid_json.json.side_effect = requests.JSONDecodeError("bad", "x", 0)
    with patch("portal.netbox.requests.request", return_value=invalid_json):
        with pytest.raises(NetBoxUnavailable):
            client.check_connection()
    with patch("portal.netbox.requests.request", return_value=response(200, [])):
        with pytest.raises(NetBoxUnavailable):
            client.check_connection()
    with patch("portal.netbox.requests.request", return_value=response(201, {})):
        with pytest.raises(NetBoxUnavailable):
            client.reserve_ip(address="10.0.0.2/24", description="vm")
    with patch(
        "portal.netbox.requests.request",
        return_value=response(200, {"prefix": "10.0.1.0/24"}),
    ):
        with pytest.raises(NetBoxUnavailable):
            client.validate_prefix(1, "10.0.0.0/24")
    with patch(
        "portal.netbox.requests.request",
        return_value=response(200, {"prefix": "10.0.0.0/24", "vrf": "bad"}),
    ):
        with pytest.raises(NetBoxUnavailable):
            client.validate_prefix(1, "10.0.0.0/24")


def test_fake_netbox_exposes_failure_modes():
    client = FakeNetBoxClient(reservations={}, prefixes={1: "10.0.0.0/24"})
    client.check_connection()
    client.validate_prefix(1, "10.0.0.0/24")
    ip_id = client.reserve_ip(address="10.0.0.2/24", description="vm")
    client.activate_ip(ip_id)
    client.unavailable = True
    for action in (
        client.check_connection,
        lambda: client.validate_prefix(1, "10.0.0.0/24"),
        lambda: client.reserve_ip(address="10.0.0.3/24", description="vm"),
        lambda: client.activate_ip(ip_id),
        lambda: client.release_ip(ip_id),
    ):
        with pytest.raises(NetBoxUnavailable):
            action()
