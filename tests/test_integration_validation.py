import pytest

from portal.validation import (
    ImageProfileCreateRequest,
    NetBoxConfigurationRequest,
    NetworkProfileRequest,
    ProxmoxConfigurationRequest,
    UserCreateRequest,
    UserUpdateRequest,
    ValidationError,
)


def network_payload(**updates):
    payload = {
        "slug": "chu-vlan-12",
        "label": "CHU VLAN 12",
        "cidr": "10.10.12.0/24",
        "gateway": "10.10.12.254",
        "dns_servers": ["10.10.1.10"],
        "bridge": "vmbr0",
        "vlan_tag": 12,
        "netbox_prefix_id": 42,
        "allow_manual_ip": True,
        "allow_automatic_ip": False,
        "enabled": True,
    }
    payload.update(updates)
    return payload


@pytest.mark.parametrize(
    ("updates", "field"),
    [
        ({"unexpected": True}, "unknown"),
        ({"allow_manual_ip": "yes"}, "allow_manual_ip"),
        ({"allow_automatic_ip": "yes"}, "allow_automatic_ip"),
        ({"allow_manual_ip": False}, "allow_manual_ip"),
        ({"pool_start": "10.10.12.10"}, "pool_start"),
        (
            {
                "allow_automatic_ip": True,
                "pool_start": "10.10.12.20",
                "pool_end": "10.10.12.10",
            },
            "pool_start",
        ),
        (
            {
                "allow_automatic_ip": True,
                "pool_start": "10.10.13.10",
                "pool_end": "10.10.13.20",
            },
            "pool_start",
        ),
        ({"excluded_ips": "10.10.12.10"}, "excluded_ips"),
        ({"excluded_ips": ["10.10.13.10"]}, "excluded_ips"),
        ({"enabled": "yes"}, "enabled"),
    ],
)
def test_network_profile_rejects_invalid_ipam_policies(updates, field):
    with pytest.raises(ValidationError) as error:
        NetworkProfileRequest.from_dict(network_payload(**updates))
    assert field in error.value.errors


def test_network_profile_normalizes_automatic_pool_and_exclusions():
    request = NetworkProfileRequest.from_dict(
        network_payload(
            allow_automatic_ip=True,
            pool_start="10.10.12.50",
            pool_end="10.10.12.60",
            excluded_ips=["10.10.12.51", "10.10.12.51"],
        )
    )
    assert request.pool_start == "10.10.12.50"
    assert request.excluded_ips == ["10.10.12.51"]


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "base_url"),
        ({"base_url": "http://netbox.example"}, "base_url"),
        ({"base_url": "https://netbox.example", "unexpected": 1}, "unknown"),
        ({"base_url": "https://netbox.example", "api_token": 42}, "api_token"),
        ({"base_url": "https://netbox.example", "ca_certificate": 42}, "ca_certificate"),
        ({"base_url": "https://netbox.example", "clear_ca": "yes"}, "clear_ca"),
        ({"base_url": "https://netbox.example", "enabled": "yes"}, "enabled"),
    ],
)
def test_netbox_configuration_validation(payload, field):
    with pytest.raises(ValidationError) as error:
        NetBoxConfigurationRequest.from_dict(payload)
    assert field in error.value.errors


def test_netbox_configuration_normalizes_url():
    request = NetBoxConfigurationRequest.from_dict(
        {"base_url": "https://netbox.example/", "api_token": "secret"}
    )
    assert request.base_url == "https://netbox.example"


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "api_url"),
        (
            {"api_url": "https://pve.example", "token_id": "portal@pve!token"},
            "api_url",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "root@pam!token",
            },
            "token_id",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "portal@pve!token",
                "token_secret": 42,
            },
            "token_secret",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "portal@pve!token",
                "ca_certificate": 42,
            },
            "ca_certificate",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "portal@pve!token",
                "clear_ca": "yes",
            },
            "clear_ca",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "portal@pve!token",
                "enabled": "yes",
            },
            "enabled",
        ),
        (
            {
                "api_url": "https://pve.example/api2/json",
                "token_id": "portal@pve!token",
                "unexpected": True,
            },
            "unknown",
        ),
    ],
)
def test_proxmox_configuration_validation(payload, field):
    with pytest.raises(ValidationError) as error:
        ProxmoxConfigurationRequest.from_dict(payload)
    assert field in error.value.errors


def test_proxmox_configuration_accepts_non_root_token():
    request = ProxmoxConfigurationRequest.from_dict(
        {
            "api_url": "https://pve.example:8006/api2/json/",
            "token_id": "portal@pve!provisioning",
            "token_secret": "secret",
        }
    )
    assert request.api_url == "https://pve.example:8006/api2/json"


@pytest.mark.parametrize(
    "payload",
    [
        {"unexpected": True},
        {
            "slug": "profile",
            "label": "ISO",
            "description": "",
            "source_type": "iso",
            "iso": "invalid",
            "template_node": "pve-a",
            "template_vmid": 9000,
        },
        {
            "slug": "profile",
            "label": "Cloud",
            "description": "",
            "source_type": "cloud_init",
            "iso": "local:iso/debian.iso",
            "template_node": "invalid node",
            "template_vmid": 1,
        },
    ],
)
def test_image_profile_validation_rejects_incoherent_sources(payload):
    with pytest.raises(ValidationError):
        ImageProfileCreateRequest.from_dict(payload)


@pytest.mark.parametrize(
    ("validator", "payload"),
    [
        (UserCreateRequest.from_dict, {}),
        (
            UserCreateRequest.from_dict,
            {
                "username": "user",
                "password": "password",
                "role": "user",
                "quota": {"unexpected": 1},
            },
        ),
        (UserUpdateRequest.from_dict, {}),
        (
            UserUpdateRequest.from_dict,
            {
                "role": "user",
                "is_active": True,
                "quota": {"unexpected": 1},
            },
        ),
    ],
)
def test_user_quota_validation_rejects_missing_and_unknown_fields(validator, payload):
    with pytest.raises(ValidationError):
        validator(payload)
