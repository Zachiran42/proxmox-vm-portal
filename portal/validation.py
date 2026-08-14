from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any, cast

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_NODE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ISO = re.compile(r"^[a-z][a-z0-9_-]*:iso/[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\.iso$")
_LINUX_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_BRIDGE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,31}$")
_FIELDS = {
    "name",
    "node",
    "profile",
    "cpu",
    "ram_mb",
    "disk_gb",
    "guest_username",
    "guest_password",
    "network_mode",
    "network_profile",
    "ipv4_cidr",
    "gateway",
    "dns_servers",
}
_VM_REQUIRED_FIELDS = _FIELDS - {
    "guest_username",
    "guest_password",
    "network_mode",
    "network_profile",
    "ipv4_cidr",
    "gateway",
    "dns_servers",
}
_USER_FIELDS = {"username", "password", "role", "quota"}
_USER_UPDATE_FIELDS = {"password", "role", "is_active", "quota"}
_VM_ACTION_FIELDS = {"action", "confirm_name"}
_INCIDENT_ACTION_FIELDS = {"action", "confirm_name"}
_QUOTA_FIELDS = {"vms", "cpu", "ram_mb", "disk_gb"}
_PROFILE_BASE_FIELDS = {"slug", "label", "description", "source_type"}
_PROFILE_FIELDS = _PROFILE_BASE_FIELDS | {"iso", "template_node", "template_vmid"}
_NETWORK_PROFILE_FIELDS = {
    "slug", "label", "cidr", "gateway", "dns_servers", "bridge",
    "vlan_tag", "netbox_prefix_id", "enabled",
}


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        self.errors = errors
        super().__init__("Requête VM invalide")


def validate_node_name(node: Any) -> str:
    """Valide un nom de nœud avant de l'insérer dans un chemin d'API PVE."""
    if not isinstance(node, str) or not _NODE.fullmatch(node):
        raise ValidationError({"node": "Nœud invalide."})
    return node


@dataclass(frozen=True)
class VMRequest:
    name: str
    node: str
    profile: str
    cpu: int
    ram_mb: int
    disk_gb: int
    guest_username: str | None
    guest_password: str | None
    network_mode: str
    network_profile: str | None
    ipv4_cidr: str | None
    gateway: str | None
    dns_servers: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VMRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        missing = _VM_REQUIRED_FIELDS - set(data)
        for field in sorted(missing):
            errors[field] = "Champ requis."

        name, node, profile = data.get("name"), data.get("node"), data.get("profile")
        if name is not None and (not isinstance(name, str) or not _NAME.fullmatch(name)):
            errors["name"] = "Nom invalide (minuscules, chiffres et tirets; 1-63 caractères)."
        if node is not None and (not isinstance(node, str) or not _NODE.fullmatch(node)):
            errors["node"] = "Nœud invalide."
        if profile is not None and (
            not isinstance(profile, str) or not _NAME.fullmatch(profile)
        ):
            errors["profile"] = "Profil d'image invalide."
        guest_username = data.get("guest_username")
        if guest_username is not None and (
            not isinstance(guest_username, str)
            or not _LINUX_USER.fullmatch(guest_username)
            or guest_username in {"root", "admin"}
        ):
            errors["guest_username"] = "Identifiant Linux non privilégié invalide."
        guest_password = data.get("guest_password")
        if guest_password is not None and (
            not isinstance(guest_password, str) or not 1 <= len(guest_password) <= 256
        ):
            errors["guest_password"] = (  # nosec B105
                "Le mot de passe SSH doit contenir entre 1 et 256 caractères."
            )

        network_mode = data.get("network_mode", "dhcp")
        network_profile = data.get("network_profile")
        if network_profile is not None and (
            not isinstance(network_profile, str) or not _NAME.fullmatch(network_profile)
        ):
            errors["network_profile"] = "Profil réseau invalide."
        ipv4_cidr = data.get("ipv4_cidr")
        gateway = data.get("gateway")
        dns_servers = data.get("dns_servers", [])
        interface = None
        if network_mode not in {"dhcp", "static"}:
            errors["network_mode"] = "Mode réseau invalide."
        elif network_mode == "dhcp":
            if ipv4_cidr is not None or gateway is not None or dns_servers:
                errors["network_mode"] = "Le mode DHCP n'accepte aucun paramètre fixe."
        else:
            try:
                interface = IPv4Interface(ipv4_cidr) if isinstance(ipv4_cidr, str) else None
                if (
                    interface is None
                    or interface.ip.is_unspecified
                    or interface.ip.is_multicast
                    or interface.ip.is_loopback
                    or interface.ip.is_link_local
                    or (
                        interface.network.prefixlen <= 30
                        and interface.ip
                        in {
                            interface.network.network_address,
                            interface.network.broadcast_address,
                        }
                    )
                ):
                    raise ValueError
            except ValueError:
                errors["ipv4_cidr"] = "Adresse IPv4 avec préfixe requise, par exemple 192.168.1.50/24."
            try:
                gateway_address = IPv4Address(gateway) if isinstance(gateway, str) else None
                if (
                    gateway_address is None
                    or gateway_address.is_unspecified
                    or gateway_address.is_multicast
                    or (interface is not None and gateway_address not in interface.network)
                ):
                    raise ValueError
            except ValueError:
                errors["gateway"] = "Passerelle IPv4 requise dans le même réseau."
            if (
                not isinstance(dns_servers, list)
                or not 1 <= len(dns_servers) <= 3
                or any(not isinstance(value, str) for value in dns_servers)
            ):
                errors["dns_servers"] = "Une à trois adresses DNS sont requises."
            else:
                try:
                    dns_servers = [str(IPv4Address(value)) for value in dns_servers]
                except ValueError:
                    errors["dns_servers"] = "Les serveurs DNS doivent être des adresses IPv4."

        for field, minimum, maximum, multiple in (
            ("cpu", 1, 32, 1),
            ("ram_mb", 512, 131072, 256),
            ("disk_gb", 8, 2048, 1),
        ):
            value = data.get(field)
            if value is not None and (type(value) is not int or not minimum <= value <= maximum or value % multiple):
                errors[field] = f"Valeur entière requise entre {minimum} et {maximum}."

        if errors:
            raise ValidationError(errors)
        return cls(
            **{field: data[field] for field in _VM_REQUIRED_FIELDS},
            guest_username=guest_username,
            guest_password=guest_password,
            network_mode=network_mode,
            network_profile=network_profile,
            ipv4_cidr=str(interface) if interface is not None else None,
            gateway=str(IPv4Address(gateway)) if network_mode == "static" else None,
            dns_servers=dns_servers if isinstance(dns_servers, list) else [],
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "node": self.node,
            "profile": self.profile,
            "cpu": self.cpu,
            "ram_mb": self.ram_mb,
            "disk_gb": self.disk_gb,
            "guest_username": self.guest_username,
            "network_mode": self.network_mode,
            "network_profile": self.network_profile,
            "ipv4_cidr": self.ipv4_cidr,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
        }


@dataclass(frozen=True)
class NetworkProfileRequest:
    slug: str
    label: str
    cidr: str
    gateway: str
    dns_servers: list[str]
    bridge: str
    vlan_tag: int | None
    netbox_prefix_id: int | None
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkProfileRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _NETWORK_PROFILE_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        for field in {"slug", "label", "cidr", "gateway", "dns_servers", "bridge"} - set(data):
            errors[field] = "Champ requis."
        slug = data.get("slug")
        label = data.get("label")
        bridge = data.get("bridge")
        if not isinstance(slug, str) or not _NAME.fullmatch(slug):
            errors["slug"] = "Identifiant réseau invalide."
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100:
            errors["label"] = "Libellé requis (100 caractères maximum)."
        if not isinstance(bridge, str) or not _BRIDGE.fullmatch(bridge):
            errors["bridge"] = "Bridge Proxmox invalide."
        network = None
        try:
            network = IPv4Network(data.get("cidr"), strict=True)
            if network.prefixlen < 8 or network.prefixlen > 30:
                raise ValueError
        except (TypeError, ValueError):
            errors["cidr"] = "Réseau IPv4 CIDR requis (préfixe /8 à /30)."
        try:
            gateway = IPv4Address(data.get("gateway"))
            if network is None or gateway not in network or gateway in {
                network.network_address, network.broadcast_address
            }:
                raise ValueError
        except (TypeError, ValueError):
            errors["gateway"] = "Passerelle utilisable requise dans ce réseau."
        dns_servers = data.get("dns_servers")
        if not isinstance(dns_servers, list) or not 1 <= len(dns_servers) <= 3:
            errors["dns_servers"] = "Une à trois adresses DNS sont requises."
            normalized_dns: list[str] = []
        else:
            try:
                normalized_dns = [str(IPv4Address(value)) for value in dns_servers]
            except (TypeError, ValueError):
                normalized_dns = []
                errors["dns_servers"] = "Les DNS doivent être des adresses IPv4."
        vlan_tag = data.get("vlan_tag")
        if vlan_tag is not None and (type(vlan_tag) is not int or not 1 <= vlan_tag <= 4094):
            errors["vlan_tag"] = "Le VLAN doit être compris entre 1 et 4094."
        netbox_prefix_id = data.get("netbox_prefix_id")
        if netbox_prefix_id is not None and (
            type(netbox_prefix_id) is not int or netbox_prefix_id < 1
        ):
            errors["netbox_prefix_id"] = "Identifiant de préfixe NetBox invalide."
        enabled = data.get("enabled", True)
        if type(enabled) is not bool:
            errors["enabled"] = "État invalide."
        if errors:
            raise ValidationError(errors)
        normalized_slug = cast(str, slug)
        normalized_label = cast(str, label).strip()
        normalized_bridge = cast(str, bridge)
        return cls(
            slug=normalized_slug,
            label=normalized_label,
            cidr=str(network),
            gateway=str(gateway),
            dns_servers=normalized_dns,
            bridge=normalized_bridge,
            vlan_tag=vlan_tag,
            netbox_prefix_id=netbox_prefix_id,
            enabled=enabled,
        )


@dataclass(frozen=True)
class VMActionRequest:
    action: str
    confirm_name: str | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VMActionRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _VM_ACTION_FIELDS
        if unknown:
            errors["body"] = "Champs non autorisés: " + ", ".join(sorted(unknown))

        action = data.get("action")
        if action not in {"start", "stop", "reboot", "delete"}:
            errors["action"] = "Action invalide."

        confirm_name = data.get("confirm_name")
        if action == "delete":
            if not isinstance(confirm_name, str) or not confirm_name:
                errors["confirm_name"] = "Le nom exact de la VM est requis."
        elif confirm_name is not None:
            errors["confirm_name"] = "Confirmation réservée à la suppression."

        if errors:
            raise ValidationError(errors)
        return cls(action=cast(str, action), confirm_name=confirm_name)


@dataclass(frozen=True)
class IncidentActionRequest:
    action: str
    confirm_name: str | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentActionRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _INCIDENT_ACTION_FIELDS
        if unknown:
            errors["body"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        action = data.get("action")
        if action not in {"resume_tracking", "close_failed"}:
            errors["action"] = "Action de résolution invalide."
        confirm_name = data.get("confirm_name")
        if action == "close_failed":
            if not isinstance(confirm_name, str) or not confirm_name:
                errors["confirm_name"] = "Le nom exact de la VM est requis."
        elif confirm_name is not None:
            errors["confirm_name"] = "Confirmation réservée à la clôture."
        if errors:
            raise ValidationError(errors)
        return cls(action=cast(str, action), confirm_name=confirm_name)

@dataclass(frozen=True)
class ImageProfileCreateRequest:
    slug: str
    label: str
    description: str
    source_type: str
    iso: str | None
    template_node: str | None
    template_vmid: int | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ImageProfileCreateRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _PROFILE_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        for field in sorted(_PROFILE_BASE_FIELDS - set(data)):
            errors[field] = "Champ requis."
        slug = data.get("slug")
        label = data.get("label")
        description = data.get("description")
        source_type = data.get("source_type")
        iso = data.get("iso")
        template_node = data.get("template_node")
        template_vmid = data.get("template_vmid")
        if not isinstance(slug, str) or not _NAME.fullmatch(slug):
            errors["slug"] = "Identifiant de profil invalide."
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100:
            errors["label"] = "Libellé requis (1 à 100 caractères)."
        if not isinstance(description, str) or len(description) > 500:
            errors["description"] = "Description invalide (500 caractères maximum)."
        if source_type not in {"iso", "cloud_init"}:
            errors["source_type"] = "Type de profil invalide."
        elif source_type == "iso":
            if not isinstance(iso, str) or not _ISO.fullmatch(iso):
                errors["iso"] = "ISO invalide; format attendu stockage:iso/fichier.iso."
            if template_node is not None or template_vmid is not None:
                errors["template"] = "Un profil ISO ne référence pas de template."
        else:
            if iso is not None:
                errors["iso"] = "Un profil cloud-init ne référence pas d'ISO."
            if not isinstance(template_node, str) or not _NODE.fullmatch(template_node):
                errors["template_node"] = "Nœud du template invalide."
            if type(template_vmid) is not int or not 100 <= template_vmid <= 999999999:
                errors["template_vmid"] = "VMID de template invalide."
        if errors:
            raise ValidationError(errors)
        return cls(
            slug=cast(str, slug),
            label=cast(str, label).strip(),
            description=cast(str, description),
            source_type=cast(str, source_type),
            iso=iso,
            template_node=template_node,
            template_vmid=template_vmid,
        )


@dataclass(frozen=True)
class UserCreateRequest:
    username: str
    password: str
    role: str
    quota_vms: int
    quota_cpu: int
    quota_ram_mb: int
    quota_disk_gb: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserCreateRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _USER_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        for field in sorted(_USER_FIELDS - set(data)):
            errors[field] = "Champ requis."

        username = data.get("username")
        password = data.get("password")
        role = data.get("role")
        quota = data.get("quota")
        if not isinstance(username, str) or not _NAME.fullmatch(username):
            errors["username"] = "Identifiant invalide."
        if not isinstance(password, str) or not 1 <= len(password) <= 256:
            errors["password"] = (  # nosec B105
                "Le mot de passe doit contenir entre 1 et 256 caractères."
            )
        if role not in {"admin", "operator", "user"}:
            errors["role"] = "Rôle invalide."
        if not isinstance(quota, dict):
            errors["quota"] = "Un objet quota est requis."
            quota = {}
        else:
            quota_unknown = set(quota) - _QUOTA_FIELDS
            if quota_unknown:
                errors["quota"] = "Champs de quota non autorisés: " + ", ".join(
                    sorted(quota_unknown)
                )
            for field in sorted(_QUOTA_FIELDS - set(quota)):
                errors[f"quota.{field}"] = "Champ requis."

        for field, maximum in (
            ("vms", 100),
            ("cpu", 512),
            ("ram_mb", 1048576),
            ("disk_gb", 102400),
        ):
            value = quota.get(field)
            if type(value) is not int or not 0 <= value <= maximum:
                errors[f"quota.{field}"] = f"Entier requis entre 0 et {maximum}."

        if errors:
            raise ValidationError(errors)
        return cls(
            username=cast(str, username),
            password=cast(str, password),
            role=cast(str, role),
            quota_vms=quota["vms"],
            quota_cpu=quota["cpu"],
            quota_ram_mb=quota["ram_mb"],
            quota_disk_gb=quota["disk_gb"],
        )


@dataclass(frozen=True)
class UserUpdateRequest:
    password: str | None
    role: str
    is_active: bool
    quota_vms: int
    quota_cpu: int
    quota_ram_mb: int
    quota_disk_gb: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserUpdateRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _USER_UPDATE_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        for field in sorted({"role", "is_active", "quota"} - set(data)):
            errors[field] = "Champ requis."

        password = data.get("password")
        role = data.get("role")
        is_active = data.get("is_active")
        quota = data.get("quota")
        if password is not None and (
            not isinstance(password, str) or not 1 <= len(password) <= 256
        ):
            errors["password"] = (  # nosec B105
                "Le mot de passe doit contenir entre 1 et 256 caractères."
            )
        if role not in {"admin", "operator", "user"}:
            errors["role"] = "Rôle invalide."
        if type(is_active) is not bool:
            errors["is_active"] = "Booléen requis."
        if not isinstance(quota, dict):
            errors["quota"] = "Un objet quota est requis."
            quota = {}
        else:
            quota_unknown = set(quota) - _QUOTA_FIELDS
            if quota_unknown:
                errors["quota"] = "Champs de quota non autorisés: " + ", ".join(
                    sorted(quota_unknown)
                )
            for field in sorted(_QUOTA_FIELDS - set(quota)):
                errors[f"quota.{field}"] = "Champ requis."

        for field, maximum in (
            ("vms", 100),
            ("cpu", 512),
            ("ram_mb", 1048576),
            ("disk_gb", 102400),
        ):
            value = quota.get(field)
            if type(value) is not int or not 0 <= value <= maximum:
                errors[f"quota.{field}"] = f"Entier requis entre 0 et {maximum}."

        if errors:
            raise ValidationError(errors)
        return cls(
            password=password,
            role=cast(str, role),
            is_active=cast(bool, is_active),
            quota_vms=quota["vms"],
            quota_cpu=quota["cpu"],
            quota_ram_mb=quota["ram_mb"],
            quota_disk_gb=quota["disk_gb"],
        )
