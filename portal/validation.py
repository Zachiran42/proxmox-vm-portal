from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any, cast
from urllib.parse import urlsplit

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_IMAGE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
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
    "usage_purpose",
    "no_patient_data_ack",
    "lifetime_days",
    "guest_username",
    "guest_password",
    "network_mode",
    "network_profile",
    "ipv4_cidr",
    "gateway",
    "dns_servers",
    "software_modules",
}
_VM_REQUIRED_FIELDS = _FIELDS - {
    "guest_username",
    "guest_password",
    "network_mode",
    "network_profile",
    "ipv4_cidr",
    "gateway",
    "dns_servers",
    "software_modules",
    "lifetime_days",
}
_USAGE_PURPOSES = {
    "technical_test",
    "functional_test",
    "training",
    "security_test",
}
_USER_FIELDS = {"username", "password", "role", "quota"}
_USER_UPDATE_FIELDS = {"password", "role", "is_active", "quota"}
_VM_ACTION_FIELDS = {"action", "confirm_name"}
_INCIDENT_ACTION_FIELDS = {"action", "confirm_name"}
_QUOTA_FIELDS = {"vms", "cpu", "ram_mb", "disk_gb"}
_PROFILE_BASE_FIELDS = {"slug", "label", "description", "source_type", "version"}
_PROFILE_FIELDS = _PROFILE_BASE_FIELDS | {"iso", "template_node", "template_vmid"}
_NETWORK_PROFILE_FIELDS = {
    "slug", "label", "cidr", "gateway", "dns_servers", "bridge",
    "vlan_tag", "netbox_prefix_id", "pool_start", "pool_end", "excluded_ips",
    "allow_manual_ip", "allow_automatic_ip", "connectivity_mode",
    "connectivity_description", "enabled",
    "sandbox_ssh_sources", "sandbox_ntp_servers", "sandbox_apt_endpoints",
    "sandbox_registry_endpoints", "sandbox_monitoring_endpoints",
}
_CONNECTIVITY_MODES = {"sandbox", "isolated", "internal", "internet", "ticket_required"}
_SOFTWARE_MODULE_FIELDS = {
    "slug", "label", "description", "install_mode", "artifacts", "required", "enabled"
}
_APT_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}$")
_OCI_REFERENCE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]{0,220}"
    r"(?:[:@][A-Za-z0-9][A-Za-z0-9._:+-]{0,127})$"
)
_NETBOX_CONFIGURATION_FIELDS = {
    "base_url", "api_token", "ca_certificate", "clear_ca", "enabled"
}
_PROXMOX_CONFIGURATION_FIELDS = {
    "api_url", "token_id", "token_secret", "ca_certificate", "clear_ca", "enabled"
}
_SIEM_CONFIGURATION_FIELDS = {"pull_token", "minimum_outcome", "enabled"}


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
    usage_purpose: str
    no_patient_data_ack: bool
    lifetime_days: int | None
    guest_username: str | None
    guest_password: str | None
    network_mode: str
    network_profile: str | None
    ipv4_cidr: str | None
    gateway: str | None
    dns_servers: list[str]
    software_modules: list[str]

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
        usage_purpose = data.get("usage_purpose")
        if usage_purpose not in _USAGE_PURPOSES:
            errors["usage_purpose"] = "Finalité de test invalide."
        no_patient_data_ack = data.get("no_patient_data_ack")
        if no_patient_data_ack is not True:
            errors["no_patient_data_ack"] = (
                "Confirmez qu’aucune donnée patient réelle ne sera utilisée."
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
        software_modules = data.get("software_modules", [])
        if (
            not isinstance(software_modules, list)
            or len(software_modules) > 32
            or any(not isinstance(value, str) or not _NAME.fullmatch(value) for value in software_modules)
        ):
            errors["software_modules"] = "Liste de modules logiciels invalide."
            software_modules = []
        else:
            software_modules = list(dict.fromkeys(software_modules))
        interface = None
        if network_mode not in {"dhcp", "static", "automatic"}:
            errors["network_mode"] = "Mode réseau invalide."
        elif network_mode in {"dhcp", "automatic"}:
            if ipv4_cidr is not None or gateway is not None or dns_servers:
                errors["network_mode"] = (
                    "Ce mode d'attribution n'accepte aucun paramètre fixe."
                )
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
            ("lifetime_days", 1, 3650, 1),
        ):
            value = data.get(field)
            if value is not None and (type(value) is not int or not minimum <= value <= maximum or value % multiple):
                errors[field] = f"Valeur entière requise entre {minimum} et {maximum}."

        if errors:
            raise ValidationError(errors)
        return cls(
            **{field: data[field] for field in _VM_REQUIRED_FIELDS},
            lifetime_days=data.get("lifetime_days"),
            guest_username=guest_username,
            guest_password=guest_password,
            network_mode=network_mode,
            network_profile=network_profile,
            ipv4_cidr=str(interface) if interface is not None else None,
            gateway=str(IPv4Address(gateway)) if network_mode == "static" else None,
            dns_servers=dns_servers if isinstance(dns_servers, list) else [],
            software_modules=software_modules,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "node": self.node,
            "profile": self.profile,
            "cpu": self.cpu,
            "ram_mb": self.ram_mb,
            "disk_gb": self.disk_gb,
            "usage_purpose": self.usage_purpose,
            "no_patient_data_ack": self.no_patient_data_ack,
            "lifetime_days": self.lifetime_days,
            "guest_username": self.guest_username,
            "network_mode": self.network_mode,
            "network_profile": self.network_profile,
            "ipv4_cidr": self.ipv4_cidr,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "software_modules": self.software_modules,
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
    pool_start: str | None
    pool_end: str | None
    excluded_ips: list[str]
    allow_manual_ip: bool
    allow_automatic_ip: bool
    connectivity_mode: str
    connectivity_description: str
    sandbox_ssh_sources: list[str]
    sandbox_ntp_servers: list[str]
    sandbox_apt_endpoints: list[str]
    sandbox_registry_endpoints: list[str]
    sandbox_monitoring_endpoints: list[str]
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
        allow_manual_ip = data.get("allow_manual_ip", True)
        allow_automatic_ip = data.get("allow_automatic_ip", False)
        if type(allow_manual_ip) is not bool:
            errors["allow_manual_ip"] = "Politique d'attribution manuelle invalide."
        if type(allow_automatic_ip) is not bool:
            errors["allow_automatic_ip"] = "Politique d'attribution automatique invalide."
        if allow_manual_ip is False and allow_automatic_ip is False:
            errors["allow_manual_ip"] = "Autorisez au moins un mode d'attribution fixe."
        connectivity_mode = data.get("connectivity_mode", "sandbox")
        if connectivity_mode not in _CONNECTIVITY_MODES:
            errors["connectivity_mode"] = "Politique de connectivité invalide."
        connectivity_description = data.get("connectivity_description", "")
        if not isinstance(connectivity_description, str) or len(
            connectivity_description.strip()
        ) > 300:
            errors["connectivity_description"] = (
                "La portée réseau doit contenir 300 caractères maximum."
            )

        pool_start = data.get("pool_start")
        pool_end = data.get("pool_end")
        normalized_start = None
        normalized_end = None
        if allow_automatic_ip is True:
            try:
                start_address = IPv4Address(pool_start)
                end_address = IPv4Address(pool_end)
                if (
                    network is None
                    or start_address not in network
                    or end_address not in network
                    or start_address > end_address
                    or int(end_address) - int(start_address) > 65535
                    or start_address
                    in {network.network_address, network.broadcast_address}
                    or end_address
                    in {network.network_address, network.broadcast_address}
                ):
                    raise ValueError
                normalized_start = str(start_address)
                normalized_end = str(end_address)
            except (TypeError, ValueError):
                errors["pool_start"] = (
                    "Plage automatique utilisable requise dans le réseau."
                )
        elif pool_start is not None or pool_end is not None:
            errors["pool_start"] = (
                "Activez l'attribution automatique avant de définir une plage."
            )

        excluded_ips = data.get("excluded_ips", [])
        normalized_excluded: list[str] = []
        if not isinstance(excluded_ips, list) or len(excluded_ips) > 128:
            errors["excluded_ips"] = (
                "Liste d'exclusions invalide (128 adresses maximum)."
            )
        else:
            try:
                normalized_excluded = list(
                    dict.fromkeys(str(IPv4Address(value)) for value in excluded_ips)
                )
                if network is None or any(
                    IPv4Address(value) not in network for value in normalized_excluded
                ):
                    raise ValueError
            except (TypeError, ValueError):
                errors["excluded_ips"] = (
                    "Les exclusions doivent appartenir au réseau."
                )
        enabled = data.get("enabled", True)
        if type(enabled) is not bool:
            errors["enabled"] = "État invalide."
        sandbox_values: dict[str, list[str]] = {}
        for field in (
            "sandbox_ssh_sources",
            "sandbox_ntp_servers",
            "sandbox_apt_endpoints",
            "sandbox_registry_endpoints",
            "sandbox_monitoring_endpoints",
        ):
            raw_values = data.get(field, [])
            if not isinstance(raw_values, list) or len(raw_values) > 32:
                errors[field] = "Liste réseau invalide (32 entrées maximum)."
                sandbox_values[field] = []
                continue
            normalized_values: list[str] = []
            try:
                for value in raw_values:
                    if not isinstance(value, str):
                        raise ValueError
                    if field == "sandbox_ssh_sources":
                        normalized_values.append(str(IPv4Network(value, strict=False)))
                    else:
                        normalized_values.append(str(IPv4Address(value)))
            except (TypeError, ValueError):
                errors[field] = (
                    "Des réseaux IPv4 CIDR sont requis."
                    if field == "sandbox_ssh_sources"
                    else "Des adresses IPv4 sont requises."
                )
                normalized_values = []
            sandbox_values[field] = list(dict.fromkeys(normalized_values))
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
            pool_start=normalized_start,
            pool_end=normalized_end,
            excluded_ips=normalized_excluded,
            allow_manual_ip=allow_manual_ip,
            allow_automatic_ip=allow_automatic_ip,
            connectivity_mode=cast(str, connectivity_mode),
            connectivity_description=cast(str, connectivity_description).strip(),
            sandbox_ssh_sources=sandbox_values["sandbox_ssh_sources"],
            sandbox_ntp_servers=sandbox_values["sandbox_ntp_servers"],
            sandbox_apt_endpoints=sandbox_values["sandbox_apt_endpoints"],
            sandbox_registry_endpoints=sandbox_values["sandbox_registry_endpoints"],
            sandbox_monitoring_endpoints=sandbox_values["sandbox_monitoring_endpoints"],
            enabled=enabled,
        )


@dataclass(frozen=True)
class SoftwareModuleRequest:
    slug: str
    label: str
    description: str
    install_mode: str
    artifacts: list[str]
    required: bool
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SoftwareModuleRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _SOFTWARE_MODULE_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        slug = data.get("slug")
        label = data.get("label")
        description = data.get("description", "")
        install_mode = data.get("install_mode")
        artifacts = data.get("artifacts", [])
        required = data.get("required", False)
        enabled = data.get("enabled", True)
        if not isinstance(slug, str) or not _NAME.fullmatch(slug):
            errors["slug"] = "Identifiant de module invalide."
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100:
            errors["label"] = "Libellé requis (100 caractères maximum)."
        if not isinstance(description, str) or len(description.strip()) > 500:
            errors["description"] = "Description limitée à 500 caractères."
        if install_mode not in {"preinstalled", "apt", "container"}:
            errors["install_mode"] = "Mode d’installation invalide."
        if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
            errors["artifacts"] = "Un à 32 artefacts sont requis."
            normalized_artifacts: list[str] = []
        else:
            normalized_artifacts = []
            matcher = _OCI_REFERENCE if install_mode == "container" else _APT_PACKAGE
            for value in artifacts:
                if not isinstance(value, str) or not matcher.fullmatch(value.strip()):
                    errors["artifacts"] = (
                        "Références OCI immuables attendues."
                        if install_mode == "container"
                        else "Noms de paquets APT invalides."
                    )
                    break
                normalized_artifacts.append(value.strip())
            normalized_artifacts = list(dict.fromkeys(normalized_artifacts))
        if type(required) is not bool:
            errors["required"] = "Booléen requis."
        if type(enabled) is not bool:
            errors["enabled"] = "Booléen requis."
        if errors:
            raise ValidationError(errors)
        return cls(
            slug=cast(str, slug),
            label=cast(str, label).strip(),
            description=cast(str, description).strip(),
            install_mode=cast(str, install_mode),
            artifacts=normalized_artifacts,
            required=required,
            enabled=enabled,
        )


def _https_origin(value: Any, field: str) -> tuple[str | None, dict[str, str]]:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 512:
        return None, {field: "URL HTTPS requise."}
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None, {field: "URL HTTPS valide sans identifiants requise."}
    return normalized, {}


@dataclass(frozen=True)
class NetBoxConfigurationRequest:
    base_url: str
    api_token: str | None
    ca_certificate: str | None
    clear_ca: bool
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetBoxConfigurationRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _NETBOX_CONFIGURATION_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        base_url, url_errors = _https_origin(data.get("base_url"), "base_url")
        errors.update(url_errors)
        api_token = data.get("api_token")
        if api_token is not None and (
            not isinstance(api_token, str) or not 1 <= len(api_token) <= 2048
        ):
            errors["api_token"] = "Token NetBox invalide."  # nosec B105
        ca_certificate = data.get("ca_certificate")
        if ca_certificate is not None and (
            not isinstance(ca_certificate, str) or len(ca_certificate) > 65536
        ):
            errors["ca_certificate"] = "Certificat CA invalide."
        clear_ca = data.get("clear_ca", False)
        enabled = data.get("enabled", True)
        if type(clear_ca) is not bool:
            errors["clear_ca"] = "Option de suppression de CA invalide."
        if type(enabled) is not bool:
            errors["enabled"] = "État invalide."
        if errors:
            raise ValidationError(errors)
        return cls(
            base_url=cast(str, base_url),
            api_token=api_token,
            ca_certificate=ca_certificate,
            clear_ca=clear_ca,
            enabled=enabled,
        )


@dataclass(frozen=True)
class ProxmoxConfigurationRequest:
    api_url: str
    token_id: str
    token_secret: str | None
    ca_certificate: str | None
    clear_ca: bool
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxmoxConfigurationRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _PROXMOX_CONFIGURATION_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        api_url, url_errors = _https_origin(data.get("api_url"), "api_url")
        errors.update(url_errors)
        if api_url is not None and not api_url.endswith("/api2/json"):
            errors["api_url"] = "L'URL Proxmox doit se terminer par /api2/json."
        token_id = data.get("token_id")
        if (
            not isinstance(token_id, str)
            or not 3 <= len(token_id) <= 255
            or "!" not in token_id
            or token_id.startswith("root@")
        ):
            errors["token_id"] = "Identifiant de token non-root requis."  # nosec B105
        token_secret = data.get("token_secret")
        if token_secret is not None and (
            not isinstance(token_secret, str) or not 1 <= len(token_secret) <= 2048
        ):
            errors["token_secret"] = "Secret du token Proxmox invalide."  # nosec B105
        ca_certificate = data.get("ca_certificate")
        if ca_certificate is not None and (
            not isinstance(ca_certificate, str) or len(ca_certificate) > 65536
        ):
            errors["ca_certificate"] = "Certificat CA invalide."
        clear_ca = data.get("clear_ca", False)
        enabled = data.get("enabled", True)
        if type(clear_ca) is not bool:
            errors["clear_ca"] = "Option de suppression de CA invalide."
        if type(enabled) is not bool:
            errors["enabled"] = "État invalide."
        if errors:
            raise ValidationError(errors)
        return cls(
            api_url=cast(str, api_url),
            token_id=cast(str, token_id),
            token_secret=token_secret,
            ca_certificate=ca_certificate,
            clear_ca=clear_ca,
            enabled=enabled,
        )


@dataclass(frozen=True)
class SiemConfigurationRequest:
    pull_token: str | None
    minimum_outcome: str
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SiemConfigurationRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _SIEM_CONFIGURATION_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        pull_token = data.get("pull_token")
        if pull_token is not None and (
            not isinstance(pull_token, str) or not 32 <= len(pull_token) <= 512
        ):
            errors["pull_token"] = "Jeton SIEM requis entre 32 et 512 caractères."  # nosec B105
        minimum_outcome = data.get("minimum_outcome", "all")
        if minimum_outcome not in {"all", "failure", "denied"}:
            errors["minimum_outcome"] = "Filtre SIEM invalide."
        enabled = data.get("enabled", False)
        if type(enabled) is not bool:
            errors["enabled"] = "État invalide."
        if errors:
            raise ValidationError(errors)
        return cls(
            pull_token=pull_token,
            minimum_outcome=cast(str, minimum_outcome),
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
    version: str
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
        version = data.get("version")
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
        if not isinstance(version, str) or not _IMAGE_VERSION.fullmatch(version):
            errors["version"] = "Version invalide (64 caractères maximum)."
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
            version=cast(str, version),
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
