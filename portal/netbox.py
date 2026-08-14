from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import requests


class NetBoxError(RuntimeError):
    """Erreur générique de l'intégration NetBox."""


class NetBoxConflict(NetBoxError):
    """L'adresse demandée est déjà enregistrée dans NetBox."""


class NetBoxUnavailable(NetBoxError):
    """NetBox ne peut pas être joint ou retourne une erreur transitoire."""


@dataclass
class NetBoxClient:
    base_url: str
    api_token: str
    ca_bundle: str = ""
    ca_certificate: str = ""
    timeout: int = 10

    @property
    def verify(self) -> bool | str:
        return self.ca_bundle or True

    def _request(self, method: str, path: str, *, payload: dict[str, Any] | None = None):
        temporary_ca: str | None = None
        try:
            verify = self.verify
            if self.ca_certificate:
                with NamedTemporaryFile(
                    mode="w", encoding="utf-8", delete=False, prefix="netbox-ca-"
                ) as ca_file:
                    ca_file.write(self.ca_certificate)
                    temporary_ca = ca_file.name
                Path(temporary_ca).chmod(0o600)
                verify = temporary_ca
            response = requests.request(
                method,
                f"{self.base_url.rstrip('/')}/api/{path.lstrip('/')}",
                headers={
                    "Authorization": f"Token {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
                verify=verify,
            )
        except requests.RequestException as error:
            raise NetBoxUnavailable("La connexion à NetBox a échoué.") from error
        finally:
            if temporary_ca is not None:
                Path(temporary_ca).unlink(missing_ok=True)
        if response.status_code in {400, 409}:
            raise NetBoxConflict("Cette adresse IP est déjà réservée dans NetBox.")
        if response.status_code >= 400:
            raise NetBoxUnavailable(f"NetBox a retourné HTTP {response.status_code}.")
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except requests.JSONDecodeError as error:
            raise NetBoxUnavailable("La réponse NetBox est invalide.") from error

    def check_connection(self) -> None:
        result = self._request("GET", "status/")
        if not isinstance(result, dict):
            raise NetBoxUnavailable("La réponse de statut NetBox est invalide.")

    def validate_prefix(self, prefix_id: int, expected_cidr: str) -> int | None:
        result = self._request("GET", f"ipam/prefixes/{prefix_id}/")
        if not isinstance(result, dict) or result.get("prefix") != expected_cidr:
            raise NetBoxUnavailable(
                "Le préfixe NetBox ne correspond pas au CIDR du profil réseau."
            )
        vrf = result.get("vrf")
        if vrf is None:
            return None
        if not isinstance(vrf, dict) or type(vrf.get("id")) is not int:
            raise NetBoxUnavailable("La VRF du préfixe NetBox est invalide.")
        return vrf["id"]

    def reserve_ip(
        self,
        *,
        address: str,
        description: str,
        dns_name: str = "",
        vrf_id: int | None = None,
    ) -> int:
        result = self._request(
            "POST",
            "ipam/ip-addresses/",
            payload={
                "address": address,
                "status": "reserved",
                "description": description[:200],
                "dns_name": dns_name[:255],
                **({"vrf": vrf_id} if vrf_id is not None else {}),
            },
        )
        if not isinstance(result, dict) or type(result.get("id")) is not int:
            raise NetBoxUnavailable("NetBox n'a pas retourné l'identifiant de réservation.")
        return result["id"]

    def activate_ip(self, ip_id: int) -> None:
        self._request("PATCH", f"ipam/ip-addresses/{ip_id}/", payload={"status": "active"})

    def release_ip(self, ip_id: int) -> None:
        self._request("DELETE", f"ipam/ip-addresses/{ip_id}/")


@dataclass
class FakeNetBoxClient:
    reservations: dict[int, str]
    prefixes: dict[int, str] = field(default_factory=dict)
    next_id: int = 1
    unavailable: bool = False

    def check_connection(self) -> None:
        if self.unavailable:
            raise NetBoxUnavailable("indisponible")

    def validate_prefix(self, prefix_id: int, expected_cidr: str) -> int | None:
        if self.unavailable or self.prefixes.get(prefix_id) != expected_cidr:
            raise NetBoxUnavailable("préfixe invalide")
        return None

    def reserve_ip(
        self, *, address: str, description: str, dns_name: str = "",
        vrf_id: int | None = None,
    ) -> int:
        if self.unavailable:
            raise NetBoxUnavailable("indisponible")
        if address in self.reservations.values():
            raise NetBoxConflict("conflit")
        ip_id = self.next_id
        self.next_id += 1
        self.reservations[ip_id] = address
        return ip_id

    def activate_ip(self, ip_id: int) -> None:
        if self.unavailable or ip_id not in self.reservations:
            raise NetBoxUnavailable("indisponible")

    def release_ip(self, ip_id: int) -> None:
        if self.unavailable:
            raise NetBoxUnavailable("indisponible")
        self.reservations.pop(ip_id, None)
