from __future__ import annotations

import json
import ssl
from dataclasses import dataclass, field
from email.message import Message
from ipaddress import ip_address
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .config import environment_value


class PVEHTTPError(HTTPError):
    """Erreur HTTP PVE conservant explicitement le statut et le message."""

    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(url, status, message, hdrs=Message(), fp=None)
        self.message = message


class PVETransportError(RuntimeError):
    """Échec réseau ou TLS vers PVE."""


class PVEProtocolError(RuntimeError):
    """Réponse PVE invalide ou inattendue."""


@dataclass(frozen=True)
class PVEVMSubmission:
    upid: str
    vmid: int


@dataclass
class PVEClient:
    """Adaptateur PVE minimal utilisant exclusivement un API token restreint."""

    api_url: str
    token_id: str
    token_secret: str
    ca_certificate: str = ""

    @classmethod
    def from_environment(cls) -> PVEClient:
        values = {
            key: environment_value(key)
            for key in (
                "PVE_API_URL",
                "PVE_TOKEN_ID",
                "PVE_TOKEN_SECRET",
                "PVE_CA_CERT",
            )
        }
        missing = [
            key
            for key in ("PVE_API_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET")
            if not values[key]
        ]
        if missing:
            raise ValueError("Variables d'environnement manquantes: " + ", ".join(missing))
        if not values["PVE_API_URL"].startswith("https://"):
            raise ValueError("PVE_API_URL doit utiliser HTTPS.")
        if values["PVE_TOKEN_ID"].startswith("root@"):
            raise ValueError("Un token root est interdit; utilisez un compte de service restreint.")
        if "!" not in values["PVE_TOKEN_ID"]:
            raise ValueError("PVE_TOKEN_ID doit être un identifiant de token PVE.")
        return cls(
            values["PVE_API_URL"].rstrip("/"),
            values["PVE_TOKEN_ID"],
            values["PVE_TOKEN_SECRET"],
            values["PVE_CA_CERT"],
        )

    @property
    def authorization_header(self) -> str:
        return f"PVEAPIToken={self.token_id}={self.token_secret}"

    def _request(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": self.authorization_header}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(
            self.api_url + path,
            data=body,
            method=method,
            headers=headers,
        )
        try:
            options: dict[str, Any] = {"timeout": 10}
            if self.ca_certificate:
                context = ssl.create_default_context()
                context.load_verify_locations(cadata=self.ca_certificate)
                # Python 3.13 active X509_STRICT par défaut. Les CA historiques
                # de Proxmox peuvent ne pas contenir l'extension keyUsage, tout
                # en restant des ancres explicitement approuvées par l'admin.
                # On conserve CERT_REQUIRED et la vérification du nom d'hôte.
                context.verify_flags &= ~ssl.VERIFY_X509_STRICT
                options["context"] = context
            with urlopen(request, **options) as response:  # nosec B310
                return json.load(response).get("data")
        except HTTPError as error:
            raise PVEHTTPError(error.code, self._http_error_message(error), error.url) from error
        except (TimeoutError, URLError, ssl.SSLError) as error:
            raise PVETransportError("La connexion à PVE a échoué.") from error
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
            raise PVEProtocolError("La réponse PVE est invalide.") from error

    @staticmethod
    def _http_error_message(error: HTTPError) -> str:
        """Extrait le détail PVE, sans perdre la raison HTTP en cas de corps invalide."""
        message = str(error.reason)
        try:
            response = json.loads(error.read().decode())
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
            return message
        errors = response.get("errors") if isinstance(response, dict) else None
        if isinstance(errors, dict):
            details = "; ".join(str(detail) for detail in errors.values())
            if details:
                return details
        return message

    def is_iso_available(self, node: str, iso: str) -> bool:
        storage, filename = iso.split(":iso/", 1)
        content = self._request(
            f"/nodes/{quote(node, safe='')}/storage/{quote(storage, safe='')}/content?content=iso"
        )
        if not isinstance(content, list):
            raise PVEProtocolError("Le contenu du stockage PVE est invalide.")
        return any(
            isinstance(item, dict)
            and item.get("volid") == f"{storage}:iso/{filename}"
            for item in content
        )

    def is_template_available(self, node: str, vmid: int) -> bool:
        result = self._request(
            f"/nodes/{quote(node, safe='')}/qemu/{vmid}/status/current"
        )
        if not isinstance(result, dict):
            raise PVEProtocolError("Le statut du template PVE est invalide.")
        return result.get("template") == 1

    def list_nodes(self) -> list[str]:
        """Retourne uniquement les nœuds PVE en ligne, triés et dédupliqués."""
        nodes = self._request("/nodes")
        if not isinstance(nodes, list):
            raise PVEProtocolError("La liste des nœuds PVE est invalide.")
        return sorted(
            {
                item["node"]
                for item in nodes
                if isinstance(item, dict)
                and isinstance(item.get("node"), str)
                and item.get("status") == "online"
            }
        )

    def list_isos(self, node: str) -> list[str]:
        """Inventorie les ISO réellement accessibles sur un nœud."""
        storages = self._request(
            f"/nodes/{quote(node, safe='')}/storage?content=iso&enabled=1"
        )
        if not isinstance(storages, list):
            raise PVEProtocolError("La liste des stockages PVE est invalide.")

        isos: set[str] = set()
        for item in storages:
            storage = item.get("storage") if isinstance(item, dict) else None
            if not isinstance(storage, str) or not storage:
                continue
            content = self._request(
                f"/nodes/{quote(node, safe='')}/storage/{quote(storage, safe='')}/content?content=iso"
            )
            if not isinstance(content, list):
                raise PVEProtocolError("Le contenu du stockage PVE est invalide.")
            for volume in content:
                volid = volume.get("volid") if isinstance(volume, dict) else None
                if isinstance(volid, str) and volid.startswith(f"{storage}:iso/"):
                    isos.add(volid)
        return sorted(isos)

    def create_vm(self, request: dict[str, Any]) -> PVEVMSubmission:
        # /cluster/nextid n'est pas une réservation atomique : trois collisions maximum.
        for retry in range(4):
            vmid = self._valid_vmid(self._request("/cluster/nextid"))
            if request.get("source_type", "iso") == "cloud_init":
                path = (
                    f"/nodes/{quote(request['template_node'], safe='')}/qemu/"
                    f"{request['template_vmid']}/clone"
                )
                payload = {
                    "newid": vmid,
                    "name": request["name"],
                    "target": request["node"],
                    "full": 1,
                }
            else:
                path = f"/nodes/{quote(request['node'], safe='')}/qemu"
                payload = {
                    "vmid": vmid,
                    "name": request["name"],
                    "cores": request["cpu"],
                    "memory": request["ram_mb"],
                    "scsihw": "virtio-scsi-pci",
                    "scsi0": f"local-lvm:{request['disk_gb']}",
                    "ide2": f"{request['iso']},media=cdrom",
                }
            try:
                result = self._request(path, method="POST", payload=payload)
            except PVEHTTPError as error:
                if retry < 3 and self._is_vmid_collision(error):
                    continue
                raise
            if not isinstance(result, str) or not result.startswith("UPID:"):
                raise PVEProtocolError("L'identifiant de tâche PVE est invalide.")
            return PVEVMSubmission(upid=result, vmid=vmid)
        raise RuntimeError("Tentatives d'allocation VMID épuisées.")  # pragma: no cover

    @staticmethod
    def _valid_vmid(vmid: Any) -> int:
        if isinstance(vmid, bool) or not isinstance(vmid, (int, str)):
            raise PVEProtocolError("Le VMID retourné par Proxmox est invalide.")
        try:
            vmid = int(vmid)
        except ValueError as error:
            raise PVEProtocolError("Le VMID retourné par Proxmox est invalide.") from error
        if vmid <= 0:
            raise PVEProtocolError("Le VMID retourné par Proxmox doit être positif.")
        return vmid

    @staticmethod
    def _is_vmid_collision(error: PVEHTTPError) -> bool:
        message = error.message.lower()
        mentions_vm = "vmid" in message or "vm " in message
        indicates_collision = "already exists" in message or "already used" in message or "already in use" in message
        return error.status in (400, 409) and mentions_vm and indicates_collision

    def get_task_status(self, node: str, upid: str) -> dict[str, str]:
        if not isinstance(upid, str) or not upid.startswith("UPID:"):
            raise PVEProtocolError("L'identifiant de tâche PVE est invalide.")
        result = self._request(
            f"/nodes/{quote(node, safe='')}/tasks/{quote(upid, safe='')}/status"
        )
        if not isinstance(result, dict) or result.get("status") not in {
            "running",
            "stopped",
        }:
            raise PVEProtocolError("Le statut de tâche PVE est invalide.")
        status = result["status"]
        exitstatus = result.get("exitstatus")
        if status == "stopped" and not isinstance(exitstatus, str):
            raise PVEProtocolError("Le résultat de tâche PVE est invalide.")
        return {"status": status, **({"exitstatus": exitstatus} if exitstatus else {})}

    def configure_cloud_init_vm(
        self,
        *,
        node: str,
        vmid: int,
        cpu: int,
        ram_mb: int,
        disk_gb: int,
        username: str,
        password: str,
    ) -> None:
        path = f"/nodes/{quote(node, safe='')}/qemu/{vmid}"
        self._request(
            f"{path}/resize",
            method="PUT",
            payload={"disk": "scsi0", "size": f"{disk_gb}G"},
        )
        self._request(
            f"{path}/config",
            method="PUT",
            payload={
                "cores": cpu,
                "memory": ram_mb,
                "ciuser": username,
                "cipassword": password,
            },
        )

    def start_vm(self, node: str, vmid: int) -> str:
        return self._vm_task(node, vmid, "status/start", method="POST", payload={})

    def stop_vm(self, node: str, vmid: int) -> str:
        return self._vm_task(node, vmid, "status/shutdown", method="POST", payload={})

    def reboot_vm(self, node: str, vmid: int) -> str:
        return self._vm_task(node, vmid, "status/reboot", method="POST", payload={})

    def delete_vm(self, node: str, vmid: int) -> str:
        return self._vm_task(node, vmid, "", method="DELETE")

    def _vm_task(
        self,
        node: str,
        vmid: int,
        suffix: str,
        *,
        method: str,
        payload: dict[str, Any] | None = None,
    ) -> str:
        path = f"/nodes/{quote(node, safe='')}/qemu/{vmid}"
        if suffix:
            path += f"/{suffix}"
        result = self._request(path, method=method, payload=payload)
        if not isinstance(result, str) or not result.startswith("UPID:"):
            raise PVEProtocolError("L'identifiant de tâche PVE est invalide.")
        return result

    def get_vm_status(self, node: str, vmid: int) -> str:
        result = self._request(
            f"/nodes/{quote(node, safe='')}/qemu/{vmid}/status/current"
        )
        if not isinstance(result, dict) or result.get("status") not in {
            "running",
            "stopped",
        }:
            raise PVEProtocolError("L'état de la VM Proxmox est invalide.")
        return result["status"]

    def get_vm_ipv4_addresses(self, node: str, vmid: int) -> list[str]:
        """Retourne les IPv4 utilisables annoncées par QEMU Guest Agent."""
        response = self._request(
            f"/nodes/{quote(node, safe='')}/qemu/{vmid}/agent/network-get-interfaces"
        )
        interfaces = response.get("result") if isinstance(response, dict) else response
        if not isinstance(interfaces, list):
            raise PVEProtocolError("Les interfaces de la VM Proxmox sont invalides.")

        addresses: set[str] = set()
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            candidates = interface.get("ip-addresses", [])
            if not isinstance(candidates, list):
                continue
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                raw = candidate.get("ip-address")
                if candidate.get("ip-address-type") != "ipv4" or not isinstance(raw, str):
                    continue
                try:
                    parsed = ip_address(raw)
                except ValueError:
                    continue
                if (
                    parsed.version == 4
                    and not parsed.is_loopback
                    and not parsed.is_link_local
                    and not parsed.is_multicast
                    and not parsed.is_unspecified
                ):
                    addresses.add(str(parsed))
        return sorted(addresses, key=lambda value: tuple(int(part) for part in value.split(".")))


@dataclass
class FakePVEClient:
    accessible_isos: dict[str, set[str]]
    requests: list[dict[str, Any]] = field(default_factory=list)
    task_statuses: list[dict[str, str]] = field(
        default_factory=lambda: [{"status": "stopped", "exitstatus": "OK"}]
    )
    templates: set[tuple[str, int]] = field(default_factory=set)
    configurations: list[dict[str, Any]] = field(default_factory=list)
    starts: list[tuple[str, int]] = field(default_factory=list)
    stops: list[tuple[str, int]] = field(default_factory=list)
    reboots: list[tuple[str, int]] = field(default_factory=list)
    deletions: list[tuple[str, int]] = field(default_factory=list)
    vm_statuses: dict[tuple[str, int], str] = field(default_factory=dict)
    vm_ipv4_addresses: dict[tuple[str, int], list[str]] = field(default_factory=dict)

    def is_iso_available(self, node: str, iso: str) -> bool:
        return iso in self.accessible_isos.get(node, set())

    def is_template_available(self, node: str, vmid: int) -> bool:
        return (node, vmid) in self.templates

    def list_nodes(self) -> list[str]:
        return sorted(self.accessible_isos)

    def list_isos(self, node: str) -> list[str]:
        return sorted(self.accessible_isos.get(node, set()))

    def create_vm(self, request: dict[str, Any]) -> PVEVMSubmission:
        self.requests.append(request)
        return PVEVMSubmission(upid=f"UPID:fake:{len(self.requests)}", vmid=100)

    def get_task_status(self, node: str, upid: str) -> dict[str, str]:
        if len(self.task_statuses) > 1:
            return self.task_statuses.pop(0)
        return self.task_statuses[0]

    def get_vm_status(self, node: str, vmid: int) -> str:
        return self.vm_statuses.get((node, vmid), "stopped")

    def get_vm_ipv4_addresses(self, node: str, vmid: int) -> list[str]:
        return list(self.vm_ipv4_addresses.get((node, vmid), []))

    def configure_cloud_init_vm(self, **configuration: Any) -> None:
        self.configurations.append(configuration)

    def start_vm(self, node: str, vmid: int) -> str:
        self.starts.append((node, vmid))
        self.vm_statuses[(node, vmid)] = "running"
        return f"UPID:fake:start:{len(self.starts)}"

    def stop_vm(self, node: str, vmid: int) -> str:
        self.stops.append((node, vmid))
        self.vm_statuses[(node, vmid)] = "stopped"
        return f"UPID:fake:stop:{len(self.stops)}"

    def reboot_vm(self, node: str, vmid: int) -> str:
        self.reboots.append((node, vmid))
        return f"UPID:fake:reboot:{len(self.reboots)}"

    def delete_vm(self, node: str, vmid: int) -> str:
        self.deletions.append((node, vmid))
        return f"UPID:fake:delete:{len(self.deletions)}"
