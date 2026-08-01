from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class PVEHTTPError(HTTPError):
    """Erreur HTTP PVE conservant explicitement le statut et le message."""

    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(url, status, message, hdrs=None, fp=None)
        self.message = message


class PVETransportError(RuntimeError):
    """Échec réseau ou TLS vers PVE."""


class PVEProtocolError(RuntimeError):
    """Réponse PVE invalide ou inattendue."""


@dataclass
class PVEClient:
    """Adaptateur PVE minimal utilisant exclusivement un API token restreint."""

    api_url: str
    token_id: str
    token_secret: str

    @classmethod
    def from_environment(cls) -> PVEClient:
        values = {key: os.environ.get(key, "").strip() for key in ("PVE_API_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET")}
        missing = [key for key, value in values.items() if not value]
        if missing:
            raise ValueError("Variables d'environnement manquantes: " + ", ".join(missing))
        if not values["PVE_API_URL"].startswith("https://"):
            raise ValueError("PVE_API_URL doit utiliser HTTPS.")
        if values["PVE_TOKEN_ID"].startswith("root@"):
            raise ValueError("Un token root est interdit; utilisez un compte de service restreint.")
        if "!" not in values["PVE_TOKEN_ID"]:
            raise ValueError("PVE_TOKEN_ID doit être un identifiant de token PVE.")
        return cls(values["PVE_API_URL"].rstrip("/"), values["PVE_TOKEN_ID"], values["PVE_TOKEN_SECRET"])

    @property
    def authorization_header(self) -> str:
        return f"PVEAPIToken={self.token_id}={self.token_secret}"

    def _request(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            self.api_url + path,
            data=body,
            method=method,
            headers={"Authorization": self.authorization_header, "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=10) as response:  # nosec B310: URL is admin-controlled configuration
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

    def create_vm(self, request: dict[str, Any]) -> str:
        # /cluster/nextid n'est pas une réservation atomique : trois collisions maximum.
        for retry in range(4):
            vmid = self._valid_vmid(self._request("/cluster/nextid"))
            # Le mapping minimal évite de transmettre des paramètres arbitraires du client.
            payload = {
                "vmid": vmid,
                "name": request["name"], "cores": request["cpu"], "memory": request["ram_mb"],
                "scsihw": "virtio-scsi-pci", "scsi0": f"local-lvm:{request['disk_gb']}",
                "ide2": f"{request['iso']},media=cdrom",
            }
            try:
                result = self._request(
                    f"/nodes/{quote(request['node'], safe='')}/qemu",
                    method="POST",
                    payload=payload,
                )
            except PVEHTTPError as error:
                if retry < 3 and self._is_vmid_collision(error):
                    continue
                raise
            if not isinstance(result, str) or not result.startswith("UPID:"):
                raise PVEProtocolError("L'identifiant de tâche PVE est invalide.")
            return result
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


@dataclass
class FakePVEClient:
    accessible_isos: dict[str, set[str]]
    requests: list[dict[str, Any]] = field(default_factory=list)
    task_statuses: list[dict[str, str]] = field(
        default_factory=lambda: [{"status": "stopped", "exitstatus": "OK"}]
    )

    def is_iso_available(self, node: str, iso: str) -> bool:
        return iso in self.accessible_isos.get(node, set())

    def list_nodes(self) -> list[str]:
        return sorted(self.accessible_isos)

    def list_isos(self, node: str) -> list[str]:
        return sorted(self.accessible_isos.get(node, set()))

    def create_vm(self, request: dict[str, Any]) -> str:
        self.requests.append(request)
        return f"UPID:fake:{len(self.requests)}"

    def get_task_status(self, node: str, upid: str) -> dict[str, str]:
        if len(self.task_statuses) > 1:
            return self.task_statuses.pop(0)
        return self.task_statuses[0]
