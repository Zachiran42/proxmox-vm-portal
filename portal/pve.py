from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass
class PVEClient:
    """Adaptateur PVE minimal utilisant exclusivement un API token restreint."""

    api_url: str
    token_id: str
    token_secret: str

    @classmethod
    def from_environment(cls) -> "PVEClient":
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
        with urlopen(request, timeout=10) as response:  # nosec B310: URL is admin-controlled configuration
            return json.load(response).get("data")

    def is_iso_available(self, node: str, iso: str) -> bool:
        storage, filename = iso.split(":iso/", 1)
        content = self._request(f"/nodes/{quote(node)}/storage/{quote(storage)}/content?content=iso")
        return any(item.get("volid") == f"{storage}:iso/{filename}" for item in content)

    def create_vm(self, request: dict[str, Any]) -> str:
        # Le mapping minimal évite de transmettre des paramètres arbitraires du client.
        payload = {
            "name": request["name"], "cores": request["cpu"], "memory": request["ram_mb"],
            "scsihw": "virtio-scsi-pci", "scsi0": f"local-lvm:{request['disk_gb']}",
            "ide2": f"{request['iso']},media=cdrom",
        }
        result = self._request(f"/nodes/{quote(request['node'])}/qemu", method="POST", payload=payload)
        return str(result)


@dataclass
class FakePVEClient:
    accessible_isos: dict[str, set[str]]
    requests: list[dict[str, Any]] = field(default_factory=list)

    def is_iso_available(self, node: str, iso: str) -> bool:
        return iso in self.accessible_isos.get(node, set())

    def create_vm(self, request: dict[str, Any]) -> str:
        self.requests.append(request)
        return f"req-{len(self.requests)}"
