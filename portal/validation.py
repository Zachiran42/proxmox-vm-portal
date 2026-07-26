from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_NODE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ISO = re.compile(r"^[a-z][a-z0-9_-]*:iso/[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\.iso$")
_FIELDS = {"name", "node", "iso", "cpu", "ram_mb", "disk_gb"}


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
    iso: str
    cpu: int
    ram_mb: int
    disk_gb: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VMRequest":
        errors: dict[str, str] = {}
        unknown = set(data) - _FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        missing = _FIELDS - set(data)
        for field in sorted(missing):
            errors[field] = "Champ requis."

        name, node, iso = data.get("name"), data.get("node"), data.get("iso")
        if name is not None and (not isinstance(name, str) or not _NAME.fullmatch(name)):
            errors["name"] = "Nom invalide (minuscules, chiffres et tirets; 1-63 caractères)."
        if node is not None and (not isinstance(node, str) or not _NODE.fullmatch(node)):
            errors["node"] = "Nœud invalide."
        if iso is not None and (not isinstance(iso, str) or not _ISO.fullmatch(iso)):
            errors["iso"] = "ISO invalide; format attendu stockage:iso/fichier.iso."

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
        return cls(**{field: data[field] for field in _FIELDS})

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "node": self.node,
            "iso": self.iso,
            "cpu": self.cpu,
            "ram_mb": self.ram_mb,
            "disk_gb": self.disk_gb,
        }
