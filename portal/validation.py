from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_NODE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ISO = re.compile(r"^[a-z][a-z0-9_-]*:iso/[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\.iso$")
_FIELDS = {"name", "node", "profile", "cpu", "ram_mb", "disk_gb"}
_USER_FIELDS = {"username", "password", "role", "quota"}
_QUOTA_FIELDS = {"vms", "cpu", "ram_mb", "disk_gb"}
_PROFILE_FIELDS = {"slug", "label", "description", "iso"}


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VMRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        missing = _FIELDS - set(data)
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
            "profile": self.profile,
            "cpu": self.cpu,
            "ram_mb": self.ram_mb,
            "disk_gb": self.disk_gb,
        }


@dataclass(frozen=True)
class ImageProfileCreateRequest:
    slug: str
    label: str
    description: str
    iso: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ImageProfileCreateRequest:
        errors: dict[str, str] = {}
        unknown = set(data) - _PROFILE_FIELDS
        if unknown:
            errors["unknown"] = "Champs non autorisés: " + ", ".join(sorted(unknown))
        for field in sorted(_PROFILE_FIELDS - set(data)):
            errors[field] = "Champ requis."
        slug = data.get("slug")
        label = data.get("label")
        description = data.get("description")
        iso = data.get("iso")
        if not isinstance(slug, str) or not _NAME.fullmatch(slug):
            errors["slug"] = "Identifiant de profil invalide."
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100:
            errors["label"] = "Libellé requis (1 à 100 caractères)."
        if not isinstance(description, str) or len(description) > 500:
            errors["description"] = "Description invalide (500 caractères maximum)."
        if not isinstance(iso, str) or not _ISO.fullmatch(iso):
            errors["iso"] = "ISO invalide; format attendu stockage:iso/fichier.iso."
        if errors:
            raise ValidationError(errors)
        assert isinstance(slug, str)
        assert isinstance(label, str)
        assert isinstance(description, str)
        assert isinstance(iso, str)
        return cls(slug=slug, label=label.strip(), description=description, iso=iso)


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
        if not isinstance(password, str) or not 14 <= len(password) <= 256:
            errors["password"] = "Le mot de passe doit contenir entre 14 et 256 caractères."
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
        assert isinstance(username, str)
        assert isinstance(password, str)
        assert isinstance(role, str)
        return cls(
            username=username,
            password=password,
            role=role,
            quota_vms=quota["vms"],
            quota_cpu=quota["cpu"],
            quota_ram_mb=quota["ram_mb"],
            quota_disk_gb=quota["disk_gb"],
        )
