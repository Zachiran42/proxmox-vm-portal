from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PACKER_PLUGIN_VERSION = "1.2.4"
DEBIAN_ISO_URL = (
    "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"
    "debian-13.6.0-amd64-netinst.iso"
)
DEBIAN_ISO_SHA256 = (
    "65273beed27b2df543b68b65630ba525cfbad8df2b12035732b2dff87d6664e7"
)

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "schema_version",
    "created_at",
    "slug",
    "label",
    "description",
    "source_type",
    "template_node",
    "template_vmid",
    "iso_url",
    "iso_sha256",
    "packer_plugin_version",
}


class ImageManifestError(ValueError):
    pass


@dataclass(frozen=True)
class ImageBuildManifest:
    schema_version: int
    created_at: str
    slug: str
    label: str
    description: str
    source_type: str
    template_node: str
    template_vmid: int
    iso_url: str
    iso_sha256: str
    packer_plugin_version: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ImageBuildManifest:
        if set(data) != _FIELDS:
            missing = sorted(_FIELDS - set(data))
            unknown = sorted(set(data) - _FIELDS)
            details = []
            if missing:
                details.append("champs absents: " + ", ".join(missing))
            if unknown:
                details.append("champs inconnus: " + ", ".join(unknown))
            raise ImageManifestError("Manifeste invalide (" + "; ".join(details) + ").")
        if data["schema_version"] != SCHEMA_VERSION:
            raise ImageManifestError("Version de manifeste non prise en charge.")
        if data["source_type"] != "cloud_init":
            raise ImageManifestError("Seuls les templates cloud-init sont publiables.")
        if not isinstance(data["slug"], str) or not _SLUG.fullmatch(data["slug"]):
            raise ImageManifestError("Slug invalide.")
        if not isinstance(data["label"], str) or not 1 <= len(data["label"].strip()) <= 100:
            raise ImageManifestError("Libelle invalide.")
        if not isinstance(data["description"], str) or len(data["description"]) > 500:
            raise ImageManifestError("Description invalide.")
        if not isinstance(data["template_node"], str) or not _NODE.fullmatch(data["template_node"]):
            raise ImageManifestError("Noeud Proxmox invalide.")
        vmid = data["template_vmid"]
        if type(vmid) is not int or not 100 <= vmid <= 999999999:
            raise ImageManifestError("VMID du template invalide.")
        if data["iso_url"] != DEBIAN_ISO_URL:
            raise ImageManifestError("URL d'ISO non approuvee.")
        if not isinstance(data["iso_sha256"], str) or not _SHA256.fullmatch(data["iso_sha256"]):
            raise ImageManifestError("Somme SHA-256 invalide.")
        if data["iso_sha256"] != DEBIAN_ISO_SHA256:
            raise ImageManifestError("Somme SHA-256 de l'ISO non approuvee.")
        if data["packer_plugin_version"] != PACKER_PLUGIN_VERSION:
            raise ImageManifestError("Version du plugin Packer non approuvee.")
        try:
            created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ImageManifestError("Date de construction invalide.") from error
        if created_at.tzinfo is None:
            raise ImageManifestError("La date de construction doit etre horodatee en UTC.")
        return cls(**data)

    def profile_payload(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "label": self.label,
            "description": self.description,
            "source_type": self.source_type,
            "template_node": self.template_node,
            "template_vmid": self.template_vmid,
        }


def load_manifest(path: Path) -> ImageBuildManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ImageManifestError("Le manifeste ne peut pas etre lu.") from error
    if not isinstance(raw, dict):
        raise ImageManifestError("Le manifeste doit etre un objet JSON.")
    return ImageBuildManifest.from_dict(raw)


def create_manifest(*, slug: str, label: str, description: str, template_node: str, template_vmid: int) -> ImageBuildManifest:
    raw = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "slug": slug,
        "label": label,
        "description": description,
        "source_type": "cloud_init",
        "template_node": template_node,
        "template_vmid": template_vmid,
        "iso_url": DEBIAN_ISO_URL,
        "iso_sha256": DEBIAN_ISO_SHA256,
        "packer_plugin_version": PACKER_PLUGIN_VERSION,
    }
    return ImageBuildManifest.from_dict(raw)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Valide les manifestes d'images du portail.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--slug", required=True)
    create.add_argument("--label", required=True)
    create.add_argument("--description", required=True)
    create.add_argument("--template-node", required=True)
    create.add_argument("--template-vmid", required=True, type=int)
    create.add_argument("--output", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("manifest", type=Path)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "create":
            manifest = create_manifest(
                slug=args.slug,
                label=args.label,
                description=args.description,
                template_node=args.template_node,
                template_vmid=args.template_vmid,
            )
            args.output.write_text(
                json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return
        manifest = load_manifest(args.manifest)
        print(json.dumps(manifest.profile_payload(), indent=2, sort_keys=True))
    except ImageManifestError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
