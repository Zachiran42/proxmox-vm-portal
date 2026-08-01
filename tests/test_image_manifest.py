from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from portal.image_manifest import (
    DEBIAN_ISO_SHA256,
    ImageBuildManifest,
    ImageManifestError,
    create_manifest,
    load_manifest,
    main,
)


def valid_manifest() -> dict:
    return asdict(
        create_manifest(
            slug="debian-13-cloud",
            label="Debian 13 Cloud",
            description="Template durci",
            template_node="pve-a",
            template_vmid=9130,
        )
    )


def test_manifest_yields_only_the_admin_profile_payload(tmp_path: Path):
    path = tmp_path / "promotion.json"
    path.write_text(json.dumps(valid_manifest()), encoding="utf-8")

    manifest = load_manifest(path)

    assert manifest.profile_payload() == {
        "slug": "debian-13-cloud",
        "label": "Debian 13 Cloud",
        "description": "Template durci",
        "source_type": "cloud_init",
        "template_node": "pve-a",
        "template_vmid": 9130,
    }
    assert "iso_sha256" not in manifest.profile_payload()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "Version"),
        ("source_type", "iso", "cloud-init"),
        ("slug", "Not valid", "Slug"),
        ("label", "", "Libelle"),
        ("description", "x" * 501, "Description"),
        ("template_node", "bad node", "Noeud"),
        ("template_vmid", 99, "VMID"),
        ("iso_url", "https://example.test/debian.iso", "ISO"),
        ("iso_sha256", "xyz", "SHA-256"),
        ("iso_sha256", "0" * 64, "SHA-256"),
        ("packer_plugin_version", "9.9.9", "plugin"),
        ("created_at", "yesterday", "Date"),
        ("created_at", "2026-08-01T12:00:00", "UTC"),
    ],
)
def test_manifest_rejects_unapproved_build_metadata(field, value, message):
    data = valid_manifest()
    data[field] = value

    with pytest.raises(ImageManifestError, match=message):
        ImageBuildManifest.from_dict(data)


def test_manifest_rejects_unknown_fields():
    data = valid_manifest()
    data["proxmox_token"] = "must-never-be-present"

    with pytest.raises(ImageManifestError, match="inconnus"):
        ImageBuildManifest.from_dict(data)


def test_manifest_rejects_missing_fields_and_invalid_json(tmp_path: Path):
    data = valid_manifest()
    del data["label"]
    with pytest.raises(ImageManifestError, match="absents"):
        ImageBuildManifest.from_dict(data)

    path = tmp_path / "invalid.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ImageManifestError, match="ne peut pas etre lu"):
        load_manifest(path)
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ImageManifestError, match="objet JSON"):
        load_manifest(path)


def test_manifest_cli_creates_then_validates_profile(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "promotion.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "image_manifest",
            "create",
            "--slug",
            "debian-13-cloud",
            "--label",
            "Debian 13 Cloud",
            "--description",
            "Template durci",
            "--template-node",
            "pve-a",
            "--template-vmid",
            "9130",
            "--output",
            str(path),
        ],
    )
    main()
    assert path.exists()

    monkeypatch.setattr(sys, "argv", ["image_manifest", "validate", str(path)])
    main()
    assert json.loads(capsys.readouterr().out)["template_vmid"] == 9130


def test_factory_sources_pin_checksum_and_remove_build_access():
    root = Path(__file__).parents[1]
    hcl = (root / "images/packer/debian-13.pkr.hcl").read_text(encoding="utf-8")
    preseed = (root / "images/packer/http/preseed.cfg.pkrtpl").read_text(encoding="utf-8")
    harden = (root / "images/packer/scripts/harden.sh").read_text(encoding="utf-8")

    assert 'version = "= 1.2.4"' in hcl
    assert DEBIAN_ISO_SHA256 in hcl
    assert "insecure_skip_tls_verify = false" in hcl
    assert "passwd/root-login boolean false" in preseed
    assert "PermitRootLogin no" in harden
    assert "passwd --lock" in harden
    assert "cloud-init clean --logs --seed" in harden
    assert "password123" not in (hcl + preseed + harden).lower()
