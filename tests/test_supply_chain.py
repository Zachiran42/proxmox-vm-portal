import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_release_actions_are_immutable_and_permissions_are_scoped():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    action_refs = re.findall(r"^\s*- uses: [^@\s]+@([^\s]+)", workflow, re.MULTILINE)

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "permissions: {}" in workflow
    assert "contents: write" in workflow
    assert "packages: write" in workflow
    assert "id-token: write" in workflow


def test_release_build_emits_and_verifies_supply_chain_evidence():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert 'cosign sign --yes --tlog-upload=false "${IMAGE}@${DIGEST}"' in workflow
    assert "cosign verify --insecure-ignore-tlog=true" in workflow
    assert "release-manifest.sigstore.json" in workflow
    assert "sbom_sha256" in workflow
    assert "SHA256SUMS" in workflow
    assert "--verify-tag" in workflow


def test_dockerfile_contains_oci_traceability_labels():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "org.opencontainers.image.source" in dockerfile
    assert "org.opencontainers.image.revision" in dockerfile
    assert "org.opencontainers.image.version" in dockerfile
