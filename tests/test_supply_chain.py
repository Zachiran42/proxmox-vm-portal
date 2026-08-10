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
    assert "cosign signing-config create --with-default-services" in workflow
    assert "--no-default-rekor" in workflow
    assert workflow.count('--signing-config "$signing_config"') == 2
    assert "--tlog-upload=false" not in workflow
    assert "cosign verify --insecure-ignore-tlog=true --use-signed-timestamps" in workflow
    assert workflow.count("--use-signed-timestamps") == 2
    assert "release-manifest.sigstore.json" in workflow
    assert "deploy/scripts/bootstrap-debian.sh" in workflow
    assert '"proxmox-vm-portal-${VERSION}-install.sh"' in workflow
    assert "sbom_sha256" in workflow
    assert "SHA256SUMS" in workflow
    assert "--verify-tag" in workflow
    assert "prepare-offline-bundle.sh" in workflow
    assert 'gh release upload "$GITHUB_REF_NAME" "$RUNNER_TEMP"/offline-release/*' in workflow


def test_dockerfile_contains_oci_traceability_labels():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "org.opencontainers.image.source" in dockerfile
    assert "org.opencontainers.image.revision" in dockerfile
    assert "org.opencontainers.image.version" in dockerfile


def test_release_operations_verify_before_pull_or_qualification():
    install = (ROOT / "deploy/scripts/install-debian.sh").read_text(encoding="utf-8")
    update = (ROOT / "deploy/scripts/update.sh").read_text(encoding="utf-8")
    qualify = (ROOT / "deploy/scripts/qualify-preproduction.sh").read_text(
        encoding="utf-8"
    )
    override = (ROOT / "deploy/compose.release.yml").read_text(encoding="utf-8")
    release_update = update.split("release)", maxsplit=1)[1]

    assert install.index("verify-published-image.sh") < install.index(
        'docker pull "$portal_image"'
    )
    assert 'bash "$SCRIPT_DIR/verify-published-image.sh"' in install
    assert release_update.index("verify-published-image.sh") < release_update.index(
        '"$COMPOSE" pull'
    )
    assert 'bash "$SCRIPT_DIR/verify-published-image.sh"' in release_update
    assert "verify-published-image.sh" in qualify
    assert 'bash "$SCRIPT_DIR/verify-published-image.sh"' in qualify
    assert override.count("build: !reset null") == 3


def test_ci_installs_the_checkout_editably_for_coverage():
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")

    assert "python -m pip install --no-deps -e ." in workflow


def test_offline_bundle_separates_connected_preparation_from_target_installation():
    prepare = (ROOT / "deploy/scripts/prepare-offline-bundle.sh").read_text(
        encoding="utf-8"
    )
    install = (ROOT / "deploy/scripts/install-offline-bundle.sh").read_text(
        encoding="utf-8"
    )

    assert "PORTAL_GITHUB_TOKEN" in prepare
    assert "verify-blob" in prepare
    assert "trusted-root create --with-default-services" in prepare
    assert "--out /work/sigstore-trusted-root.json" not in prepare
    assert 'chmod 0755 "$bundle_dir" "$bundle_dir/evidence"' in prepare
    assert 'chmod 0444 "$bundle_dir"/evidence/*' in prepare
    assert "PORTAL_SOURCE_ROOT" in prepare
    assert prepare.index("verify-blob") < prepare.index('pull "$image"')
    assert "docker save" in prepare
    assert "offline-images.json" in prepare
    assert "publisher_image_id" in prepare
    assert 'docker image rm --force "${exported_image_ids[@]}"' in prepare
    assert prepare.index('docker image rm --force "${exported_image_ids[@]}"') < prepare.index(
        'docker load --input "$bundle_dir/images/$archive"'
    )
    assert "images.tar" not in prepare
    assert "download-offline-debs.sh" in prepare
    assert "diff --cached --quiet" in prepare
    assert "spdx.json" in prepare
    assert "PORTAL_GITHUB_TOKEN" not in install
    assert "curl " not in install
    assert "wget " not in install
    assert "ghcr.io" in install  # immutable image identity, never contacted
    assert "offline-images.json" in install
    assert 'docker load --input "$BUNDLE_DIR/images/$archive"' in install
    assert 'docker image inspect "$reference"' in install
    assert "publisher_image_id" in install
    assert "== \"$publisher_image_id\"" not in install
    assert "images.tar" not in install
    assert "expected_runtime_references" in install
    assert "--network none" in install
    assert "--use-signed-timestamps" in install
    assert "sha256sum --check --strict" in install
    assert install.index("sha256sum --check --strict") < install.index(
        "dpkg --install"
    )
    assert install.index("verify-blob") < install.index('tar -xzf')
    assert "PORTAL_DEPLOY_MODE offline" in install
    assert "--update" in install
    assert "dpkg --compare-versions" in install
    assert '"$candidate" gt "$installed"' in install
    assert "deploy/scripts/backup.sh" in install
    assert install.index("verify-blob") < install.index("deploy/scripts/backup.sh")


def test_offline_bundle_can_complete_an_existing_immutable_release():
    workflow = (ROOT / ".github/workflows/offline-bundle.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "release_tag:" in workflow
    assert "PORTAL_SOURCE_ROOT:" in workflow
    assert "packages: read" in workflow
    assert "contents: write" in workflow
    assert "gh release upload" in workflow
    assert '--repo "$GITHUB_REPOSITORY"' in workflow


def test_offline_bundle_contains_all_runtime_and_docker_prerequisites():
    downloader = (ROOT / "deploy/scripts/download-offline-debs.sh").read_text(
        encoding="utf-8"
    )

    for package in (
        "age",
        "ca-certificates",
        "jq",
        "openssl",
        "docker-ce",
        "containerd.io",
        "docker-compose-plugin",
    ):
        assert package in downloader
    assert "DEBIAN-PACKAGES.tsv" in downloader
