import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
BOOTSTRAP = ROOT / "deploy/scripts/bootstrap-debian.sh"


def test_private_bootstrap_is_pinned_and_defensive():
    script = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'RELEASE_TAG="v0.19.0"' in script
    assert 'RELEASE_VERSION="0.19.0"' in script
    assert 'TARGET_DIR="/opt/proxmox-vm-portal"' in script
    assert "mktemp -d /tmp/proxmox-vm-portal." in script
    assert "--proto '=https' --tlsv1.2" in script
    assert "curl --config -" in script
    assert '"$API_ROOT/tarball/$RELEASE_TAG"' in script
    assert "manifest_digest =~ ^sha256:" in script
    assert "manifest_commit =~ ^[0-9a-f]{40}$" in script
    assert '"$API_ROOT/git/ref/tags/$RELEASE_TAG"' in script
    assert '"$API_ROOT/git/tags/$tag_object"' in script
    assert "Le tag de release doit être annoté" in script
    assert 'object.sha\' "$tag_json") == "$manifest_commit"' in script
    assert 'archive_commit == "$tag_object"' in script
    assert "Les liens symboliques sont interdits" in script
    assert "[[ ! -e $TARGET_DIR ]]" in script
    assert "PORTAL_DEPLOY_MODE release" in script


def test_bootstrap_fails_closed_before_network_or_filesystem_changes():
    script = BOOTSTRAP.read_text(encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("PORTAL_GITHUB_TOKEN", None)

    result = subprocess.run(
        ["bash", str(BOOTSTRAP)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stderr in {
        "Exécutez ce bootstrap avec sudo.\n",
        "PORTAL_GITHUB_TOKEN est requis tant que le dépôt et GHCR restent privés.\n",
    }
    assert script.index("PORTAL_GITHUB_TOKEN est requis") < script.index(
        "apt-get update"
    )


def test_installer_authenticates_to_ghcr_without_exposing_the_token():
    script = (ROOT / "deploy/scripts/install-debian.sh").read_text(encoding="utf-8")

    assert 'printf \'%s\' "$PORTAL_GITHUB_TOKEN" | docker login ghcr.io' in script
    assert "--password-stdin" in script
    assert "unset PORTAL_GITHUB_TOKEN" in script
    assert "--password " not in script
