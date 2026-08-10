import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
DIGEST = "a" * 64
REPOSITORY = "hugofelix088-spec/proxmox-vm-portal"
IMAGE = f"ghcr.io/{REPOSITORY}@sha256:{DIGEST}"


def fake_docker_environment(tmp_path: Path) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$PORTAL_TEST_DOCKER_LOG"\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment['PATH']}"
    environment["PORTAL_TEST_DOCKER_LOG"] = str(log)
    environment["PORTAL_DOCKER_CONFIG_DIR"] = str(tmp_path / "no-docker-config")
    return environment, log


def run_script(script: str, *arguments: str, environment: dict[str, str]):
    return subprocess.run(
        ["bash", str(ROOT / script), *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_compose_wrapper_uses_only_the_base_file_in_source_mode(tmp_path):
    environment, log = fake_docker_environment(tmp_path)
    env_file = tmp_path / "portal.env"
    env_file.write_text(
        "PORTAL_DEPLOY_MODE=source\nPORTAL_IMAGE=proxmox-vm-portal:0.19.1\n",
        encoding="utf-8",
    )
    environment["PORTAL_ENV_FILE"] = str(env_file)

    result = run_script("deploy/scripts/compose.sh", "config", environment=environment)

    assert result.returncode == 0, result.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    assert arguments.count("-f") == 1
    assert str(ROOT / "compose.yml") in arguments
    assert str(ROOT / "deploy/compose.release.yml") not in arguments


def test_compose_wrapper_removes_builds_for_a_digest_release(tmp_path):
    environment, log = fake_docker_environment(tmp_path)
    env_file = tmp_path / "portal.env"
    env_file.write_text(
        f"PORTAL_DEPLOY_MODE=release\nPORTAL_IMAGE={IMAGE}\n",
        encoding="utf-8",
    )
    environment["PORTAL_ENV_FILE"] = str(env_file)

    result = run_script("deploy/scripts/compose.sh", "config", environment=environment)

    assert result.returncode == 0, result.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    assert arguments.count("-f") == 2
    assert str(ROOT / "deploy/compose.release.yml") in arguments


def test_compose_wrapper_forbids_every_pull_in_offline_mode(tmp_path):
    environment, log = fake_docker_environment(tmp_path)
    env_file = tmp_path / "portal.env"
    env_file.write_text(
        f"PORTAL_DEPLOY_MODE=offline\nPORTAL_IMAGE={IMAGE}\n",
        encoding="utf-8",
    )
    environment["PORTAL_ENV_FILE"] = str(env_file)

    result = run_script("deploy/scripts/compose.sh", "config", environment=environment)

    assert result.returncode == 0, result.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    assert arguments.count("-f") == 3
    assert str(ROOT / "deploy/compose.release.yml") in arguments
    assert str(ROOT / "deploy/compose.offline.yml") in arguments


def test_offline_override_disables_registry_access_for_all_services():
    override = (ROOT / "deploy/compose.offline.yml").read_text(encoding="utf-8")

    assert override.count("pull_policy: never") == 8
    for service in ("db", "migrate", "api", "worker", "proxy", "keycloak-db", "keycloak", "pwpush"):
        assert f"  {service}:" in override


def test_compose_wrapper_rejects_a_mutable_release_tag(tmp_path):
    environment, log = fake_docker_environment(tmp_path)
    env_file = tmp_path / "portal.env"
    env_file.write_text(
        "PORTAL_DEPLOY_MODE=release\nPORTAL_IMAGE=ghcr.io/example/portal:latest\n",
        encoding="utf-8",
    )
    environment["PORTAL_ENV_FILE"] = str(env_file)

    result = run_script("deploy/scripts/compose.sh", "config", environment=environment)

    assert result.returncode == 1
    assert "par digest" in result.stderr
    assert not log.exists()


def test_cosign_verification_is_exact_and_confined(tmp_path):
    environment, log = fake_docker_environment(tmp_path)

    result = run_script(
        "deploy/scripts/verify-published-image.sh",
        IMAGE,
        "v0.19.1",
        REPOSITORY,
        "private",
        environment=environment,
    )

    assert result.returncode == 0, result.stderr
    arguments = log.read_text(encoding="utf-8").splitlines()
    assert "--read-only" in arguments
    assert "--cap-drop" in arguments
    assert "ALL" in arguments
    assert "--insecure-ignore-tlog=true" in arguments
    assert "--use-signed-timestamps" in arguments
    assert (
        "https://github.com/hugofelix088-spec/proxmox-vm-portal/"
        ".github/workflows/release.yml@refs/tags/v0.19.1"
    ) in arguments
    assert IMAGE in arguments
    assert any("cosign:v3.0.6@sha256:" in argument for argument in arguments)


def test_public_cosign_verification_requires_transparency_log(tmp_path):
    environment, log = fake_docker_environment(tmp_path)

    result = run_script(
        "deploy/scripts/verify-published-image.sh",
        IMAGE,
        "v0.19.1",
        REPOSITORY,
        "public",
        environment=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "--insecure-ignore-tlog=true" not in log.read_text(encoding="utf-8")


def test_cosign_verification_rejects_another_repository_before_docker(tmp_path):
    environment, log = fake_docker_environment(tmp_path)

    result = run_script(
        "deploy/scripts/verify-published-image.sh",
        IMAGE,
        "v0.19.1",
        "another-owner/another-repository",
        environment=environment,
    )

    assert result.returncode == 1
    assert "ne correspond pas" in result.stderr
    assert not log.exists()


def test_version_check_does_not_require_a_tag_on_a_branch_push(tmp_path):
    environment, _ = fake_docker_environment(tmp_path)
    environment["GITHUB_REF_TYPE"] = "branch"
    environment["GITHUB_SHA"] = "0" * 40

    result = run_script(
        "deploy/scripts/verify-release.sh",
        "v0.19.1",
        environment=environment,
    )

    assert result.returncode == 0, result.stderr
    assert "cohérente" in result.stdout
