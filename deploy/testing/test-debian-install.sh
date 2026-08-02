#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CONTAINER="portal-debian-install-test-$$"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --privileged --name "$CONTAINER" debian:13-slim sleep infinity >/dev/null
docker cp "$ROOT_DIR/." "$CONTAINER:/opt/proxmox-vm-portal"
docker exec "$CONTAINER" /bin/bash /opt/proxmox-vm-portal/deploy/testing/prepare-debian-fixture.sh
docker exec --env PORTAL_INSTALL_VALIDATE_ONLY=1 "$CONTAINER" \
    /bin/bash /opt/proxmox-vm-portal/deploy/scripts/install-debian.sh
docker exec "$CONTAINER" docker image inspect proxmox-vm-portal:0.18.0 \
    --format 'user={{.Config.User}} image={{index .RepoTags 0}}'

echo "Dépendances, Docker et construction sur Debian 13 vierge validés."
