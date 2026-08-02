#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

if [[ $# -ne 1 || ! $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Usage: $0 vMAJEUR.MINEUR.CORRECTIF[-PRERELEASE]" >&2
    exit 1
fi

tag=$1
version=${tag#v}
version=${version%%-*}
regex_version=${version//./\\.}

expect_exact() {
    local file=$1 pattern=$2 description=$3
    if [[ $(grep -Ec "$pattern" "$ROOT_DIR/$file") -ne 1 ]]; then
        echo "$description ne correspond pas exactement à $version dans $file." >&2
        exit 1
    fi
}

expect_exact pyproject.toml "^version = \"$regex_version\"$" "La version Python"
expect_exact compose.yml "proxmox-vm-portal:$regex_version\\}" "L'image Compose par défaut"
expect_exact .env.production.example "^PORTAL_IMAGE=proxmox-vm-portal:$regex_version$" "L'image de production"
expect_exact deploy/scripts/install-debian.sh "proxmox-vm-portal:$regex_version" "L'image de l'installateur"
expect_exact deploy/testing/test-debian-install.sh "proxmox-vm-portal:$regex_version" "L'image du test Debian"

if [[ -n ${GITHUB_SHA:-} ]]; then
    [[ $(git -C "$ROOT_DIR" cat-file -t "$tag") == tag ]] || {
        echo "Le tag $tag doit être annoté." >&2
        exit 1
    }
    tag_commit=$(git -C "$ROOT_DIR" rev-list -n 1 "$tag")
    [[ $tag_commit == "$GITHUB_SHA" ]] || {
        echo "Le tag $tag ne pointe pas vers le commit exécuté." >&2
        exit 1
    }
    git -C "$ROOT_DIR" merge-base --is-ancestor "$GITHUB_SHA" origin/main || {
        echo "Le commit de release n'appartient pas à origin/main." >&2
        exit 1
    }
fi

echo "Release $tag cohérente sur toutes les surfaces versionnées."
