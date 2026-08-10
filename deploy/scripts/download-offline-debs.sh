#!/bin/bash
set -Eeuo pipefail

OUTPUT_DIR=${1:-/out}
[[ $(dpkg --print-architecture) == amd64 ]] || {
    echo "La préparation hors ligne prend actuellement en charge Debian amd64 uniquement." >&2
    exit 1
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gpg apt-rdepends
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
# shellcheck source=/dev/null
. /etc/os-release
printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
    "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.sources
apt-get update

roots=(
    age ca-certificates curl jq openssl tar
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
)
mapfile -t packages < <(
    apt-rdepends "${roots[@]}" 2>/dev/null |
        sed -n '/^[a-z0-9][a-z0-9+.-]*\(:[a-z0-9]+\)\?$/p' |
        sort -u
)

install -d -m 0755 "$OUTPUT_DIR"
cd "$OUTPUT_DIR"
downloads=()
for package in "${packages[@]}"; do
    candidate=$(apt-cache policy "$package" | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p')
    if [[ -n $candidate && $candidate != '(none)' ]]; then
        downloads+=("$package=$candidate")
    fi
done
apt-get download "${downloads[@]}"
printf '%s\n' "${roots[@]}" > PACKAGE_ROOTS
printf 'package\tversion\tarchitecture\tsha256\n' > DEBIAN-PACKAGES.tsv
for archive in ./*.deb; do
    printf '%s\t%s\t%s\t%s\n' \
        "$(dpkg-deb --field "$archive" Package)" \
        "$(dpkg-deb --field "$archive" Version)" \
        "$(dpkg-deb --field "$archive" Architecture)" \
        "$(sha256sum "$archive" | cut -d' ' -f1)" >> DEBIAN-PACKAGES.tsv
done
