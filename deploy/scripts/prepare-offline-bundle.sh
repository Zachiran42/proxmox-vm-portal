#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "${PORTAL_SOURCE_ROOT:-$SCRIPT_DIR/../..}" && pwd)
REPOSITORY="hugofelix088-spec/proxmox-vm-portal"
RELEASE_TAG=${PORTAL_RELEASE_TAG:-v0.22.0}
OUTPUT_DIR=${1:-$PWD}
API_ROOT="https://api.github.com/repos/$REPOSITORY"
COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
work_dir=""

cleanup() {
    unset PORTAL_GITHUB_TOKEN
    if [[ -n $work_dir && $work_dir == /tmp/proxmox-vm-portal-offline.* ]]; then
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT

fail() { echo "$1" >&2; exit 1; }
for command in curl docker git jq sha256sum tar; do
    command -v "$command" >/dev/null || fail "$command est requis sur le poste de préparation."
done
[[ -n ${PORTAL_GITHUB_TOKEN:-} ]] || fail \
    "PORTAL_GITHUB_TOKEN est requis uniquement sur le poste connecté de préparation."
[[ ${PORTAL_GITHUB_USERNAME:-hugofelix088-spec} =~ ^[A-Za-z0-9-]+$ ]] || fail \
    "PORTAL_GITHUB_USERNAME est invalide."
[[ $RELEASE_TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Tag de release invalide."
[[ $(dpkg --print-architecture 2>/dev/null || true) == amd64 ]] || fail \
    "Exécutez la préparation sur un poste Linux amd64 avec Docker."

work_dir=$(mktemp -d /tmp/proxmox-vm-portal-offline.XXXXXXXX)
docker_config="$work_dir/docker-config"
bundle_dir="$work_dir/proxmox-vm-portal-offline-${RELEASE_TAG#v}-amd64"
mkdir -p "$docker_config" "$bundle_dir/evidence" "$bundle_dir/debs" "$bundle_dir/images"

github_curl() {
    printf 'header = "Authorization: Bearer %s"\n' "$PORTAL_GITHUB_TOKEN" |
        curl --config - --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        -H "Accept: $1" -H "X-GitHub-Api-Version: 2022-11-28" "$2" "${@:3}"
}

release_json="$work_dir/release.json"
github_curl application/vnd.github+json "$API_ROOT/releases/tags/$RELEASE_TAG" \
    --output "$release_json"
[[ $(jq -r '.tag_name' "$release_json") == "$RELEASE_TAG" ]] || fail "Release inattendue."
[[ $(jq -r '.draft, .prerelease' "$release_json") == $'false\nfalse' ]] || fail \
    "Une release brouillon ou préversion ne peut pas être exportée."

download_asset() {
    local name=$1 destination=$2 url
    url=$(jq -r --arg name "$name" '.assets[] | select(.name == $name) | .url' "$release_json")
    [[ $url == "$API_ROOT/releases/assets/"* ]] || fail "Asset absent: $name"
    github_curl application/octet-stream "$url" --output "$destination"
}
download_asset release-manifest.json "$bundle_dir/evidence/release-manifest.json"
download_asset release-manifest.sigstore.json "$bundle_dir/evidence/release-manifest.sigstore.json"

manifest="$bundle_dir/evidence/release-manifest.json"
version=$(jq -r '.version' "$manifest")
image=$(jq -r '.image + "@" + .digest' "$manifest")
commit=$(jq -r '.commit' "$manifest")
[[ $RELEASE_TAG == "v$version" ]] || fail "Le manifeste ne correspond pas au tag."
[[ $image =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$ ]] || fail \
    "Référence d'image invalide dans le manifeste."
[[ $(git -C "$ROOT_DIR" rev-parse "$RELEASE_TAG^{}") == "$commit" ]] || fail \
    "Le tag Git local ne correspond pas au commit signé."
[[ $(git -C "$ROOT_DIR" rev-parse HEAD) == "$commit" ]] || fail \
    "Le poste de préparation doit avoir extrait exactement $RELEASE_TAG."
if ! git -C "$ROOT_DIR" diff --quiet || ! git -C "$ROOT_DIR" diff --cached --quiet; then
    fail "Les fichiers suivis du checkout de préparation sont modifiés; export refusé."
fi

sbom_name=$(jq -r '.sbom.file' "$manifest")
sbom_sha256=$(jq -r '.sbom.sha256' "$manifest")
[[ $sbom_name == "proxmox-vm-portal-${version}.spdx.json" ]] || fail \
    "Nom de SBOM inattendu dans le manifeste."
[[ $sbom_sha256 =~ ^[0-9a-f]{64}$ ]] || fail "Empreinte SBOM invalide."
download_asset "$sbom_name" "$bundle_dir/evidence/$sbom_name"
[[ $(sha256sum "$bundle_dir/evidence/$sbom_name" | cut -d' ' -f1) == "$sbom_sha256" ]] || fail \
    "Le SBOM ne correspond pas au manifeste signé."

identity="https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}"
docker pull "$COSIGN_IMAGE"
docker run --rm --user 0:0 --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --tmpfs /tmp:size=32m,mode=1777 \
    --env HOME=/tmp/cosign-home "$COSIGN_IMAGE" \
    trusted-root create --with-default-services \
    > "$bundle_dir/evidence/sigstore-trusted-root.json"
chmod 0755 "$bundle_dir" "$bundle_dir/evidence"
chmod 0444 "$bundle_dir"/evidence/*
docker run --rm --network none --read-only --cap-drop ALL \
    --user 0:0 \
    --security-opt no-new-privileges:true --tmpfs /tmp:size=32m,mode=1777 \
    --env HOME=/tmp/cosign-home \
    --volume "$bundle_dir/evidence:/work:ro" "$COSIGN_IMAGE" verify-blob \
    --trusted-root /work/sigstore-trusted-root.json \
    --bundle /work/release-manifest.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --use-signed-timestamps \
    --insecure-ignore-tlog=true /work/release-manifest.json

printf '%s' "$PORTAL_GITHUB_TOKEN" | docker --config "$docker_config" login ghcr.io \
    --username "${PORTAL_GITHUB_USERNAME:-hugofelix088-spec}" --password-stdin >/dev/null
docker --config "$docker_config" pull "$image"

mapfile -t service_images < <(
    sed -n 's/^[[:space:]]*image:[[:space:]]*//p' "$ROOT_DIR/compose.yml" |
        sed 's/[[:space:]]*$//' | grep -Fv "\${" | sort -u
)
for service_image in "${service_images[@]}"; do
    docker --config "$docker_config" pull "$service_image"
done

image_metadata="$bundle_dir/evidence/offline-images.json"
jq -n --arg signed_image "$image" --arg version "$version" --arg commit "$commit" \
    '{schema: 2, signed_image: $signed_image, version: $version, commit: $commit, images: []}' \
    > "$image_metadata"

add_image_archive() {
    local role=$1 source=$2 reference=$3 archive=$4 publisher_image_id archive_sha256 temporary
    [[ $archive =~ ^[0-9]{2}\.tar$ ]] || fail "Nom d'archive d'image invalide."
    [[ $reference != *$'\n'* && $reference != *$'\r'* && $reference != *@* ]] || fail \
        "Référence locale d'image invalide."
    docker image inspect "$source" >/dev/null
    docker tag "$source" "$reference"
    publisher_image_id=$(docker image inspect --format '{{.Id}}' "$reference")
    [[ $publisher_image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail \
        "Identifiant d'image du moteur de publication invalide."
    docker save --output "$bundle_dir/images/$archive" "$reference"
    archive_sha256=$(sha256sum "$bundle_dir/images/$archive" | cut -d' ' -f1)
    temporary=$(mktemp "$work_dir/image-metadata.XXXXXXXX")
    jq --arg role "$role" --arg source "$source" --arg reference "$reference" \
        --arg archive "$archive" --arg publisher_image_id "$publisher_image_id" \
        --arg archive_sha256 "$archive_sha256" \
        '.images += [{role: $role, source: $source, reference: $reference,
            archive: $archive, publisher_image_id: $publisher_image_id,
            archive_sha256: $archive_sha256}]' \
        "$image_metadata" > "$temporary"
    mv "$temporary" "$image_metadata"
}

portal_offline_image="${image%@*}:offline-${version}"
cosign_offline_image=${COSIGN_IMAGE%@*}
add_image_archive portal "$image" "$portal_offline_image" 00.tar
add_image_archive cosign "$COSIGN_IMAGE" "$cosign_offline_image" 01.tar
archive_index=2
for service_image in "${service_images[@]}"; do
    printf -v archive_name '%02d.tar' "$archive_index"
    add_image_archive runtime "$service_image" "${service_image%@*}" "$archive_name"
    archive_index=$((archive_index + 1))
done

expected_images=$((2 + ${#service_images[@]}))
[[ $(jq '.images | length' "$image_metadata") -eq $expected_images ]] || fail \
    "Le catalogue d'images hors ligne est incomplet."
mapfile -t exported_image_ids < <(jq -r '.images[].publisher_image_id' "$image_metadata" | sort -u)
docker image rm --force "${exported_image_ids[@]}" >/dev/null
while IFS=$'\t' read -r archive reference expected_sha256; do
    [[ $(sha256sum "$bundle_dir/images/$archive" | cut -d' ' -f1) == "$expected_sha256" ]] || fail \
        "L'archive $archive a changé avant son test de rechargement."
    docker load --input "$bundle_dir/images/$archive" >/dev/null
    docker image inspect "$reference" >/dev/null || fail \
        "L'étiquette $reference ne survit pas à un export/import Docker."
done < <(jq -r '.images[] | [.archive, .reference, .archive_sha256] | @tsv' \
    "$image_metadata")
chmod 0444 "$image_metadata" "$bundle_dir"/images/*.tar

git -C "$ROOT_DIR" archive --format=tar.gz --output "$bundle_dir/source.tar.gz" "$RELEASE_TAG"
tar -xOf "$bundle_dir/source.tar.gz" deploy/scripts/install-offline-bundle.sh \
    > "$bundle_dir/install-offline.sh"
chmod 0755 "$bundle_dir/install-offline.sh"
docker run --rm --platform linux/amd64 \
    --volume "$SCRIPT_DIR/download-offline-debs.sh:/prepare/download-debs.sh:ro" \
    --volume "$bundle_dir/debs:/out" debian:13-slim \
    bash /prepare/download-debs.sh /out

(
    cd "$bundle_dir"
    checksums=$(mktemp "$work_dir/checksums.XXXXXXXX")
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$checksums"
    mv "$checksums" SHA256SUMS
)
install -d -m 0755 "$OUTPUT_DIR"
bundle_archive="$OUTPUT_DIR/$(basename "$bundle_dir").tar.gz"
tar -C "$work_dir" -czf "$bundle_archive" "$(basename "$bundle_dir")"
(cd "$OUTPUT_DIR" && sha256sum "$(basename "$bundle_archive")" > "$(basename "$bundle_archive").sha256")

echo "Bundle hors ligne créé: $bundle_archive"
echo "Empreinte à conserver dans la CMDB et à vérifier après transfert:"
cat "$bundle_archive.sha256"
