#!/bin/bash
set -Eeuo pipefail
umask 077

REPOSITORY="hugofelix088-spec/proxmox-vm-portal"
RELEASE_TAG="v0.18.1"
RELEASE_VERSION="0.18.1"
TARGET_DIR="/opt/proxmox-vm-portal"
API_ROOT="https://api.github.com/repos/$REPOSITORY"
work_dir=""

cleanup() {
    unset PORTAL_GITHUB_TOKEN
    if [[ -n $work_dir && $work_dir == /tmp/proxmox-vm-portal.* && -d $work_dir ]]; then
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT

fail() {
    echo "$1" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "Exécutez ce bootstrap avec sudo."
[[ -r /etc/os-release ]] || fail "Impossible d'identifier le système."
# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == debian ]] || fail "Ce bootstrap prend uniquement en charge Debian."
[[ -n ${PORTAL_GITHUB_TOKEN:-} ]] || fail \
    "PORTAL_GITHUB_TOKEN est requis tant que le dépôt et GHCR restent privés."
[[ ${PORTAL_GITHUB_USERNAME:-hugofelix088-spec} =~ ^[A-Za-z0-9-]+$ ]] || fail \
    "PORTAL_GITHUB_USERNAME est invalide."
[[ ! -e $TARGET_DIR ]] || fail \
    "$TARGET_DIR existe déjà. Utilisez deploy/scripts/update.sh pour une installation existante."

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl jq tar

github_curl() {
    printf 'header = "Authorization: Bearer %s"\n' "$PORTAL_GITHUB_TOKEN" | \
        curl --config - --proto '=https' --tlsv1.2 \
        --fail --silent --show-error --location \
        -H "Accept: $1" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$2" "${@:3}"
}

work_dir=$(mktemp -d /tmp/proxmox-vm-portal.XXXXXXXX)
release_json="$work_dir/release.json"
manifest_file="$work_dir/release-manifest.json"
archive_file="$work_dir/source.tar.gz"
extract_dir="$work_dir/source"

github_curl application/vnd.github+json \
    "$API_ROOT/releases/tags/$RELEASE_TAG" --output "$release_json"
[[ $(jq -r '.tag_name' "$release_json") == "$RELEASE_TAG" ]] || fail \
    "La release GitHub ne correspond pas à $RELEASE_TAG."
[[ $(jq -r '.draft' "$release_json") == false ]] || fail "La release est encore en brouillon."
[[ $(jq -r '.prerelease' "$release_json") == false ]] || fail "La release est une préversion."

manifest_url=$(jq -r \
    '.assets[] | select(.name == "release-manifest.json") | .url' "$release_json")
[[ $manifest_url == "$API_ROOT/releases/assets/"* ]] || fail \
    "Le manifeste de release est absent ou provient d'une URL inattendue."
github_curl application/octet-stream "$manifest_url" --output "$manifest_file"

manifest_version=$(jq -r '.version' "$manifest_file")
manifest_image=$(jq -r '.image' "$manifest_file")
manifest_digest=$(jq -r '.digest' "$manifest_file")
manifest_commit=$(jq -r '.commit' "$manifest_file")
[[ $manifest_version == "$RELEASE_VERSION" ]] || fail "Version de manifeste inattendue."
[[ $manifest_image == "ghcr.io/${REPOSITORY,,}" ]] || fail "Image de manifeste inattendue."
[[ $manifest_digest =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Digest de manifeste invalide."
[[ $manifest_commit =~ ^[0-9a-f]{40}$ ]] || fail "Commit de manifeste invalide."

github_curl application/vnd.github+json \
    "$API_ROOT/tarball/$RELEASE_TAG" --output "$archive_file"
if tar -tzf "$archive_file" | grep -Eq '(^|/)\.\.(/|$)|^/'; then
    fail "L'archive GitHub contient un chemin non sûr."
fi
mkdir "$extract_dir"
tar -xzf "$archive_file" -C "$extract_dir" --no-same-owner --no-same-permissions
mapfile -t archive_roots < <(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d -print)
[[ ${#archive_roots[@]} -eq 1 ]] || fail "Structure d'archive GitHub inattendue."
source_dir=${archive_roots[0]}
archive_commit=${source_dir##*/}
archive_commit=${archive_commit##*-}
[[ $archive_commit =~ ^[0-9a-f]{7,40}$ && $manifest_commit == "$archive_commit"* ]] || fail \
    "L'archive GitHub ne correspond pas au commit du manifeste."
[[ -f $source_dir/deploy/scripts/install-debian.sh ]] || fail "Installateur absent de l'archive."
[[ -z $(find "$source_dir" -type l -print -quit) ]] || fail "Les liens symboliques sont interdits."

install -d -o root -g root -m 0755 "$TARGET_DIR"
cp -a "$source_dir/." "$TARGET_DIR/"
chown -R root:root "$TARGET_DIR"
chmod -R go-w "$TARGET_DIR"
install -m 0600 "$TARGET_DIR/.env.production.example" "$TARGET_DIR/.env.production"

set_env_value() {
    local key=$1 value=$2 escaped
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail "$key contient un retour à la ligne."
    escaped=${value//\\/\\\\}
    escaped=${escaped//&/\\&}
    escaped=${escaped//|/\\|}
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$TARGET_DIR/.env.production"
}

prompt_value() {
    local variable=$1 label=$2 pattern=$3 value
    value=${!variable:-}
    while [[ ! $value =~ $pattern ]]; do
        read -r -p "$label : " value </dev/tty
        [[ -n $value ]] || echo "La valeur est obligatoire." >&2
    done
    printf -v "$variable" '%s' "$value"
}

prompt_value PORTAL_DOMAIN "Nom DNS du portail" '^[A-Za-z0-9.-]+$'
prompt_value ACME_EMAIL "Adresse email ACME" '^[^[:space:]@]+@[^[:space:]@]+$'
prompt_value PVE_API_URL "URL HTTPS de l API Proxmox" '^https://[^[:space:]]+$'
prompt_value PVE_TOKEN_ID "Identifiant du token Proxmox (utilisateur@realm!token)" \
    '^[^[:space:]]+@[^[:space:]!]+![^[:space:]]+$'
[[ $PVE_TOKEN_ID != root@* ]] || fail "Un token root@… est interdit."
prompt_value BACKUP_AGE_RECIPIENT "Destinataire age des sauvegardes" '^age1[0-9a-z]+$'

set_env_value PORTAL_DEPLOY_MODE release
set_env_value PORTAL_IMAGE "$manifest_image@$manifest_digest"
set_env_value PORTAL_RELEASE_TAG "$RELEASE_TAG"
set_env_value PORTAL_RELEASE_REPOSITORY "$REPOSITORY"
set_env_value PORTAL_RELEASE_TRANSPARENCY private
set_env_value PORTAL_DOMAIN "$PORTAL_DOMAIN"
set_env_value ACME_EMAIL "$ACME_EMAIL"
set_env_value PVE_API_URL "$PVE_API_URL"
set_env_value PVE_TOKEN_ID "$PVE_TOKEN_ID"
set_env_value BACKUP_AGE_RECIPIENT "$BACKUP_AGE_RECIPIENT"

install -d -m 0755 "$TARGET_DIR/deploy/release-evidence/$RELEASE_TAG"
install -m 0644 "$manifest_file" \
    "$TARGET_DIR/deploy/release-evidence/$RELEASE_TAG/release-manifest.json"

echo "Source $RELEASE_TAG préparée depuis le commit $manifest_commit."
echo "L'image $manifest_image@$manifest_digest sera vérifiée avant son téléchargement."
export PORTAL_GITHUB_USERNAME=${PORTAL_GITHUB_USERNAME:-hugofelix088-spec}
bash "$TARGET_DIR/deploy/scripts/install-debian.sh"
