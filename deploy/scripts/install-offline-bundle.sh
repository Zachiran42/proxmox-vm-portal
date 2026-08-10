#!/bin/bash
set -Eeuo pipefail
umask 077

BUNDLE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TARGET_DIR=/opt/proxmox-vm-portal
COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
operation=install
rollback_dir=""
extract_dir=""
if [[ ${1:-} == --update ]]; then
    operation=update
elif [[ $# -ne 0 ]]; then
    echo "Usage: $0 [--update]" >&2
    exit 1
fi

cleanup() {
    local status=$?
    if [[ $status -ne 0 ]]; then
        if [[ $extract_dir == /opt/.proxmox-vm-portal.update.* && -d $extract_dir ]]; then
            rm -rf -- "$extract_dir"
        fi
        if [[ $rollback_dir == /opt/.proxmox-vm-portal.rollback.* && -d $rollback_dir ]]; then
            echo "Échec après permutation des sources. Repli conservé dans $rollback_dir." >&2
            echo "N'effectuez pas de restauration automatique après migration; suivez BACKUP_RESTORE.md." >&2
        fi
    fi
}
trap cleanup EXIT

fail() { echo "$1" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "Exécutez cet installateur avec sudo."
[[ -r /etc/os-release ]] || fail "Impossible d'identifier Debian."
# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || fail \
    "Ce bundle exige Debian 13."
[[ $(dpkg --print-architecture) == amd64 ]] || fail "Ce bundle exige amd64."
if [[ $operation == install ]]; then
    [[ ! -e $TARGET_DIR ]] || fail \
        "$TARGET_DIR existe déjà; utilisez ce bundle avec --update."
else
    [[ -d $TARGET_DIR && -s $TARGET_DIR/.env.production ]] || fail \
        "Aucune installation existante ne peut être mise à jour."
    current_mode=$(sed -n 's/^PORTAL_DEPLOY_MODE=//p' "$TARGET_DIR/.env.production" | tail -n 1)
    [[ $current_mode == offline ]] || fail \
        "--update est réservé à une installation existante en mode offline."
fi
for required in SHA256SUMS source.tar.gz images.tar evidence/release-manifest.json \
    evidence/release-manifest.sigstore.json evidence/sigstore-trusted-root.json; do
    [[ -s $BUNDLE_DIR/$required ]] || fail "Fichier absent du bundle: $required"
done

(cd "$BUNDLE_DIR" && sha256sum --check --strict SHA256SUMS) || fail \
    "L'intégrité du bundle est invalide."
mapfile -t debs < <(find "$BUNDLE_DIR/debs" -maxdepth 1 -type f -name '*.deb' -print | sort)
[[ ${#debs[@]} -gt 0 ]] || fail "Les paquets Debian hors ligne sont absents."
export DEBIAN_FRONTEND=noninteractive
install_debs=()
for archive in "${debs[@]}"; do
    package=$(dpkg-deb --field "$archive" Package)
    candidate=$(dpkg-deb --field "$archive" Version)
    installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
    if [[ -z $installed ]] || dpkg --compare-versions "$candidate" gt "$installed"; then
        install_debs+=("$archive")
    fi
done
if [[ ${#install_debs[@]} -gt 0 ]]; then
    if ! dpkg --install "${install_debs[@]}"; then
        apt-get --fix-broken install -y --no-download
    fi
fi
[[ -z $(dpkg --audit) ]] || fail "Des paquets Debian restent dans un état incohérent."
systemctl enable --now docker

docker load --input "$BUNDLE_DIR/images.tar" >/dev/null
manifest="$BUNDLE_DIR/evidence/release-manifest.json"
version=$(jq -r '.version' "$manifest")
image=$(jq -r '.image + "@" + .digest' "$manifest")
commit=$(jq -r '.commit' "$manifest")
tag="v$version"
repository=$(jq -r '.image | sub("^ghcr.io/"; "")' "$manifest")
[[ $image =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$ ]] || fail \
    "Image invalide dans le manifeste."
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail "Commit invalide dans le manifeste."
docker image inspect "$image" >/dev/null || fail "L'image signée n'est pas présente dans le bundle."

identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${tag}"
docker run --rm --network none --read-only --cap-drop ALL \
    --user 0:0 \
    --security-opt no-new-privileges:true --tmpfs /tmp:size=32m,mode=1777 \
    --env HOME=/tmp/cosign-home \
    --volume "$BUNDLE_DIR/evidence:/work:ro" "$COSIGN_IMAGE" verify-blob \
    --trusted-root /work/sigstore-trusted-root.json \
    --bundle /work/release-manifest.sigstore.json \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --use-signed-timestamps \
    --insecure-ignore-tlog=true /work/release-manifest.json

if tar -tzf "$BUNDLE_DIR/source.tar.gz" | grep -Eq '(^|/)\.\.(/|$)|^/'; then
    fail "L'archive source contient un chemin dangereux."
fi
extract_dir=$TARGET_DIR
if [[ $operation == update ]]; then
    current_tag=$(sed -n 's/^PORTAL_RELEASE_TAG=//p' "$TARGET_DIR/.env.production" | tail -n 1)
    current_version=${current_tag#v}
    [[ $current_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail \
        "La version hors ligne installée est invalide."
    dpkg --compare-versions "$version" gt "$current_version" || fail \
        "Le bundle doit être plus récent que la version installée $current_tag."
    extract_dir="/opt/.proxmox-vm-portal.update.$$"
    [[ ! -e $extract_dir ]] || fail "Le répertoire temporaire de mise à jour existe déjà."
fi
install -d -o root -g root -m 0755 "$extract_dir"
tar -xzf "$BUNDLE_DIR/source.tar.gz" -C "$extract_dir" --no-same-owner --no-same-permissions
[[ -z $(find "$extract_dir" -type l -print -quit) ]] || fail \
    "Les liens symboliques sont interdits dans la source."
chown -R root:root "$extract_dir"
chmod -R go-w "$extract_dir"

if [[ $operation == update ]]; then
    echo "Création de la sauvegarde chiffrée préalable à la mise à jour."
    bash "$TARGET_DIR/deploy/scripts/backup.sh"
    install -m 0600 "$TARGET_DIR/.env.production" "$extract_dir/.env.production"
    cp -a "$TARGET_DIR/deploy/secrets/." "$extract_dir/deploy/secrets/"
    if [[ -d $TARGET_DIR/deploy/release-evidence ]]; then
        install -d -m 0755 "$extract_dir/deploy/release-evidence"
        cp -a "$TARGET_DIR/deploy/release-evidence/." \
            "$extract_dir/deploy/release-evidence/"
    fi
    bash "$TARGET_DIR/deploy/scripts/compose.sh" down
    rollback_dir="/opt/.proxmox-vm-portal.rollback.${current_version}.$$"
    [[ ! -e $rollback_dir ]] || fail "Le répertoire de repli existe déjà."
    mv "$TARGET_DIR" "$rollback_dir"
    mv "$extract_dir" "$TARGET_DIR"
    echo "Ancienne source conservée temporairement dans $rollback_dir."
else
    install -m 0600 "$TARGET_DIR/.env.production.example" "$TARGET_DIR/.env.production"
fi
evidence_dir="$TARGET_DIR/deploy/release-evidence/$tag"
install -d -m 0755 "$evidence_dir"
install -m 0644 "$BUNDLE_DIR/evidence/"* "$evidence_dir/"
printf 'image=%s\ntag=%s\ncommit=%s\n' "$image" "$tag" "$commit" \
    > "$evidence_dir/offline-verification.txt"
chmod 0644 "$evidence_dir/offline-verification.txt"

set_env_value() {
    local key=$1 value=$2 escaped
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail "$key contient un retour à la ligne."
    escaped=${value//\\/\\\\}; escaped=${escaped//&/\\&}; escaped=${escaped//|/\\|}
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$TARGET_DIR/.env.production"
}
prompt_value() {
    local variable=$1 label=$2 pattern=$3 value
    value=${!variable:-}
    while [[ ! $value =~ $pattern ]]; do
        read -r -p "$label : " value </dev/tty
    done
    printf -v "$variable" '%s' "$value"
}
set_env_value PORTAL_DEPLOY_MODE offline
set_env_value PORTAL_IMAGE "$image"
set_env_value PORTAL_RELEASE_TAG "$tag"
set_env_value PORTAL_RELEASE_REPOSITORY "$repository"
set_env_value PORTAL_RELEASE_TRANSPARENCY private

if [[ $operation == install ]]; then
    prompt_value PORTAL_DOMAIN "Nom DNS interne du portail" '^[A-Za-z0-9.-]+$'
    prompt_value ACME_EMAIL "Adresse email PKI/ACME interne" '^[^[:space:]@]+@[^[:space:]@]+$'
    prompt_value PVE_API_URL "URL HTTPS de l API Proxmox" '^https://[^[:space:]]+$'
    prompt_value PVE_TOKEN_ID "Identifiant du token Proxmox" '^[^[:space:]]+@[^[:space:]!]+![^[:space:]]+$'
    [[ $PVE_TOKEN_ID != root@* ]] || fail "Un token root@… est interdit."
    prompt_value BACKUP_AGE_RECIPIENT "Destinataire age des sauvegardes" '^age1[0-9a-z]+$'
    set_env_value PORTAL_DOMAIN "$PORTAL_DOMAIN"
    set_env_value ACME_EMAIL "$ACME_EMAIL"
    set_env_value PVE_API_URL "$PVE_API_URL"
    set_env_value PVE_TOKEN_ID "$PVE_TOKEN_ID"
    set_env_value BACKUP_AGE_RECIPIENT "$BACKUP_AGE_RECIPIENT"
fi

echo "Bundle $tag vérifié sans accès réseau; démarrage de l'installation locale."
bash "$TARGET_DIR/deploy/scripts/install-debian.sh"
if [[ $operation == update ]]; then
    if [[ $rollback_dir == /opt/.proxmox-vm-portal.rollback.* && -d $rollback_dir ]]; then
        rm -rf -- "$rollback_dir"
    else
        fail "Chemin de nettoyage du repli inattendu; suppression refusée."
    fi
    echo "Mise à jour hors ligne de $current_tag vers $tag terminée."
fi
