#!/bin/bash
set -Eeuo pipefail
umask 077

BUNDLE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TARGET_DIR=/opt/proxmox-vm-portal
COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
COSIGN_OFFLINE_IMAGE=${COSIGN_IMAGE%@*}
operation=install
install_profile=quick
rollback_dir=""
extract_dir=""
case ${1:-} in
    "") ;;
    --production) install_profile=production ;;
    --update) operation=update ;;
    *) echo "Usage: $0 [--production|--update]" >&2; exit 1 ;;
esac

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
for required in SHA256SUMS source.tar.gz evidence/release-manifest.json \
    evidence/release-manifest.sigstore.json evidence/sigstore-trusted-root.json \
    evidence/offline-images.json; do
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

manifest="$BUNDLE_DIR/evidence/release-manifest.json"
image_metadata="$BUNDLE_DIR/evidence/offline-images.json"
version=$(jq -r '.version' "$manifest")
image=$(jq -r '.image + "@" + .digest' "$manifest")
commit=$(jq -r '.commit' "$manifest")
tag="v$version"
repository=$(jq -r '.image | sub("^ghcr.io/"; "")' "$manifest")
[[ $image =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$ ]] || fail \
    "Image invalide dans le manifeste."
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail "Commit invalide dans le manifeste."
[[ $(jq -r '.schema' "$image_metadata") == 2 ]] || fail "Catalogue d'images invalide."
[[ $(jq -r '.signed_image' "$image_metadata") == "$image" ]] || fail \
    "Le catalogue d'images ne correspond pas au manifeste signé."
[[ $(jq -r '.version' "$image_metadata") == "$version" ]] || fail \
    "Le catalogue d'images ne correspond pas à la version signée."
[[ $(jq -r '.commit' "$image_metadata") == "$commit" ]] || fail \
    "Le catalogue d'images ne correspond pas au commit signé."
[[ $(jq '.images | length' "$image_metadata") -ge 3 ]] || fail \
    "Le catalogue d'images hors ligne est incomplet."

portal_image=""
cosign_image=""
runtime_images=0
runtime_references=()
while IFS=$'\t' read -r role archive reference publisher_image_id expected_sha256; do
    [[ $archive =~ ^[0-9]{2}\.tar$ ]] || fail "Nom d'archive d'image invalide."
    [[ $reference =~ ^[A-Za-z0-9._:/-]+$ && $reference == *:* && $reference != *@* ]] || fail \
        "Référence locale d'image invalide."
    [[ $publisher_image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail \
        "Identifiant d'image du moteur de publication invalide."
    [[ $expected_sha256 =~ ^[0-9a-f]{64}$ ]] || fail "Empreinte d'archive d'image invalide."
    [[ -s $BUNDLE_DIR/images/$archive ]] || fail "Archive d'image absente: $archive"
    [[ $(sha256sum "$BUNDLE_DIR/images/$archive" | cut -d' ' -f1) == "$expected_sha256" ]] || fail \
        "L'archive d'image $archive ne correspond pas au catalogue."
    docker load --input "$BUNDLE_DIR/images/$archive" >/dev/null
    docker image inspect "$reference" >/dev/null || fail \
        "L'étiquette d'image $reference est absente après rechargement."
    case "$role" in
        portal)
            [[ -z $portal_image ]] || fail "Plusieurs images portail sont déclarées."
            portal_image=$reference
            ;;
        cosign)
            [[ -z $cosign_image ]] || fail "Plusieurs images Cosign sont déclarées."
            cosign_image=$reference
            ;;
        runtime)
            runtime_images=$((runtime_images + 1))
            runtime_references+=("$reference")
            ;;
        *) fail "Rôle d'image hors ligne invalide." ;;
    esac
done < <(jq -r '.images[] | [.role, .archive, .reference, .publisher_image_id,
        .archive_sha256] | @tsv' \
    "$image_metadata")
[[ $portal_image == "${image%@*}:offline-${version}" ]] || fail \
    "La référence locale du portail est inattendue."
[[ $cosign_image == "$COSIGN_OFFLINE_IMAGE" ]] || fail "La référence locale Cosign est inattendue."
[[ $runtime_images -eq 4 ]] || fail "Les quatre images de service ne sont pas toutes présentes."
expected_runtime_references=$'caddy:2.11.3-alpine\npglombardo/pwpush:2.9.0\npostgres:17.10-bookworm\nquay.io/keycloak/keycloak:26.7.0'
[[ $(printf '%s\n' "${runtime_references[@]}" | sort) == "$expected_runtime_references" ]] || fail \
    "Les références locales des images de service sont inattendues."
[[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    "$portal_image") == "$commit" ]] || fail "Le commit de l'image portail est inattendu."
[[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
    "$portal_image") == "$version" ]] || fail "La version de l'image portail est inattendue."

identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${tag}"
docker run --rm --network none --read-only --cap-drop ALL \
    --user 0:0 \
    --security-opt no-new-privileges:true --tmpfs /tmp:size=32m,mode=1777 \
    --env HOME=/tmp/cosign-home \
    --volume "$BUNDLE_DIR/evidence:/work:ro" "$cosign_image" verify-blob \
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
printf 'image=%s\nsigned_image=%s\ntag=%s\ncommit=%s\n' \
    "$portal_image" "$image" "$tag" "$commit" \
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
set_env_value PORTAL_IMAGE "$portal_image"
set_env_value PORTAL_RELEASE_TAG "$tag"
set_env_value PORTAL_RELEASE_REPOSITORY "$repository"
set_env_value PORTAL_RELEASE_TRANSPARENCY private

if [[ $operation == install ]]; then
    if [[ $install_profile == quick ]]; then
        PORTAL_DOMAIN=${PORTAL_INSTALL_IP:-$(ip -o -4 addr show scope global | \
            awk 'NR == 1 {sub(/\/.*/, "", $4); print $4}')}
        [[ $PORTAL_DOMAIN =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail \
            "Impossible de détecter l'adresse IPv4. Utilisez PORTAL_INSTALL_IP=x.x.x.x."
        IFS=. read -r ip1 ip2 ip3 ip4 <<< "$PORTAL_DOMAIN"
        for octet in "$ip1" "$ip2" "$ip3" "$ip4"; do
            ((10#$octet >= 0 && 10#$octet <= 255)) || fail \
                "Adresse IPv4 détectée invalide."
        done
        ACME_EMAIL=admin@localhost.invalid
        PVE_API_URL=https://127.0.0.1:65535/api2/json
        PVE_TOKEN_ID=portal@pve!unconfigured
        backup_identity=/root/proxmox-vm-portal-backup.agekey
        if [[ ! -s $backup_identity ]]; then
            age-keygen -o "$backup_identity"
            chmod 0600 "$backup_identity"
        fi
        BACKUP_AGE_RECIPIENT=$(age-keygen -y "$backup_identity")
        set_env_value PORTAL_FIRST_BOOT_MODE true
    else
        prompt_value PORTAL_DOMAIN "Nom DNS interne du portail" '^[A-Za-z0-9.-]+$'
        prompt_value ACME_EMAIL "Adresse email PKI/ACME interne" '^[^[:space:]@]+@[^[:space:]@]+$'
        prompt_value PVE_API_URL "URL HTTPS de l API Proxmox" '^https://[^[:space:]]+$'
        prompt_value PVE_TOKEN_ID "Identifiant du token Proxmox" '^[^[:space:]]+@[^[:space:]!]+![^[:space:]]+$'
        [[ $PVE_TOKEN_ID != root@* ]] || fail "Un token root@… est interdit."
        prompt_value BACKUP_AGE_RECIPIENT "Destinataire age des sauvegardes" '^age1[0-9a-z]+$'
        set_env_value PORTAL_FIRST_BOOT_MODE false
    fi
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
