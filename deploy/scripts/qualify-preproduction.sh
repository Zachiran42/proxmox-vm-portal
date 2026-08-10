#!/bin/bash
set -uo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE="$SCRIPT_DIR/compose.sh"
failures=0
warnings=0

pass() { printf 'OK    %s\n' "$1"; }
fail() { printf 'ECHEC %s\n' "$1" >&2; failures=$((failures + 1)); }
check() {
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

if [[ $EUID -ne 0 ]]; then
    echo "Exécutez ce script avec sudo sur la VM Debian de préproduction." >&2
    exit 2
fi

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
fi
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] \
    && pass "Debian 13 détectée" || fail "Debian 13 est obligatoire pour cette recette"
[[ $(cat /proc/1/comm 2>/dev/null) == systemd ]] \
    && pass "systemd est PID 1" || fail "systemd n'est pas PID 1"
check "Docker actif" systemctl is-active --quiet docker
check "Docker activé au démarrage" systemctl is-enabled --quiet docker

if [[ $(stat -c '%u' "$ROOT_DIR" 2>/dev/null) == 0 ]] \
    && [[ -z $(find "$ROOT_DIR" -xdev \( -perm -002 -o -perm -020 \) -print -quit) ]]; then
    pass "Dépôt détenu par root et non modifiable par groupe/autres"
else
    fail "Permissions du dépôt non conformes"
fi

SECRETS_DIR="$ROOT_DIR/deploy/secrets"
if [[ -d $SECRETS_DIR && ! -L $SECRETS_DIR ]] \
    && [[ $(stat -c '%u:%a' "$SECRETS_DIR") == 0:700 ]] \
    && [[ -z $(find "$SECRETS_DIR" \( -type l -o \
        \( -type f \! -name .gitignore \( \! -user root -o \! -perm 600 \) \) \) \
        -print -quit) ]]; then
    pass "Répertoire et fichiers secrets protégés"
else
    fail "Permissions ou liens des secrets non conformes"
fi
for secret in portal_db_password portal_database_url portal_session_secret \
    portal_admin_password_hash pve_token_secret portal_metrics_token; do
    [[ -s $SECRETS_DIR/$secret ]] \
        && pass "Secret requis présent: $secret" || fail "Secret requis absent: $secret"
done

check "Configuration Compose valide" "$COMPOSE" config --quiet
deploy_mode=$(sed -n 's/^PORTAL_DEPLOY_MODE=//p' "$ROOT_DIR/.env.production" | tail -n 1)
if [[ $deploy_mode == release ]]; then
    portal_image=$(sed -n 's/^PORTAL_IMAGE=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    release_tag=$(sed -n 's/^PORTAL_RELEASE_TAG=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    release_repository=$(sed -n 's/^PORTAL_RELEASE_REPOSITORY=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    release_transparency=$(sed -n 's/^PORTAL_RELEASE_TRANSPARENCY=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    check "Signature de l'image publiée" bash "$SCRIPT_DIR/verify-published-image.sh" \
        "$portal_image" "$release_tag" "$release_repository" \
        "${release_transparency:-private}"
elif [[ $deploy_mode == offline ]]; then
    release_tag=$(sed -n 's/^PORTAL_RELEASE_TAG=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    portal_image=$(sed -n 's/^PORTAL_IMAGE=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    evidence_dir="$ROOT_DIR/deploy/release-evidence/$release_tag"
    check "Preuve du bundle hors ligne" grep -Fqx "image=$portal_image" \
        "$evidence_dir/offline-verification.txt"
    check "Image hors ligne présente" docker image inspect "$portal_image"
fi
for service in db api worker proxy; do
    container=$($COMPOSE ps -q "$service" 2>/dev/null)
    if [[ -z $container ]]; then
        fail "Service $service absent"
        continue
    fi
    state=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)
    [[ $state == running ]] && pass "Service $service actif" || fail "Service $service non actif"
done

for service in api worker; do
    container=$($COMPOSE ps -q "$service" 2>/dev/null)
    [[ -n $container ]] || continue
    confinement=$(docker inspect -f \
        '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' \
        "$container" 2>/dev/null)
    if [[ $confinement == 10001:10001\|true\|*ALL*\|*no-new-privileges* ]]; then
        pass "Confinement du service $service"
    else
        fail "Confinement du service $service non conforme"
    fi
    mounts=$(docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' \
        "$container" 2>/dev/null)
    if grep -q '/var/run/docker.sock' <<< "$mounts"; then
        fail "Socket Docker monté dans $service"
    else
        pass "Aucun socket Docker dans $service"
    fi
done

if command -v systemctl >/dev/null && systemctl is-active --quiet nftables \
    && command -v nft >/dev/null \
    && [[ -n $(nft list ruleset 2>/dev/null) ]]; then
    pass "Pare-feu nftables actif avec un ruleset"
else
    fail "Pare-feu nftables inactif ou vide"
fi

PORTAL_URL=${1:-}
if [[ -z $PORTAL_URL && -r $ROOT_DIR/.env.production ]]; then
    domain=$(sed -n 's/^PORTAL_DOMAIN=//p' "$ROOT_DIR/.env.production" | tail -n 1)
    [[ -n $domain ]] && PORTAL_URL="https://$domain"
fi
if [[ $PORTAL_URL == https://* ]] && command -v curl >/dev/null; then
    PORTAL_URL=${PORTAL_URL%/}
    headers=$(mktemp)
    if curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --dump-header "$headers" --output /dev/null "$PORTAL_URL/healthz"; then
        pass "TLS et healthcheck publics"
        grep -Eqi '^strict-transport-security:' "$headers" \
            && pass "En-tête HSTS public" || fail "En-tête HSTS absent"
        grep -Eqi '^content-security-policy:' "$headers" \
            && pass "En-tête CSP public" || fail "En-tête CSP absent"
    else
        fail "TLS ou healthcheck public invalide"
    fi
    rm -f -- "$headers"
else
    fail "URL HTTPS publique absente ou invalide"
fi

if "$COMPOSE" exec -T api python -c \
    'from portal.pve import PVEClient; c=PVEClient.from_environment(); n=c.list_nodes(); assert n; [c.list_isos(x) for x in n]' \
    >/dev/null 2>&1; then
    pass "Inventaire Proxmox accessible avec le token du portail"
else
    fail "Inventaire Proxmox inaccessible ou vide"
fi

printf '\nRésultat: %d échec(s), %d avertissement(s).\n' "$failures" "$warnings"
[[ $failures -eq 0 ]]
