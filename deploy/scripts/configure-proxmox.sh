#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE="$ROOT_DIR/.env.production"
SECRET_FILE="$ROOT_DIR/deploy/secrets/pve_token_secret"
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"
rollback_dir=""

fail() { echo "$1" >&2; exit 1; }
cleanup() {
    local status=$?
    if [[ $status -ne 0 && -n $rollback_dir && -d $rollback_dir ]]; then
        install -m 0600 "$rollback_dir/environment" "$ENV_FILE"
        if [[ -s $rollback_dir/token ]]; then
            install -m 0600 "$rollback_dir/token" "$SECRET_FILE"
        else
            rm -f -- "$SECRET_FILE"
        fi
        echo "Échec de configuration; les anciennes valeurs ont été restaurées." >&2
    fi
    if [[ $rollback_dir == /tmp/proxmox-vm-portal-pve.* ]]; then
        rm -rf -- "$rollback_dir"
    fi
}
trap cleanup EXIT
[[ $EUID -eq 0 ]] || fail "Exécutez ce script avec sudo."
[[ -s $ENV_FILE ]] || fail "Installation du portail introuvable."

while [[ ! ${PVE_API_URL:-} =~ ^https://[^[:space:]]+/api2/json/?$ ]]; do
    read -r -p "URL HTTPS Proxmox (…/api2/json) : " PVE_API_URL </dev/tty
done
while [[ ! ${PVE_TOKEN_ID:-} =~ ^[^[:space:]]+@[^[:space:]!]+![^[:space:]]+$ ]]; do
    read -r -p "Identifiant du token Proxmox : " PVE_TOKEN_ID </dev/tty
done
[[ $PVE_TOKEN_ID != root@* ]] || fail "Un token root@… est interdit."
while [[ -z ${PVE_TOKEN_SECRET:-} ]]; do
    read -r -s -p "Secret du token Proxmox : " PVE_TOKEN_SECRET </dev/tty
    echo
done

rollback_dir=$(mktemp -d /tmp/proxmox-vm-portal-pve.XXXXXXXX)
install -m 0600 "$ENV_FILE" "$rollback_dir/environment"
if [[ -s $SECRET_FILE ]]; then
    install -m 0600 "$SECRET_FILE" "$rollback_dir/token"
else
    install -m 0600 /dev/null "$rollback_dir/token"
fi

set_env_value() {
    local key=$1 value=$2 escaped
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail "$key contient un retour à la ligne."
    escaped=${value//\\/\\\\}; escaped=${escaped//&/\\&}; escaped=${escaped//|/\\|}
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
}
set_env_value PVE_API_URL "${PVE_API_URL%/}"
set_env_value PVE_TOKEN_ID "$PVE_TOKEN_ID"
set_env_value PORTAL_FIRST_BOOT_MODE false
install -m 0600 /dev/null "$SECRET_FILE"
printf '%s' "$PVE_TOKEN_SECRET" > "$SECRET_FILE"
unset PVE_TOKEN_SECRET

"$COMPOSE" config --quiet
"$COMPOSE" up -d --wait --force-recreate api worker
echo "Configuration Proxmox appliquée."
