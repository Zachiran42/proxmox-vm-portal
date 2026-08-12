#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE="$ROOT_DIR/.env.production"
SECRET_FILE="$ROOT_DIR/deploy/secrets/pve_token_secret"
CA_FILE="$ROOT_DIR/deploy/secrets/pve_ca_cert"
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"
rollback_dir=""

fail() { echo "$1" >&2; exit 1; }
cleanup() {
    local status=$?
    if [[ $status -ne 0 && -n $rollback_dir && -d $rollback_dir ]]; then
        install -m 0600 "$rollback_dir/environment" "$ENV_FILE"
        if [[ -s $rollback_dir/token ]]; then
            install -m 0400 -o 10001 -g 10001 "$rollback_dir/token" "$SECRET_FILE"
        else
            rm -f -- "$SECRET_FILE"
        fi
        if [[ -s $rollback_dir/ca ]]; then
            install -m 0400 -o 10001 -g 10001 "$rollback_dir/ca" "$CA_FILE"
        else
            install -m 0400 -o 10001 -g 10001 /dev/null "$CA_FILE"
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

tls_probe() {
    local ca=${1:-} options=(--silent --show-error --output /dev/null \
        --connect-timeout 10 --max-time 15)
    [[ -z $ca ]] || options+=(--cacert "$ca")
    curl "${options[@]}" "${PVE_API_URL%/}/version"
}

if tls_probe; then
    :
elif [[ -s $CA_FILE ]] && tls_probe "$CA_FILE"; then
    :
else
    echo "La CA qui signe le certificat Proxmox n'est pas approuvée." >&2
    while [[ -z ${PVE_CA_SOURCE:-} || ! -r ${PVE_CA_SOURCE:-} ]]; do
        read -r -p "Chemin local de la CA publique Proxmox (PEM) : " PVE_CA_SOURCE </dev/tty
    done
    grep -q -- 'PRIVATE KEY' "$PVE_CA_SOURCE" && fail \
        "Le fichier de CA ne doit contenir aucune clé privée."
    openssl x509 -in "$PVE_CA_SOURCE" -noout >/dev/null 2>&1 || fail \
        "Le fichier fourni n'est pas un certificat PEM valide."
    tls_probe "$PVE_CA_SOURCE" || fail \
        "La CA fournie ne valide pas l'adresse Proxmox configurée."
fi
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
if [[ -s $CA_FILE ]]; then
    install -m 0600 "$CA_FILE" "$rollback_dir/ca"
else
    install -m 0600 /dev/null "$rollback_dir/ca"
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
chown 10001:10001 "$SECRET_FILE"
chmod 0400 "$SECRET_FILE"
if [[ -n ${PVE_CA_SOURCE:-} ]]; then
    install -m 0400 -o 10001 -g 10001 "$PVE_CA_SOURCE" "$CA_FILE"
elif [[ ! -e $CA_FILE ]]; then
    install -m 0400 -o 10001 -g 10001 /dev/null "$CA_FILE"
fi
unset PVE_TOKEN_SECRET

"$COMPOSE" config --quiet
echo "Vérification chiffrée de l'API et du token Proxmox…"
"$COMPOSE" run --rm --no-deps api \
    flask --app portal:create_app check-proxmox
"$COMPOSE" up -d --wait --force-recreate api worker
echo "Configuration Proxmox validée et appliquée."
