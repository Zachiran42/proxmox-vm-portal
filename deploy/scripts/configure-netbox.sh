#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE="$ROOT_DIR/.env.production"
TOKEN_FILE="$ROOT_DIR/deploy/secrets/portal_netbox_api_token"
CA_FILE="$ROOT_DIR/deploy/secrets/portal_netbox_ca_cert"
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"

fail() { echo "$1" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "Exécutez ce script avec sudo."
[[ -s $ENV_FILE ]] || fail "Installation du portail introuvable."

read -r -p "URL HTTPS NetBox (ex: https://netbox.infra.chu.fr) : " NETBOX_URL </dev/tty
[[ $NETBOX_URL =~ ^https://[^/[:space:]]+/?$ ]] || fail "Une URL HTTPS NetBox valide est requise."
read -r -s -p "Token API NetBox en écriture : " NETBOX_TOKEN </dev/tty
echo
[[ -n $NETBOX_TOKEN ]] || fail "Le token NetBox est requis."
read -r -p "Chemin de la CA NetBox (vide si déjà approuvée) : " NETBOX_CA_SOURCE </dev/tty
if [[ -n $NETBOX_CA_SOURCE ]]; then
    [[ -r $NETBOX_CA_SOURCE ]] || fail "CA NetBox illisible."
    grep -q -- 'PRIVATE KEY' "$NETBOX_CA_SOURCE" && fail "Le fichier de CA ne doit contenir aucune clé privée."
    openssl x509 -in "$NETBOX_CA_SOURCE" -noout >/dev/null 2>&1 || fail "Certificat PEM invalide."
fi

set_env_value() {
    local key=$1 value=$2 escaped
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail "$key contient un retour à la ligne."
    escaped=${value//\\/\\\\}; escaped=${escaped//&/\\&}; escaped=${escaped//|/\\|}
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

set_env_value PORTAL_NETBOX_URL "${NETBOX_URL%/}"
set_env_value PORTAL_NETBOX_CA_BUNDLE "$([[ -n $NETBOX_CA_SOURCE ]] && printf /run/secrets/portal_netbox_ca_cert)"
install -m 0400 -o 10001 -g 10001 /dev/null "$TOKEN_FILE"
printf '%s' "$NETBOX_TOKEN" > "$TOKEN_FILE"
if [[ -n $NETBOX_CA_SOURCE ]]; then
    install -m 0400 -o 10001 -g 10001 "$NETBOX_CA_SOURCE" "$CA_FILE"
else
    install -m 0400 -o 10001 -g 10001 /dev/null "$CA_FILE"
fi
unset NETBOX_TOKEN

cd "$ROOT_DIR"
"$COMPOSE" config --quiet
"$COMPOSE" run --rm --no-deps api flask --app portal:create_app check-netbox
"$COMPOSE" up -d --wait --force-recreate api worker
echo "NetBox validé et activé. Vous pouvez maintenant associer un préfixe aux profils réseau."
