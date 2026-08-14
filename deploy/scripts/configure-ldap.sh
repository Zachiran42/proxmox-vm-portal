#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE="$ROOT_DIR/.env.production"
SECRET_FILE="$ROOT_DIR/deploy/secrets/portal_ldap_bind_password"
CA_FILE="$ROOT_DIR/deploy/secrets/portal_ldap_ca_cert"
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"
rollback_dir=""

fail() { echo "$1" >&2; exit 1; }
cleanup() {
    local status=$?
    if [[ $status -ne 0 && -n $rollback_dir && -d $rollback_dir ]]; then
        install -m 0600 "$rollback_dir/environment" "$ENV_FILE"
        install -m 0400 -o 10001 -g 10001 "$rollback_dir/password" "$SECRET_FILE"
        install -m 0400 -o 10001 -g 10001 "$rollback_dir/ca" "$CA_FILE"
        echo "Échec de configuration; les anciennes valeurs LDAP ont été restaurées." >&2
    fi
    if [[ $rollback_dir == /tmp/proxmox-vm-portal-ldap.* ]]; then
        rm -rf -- "$rollback_dir"
    fi
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || fail "Exécutez ce script avec sudo."
[[ -s $ENV_FILE ]] || fail "Installation du portail introuvable."

while [[ ! ${PORTAL_LDAP_URI:-} =~ ^ldaps?://[^/[:space:]]+$ ]]; do
    read -r -p "URL LDAP sécurisée (ldap:// avec StartTLS ou ldaps://) : " PORTAL_LDAP_URI </dev/tty
done
while [[ -z ${PORTAL_LDAP_BASE_DN:-} ]]; do
    read -r -p "Base DN des utilisateurs (ex: DC=chu,DC=fr) : " PORTAL_LDAP_BASE_DN </dev/tty
done
read -r -p "DN du compte de lecture LDAP : " PORTAL_LDAP_BIND_DN </dev/tty
[[ -n $PORTAL_LDAP_BIND_DN ]] || fail "Un compte de lecture LDAP est requis."
while [[ -z ${PORTAL_LDAP_BIND_PASSWORD:-} ]]; do
    read -r -s -p "Secret du compte de lecture LDAP : " PORTAL_LDAP_BIND_PASSWORD </dev/tty
    echo
done
read -r -p "Filtre utilisateur [(sAMAccountName={username})] : " PORTAL_LDAP_USER_FILTER </dev/tty
PORTAL_LDAP_USER_FILTER=${PORTAL_LDAP_USER_FILTER:-'(sAMAccountName={username})'}
read -r -p "DN du groupe utilisateurs autorisés : " PORTAL_LDAP_GROUP_USER </dev/tty
[[ -n $PORTAL_LDAP_GROUP_USER ]] || fail "Le groupe utilisateurs est requis."
read -r -p "DN du groupe administrateurs (optionnel) : " PORTAL_LDAP_GROUP_ADMIN </dev/tty
read -r -p "DN du groupe opérateurs (optionnel) : " PORTAL_LDAP_GROUP_OPERATOR </dev/tty
read -r -p "Chemin de la CA publique LDAP/AD (vide si déjà approuvée) : " PORTAL_LDAP_CA_SOURCE </dev/tty

if [[ -n $PORTAL_LDAP_CA_SOURCE ]]; then
    [[ -r $PORTAL_LDAP_CA_SOURCE ]] || fail "CA LDAP illisible."
    grep -q -- 'PRIVATE KEY' "$PORTAL_LDAP_CA_SOURCE" && fail \
        "Le fichier de CA ne doit contenir aucune clé privée."
    openssl x509 -in "$PORTAL_LDAP_CA_SOURCE" -noout >/dev/null 2>&1 || fail \
        "Le fichier fourni n'est pas un certificat PEM valide."
fi

rollback_dir=$(mktemp -d /tmp/proxmox-vm-portal-ldap.XXXXXXXX)
install -m 0600 "$ENV_FILE" "$rollback_dir/environment"
[[ -e $SECRET_FILE ]] && install -m 0600 "$SECRET_FILE" "$rollback_dir/password" || install -m 0600 /dev/null "$rollback_dir/password"
[[ -e $CA_FILE ]] && install -m 0600 "$CA_FILE" "$rollback_dir/ca" || install -m 0600 /dev/null "$rollback_dir/ca"

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
set_env_value PORTAL_LDAP_URI "$PORTAL_LDAP_URI"
set_env_value PORTAL_LDAP_BIND_DN "$PORTAL_LDAP_BIND_DN"
set_env_value PORTAL_LDAP_BASE_DN "$PORTAL_LDAP_BASE_DN"
set_env_value PORTAL_LDAP_USER_FILTER "$PORTAL_LDAP_USER_FILTER"
set_env_value PORTAL_LDAP_GROUP_USER "$PORTAL_LDAP_GROUP_USER"
set_env_value PORTAL_LDAP_GROUP_ADMIN "$PORTAL_LDAP_GROUP_ADMIN"
set_env_value PORTAL_LDAP_GROUP_OPERATOR "$PORTAL_LDAP_GROUP_OPERATOR"
set_env_value PORTAL_LDAP_CA_FILE "$([[ -n $PORTAL_LDAP_CA_SOURCE ]] && printf /run/secrets/portal_ldap_ca_cert)"
set_env_value PORTAL_LDAP_START_TLS true

install -m 0400 -o 10001 -g 10001 /dev/null "$SECRET_FILE"
printf '%s' "$PORTAL_LDAP_BIND_PASSWORD" > "$SECRET_FILE"
if [[ -n $PORTAL_LDAP_CA_SOURCE ]]; then
    install -m 0400 -o 10001 -g 10001 "$PORTAL_LDAP_CA_SOURCE" "$CA_FILE"
else
    install -m 0400 -o 10001 -g 10001 /dev/null "$CA_FILE"
fi
unset PORTAL_LDAP_BIND_PASSWORD

cd "$ROOT_DIR"
"$COMPOSE" config --quiet
"$COMPOSE" run --rm --no-deps api flask --app portal:create_app check-ldap
"$COMPOSE" up -d --wait --force-recreate api worker
echo "LDAP/LDAPS validé et activé. Testez un compte utilisateur avant de désactiver les comptes locaux."
