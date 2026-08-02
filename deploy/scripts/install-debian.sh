#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
SECRETS_DIR="$ROOT_DIR/deploy/secrets"
ENV_FILE="$ROOT_DIR/.env.production"

if [[ $EUID -ne 0 ]]; then
    echo "Exécutez ce script avec sudo sur Debian." >&2
    exit 1
fi
if [[ ! -r /etc/os-release ]] || ! grep -q '^ID=debian$' /etc/os-release; then
    echo "Ce script prend uniquement en charge Debian." >&2
    exit 1
fi
if [[ $(stat -c '%u' "$ROOT_DIR") != 0 ]] || find "$ROOT_DIR" -xdev \
    \( -perm -002 -o -perm -020 \) -print -quit | grep -q .; then
    echo "Le dépôt doit appartenir à root et ne pas être modifiable par groupe/autres." >&2
    exit 1
fi

install_docker() {
    if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
        return
    fi
    apt-get update
    apt-get install -y ca-certificates curl age openssl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    . /etc/os-release
    printf 'Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
        "$VERSION_CODENAME" "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/docker.sources
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

secret() {
    local path="$SECRETS_DIR/$1"
    [[ -e $path ]] || openssl rand -base64 48 | tr -d '\n' > "$path"
    chmod 0600 "$path"
}

install_docker
command -v age >/dev/null || { apt-get update && apt-get install -y age; }
command -v openssl >/dev/null || { apt-get update && apt-get install -y openssl; }
install -d -m 0700 "$SECRETS_DIR"
[[ -e $ENV_FILE ]] || install -m 0600 "$ROOT_DIR/.env.production.example" "$ENV_FILE"

setting() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
for required in PORTAL_DOMAIN ACME_EMAIL PVE_API_URL PVE_TOKEN_ID BACKUP_AGE_RECIPIENT; do
    value=$(setting "$required")
    if [[ -z $value || $value == *example.* ]]; then
        echo "Renseignez $required dans $ENV_FILE avant l'installation." >&2
        exit 1
    fi
done
[[ $(setting BACKUP_AGE_RECIPIENT) == age1* ]] || {
    echo "BACKUP_AGE_RECIPIENT doit être un destinataire age (age1...)." >&2
    exit 1
}

for name in portal_db_password portal_session_secret keycloak_db_password \
    keycloak_admin_password pwpush_master_key pwpush_secret_key_base; do
    secret "$name"
done
for name in portal_oidc_client_secret portal_pwpush_api_token; do
    [[ -e $SECRETS_DIR/$name ]] || install -m 0600 /dev/null "$SECRETS_DIR/$name"
done

db_password=$(cat "$SECRETS_DIR/portal_db_password")
printf 'postgresql+psycopg://portal:%s@db:5432/portal' "$db_password" > "$SECRETS_DIR/portal_database_url"

if [[ ! -s $SECRETS_DIR/pve_token_secret ]]; then
    read -rsp "Secret du token API Proxmox: " pve_secret
    echo
    [[ -n $pve_secret ]] || { echo "Le secret Proxmox est obligatoire." >&2; exit 1; }
    printf '%s' "$pve_secret" > "$SECRETS_DIR/pve_token_secret"
    unset pve_secret
fi

cd "$ROOT_DIR"
profiles=$(setting COMPOSE_PROFILES)
if [[ ,$profiles, == *,keycloak,* ]]; then
    install -m 0644 deploy/caddy/sites/keycloak.caddy.disabled deploy/caddy/sites/keycloak.caddy
fi
if [[ ,$profiles, == *,pwpush,* ]]; then
    install -m 0644 deploy/caddy/sites/pwpush.caddy.disabled deploy/caddy/sites/pwpush.caddy
fi
docker compose --env-file "$ENV_FILE" -f compose.yml build api
if [[ ${PORTAL_INSTALL_VALIDATE_ONLY:-0} == 1 ]]; then
    portal_image=$(setting PORTAL_IMAGE)
    docker image inspect "${portal_image:-proxmox-vm-portal:0.14.0}" >/dev/null
    echo "Validation Debian terminée après la construction de l'image."
    exit 0
fi
if [[ ! -s $SECRETS_DIR/portal_admin_password_hash ]]; then
    read -rsp "Mot de passe initial de l'administrateur (16 caractères minimum): " admin_password
    echo
    read -rsp "Confirmation: " admin_confirmation
    echo
    [[ $admin_password == "$admin_confirmation" ]] || { echo "Les mots de passe diffèrent." >&2; exit 1; }
    [[ ${#admin_password} -ge 16 ]] || { echo "Mot de passe trop court." >&2; exit 1; }
    printf '%s' "$admin_password" | docker run --rm -i "$(grep '^PORTAL_IMAGE=' "$ENV_FILE" | cut -d= -f2-)" \
        python -c 'import sys; from werkzeug.security import generate_password_hash; print(generate_password_hash(sys.stdin.read(), method="scrypt"))' \
        > "$SECRETS_DIR/portal_admin_password_hash"
    unset admin_password admin_confirmation
fi

docker compose --env-file "$ENV_FILE" -f compose.yml config --quiet
docker compose --env-file "$ENV_FILE" -f compose.yml up -d --wait
user_count=$(docker compose --env-file "$ENV_FILE" -f compose.yml exec -T db \
    psql -U portal -d portal -tAc 'SELECT count(*) FROM users')
if [[ $user_count == 0 ]]; then
    docker compose --env-file "$ENV_FILE" -f compose.yml exec -T api \
        flask --app portal:create_app bootstrap-admin
else
    echo "Bootstrap administrateur ignoré: la base contient déjà un utilisateur."
fi

echo "Installation terminée. Vérifiez https://$(grep '^PORTAL_DOMAIN=' "$ENV_FILE" | cut -d= -f2-)"
echo "Configurez DNS, pare-feu hôte, ACL Proxmox et sauvegardes hors site selon docs/DEPLOYMENT.md."
