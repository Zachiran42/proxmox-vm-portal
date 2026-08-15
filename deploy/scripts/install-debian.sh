#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
SECRETS_DIR="$ROOT_DIR/deploy/secrets"
ENV_FILE="$ROOT_DIR/.env.production"
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"

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
    # shellcheck source=/dev/null
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

harden_portal_secrets() {
    local name path
    for name in portal_database_url portal_session_secret \
        portal_admin_password_hash pve_token_secret portal_oidc_client_secret \
        portal_ldap_bind_password portal_ldap_ca_cert pve_ca_cert \
        portal_netbox_api_token portal_netbox_ca_cert \
        portal_pwpush_api_token portal_metrics_token; do
        path="$SECRETS_DIR/$name"
        if [[ -e $path ]]; then
            chown 10001:10001 "$path"
            chmod 0400 "$path"
        fi
    done
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
    keycloak_admin_password pwpush_master_key pwpush_secret_key_base \
    portal_metrics_token; do
    secret "$name"
done
for name in pve_ca_cert portal_oidc_client_secret portal_ldap_bind_password \
    portal_ldap_ca_cert portal_netbox_api_token portal_netbox_ca_cert \
    portal_pwpush_api_token; do
    [[ -e $SECRETS_DIR/$name ]] || install -m 0600 /dev/null "$SECRETS_DIR/$name"
done

db_password=$(cat "$SECRETS_DIR/portal_db_password")
printf 'postgresql+psycopg://portal:%s@db:5432/portal' "$db_password" > "$SECRETS_DIR/portal_database_url"

if [[ ! -s $SECRETS_DIR/pve_token_secret ]]; then
    if [[ $(setting PORTAL_FIRST_BOOT_MODE) == true ]]; then
        secret pve_token_secret
    else
        read -rsp "Secret du token API Proxmox: " pve_secret
        echo
        [[ -n $pve_secret ]] || { echo "Le secret Proxmox est obligatoire." >&2; exit 1; }
        printf '%s' "$pve_secret" > "$SECRETS_DIR/pve_token_secret"
        unset pve_secret
    fi
fi

cd "$ROOT_DIR"
profiles=$(setting COMPOSE_PROFILES)
if [[ ,$profiles, == *,keycloak,* ]]; then
    install -m 0644 deploy/caddy/sites/keycloak.caddy.disabled deploy/caddy/sites/keycloak.caddy
fi
if [[ ,$profiles, == *,pwpush,* ]]; then
    install -m 0644 deploy/caddy/sites/pwpush.caddy.disabled deploy/caddy/sites/pwpush.caddy
fi
deploy_mode=$(setting PORTAL_DEPLOY_MODE)
deploy_mode=${deploy_mode:-source}
portal_image=$(setting PORTAL_IMAGE)
case "$deploy_mode" in
    source)
        "$COMPOSE" build api
        portal_image=${portal_image:-proxmox-vm-portal:0.23.1}
        ;;
    release)
        release_tag=$(setting PORTAL_RELEASE_TAG)
        release_repository=$(setting PORTAL_RELEASE_REPOSITORY)
        release_transparency=$(setting PORTAL_RELEASE_TRANSPARENCY)
        [[ -n $portal_image && -n $release_tag && -n $release_repository ]] || {
            echo "PORTAL_IMAGE, PORTAL_RELEASE_TAG et PORTAL_RELEASE_REPOSITORY sont requis en mode release." >&2
            exit 1
        }
        if [[ -n ${PORTAL_GITHUB_TOKEN:-} ]]; then
            github_username=${PORTAL_GITHUB_USERNAME:-}
            [[ $github_username =~ ^[A-Za-z0-9-]+$ ]] || {
                echo "PORTAL_GITHUB_USERNAME est requis pour l'authentification GHCR." >&2
                exit 1
            }
            printf '%s' "$PORTAL_GITHUB_TOKEN" | docker login ghcr.io \
                --username "$github_username" --password-stdin
            unset PORTAL_GITHUB_TOKEN
        fi
        bash "$SCRIPT_DIR/verify-published-image.sh" "$portal_image" "$release_tag" \
            "$release_repository" "${release_transparency:-private}"
        docker pull "$portal_image"
        ;;
    offline)
        release_tag=$(setting PORTAL_RELEASE_TAG)
        release_repository=$(setting PORTAL_RELEASE_REPOSITORY)
        evidence_dir="$ROOT_DIR/deploy/release-evidence/$release_tag"
        manifest_file="$evidence_dir/release-manifest.json"
        verification_file="$evidence_dir/offline-verification.txt"
        [[ -n $portal_image && -n $release_tag && -n $release_repository ]] || {
            echo "PORTAL_IMAGE, PORTAL_RELEASE_TAG et PORTAL_RELEASE_REPOSITORY sont requis en mode offline." >&2
            exit 1
        }
        [[ -s $manifest_file && -s $verification_file ]] || {
            echo "Les preuves de vérification du bundle hors ligne sont absentes." >&2
            exit 1
        }
        grep -Fqx "image=$portal_image" "$verification_file" || {
            echo "La preuve hors ligne ne correspond pas à PORTAL_IMAGE." >&2
            exit 1
        }
        grep -Fqx "tag=$release_tag" "$verification_file" || {
            echo "La preuve hors ligne ne correspond pas à PORTAL_RELEASE_TAG." >&2
            exit 1
        }
        docker image inspect "$portal_image" >/dev/null || {
            echo "L'image applicative vérifiée n'est pas chargée localement." >&2
            exit 1
        }
        ;;
    *)
        echo "PORTAL_DEPLOY_MODE doit valoir source, release ou offline." >&2
        exit 1
        ;;
esac
harden_portal_secrets
if [[ ${PORTAL_INSTALL_VALIDATE_ONLY:-0} == 1 ]]; then
    docker image inspect "$portal_image" >/dev/null
    echo "Validation Debian terminée après la préparation de l'image."
    exit 0
fi
if [[ ! -s $SECRETS_DIR/portal_admin_password_hash ]]; then
    if [[ $(setting PORTAL_FIRST_BOOT_MODE) == true ]]; then
        admin_password='admin'
        initial_credentials=/root/proxmox-vm-portal-initial-credentials.txt
        install -m 0600 /dev/null "$initial_credentials"
        printf 'URL=https://%s\nUtilisateur=%s\nMot de passe=%s\n' \
            "$(setting PORTAL_DOMAIN)" "$(setting PORTAL_ADMIN_USERNAME)" \
            "$admin_password" > "$initial_credentials"
    else
        read -rsp "Mot de passe initial de l'administrateur: " admin_password
        echo
        read -rsp "Confirmation: " admin_confirmation
        echo
        [[ $admin_password == "$admin_confirmation" ]] || { echo "Les mots de passe diffèrent." >&2; exit 1; }
        [[ -n $admin_password ]] || { echo "Le mot de passe ne peut pas être vide." >&2; exit 1; }
    fi
    printf '%s' "$admin_password" | docker run --rm -i "$portal_image" \
        python -c 'import sys; from werkzeug.security import generate_password_hash; print(generate_password_hash(sys.stdin.read(), method="scrypt"))' \
        > "$SECRETS_DIR/portal_admin_password_hash"
    unset admin_password admin_confirmation
fi
harden_portal_secrets

"$COMPOSE" config --quiet
"$COMPOSE" up -d --wait
user_count=$("$COMPOSE" exec -T db \
    psql -U portal -d portal -tAc 'SELECT count(*) FROM users')
if [[ $user_count == 0 ]]; then
    "$COMPOSE" exec -T api \
        flask --app portal:create_app bootstrap-admin
else
    echo "Bootstrap administrateur ignoré: la base contient déjà un utilisateur."
fi

echo "Installation terminée. Vérifiez https://$(grep '^PORTAL_DOMAIN=' "$ENV_FILE" | cut -d= -f2-)"
if [[ $(setting PORTAL_FIRST_BOOT_MODE) == true ]]; then
    echo "Identifiants initiaux: /root/proxmox-vm-portal-initial-credentials.txt"
    echo "Clé privée de sauvegarde à exporter hors de la VM: /root/proxmox-vm-portal-backup.agekey"
    echo "Configurez ensuite Proxmox avec: $ROOT_DIR/deploy/scripts/configure-proxmox.sh"
fi
echo "Configurez DNS, pare-feu hôte, ACL Proxmox et sauvegardes hors site selon docs/DEPLOYMENT.md."
