#!/bin/bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE=${PORTAL_ENV_FILE:-$ROOT_DIR/.env.production}
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"
[[ -r $ENV_FILE ]] || { echo "Configuration absente: $ENV_FILE" >&2; exit 1; }
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
BACKUP_AGE_RECIPIENT=${BACKUP_AGE_RECIPIENT:-$(env_value BACKUP_AGE_RECIPIENT)}
BACKUP_DIRECTORY=${BACKUP_DIRECTORY:-$(env_value BACKUP_DIRECTORY)}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-$(env_value COMPOSE_PROJECT_NAME)}
: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT est obligatoire}"
BACKUP_DIRECTORY=${BACKUP_DIRECTORY:-/var/backups/proxmox-vm-portal}
install -d -m 0700 "$BACKUP_DIRECTORY"
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT

"$COMPOSE" exec -T db pg_dump -U portal -d portal -Fc > "$tmpdir/portal.dump"
if [[ -n $("$COMPOSE" ps -q keycloak-db 2>/dev/null) ]]; then
    "$COMPOSE" exec -T keycloak-db pg_dump -U keycloak -d keycloak -Fc > "$tmpdir/keycloak.dump"
fi
project=${COMPOSE_PROJECT_NAME:-proxmox-vm-portal}
if docker volume inspect "${project}_pwpush_data" >/dev/null 2>&1; then
    docker run --rm --volume "${project}_pwpush_data:/source:ro" --volume "$tmpdir:/backup" \
        alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
        tar -czf /backup/pwpush-data.tar.gz -C /source .
fi
install -m 0600 "$ENV_FILE" "$tmpdir/env.production"
cp -a "$ROOT_DIR/deploy/secrets" "$tmpdir/secrets"
date -u +%FT%TZ > "$tmpdir/created-at"
archive="$BACKUP_DIRECTORY/portal-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age"
tar -C "$tmpdir" -czf - . | age -r "$BACKUP_AGE_RECIPIENT" -o "$archive"
echo "Sauvegarde chiffrée créée: $archive"
