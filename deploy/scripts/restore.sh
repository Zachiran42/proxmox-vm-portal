#!/bin/bash
set -Eeuo pipefail
umask 077

if [[ $# -lt 2 || $2 != --yes ]]; then
    echo "Usage: $0 SAUVEGARDE.tar.gz.age --yes [--restore-config]" >&2
    exit 1
fi
BACKUP=$(realpath "$1")
RESTORE_CONFIG=${3:-}
: "${AGE_IDENTITY_FILE:?AGE_IDENTITY_FILE doit pointer vers la clé privée age}"
[[ -r $AGE_IDENTITY_FILE ]] || { echo "Clé age illisible." >&2; exit 1; }
[[ -r $BACKUP ]] || { echo "Sauvegarde illisible." >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
age -d -i "$AGE_IDENTITY_FILE" "$BACKUP" | tar -C "$tmpdir" -xzf -
[[ -s $tmpdir/portal.dump ]] || { echo "Archive invalide: portal.dump absent." >&2; exit 1; }

"$COMPOSE" stop api worker migrate
"$COMPOSE" up -d --wait db
"$COMPOSE" exec -T db pg_restore -U portal -d portal --clean --if-exists --no-owner < "$tmpdir/portal.dump"
if [[ -s $tmpdir/keycloak.dump ]]; then
    "$COMPOSE" up -d --wait keycloak-db
    "$COMPOSE" exec -T keycloak-db pg_restore -U keycloak -d keycloak --clean --if-exists --no-owner < "$tmpdir/keycloak.dump"
fi
if [[ -s $tmpdir/pwpush-data.tar.gz ]]; then
    project=${COMPOSE_PROJECT_NAME:-proxmox-vm-portal}
    "$COMPOSE" stop pwpush 2>/dev/null || true
    docker volume create "${project}_pwpush_data" >/dev/null
    docker run --rm --volume "${project}_pwpush_data:/target" --volume "$tmpdir:/backup:ro" \
        alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
        sh -ec 'find /target -mindepth 1 -delete; tar -xzf /backup/pwpush-data.tar.gz -C /target'
fi
if [[ $RESTORE_CONFIG == --restore-config ]]; then
    install -m 0600 "$tmpdir/env.production" "$ROOT_DIR/.env.production"
    cp -a "$tmpdir/secrets/." "$ROOT_DIR/deploy/secrets/"
fi
"$COMPOSE" up -d --wait
echo "Restauration terminée. Contrôlez les journaux et réalisez un test fonctionnel."
