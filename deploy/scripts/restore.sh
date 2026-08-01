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
archive="$tmpdir/backup.tar.gz"
restore_dir="$tmpdir/content"
mkdir -m 0700 "$restore_dir"
age -d -i "$AGE_IDENTITY_FILE" "$BACKUP" > "$archive"
if tar -tzf "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    echo "Archive invalide: chemin dangereux." >&2
    exit 1
fi
if tar -tvzf "$archive" | grep -Eq '^[lh]'; then
    echo "Archive invalide: liens interdits." >&2
    exit 1
fi
tar --no-same-owner --no-same-permissions -C "$restore_dir" -xzf "$archive"
[[ -s $restore_dir/portal.dump ]] || { echo "Archive invalide: portal.dump absent." >&2; exit 1; }

"$COMPOSE" stop api worker migrate
"$COMPOSE" up -d --wait db
"$COMPOSE" exec -T db pg_restore -U portal -d portal --clean --if-exists --no-owner < "$restore_dir/portal.dump"
if [[ -s $restore_dir/keycloak.dump ]]; then
    "$COMPOSE" up -d --wait keycloak-db
    "$COMPOSE" exec -T keycloak-db pg_restore -U keycloak -d keycloak --clean --if-exists --no-owner < "$restore_dir/keycloak.dump"
fi
if [[ -s $restore_dir/pwpush-data.tar.gz ]]; then
    if tar -tzf "$restore_dir/pwpush-data.tar.gz" | grep -Eq '(^/|(^|/)\.\.(/|$))' \
        || tar -tvzf "$restore_dir/pwpush-data.tar.gz" | grep -Eq '^[lh]'; then
        echo "Archive invalide: contenu Password Pusher dangereux." >&2
        exit 1
    fi
    project=${COMPOSE_PROJECT_NAME:-proxmox-vm-portal}
    "$COMPOSE" stop pwpush 2>/dev/null || true
    docker volume create "${project}_pwpush_data" >/dev/null
    docker run --rm --volume "${project}_pwpush_data:/target" --volume "$restore_dir:/backup:ro" \
        alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
        sh -ec 'find /target -mindepth 1 -delete; tar -xzf /backup/pwpush-data.tar.gz -C /target'
fi
if [[ $RESTORE_CONFIG == --restore-config ]]; then
    [[ -f $restore_dir/env.production && -d $restore_dir/secrets ]] || {
        echo "Archive invalide: configuration absente." >&2
        exit 1
    }
    install -m 0600 "$restore_dir/env.production" "$ROOT_DIR/.env.production"
    cp -a "$restore_dir/secrets/." "$ROOT_DIR/deploy/secrets/"
fi
"$COMPOSE" up -d --wait
echo "Restauration terminée. Contrôlez les journaux et réalisez un test fonctionnel."
