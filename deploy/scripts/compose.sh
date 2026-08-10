#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE=${PORTAL_ENV_FILE:-$ROOT_DIR/.env.production}

if [ ! -f "$ENV_FILE" ]; then
    echo "Configuration absente: $ENV_FILE" >&2
    exit 1
fi

env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
deploy_mode=${PORTAL_DEPLOY_MODE:-$(env_value PORTAL_DEPLOY_MODE)}
deploy_mode=${deploy_mode:-source}

case "$deploy_mode" in
    source)
        exec docker compose --project-directory "$ROOT_DIR" --env-file "$ENV_FILE" \
            -f "$ROOT_DIR/compose.yml" "$@"
        ;;
    release)
        portal_image=$(env_value PORTAL_IMAGE)
        if ! printf '%s\n' "$portal_image" \
            | grep -Eq '^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$'; then
            echo "En mode release, PORTAL_IMAGE doit être une référence GHCR par digest." >&2
            exit 1
        fi
        exec docker compose --project-directory "$ROOT_DIR" --env-file "$ENV_FILE" \
            -f "$ROOT_DIR/compose.yml" -f "$ROOT_DIR/deploy/compose.release.yml" "$@"
        ;;
    offline)
        portal_image=$(env_value PORTAL_IMAGE)
        if ! printf '%s\n' "$portal_image" \
            | grep -Eq '^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+:offline-[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "En mode offline, PORTAL_IMAGE doit être la référence locale créée par le bundle." >&2
            exit 1
        fi
        exec docker compose --project-directory "$ROOT_DIR" --env-file "$ENV_FILE" \
            -f "$ROOT_DIR/compose.yml" -f "$ROOT_DIR/deploy/compose.release.yml" \
            -f "$ROOT_DIR/deploy/compose.offline.yml" "$@"
        ;;
    *)
        echo "PORTAL_DEPLOY_MODE doit valoir source, release ou offline." >&2
        exit 1
        ;;
esac
