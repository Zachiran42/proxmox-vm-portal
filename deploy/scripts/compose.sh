#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
ENV_FILE=${PORTAL_ENV_FILE:-$ROOT_DIR/.env.production}

if [ ! -f "$ENV_FILE" ]; then
    echo "Configuration absente: $ENV_FILE" >&2
    exit 1
fi

exec docker compose --project-directory "$ROOT_DIR" --env-file "$ENV_FILE" -f "$ROOT_DIR/compose.yml" "$@"
