#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"

"$SCRIPT_DIR/backup.sh"
git -C "$ROOT_DIR" pull --ff-only
"$COMPOSE" pull --ignore-buildable
"$COMPOSE" build --pull api
"$COMPOSE" run --rm migrate
"$COMPOSE" up -d --wait --remove-orphans
"$COMPOSE" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5)"
echo "Mise à jour terminée."
