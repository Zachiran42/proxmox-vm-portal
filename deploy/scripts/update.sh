#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE="$ROOT_DIR/deploy/scripts/compose.sh"

if [[ $# -ne 1 || ! $1 =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "Usage: $0 COMMIT_ORIGIN_MAIN_ATTENDU" >&2
    exit 1
fi
expected_commit=${1,,}

"$SCRIPT_DIR/backup.sh"
git -C "$ROOT_DIR" fetch --prune origin main
remote_commit=$(git -C "$ROOT_DIR" rev-parse 'origin/main^{commit}')
if [[ $remote_commit != "$expected_commit" ]]; then
    echo "Le commit distant ne correspond pas au commit approuvé; mise à jour refusée." >&2
    exit 1
fi
git -C "$ROOT_DIR" merge --ff-only "$remote_commit"
"$COMPOSE" pull --ignore-buildable
"$COMPOSE" build --pull api
"$COMPOSE" run --rm migrate
"$COMPOSE" up -d --wait --remove-orphans
"$COMPOSE" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5)"
echo "Mise à jour terminée."
