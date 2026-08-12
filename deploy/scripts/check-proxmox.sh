#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

exec "$SCRIPT_DIR/compose.sh" run --rm --no-deps api \
    flask --app portal:create_app check-proxmox
