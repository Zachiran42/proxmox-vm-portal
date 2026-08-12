#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

exec "$SCRIPT_DIR/compose.sh" exec api \
    flask --app portal:create_app reset-admin-password "$@"
