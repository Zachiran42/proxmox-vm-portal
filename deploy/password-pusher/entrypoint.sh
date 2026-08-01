#!/bin/sh
set -eu

export PWPUSH_MASTER_KEY="$(cat /run/secrets/pwpush_master_key)"
export SECRET_KEY_BASE="$(cat /run/secrets/pwpush_secret_key_base)"
exec /usr/local/bin/docker-entrypoint "$@"
