#!/bin/bash
set -Eeuo pipefail
umask 077

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 UTILISATEUR_PVE ID_TOKEN POLITIQUE_JSON" >&2
    exit 2
fi
if [[ $EUID -ne 0 || ! -x /usr/sbin/pveum ]]; then
    echo "Ce script doit être exécuté par root sur un nœud Proxmox." >&2
    exit 2
fi

PVE_USER=$1
TOKEN_ID=$2
POLICY=$3
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
[[ $PVE_USER != root@* ]] || { echo "Un utilisateur root est interdit." >&2; exit 1; }
[[ $TOKEN_ID =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Identifiant de token invalide." >&2; exit 2; }
[[ -r $POLICY ]] || { echo "Politique ACL illisible: $POLICY" >&2; exit 2; }

metadata=$(mktemp)
permissions=$(mktemp)
trap 'rm -f -- "$metadata" "$permissions"' EXIT

/usr/sbin/pveum user token list "$PVE_USER" --output-format json > "$metadata"
python3 - "$metadata" "$TOKEN_ID" <<'PY'
import json
import sys

entries = json.load(open(sys.argv[1], encoding="utf-8"))
token = next((item for item in entries if item.get("tokenid") == sys.argv[2]), None)
if token is None:
    raise SystemExit("Token introuvable.")
if token.get("privsep") not in (1, True, "1"):
    raise SystemExit("Le token doit utiliser la séparation de privilèges.")
PY

/usr/sbin/pveum user token permissions "$PVE_USER" "$TOKEN_ID" \
    --output-format json > "$permissions"
PYTHONPATH="$ROOT_DIR" python3 -m portal.acl_policy "$permissions" "$POLICY"
echo "Audit ACL terminé sans afficher ni lire le secret du token."
