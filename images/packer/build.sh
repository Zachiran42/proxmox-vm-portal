#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

required=(
    PACKER_PVE_URL
    PACKER_PVE_USERNAME
    PACKER_PVE_TOKEN
    PACKER_PVE_NODE
    PACKER_PVE_POOL
    PACKER_PVE_ISO_STORAGE
    PACKER_PVE_VM_STORAGE
)
for name in "${required[@]}"; do
    if [[ -z ${!name:-} ]]; then
        echo "Variable requise absente: $name" >&2
        exit 1
    fi
done
if [[ $PACKER_PVE_URL != https://* ]]; then
    echo "PACKER_PVE_URL doit utiliser HTTPS." >&2
    exit 1
fi
if [[ $PACKER_PVE_USERNAME == root@* || $PACKER_PVE_USERNAME != *'!'* ]]; then
    echo "Utilisez un token PVE complet appartenant a un compte non-root." >&2
    exit 1
fi
command -v packer >/dev/null || { echo "Packer est requis." >&2; exit 1; }
command -v openssl >/dev/null || { echo "OpenSSL est requis." >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 est requis." >&2; exit 1; }

build_password=$(openssl rand -base64 36 | tr -d '\r\n')
build_password_hash=$(printf '%s' "$build_password" | openssl passwd -6 -stdin)
export PKR_VAR_proxmox_url="$PACKER_PVE_URL"
export PKR_VAR_proxmox_username="$PACKER_PVE_USERNAME"
export PKR_VAR_proxmox_token="$PACKER_PVE_TOKEN"
export PKR_VAR_proxmox_node="$PACKER_PVE_NODE"
export PKR_VAR_proxmox_pool="$PACKER_PVE_POOL"
export PKR_VAR_iso_storage_pool="$PACKER_PVE_ISO_STORAGE"
export PKR_VAR_vm_storage_pool="$PACKER_PVE_VM_STORAGE"
export PKR_VAR_bridge="${PACKER_PVE_BRIDGE:-vmbr0}"
export PKR_VAR_template_vmid="${PACKER_TEMPLATE_VMID:-9130}"
export PKR_VAR_template_name="${PACKER_TEMPLATE_NAME:-debian-13-cloudinit}"
export PKR_VAR_build_username="${PACKER_BUILD_USERNAME:-packer}"
export PKR_VAR_build_password="$build_password"
export PKR_VAR_build_password_hash="$build_password_hash"
trap 'unset build_password build_password_hash PKR_VAR_proxmox_token PKR_VAR_build_password PKR_VAR_build_password_hash' EXIT

packer init "$SCRIPT_DIR/debian-13.pkr.hcl"
packer fmt -check "$SCRIPT_DIR/debian-13.pkr.hcl"
packer validate "$SCRIPT_DIR/debian-13.pkr.hcl"
packer build "$SCRIPT_DIR/debian-13.pkr.hcl"

python3 "$ROOT_DIR/portal/image_manifest.py" create \
    --slug debian-13-cloud \
    --label "Debian 13 Cloud" \
    --description "Debian 13.6 durci, cloud-init, construit depuis l'ISO officielle verifiee" \
    --template-node "$PACKER_PVE_NODE" \
    --template-vmid "$PKR_VAR_template_vmid" \
    --output "$SCRIPT_DIR/promotion.json"
echo "Template construit. Validez images/packer/promotion.json avant sa publication dans le portail."
