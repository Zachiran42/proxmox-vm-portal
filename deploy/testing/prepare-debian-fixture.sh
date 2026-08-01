#!/bin/bash
set -Eeuo pipefail
umask 077

ROOT_DIR=/opt/proxmox-vm-portal
cd "$ROOT_DIR"
cp .env.production.example .env.production
sed -i \
    -e 's/^PORTAL_DOMAIN=.*/PORTAL_DOMAIN=localhost/' \
    -e 's/^ACME_EMAIL=.*/ACME_EMAIL=security-test@invalid.test/' \
    -e 's|^PVE_API_URL=.*|PVE_API_URL=https://pve.invalid.test:8006/api2/json|' \
    -e 's/^PVE_TOKEN_ID=.*/PVE_TOKEN_ID=portal@pve!security-test/' \
    -e 's/^BACKUP_AGE_RECIPIENT=.*/BACKUP_AGE_RECIPIENT=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq/' \
    .env.production

install -d -m 0700 deploy/secrets
printf '%s' 'test-pve-token-secret' > deploy/secrets/pve_token_secret
printf '%s' 'scrypt:32768:8:1$fixture$fixture' > deploy/secrets/portal_admin_password_hash
chmod 0600 deploy/secrets/pve_token_secret deploy/secrets/portal_admin_password_hash

install -m 0755 deploy/testing/systemctl-dind.sh /usr/local/bin/systemctl
chown -R root:root "$ROOT_DIR"
find "$ROOT_DIR" -xdev -type d -exec chmod go-w {} +
find "$ROOT_DIR" -xdev -type f -exec chmod go-w {} +
