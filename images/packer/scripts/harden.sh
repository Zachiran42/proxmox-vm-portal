#!/bin/bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre execute par sudo." >&2
    exit 1
fi
if [[ ! ${BUILD_USERNAME:-} =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || [[ $BUILD_USERNAME == root || $BUILD_USERNAME == admin ]]; then
    echo "Compte de construction invalide." >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y full-upgrade
apt-get install -y --no-install-recommends cloud-init cloud-initramfs-growroot qemu-guest-agent sudo ca-certificates

install -d -m 0755 /etc/ssh/sshd_config.d /etc/cloud/cloud.cfg.d
printf '%s\n' \
    'PermitRootLogin no' \
    'PermitEmptyPasswords no' \
    'PasswordAuthentication yes' \
    'KbdInteractiveAuthentication no' \
    > /etc/ssh/sshd_config.d/90-portal-template.conf
printf '%s\n' \
    'disable_root: true' \
    'ssh_pwauth: true' \
    'chpasswd:' \
    '  expire: true' \
    > /etc/cloud/cloud.cfg.d/90-portal-security.cfg

sshd -t
systemctl enable qemu-guest-agent

rm -f "/etc/sudoers.d/99-packer-build"
passwd --lock "$BUILD_USERNAME"
usermod --shell /usr/sbin/nologin "$BUILD_USERNAME"
chage --expiredate 1 "$BUILD_USERNAME"
rm -rf "/home/$BUILD_USERNAME/.ssh"

cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
find /var/log -type f -exec truncate -s 0 {} \;
sync
