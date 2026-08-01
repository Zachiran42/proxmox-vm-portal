#!/bin/sh
set -eu

# Adaptateur exclusivement destiné au conteneur Debian de test sans systemd.
case " $* " in
    *" enable --now docker "*)
        # VFS is limited to this nested-Docker harness: overlay2 cannot be
        # mounted on top of the validation container's overlay filesystem.
        nohup dockerd --storage-driver=vfs --host=unix:///var/run/docker.sock >/var/log/dockerd-test.log 2>&1 &
        attempts=0
        until docker info >/dev/null 2>&1; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 60 ]; then
                cat /var/log/dockerd-test.log >&2
                exit 1
            fi
            sleep 1
        done
        ;;
esac
