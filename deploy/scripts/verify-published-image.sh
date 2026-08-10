#!/bin/bash
set -Eeuo pipefail

COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "Usage: $0 IMAGE@sha256:DIGEST vVERSION OWNER/REPOSITORY [private|public]" >&2
    exit 1
fi

portal_image=$1
release_tag=$2
repository=$3
transparency=${4:-private}
repository_lower=${repository,,}

[[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
    echo "PORTAL_RELEASE_REPOSITORY doit avoir la forme propriétaire/dépôt." >&2
    exit 1
}
[[ $release_tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] || {
    echo "PORTAL_RELEASE_TAG doit être un tag SemVer commençant par v." >&2
    exit 1
}
[[ $portal_image =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$ ]] || {
    echo "PORTAL_IMAGE doit être une image GHCR épinglée par digest sha256." >&2
    exit 1
}
[[ $portal_image == "ghcr.io/${repository_lower}@sha256:"* ]] || {
    echo "PORTAL_IMAGE ne correspond pas à PORTAL_RELEASE_REPOSITORY." >&2
    exit 1
}
[[ $transparency == private || $transparency == public ]] || {
    echo "PORTAL_RELEASE_TRANSPARENCY doit valoir private ou public." >&2
    exit 1
}

identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${release_tag}"
docker_args=(
    run --rm --read-only --user 0:0 --cap-drop ALL
    --security-opt no-new-privileges:true --tmpfs "/tmp:size=32m,mode=1777"
    --env HOME=/tmp/cosign-home
)
docker_config_dir=${PORTAL_DOCKER_CONFIG_DIR:-/root/.docker}
if [[ -f $docker_config_dir/config.json ]]; then
    docker_args+=(--env DOCKER_CONFIG=/docker-config --volume "$docker_config_dir:/docker-config:ro")
fi

verify_args=(
    verify
    --certificate-identity "$identity"
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
    --use-signed-timestamps
)
if [[ $transparency == private ]]; then
    verify_args+=(--insecure-ignore-tlog=true)
fi
verify_args+=("$portal_image")

docker "${docker_args[@]}" "$COSIGN_IMAGE" "${verify_args[@]}" >/dev/null
echo "Signature vérifiée pour $portal_image avec l'identité $identity."
