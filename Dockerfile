FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS runtime

ARG PORTAL_VERSION=dev
ARG PORTAL_VCS_REF=unknown
ARG PORTAL_SOURCE=https://github.com/hugofelix088-spec/proxmox-vm-portal

LABEL org.opencontainers.image.source="$PORTAL_SOURCE" \
      org.opencontainers.image.description="Secure self-hosted Proxmox VM provisioning portal" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="$PORTAL_VERSION" \
      org.opencontainers.image.revision="$PORTAL_VCS_REF"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORTAL_SESSION_COOKIE_SECURE=true

RUN addgroup -S -g 10001 portal \
    && adduser -S -D -H -u 10001 -G portal -s /sbin/nologin portal

WORKDIR /app
COPY pyproject.toml requirements.lock README.md ./
COPY portal ./portal
COPY migrations ./migrations
RUN pip install --disable-pip-version-check --require-hashes -r requirements.lock \
    && pip install --disable-pip-version-check --no-deps .

USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=4", "--timeout=60", "--access-logfile=-", "--error-logfile=-", "portal:create_app()"]
