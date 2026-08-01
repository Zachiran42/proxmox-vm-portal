FROM python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS runtime

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
