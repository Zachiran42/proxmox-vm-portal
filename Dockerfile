FROM python:3.13.14-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORTAL_SESSION_COOKIE_SECURE=true

RUN groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --home-dir /app --shell /usr/sbin/nologin portal

WORKDIR /app
COPY pyproject.toml README.md ./
COPY portal ./portal
COPY migrations ./migrations
RUN pip install --disable-pip-version-check .

USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=4", "--timeout=60", "--access-logfile=-", "--error-logfile=-", "portal:create_app()"]
