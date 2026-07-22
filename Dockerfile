# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12.4

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --upgrade pip \
    && /opt/venv/bin/python -m pip install --requirement requirements.txt \
    && /opt/venv/bin/python -m pip uninstall --yes pip setuptools wheel jaraco.context

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG APP_UID=10001
ARG APP_GID=10001
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="NetSentinel" \
      org.opencontainers.image.description="Defensive network metadata monitoring and SOC investigation platform" \
      org.opencontainers.image.source="https://github.com/Adam-Ghanem/NetSentinel" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    HOME=/home/netsentinel

RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${APP_GID}" netsentinel \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin netsentinel \
    && install -d -o netsentinel -g netsentinel /app /data /app/reports

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=netsentinel:netsentinel app ./app
COPY --chown=netsentinel:netsentinel dashboard ./dashboard
COPY --chown=netsentinel:netsentinel rules ./rules
COPY --chown=netsentinel:netsentinel migrations ./migrations
COPY --chown=netsentinel:netsentinel scripts ./scripts
COPY --chown=netsentinel:netsentinel alembic.ini ./
COPY --chown=netsentinel:netsentinel assets ./assets

USER netsentinel:netsentinel

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3).read()"]

STOPSIGNAL SIGTERM

CMD ["streamlit", "run", "dashboard/streamlit_app.py"]
