# syntax=docker/dockerfile:1.7
# ---------- Étape 1 : construction des dépendances ----------
FROM python:3.12-slim-trixie AS builder 

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-compile -r requirements.txt

# ---------- Étape 2 : image d'exécution minimale ----------
FROM python:3.12-slim-trixie AS runtime 

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libzstd1=1.5.7+dfsg-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="passcheck" \
      org.opencontainers.image.description="Verificateur de mots de passe - Challenge DevSecOps"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DB_PATH=/data/app.db

# Utilisateur non-root dédié, sans shell de connexion
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data && chown app:app /data

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
# Code appartenant à root : l'utilisateur applicatif ne peut pas le modifier
COPY --chown=root:root app/ ./app/

USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]

# Gunicorn (serveur WSGI de production) au lieu du serveur de développement Flask
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "2", \
     "--timeout", "30", "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", "--forwarded-allow-ips", "*", \
     "--no-control-socket", "app.main:create_app()"]