# ==============================================================================
# Trusted OSS Supply Chain Platform - Chainguard/Wolfi Zero-CVE NAS Appliance
# Combines:
#   1. Nginx Gateway (Port 8080)
#   2. ClamAV Antivirus Daemon (clamd + freshclam on port 3310)
#   3. Trusted OSS Gatekeeper (FastAPI on port 8000, Python 3.13)
#   4. Dual Cryptographic Signer (RSA-3072 GPG + NIST FIPS 204 ML-DSA-65 PQC)
# ==============================================================================
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apk add --no-cache \
    python-3.13 \
    py3.13-pip

WORKDIR /build
COPY gatekeeper/requirements.txt /build/requirements.txt

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r /build/requirements.txt

# ------------------------------------------------------------------------------
# Minimal Zero-CVE Runtime Stage (No pip, compilers, or build tooling)
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest

LABEL org.opencontainers.image.title="Trusted OSS Harbor NAS Appliance" \
      org.opencontainers.image.description="Zero-CVE Chainguard/Wolfi all-in-one Trusted OSS Supply Chain Gatekeeper, ClamAV Antivirus, and PQC Signer" \
      org.opencontainers.image.source="https://github.com/jsoehner/trusted-oss-harbor" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    OSS_DATA_ROOT=/data \
    CLAMAV_HOST=127.0.0.1 \
    CLAMAV_PORT=3310 \
    CVSS_FAIL_THRESHOLD=7.0 \
    AUTO_PROMOTE_CLEAN_ARTIFACTS=true \
    PQC_SIGNING_ENABLED=true

# 1. Install minimal runtime packages from Chainguard Wolfi
RUN apk add --no-cache \
    bash \
    ca-certificates \
    clamav-1.5 \
    curl \
    gpg \
    gpg-agent \
    nginx-stable \
    python-3.13 \
    supervisor

# 2. Create service users and runtime directories
RUN addgroup -g 10001 -S gatekeeper && \
    adduser -u 10001 -S -G gatekeeper -h /home/gatekeeper -s /sbin/nologin gatekeeper && \
    addgroup -S clamav && \
    adduser -S -G clamav -H -s /sbin/nologin clamav && \
    addgroup -S nginx && \
    adduser -S -G nginx -H -s /sbin/nologin nginx && \
    mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav /var/log/supervisor /var/lib/nginx/tmp /run/nginx /etc/nginx/conf.d /data && \
    chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav && \
    chown -R gatekeeper:gatekeeper /data

# 3. Copy prebuilt Python 3.13 virtual environment
COPY --from=builder /opt/venv /opt/venv

# 4. Configure Nginx (main config includes conf.d/*.conf)
RUN printf 'worker_processes auto;\nerror_log stderr notice;\npid /run/nginx/nginx.pid;\nevents {\n    worker_connections 1024;\n}\nhttp {\n    include /etc/nginx/mime.types;\n    default_type application/octet-stream;\n    sendfile on;\n    keepalive_timeout 65;\n    access_log /dev/stdout;\n    include /etc/nginx/conf.d/*.conf;\n}\n' > /etc/nginx/nginx.conf
COPY config/nginx/appliance-gateway.conf /etc/nginx/conf.d/default.conf

# 5. Configure ClamAV & Freshclam
COPY config/clamav/clamd.conf /etc/clamav/clamd.conf
COPY config/clamav/freshclam.conf /etc/clamav/freshclam.conf

# 6. Copy Gatekeeper Application Code & Catalogs
WORKDIR /app
COPY gatekeeper/app /app/app
COPY config/catalog /app/config/catalog
COPY config/catalog /config/catalog

# 7. Configure Supervisord & Entrypoint
COPY config/supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY scripts/nas_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 8. Persistent storage volume, healthcheck, and exposed gateway port
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
