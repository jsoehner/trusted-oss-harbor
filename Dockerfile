# ==============================================================================
# Trusted OSS Supply Chain Platform - NAS Appliance Container
# Combines:
#   1. Nginx Gateway (Port 8080)
#   2. ClamAV Antivirus Daemon (clamd + freshclam on port 3310)
#   3. Trusted OSS Gatekeeper (FastAPI on port 8000)
#   4. Dual Cryptographic Signer (RSA-3072 GPG + NIST FIPS 204 ML-DSA-65 PQC)
# ==============================================================================
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="Trusted OSS Harbor NAS Appliance" \
      org.opencontainers.image.description="All-in-one Trusted OSS Supply Chain Gatekeeper, ClamAV Antivirus, and PQC Signer for NAS and homelabs" \
      org.opencontainers.image.source="https://github.com/jsoehner/trusted-oss-harbor" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OSS_DATA_ROOT=/data \
    CLAMAV_HOST=127.0.0.1 \
    CLAMAV_PORT=3310 \
    CVSS_FAIL_THRESHOLD=7.0 \
    AUTO_PROMOTE_CLEAN_ARTIFACTS=true \
    PQC_SIGNING_ENABLED=true

# 1. Install system runtime prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    curl \
    gnupg \
    nginx \
    procps \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# 2. Configure Nginx (Remove default Debian sites and load appliance gateway)
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default /etc/nginx/conf.d/*
COPY config/nginx/appliance-gateway.conf /etc/nginx/conf.d/default.conf

# 3. Configure ClamAV & Freshclam
COPY config/clamav/clamd.conf /etc/clamav/clamd.conf
COPY config/clamav/freshclam.conf /etc/clamav/freshclam.conf

# Ensure runtime directories exist
RUN mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav /var/log/supervisor /data && \
    chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav

# 4. Install Python Gatekeeper Dependencies
WORKDIR /app
COPY gatekeeper/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 5. Copy Gatekeeper Application Code & Catalogs
COPY gatekeeper/app /app/app
COPY config/catalog /app/config/catalog
COPY config/catalog /config/catalog

# 6. Configure Supervisord & Entrypoint
COPY config/supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY scripts/nas_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 7. Persistent storage volume and exposed gateway port
VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
