# ==============================================================================
# Trusted OSS Gatekeeper - Chainguard/Wolfi Zero-CVE Multi-Stage Image
# ==============================================================================
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apk add --no-cache \
    python-3.13 \
    py3.13-pip

WORKDIR /build
COPY requirements.txt /build/requirements.txt

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r /build/requirements.txt

# ------------------------------------------------------------------------------
# Minimal Non-Root Runtime Stage
# ------------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

RUN apk add --no-cache \
    ca-certificates \
    curl \
    gpg \
    gpg-agent \
    python-3.13 && \
    addgroup -g 10001 -S gatekeeper && \
    adduser -u 10001 -S -G gatekeeper -h /home/gatekeeper -s /sbin/nologin gatekeeper

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app /app/app

USER gatekeeper

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
