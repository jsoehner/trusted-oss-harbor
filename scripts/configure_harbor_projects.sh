#!/usr/bin/env bash
# ==============================================================================
# Configure Harbor Registry Endpoints & Proxy Cache Projects for Chainguard
# Registers https://cgr.dev as a Harbor upstream endpoint and provisions the
# 'chainguard-cache' Proxy Cache project for cgr.dev/chainguard/jre & python.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env"
else
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env.example"
fi

HARBOR_API_URL="${HARBOR_API_URL:-https://${HARBOR_DOMAIN}/api/v2.0}"
DRY_RUN="false"

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="true"
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Would register upstream endpoint 'chainguard-cgr' (https://cgr.dev) at ${HARBOR_API_URL}/registries"
  echo "[DRY-RUN] Would create Harbor Proxy Cache project 'chainguard-cache' with auto_scan=true"
  echo "[DRY-RUN] Cached images available at:"
  echo "  - ${HARBOR_DOMAIN}/chainguard-cache/chainguard/jre:latest"
  echo "  - ${HARBOR_DOMAIN}/chainguard-cache/chainguard/python:latest"
  exit 0
fi

echo "[INFO] Registering Chainguard (https://cgr.dev) upstream registry in Harbor..."
curl -fsSL -u "admin:${HARBOR_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -X POST "${HARBOR_API_URL}/registries" \
  -d '{
    "name": "chainguard-cgr",
    "type": "docker-registry",
    "url": "https://cgr.dev",
    "description": "Chainguard Zero-CVE Container Registry (cgr.dev)",
    "insecure": false
  }' || true

REGISTRY_ID="$(curl -fsSL -u "admin:${HARBOR_ADMIN_PASSWORD}" \
  "${HARBOR_API_URL}/registries?q=name%3D~chainguard-cgr" \
  | python3 -c "import sys, json; data = json.load(sys.stdin); print(data[0]['id'])")"

echo "[INFO] Creating 'chainguard-cache' Proxy Cache project (registry_id=${REGISTRY_ID})..."
curl -fsSL -u "admin:${HARBOR_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -X POST "${HARBOR_API_URL}/projects" \
  -d "{
    \"project_name\": \"chainguard-cache\",
    \"registry_id\": ${REGISTRY_ID},
    \"public\": false,
    \"metadata\": {
      \"auto_scan\": \"true\",
      \"enable_content_trust_cosign\": \"true\",
      \"prevent_vul\": \"true\",
      \"severity\": \"high\"
    }
  }" || true

echo "[OK] Harbor 'chainguard-cache' Proxy Cache configured for cgr.dev/chainguard/jre and cgr.dev/chainguard/python."
