#!/usr/bin/env bash
# ==============================================================================
# Bootstrap Host Persistent Storage, NVD Cache, and Harbor Configuration
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

OSS_DATA_ROOT="${OSS_DATA_ROOT:-/home/jsoehner/trusted-oss-data}"
HARBOR_VERSION="${HARBOR_VERSION:-v2.12.2}"
NVD_CACHE_RELEASE_URL="${NVD_CACHE_RELEASE_URL:-https://github.com/jsoehner/nvd-cache/releases/download/latest-nvd-data/odc.mv.db.zip}"

init_storage() {
  echo "[INFO] Initializing persistent storage hierarchy at ${OSS_DATA_ROOT}..."
  mkdir -p \
    "${OSS_DATA_ROOT}/harbor/registry" \
    "${OSS_DATA_ROOT}/harbor/database" \
    "${OSS_DATA_ROOT}/harbor/redis" \
    "${OSS_DATA_ROOT}/harbor/job_logs" \
    "${OSS_DATA_ROOT}/harbor/secret/cert" \
    "${OSS_DATA_ROOT}/packages/quarantine" \
    "${OSS_DATA_ROOT}/packages/trusted-maven" \
    "${OSS_DATA_ROOT}/packages/trusted-pypi" \
    "${OSS_DATA_ROOT}/scanners/clamav" \
    "${OSS_DATA_ROOT}/scanners/trivy" \
    "${OSS_DATA_ROOT}/scanners/nvd-cache/11.0" \
    "${OSS_DATA_ROOT}/keys/gnupg" \
    "${OSS_DATA_ROOT}/keys/cosign" \
    "${OSS_DATA_ROOT}/keys/public" \
    "${OSS_DATA_ROOT}/audit"

  chmod 0700 "${OSS_DATA_ROOT}/keys/gnupg" "${OSS_DATA_ROOT}/keys/cosign"
  echo "[OK] Storage hierarchy ready at ${OSS_DATA_ROOT}"
}

sync_nvd() {
  echo "[INFO] Seeding OWASP NVD database from ${NVD_CACHE_RELEASE_URL}..."
  local tmp_zip
  tmp_zip="$(mktemp /tmp/odc.mv.db.XXXXXX.zip)"
  trap 'rm -f "${tmp_zip}"' RETURN
  curl -fsSL -o "${tmp_zip}" "${NVD_CACHE_RELEASE_URL}"
  unzip -q -o "${tmp_zip}" -d "${OSS_DATA_ROOT}/scanners/nvd-cache/11.0/"
  cp -f "${OSS_DATA_ROOT}/scanners/nvd-cache/11.0/odc.mv.db" "${OSS_DATA_ROOT}/scanners/nvd-cache/odc.mv.db"
  echo "[OK] Seeded NVD H2 database into ${OSS_DATA_ROOT}/scanners/nvd-cache"
}

render_harbor_config() {
  echo "[INFO] Rendering config/harbor/harbor.yml from template..."
  sed \
    -e "s|\${HARBOR_DOMAIN}|${HARBOR_DOMAIN}|g" \
    -e "s|\${OSS_DATA_ROOT}|${OSS_DATA_ROOT}|g" \
    -e "s|\${HARBOR_ADMIN_PASSWORD}|${HARBOR_ADMIN_PASSWORD}|g" \
    -e "s|\${HARBOR_DB_PASSWORD}|${HARBOR_DB_PASSWORD}|g" \
    "${PROJECT_ROOT}/config/harbor/harbor.yml.tmpl" > "${PROJECT_ROOT}/config/harbor/harbor.yml"
  chmod 0600 "${PROJECT_ROOT}/config/harbor/harbor.yml"
  echo "[OK] Wrote ${PROJECT_ROOT}/config/harbor/harbor.yml"
}

download_harbor_installer() {
  local installer_dir="${PROJECT_ROOT}/harbor-installer"
  mkdir -p "${installer_dir}"
  local tarball="${installer_dir}/harbor-online-installer-${HARBOR_VERSION}.tgz"
  if [[ ! -f "${tarball}" ]]; then
    echo "[INFO] Downloading Harbor online installer (${HARBOR_VERSION})..."
    curl -fsSL -o "${tarball}" \
      "https://github.com/goharbor/harbor/releases/download/${HARBOR_VERSION}/harbor-online-installer-${HARBOR_VERSION}.tgz"
  fi
  tar -xzf "${tarball}" -C "${installer_dir}"
  cp -f "${PROJECT_ROOT}/config/harbor/harbor.yml" "${installer_dir}/harbor/harbor.yml"
  echo "[OK] Harbor installer prepared in ${installer_dir}/harbor"
}

case "${1:-}" in
  --init-storage-only)
    init_storage
    ;;
  --sync-nvd-only)
    init_storage
    sync_nvd
    ;;
  *)
    init_storage
    sync_nvd
    render_harbor_config
    download_harbor_installer
    ;;
esac
