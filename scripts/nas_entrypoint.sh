#!/usr/bin/env bash
# ==============================================================================
# Trusted OSS NAS Appliance Container Entrypoint
# ==============================================================================
set -euo pipefail

OSS_DATA_ROOT="${OSS_DATA_ROOT:-/data}"

echo "[NAS-APPLIANCE] ========================================================"
echo "[NAS-APPLIANCE] Starting Trusted OSS Supply Chain Appliance"
echo "[NAS-APPLIANCE] Data Root: ${OSS_DATA_ROOT}"
echo "[NAS-APPLIANCE] ========================================================"

# 1. Initialize persistent storage hierarchy under OSS_DATA_ROOT
mkdir -p \
  "${OSS_DATA_ROOT}/packages/quarantine" \
  "${OSS_DATA_ROOT}/packages/trusted-maven" \
  "${OSS_DATA_ROOT}/packages/trusted-pypi" \
  "${OSS_DATA_ROOT}/scanners/clamav" \
  "${OSS_DATA_ROOT}/keys/gnupg" \
  "${OSS_DATA_ROOT}/keys/mldsa" \
  "${OSS_DATA_ROOT}/keys/public" \
  "${OSS_DATA_ROOT}/keys/cosign" \
  "${OSS_DATA_ROOT}/audit" \
  /var/log/supervisor \
  /var/run/clamav \
  /var/log/clamav

# 2. Enforce strict permissions on private key directories
chmod 0700 \
  "${OSS_DATA_ROOT}/keys/gnupg" \
  "${OSS_DATA_ROOT}/keys/mldsa" \
  "${OSS_DATA_ROOT}/keys/cosign" 2>/dev/null || true

# 3. ClamAV runtime permissions & persistence symlink
chown -R clamav:clamav /var/run/clamav /var/log/clamav 2>/dev/null || true

if [[ ! -L /var/lib/clamav ]]; then
  if [[ -d /var/lib/clamav ]] && [[ ! -e "${OSS_DATA_ROOT}/scanners/clamav/main.cvd" ]]; then
    cp -rn /var/lib/clamav/* "${OSS_DATA_ROOT}/scanners/clamav/" 2>/dev/null || true
  fi
  rm -rf /var/lib/clamav
  ln -sf "${OSS_DATA_ROOT}/scanners/clamav" /var/lib/clamav
fi
chown -R clamav:clamav "${OSS_DATA_ROOT}/scanners/clamav" /var/lib/clamav 2>/dev/null || true

# 4. Check for existing ClamAV definitions; run initial freshclam if starting supervisor and completely unseeded
if [[ "${1:-}" == *"supervisord"* ]]; then
  HAS_CLAM_DB=false
  for dbfile in "${OSS_DATA_ROOT}/scanners/clamav"/*.{cvd,cld}; do
    if [[ -f "${dbfile}" ]]; then
      HAS_CLAM_DB=true
      break
    fi
  done

  if [[ "${HAS_CLAM_DB}" == "false" ]]; then
    echo "[NAS-APPLIANCE] No virus definitions found in ${OSS_DATA_ROOT}/scanners/clamav."
    echo "[NAS-APPLIANCE] Attempting initial database sync via freshclam..."
    freshclam --stdout || echo "[NAS-APPLIANCE] Notice: initial freshclam sync returned non-zero, freshclam daemon will retry in background."
  fi
fi

# 5. Export environment variables for child processes
export PYTHONPATH="/app:${PYTHONPATH:-}"
export OSS_DATA_ROOT="${OSS_DATA_ROOT}"
export GNUPGHOME="${GNUPGHOME:-${OSS_DATA_ROOT}/keys/gnupg}"
export COSIGN_PRIVATE_KEY_PATH="${COSIGN_PRIVATE_KEY_PATH:-${OSS_DATA_ROOT}/keys/cosign/cosign.key}"
export COSIGN_PUBLIC_KEY_PATH="${COSIGN_PUBLIC_KEY_PATH:-${OSS_DATA_ROOT}/keys/cosign/cosign.pub}"
export CLAMAV_HOST="${CLAMAV_HOST:-127.0.0.1}"
export CLAMAV_PORT="${CLAMAV_PORT:-3310}"

echo "[NAS-APPLIANCE] Storage and daemon prerequisites verified. Executing supervisor..."
exec "$@"
