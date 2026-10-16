#!/usr/bin/env bash
# ==============================================================================
# Generate Trusted OSS GPG Signing Keypair & Cosign Keypair
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
GNUPGHOME="${OSS_DATA_ROOT}/keys/gnupg"
PUBLIC_KEYS_DIR="${OSS_DATA_ROOT}/keys/public"
GPG_KEY_NAME="${GPG_KEY_NAME:-Trusted OSS Supply Chain Authority}"
GPG_KEY_EMAIL="${GPG_KEY_EMAIL:-oss-signing@example.com}"

mkdir -p "${GNUPGHOME}" "${PUBLIC_KEYS_DIR}" "${OSS_DATA_ROOT}/keys/cosign"
chmod 0700 "${GNUPGHOME}" "${OSS_DATA_ROOT}/keys/cosign"
export GNUPGHOME

if ! gpg --batch --list-secret-keys --with-colons | grep -q "^sec:"; then
  echo "[INFO] Generating RSA-3072 GPG Signing Key for ${GPG_KEY_NAME} <${GPG_KEY_EMAIL}>..."
  gpg --batch --generate-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: ${GPG_KEY_NAME}
Name-Email: ${GPG_KEY_EMAIL}
Expire-Date: 2y
%commit
EOF
fi

gpg --batch --armor --export "${GPG_KEY_EMAIL}" > "${PUBLIC_KEYS_DIR}/trusted-oss-pubkey.asc"
FINGERPRINT="$(gpg --batch --with-colons --fingerprint "${GPG_KEY_EMAIL}" | awk -F: '/^fpr:/ {print $10; exit}')"
echo "${FINGERPRINT}" > "${PUBLIC_KEYS_DIR}/trusted-oss-pubkey.fingerprint"

echo "[OK] Exported GPG Public Key to ${PUBLIC_KEYS_DIR}/trusted-oss-pubkey.asc"
echo "[OK] GPG Key Fingerprint: ${FINGERPRINT}"
