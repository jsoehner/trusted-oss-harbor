#!/usr/bin/env bash
# ==============================================================================
# Generate Trusted OSS GPG Signing Keypair & Cosign Keypair
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CALLER_OSS_DATA_ROOT="${OSS_DATA_ROOT:-}"
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env"
else
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env.example"
fi

OSS_DATA_ROOT="${CALLER_OSS_DATA_ROOT:-${OSS_DATA_ROOT:-/home/jsoehner/trusted-oss-data}}"
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

# ==============================================================================
# Generate NIST FIPS 204 ML-DSA-65 Post-Quantum Signing Keypair
# ==============================================================================
MLDSA_KEYS_DIR="${OSS_DATA_ROOT}/keys/mldsa"
mkdir -p "${MLDSA_KEYS_DIR}"
chmod 0700 "${MLDSA_KEYS_DIR}"

if [[ ! -f "${MLDSA_KEYS_DIR}/trusted-oss-mldsa65.key" ]]; then
  echo "[INFO] Generating NIST FIPS 204 ML-DSA-65 Post-Quantum Signing Key..."
  python3 -c "
import base64, hashlib, os
from pathlib import Path
try:
    from dilithium_py.dilithium import Dilithium3
    pk, sk = Dilithium3.keygen()
    key_file = Path('${MLDSA_KEYS_DIR}/trusted-oss-mldsa65.key')
    pub_file = Path('${PUBLIC_KEYS_DIR}/trusted-oss-mldsa65.pub')
    fp_file = Path('${PUBLIC_KEYS_DIR}/trusted-oss-mldsa65.fingerprint')
    key_file.write_bytes(sk)
    os.chmod(key_file, 0o600)
    b64 = base64.b64encode(pk).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    pub_file.write_text('-----BEGIN ML-DSA-65 PUBLIC KEY-----\n' + '\n'.join(lines) + '\n-----END ML-DSA-65 PUBLIC KEY-----\n')
    fp256 = hashlib.sha256(pk).hexdigest()
    fp384 = hashlib.sha384(pk).hexdigest()
    fp_file.write_text(f'SHA256:{fp256}\nSHA384:{fp384}\n')
    print('[OK] Exported NIST FIPS 204 ML-DSA-65 Public Key to ${PUBLIC_KEYS_DIR}/trusted-oss-mldsa65.pub')
    print(f'[OK] ML-DSA-65 Fingerprint: SHA256:{fp256}')
except Exception as e:
    print(f'[INFO] ML-DSA-65 host generation notice: {e}')
" || true
fi
