#!/usr/bin/env bash
# ==============================================================================
# End-to-End Verification of Quarantine -> ClamAV -> CVE -> GPG Sign -> Serve
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"

if [[ ! -x "${VENV_DIR}/bin/pytest" ]]; then
  echo "[INFO] Creating local Python virtual environment in ${VENV_DIR}..."
  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
  "${VENV_DIR}/bin/pip" install --quiet -r "${PROJECT_ROOT}/gatekeeper/requirements.txt"
fi

echo "[INFO] Running automated Quarantine-Scan-Sign Gatekeeper test suite..."
PYTHONPATH="${PROJECT_ROOT}/gatekeeper" "${VENV_DIR}/bin/pytest" "${PROJECT_ROOT}/gatekeeper/tests" -v
echo "[OK] All Trusted OSS Supply Chain E2E verification checks passed."
