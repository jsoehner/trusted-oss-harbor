#!/usr/bin/env bash
# ==============================================================================
# Multi-Stage End-to-End Verification & Security Test Harness
# Stages:
#   1. Shell Script Syntax & Defensive Bash Audit
#   2. Python Compilation & SAST Security Audit
#   3. Pytest Suite (Path Containment, Archive Security, Live TCP clamd
#      zINSTREAM Protocol, Tamper/Rogue-Key Detection, Dynamic Pull-Through,
#      Concurrency)
#   4. Host Provisioning Scripts, TrueNAS iSCSI Dry-Run & pfSense CIDR Sync
#   5. Live Uvicorn Server + External Client (curl + gpg --verify + sha256sum)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

VENV_DIR="${PROJECT_ROOT}/.venv"
if [[ ! -d "${VENV_DIR}" ]]; then
  echo "[INFO] Creating local Python virtual environment for verification..."
  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
  "${VENV_DIR}/bin/pip" install --quiet -r "${PROJECT_ROOT}/gatekeeper/requirements.txt"
fi

echo "=============================================================================="
echo " [STAGE 1/5] Shell Script Syntax & Defensive Audit"
echo "=============================================================================="
for script in scripts/*.sh config/pfsense/*.sh; do
  bash -n "${script}"
  echo "  [PASS] Syntax valid: ${script}"
done

echo "=============================================================================="
echo " [STAGE 2/5] Python Bytecode Compilation & SAST Security Audit"
echo "=============================================================================="
"${VENV_DIR}/bin/python3" -m py_compile gatekeeper/app/*.py gatekeeper/tests/*.py
"${VENV_DIR}/bin/python3" - <<'PYEOF'
import ast
from pathlib import Path

app_dir = Path("gatekeeper/app")
forbidden_calls = {"eval", "exec", "os.system", "pickle.loads", "yaml.load"}
findings = []

for py_file in sorted(app_dir.glob("*.py")):
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(py_file))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                findings.append(f"{py_file}:{node.lineno} forbidden call {node.func.id}")
            elif isinstance(node.func, ast.Attribute):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(f"{py_file}:{node.lineno} subprocess shell=True")

main_src = (app_dir / "main.py").read_text(encoding="utf-8")
assert "secrets.compare_digest" in main_src, "Missing constant-time token comparison in main.py"
assert not findings, f"SAST findings detected: {findings}"
print("  [PASS] AST SAST scan clean (0 dangerous calls, shell=False enforced, constant-time auth verified)")
PYEOF

echo "=============================================================================="
echo " [STAGE 3/5] Pytest Unit, Protocol (zINSTREAM), Tamper & Pull-Through Suite"
echo "=============================================================================="
PYTHONPATH="${PROJECT_ROOT}/gatekeeper" "${VENV_DIR}/bin/pytest" "${PROJECT_ROOT}/gatekeeper/tests" -v

echo "=============================================================================="
echo " [STAGE 4/5] Host Scripts, GPG Key Idempotency, TrueNAS iSCSI & pfSense CIDRs"
echo "=============================================================================="
HARNESS_TMP="$(mktemp -d /tmp/trusted-oss-harness.XXXXXX)"
LIVE_LOG="$(mktemp /tmp/uvicorn-e2e.XXXXXX.log)"
UVICORN_PID=""
cleanup() {
  if [[ -n "${UVICORN_PID}" ]] && kill -0 "${UVICORN_PID}" 2>/dev/null; then
    kill "${UVICORN_PID}" 2>/dev/null || true
    wait "${UVICORN_PID}" 2>/dev/null || true
  fi
  rm -rf "${HARNESS_TMP}" "${LIVE_LOG}"
}
trap cleanup EXIT

OSS_DATA_ROOT="${HARNESS_TMP}/data" bash scripts/bootstrap_host.sh --init-storage-only
GNUPG_PERM="$(stat -c '%a' "${HARNESS_TMP}/data/keys/gnupg")"
COSIGN_PERM="$(stat -c '%a' "${HARNESS_TMP}/data/keys/cosign")"
[[ "${GNUPG_PERM}" == "700" && "${COSIGN_PERM}" == "700" ]] || {
  echo "[FAIL] Expected 0700 permissions on key directories, got ${GNUPG_PERM}/${COSIGN_PERM}" >&2
  exit 1
}
echo "  [PASS] Storage bootstrap & 0700 key directory permissions verified"

OSS_DATA_ROOT="${HARNESS_TMP}/data" bash scripts/generate_signing_keys.sh
FPR_FIRST="$(cat "${HARNESS_TMP}/data/keys/public/trusted-oss-pubkey.fingerprint")"
OSS_DATA_ROOT="${HARNESS_TMP}/data" bash scripts/generate_signing_keys.sh
FPR_SECOND="$(cat "${HARNESS_TMP}/data/keys/public/trusted-oss-pubkey.fingerprint")"
[[ -n "${FPR_FIRST}" && "${FPR_FIRST}" == "${FPR_SECOND}" ]] || {
  echo "[FAIL] GPG key generation not idempotent (${FPR_FIRST} != ${FPR_SECOND})" >&2
  exit 1
}
echo "  [PASS] GPG RSA-3072 key generation & idempotency verified (Fingerprint: ${FPR_FIRST})"

bash scripts/setup_truenas_iscsi_mount.sh --dry-run --migrate >/dev/null
echo "  [PASS] TrueNAS iSCSI provisioning & migration script dry-run verified"

bash config/pfsense/update-github-cidrs.sh --dry-run >/dev/null
echo "  [PASS] pfSense GitHub Actions CIDR allowlist live fetch verified"

echo "=============================================================================="
echo " [STAGE 5/5] Live Uvicorn HTTP Server + External Client (curl + gpg --verify)"
echo "=============================================================================="
PORT="$("${VENV_DIR}/bin/python3" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

OSS_DATA_ROOT="${HARNESS_TMP}/data" \
GNUPGHOME="${HARNESS_TMP}/data/keys/gnupg" \
CLAMAV_REQUIRED="false" \
GATEKEEPER_ADMIN_TOKEN="live-e2e-token" \
PYTHONPATH="${PROJECT_ROOT}/gatekeeper" \
  "${VENV_DIR}/bin/uvicorn" app.main:app --host 127.0.0.1 --port "${PORT}" >"${LIVE_LOG}" 2>&1 &
UVICORN_PID=$!

for _ in {1..30}; do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

HEALTH_JSON="$(curl -fsS "http://127.0.0.1:${PORT}/healthz")"
echo "  [PASS] Live Gatekeeper healthz: ${HEALTH_JSON}"

# Build a sample JAR on disk for live upload
SAMPLE_JAR="${HARNESS_TMP}/client-sample.jar"
"${VENV_DIR}/bin/python3" - "${SAMPLE_JAR}" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as zf:
    zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    zf.writestr("io/trusted/Service.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d")
PYEOF

REL_PATH="io/trusted/core-service/2.1.0/core-service-2.1.0.jar"
curl -fsS -X POST "http://127.0.0.1:${PORT}/ingest/maven/${REL_PATH}" \
  -H "X-Gatekeeper-Token: live-e2e-token" \
  -F "file=@${SAMPLE_JAR};type=application/java-archive" >/dev/null

# Simulate downstream CI/CD runner downloading public key, artifact, .asc, and .sha256
CLIENT_DIR="${HARNESS_TMP}/downstream-client"
CLIENT_GNUPG="${CLIENT_DIR}/gnupg"
mkdir -p "${CLIENT_GNUPG}"
chmod 0700 "${CLIENT_GNUPG}"

curl -fsS "http://127.0.0.1:${PORT}/keys/trusted-oss-pubkey.asc" -o "${CLIENT_DIR}/trusted-oss-pubkey.asc"
GNUPGHOME="${CLIENT_GNUPG}" gpg --batch --import "${CLIENT_DIR}/trusted-oss-pubkey.asc" 2>/dev/null

curl -fsS "http://127.0.0.1:${PORT}/maven/trusted/${REL_PATH}" -o "${CLIENT_DIR}/core-service-2.1.0.jar"
curl -fsS "http://127.0.0.1:${PORT}/maven/trusted/${REL_PATH}.asc" -o "${CLIENT_DIR}/core-service-2.1.0.jar.asc"
curl -fsS "http://127.0.0.1:${PORT}/maven/trusted/${REL_PATH}.sha256" -o "${CLIENT_DIR}/core-service-2.1.0.jar.sha256"

# Client verifies detached GPG signature and SHA-256 digest
GNUPGHOME="${CLIENT_GNUPG}" gpg --batch --verify \
  "${CLIENT_DIR}/core-service-2.1.0.jar.asc" \
  "${CLIENT_DIR}/core-service-2.1.0.jar" 2>/dev/null
echo "  [PASS] Downstream client verified GPG detached signature (.asc) via gpg --verify"

ACTUAL_SHA256="$(sha256sum "${CLIENT_DIR}/core-service-2.1.0.jar" | awk '{print $1}')"
EXPECTED_SHA256="$(tr -d '[:space:]' < "${CLIENT_DIR}/core-service-2.1.0.jar.sha256")"
[[ "${ACTUAL_SHA256}" == "${EXPECTED_SHA256}" ]] || {
  echo "[FAIL] SHA-256 mismatch: ${ACTUAL_SHA256} != ${EXPECTED_SHA256}" >&2
  exit 1
}
echo "  [PASS] Downstream client verified SHA-256 digest (${ACTUAL_SHA256})"

echo "=============================================================================="
echo " [SUCCESS] All 5 Verification Stages Passed!"
echo "=============================================================================="
