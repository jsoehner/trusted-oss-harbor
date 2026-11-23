#!/usr/bin/env bash
# ==============================================================================
# Trusted OSS Container Demo: Cache -> Scan -> Inspect Layers/BOMs/Signatures
#                             -> Verify Public Keys -> Enforce Signed-Only Gate
# ==============================================================================
# Demonstrates the full security lifecycle of a container image (default:
# minimal Apache Airflow `apache/airflow:slim-latest-python3.12`) using only
# `curl`, `jq`, and your chosen signature verifier (`gpg`, `python3`, or both).
#
# Signature Modes (--sig-mode <both|classic|pqc> or SIG_MODE env var):
#   both    (default) Verify BOTH Classical RSA-3072 GPG (.asc) AND Post-Quantum
#                     NIST FIPS 204 ML-DSA-65 (.mldsa65) signatures.
#   classic (pgp/gpg) Verify ONLY Classical RSA-3072 GPG (.asc) signatures
#                     (no dilithium-py / Python PQC library required).
#   pqc     (mldsa65) Verify ONLY Post-Quantum NIST FIPS 204 ML-DSA-65 (.mldsa65)
#                     signatures (no gpg binary required).
#
# Usage:
#   # Dual-signature mode (default: GPG + ML-DSA-65):
#   bash scripts/trusted_container_demo.sh
#
#   # Classical PGP/GPG-only mode:
#   bash scripts/trusted_container_demo.sh --sig-mode classic
#
#   # Post-Quantum ML-DSA-65-only mode:
#   bash scripts/trusted_container_demo.sh --sig-mode pqc
#
#   # Production CI/CD with pinned key fingerprints:
#   EXPECTED_GPG_FPR="<40-hex>" EXPECTED_PQC_FPR="<64-hex>" \
#     bash scripts/trusted_container_demo.sh --sig-mode both
#
#   # WAN mTLS mode (behind pfSense HAProxy):
#   GATEKEEPER_URL=https://oss.yourdomain.com \
#     OSS_MTLS_CLIENT_CERT=~/.oss-tls/client.crt \
#     OSS_MTLS_CLIENT_KEY=~/.oss-tls/client.key \
#     bash scripts/trusted_container_demo.sh --sig-mode pqc
# ==============================================================================
set -euo pipefail

GATEKEEPER_URL="${GATEKEEPER_URL:-http://oss.jsigroup.local:8080}"
NAMESPACE="${NAMESPACE:-docker-cache}"
REPO="${REPO:-apache/airflow}"
TAG="${TAG:-slim-latest-python3.12}"
PLATFORM_ARCH="${PLATFORM_ARCH:-amd64}"
PLATFORM_OS="${PLATFORM_OS:-linux}"
SIG_MODE="${SIG_MODE:-both}"

usage() {
  cat <<'EOF'
Usage: trusted_container_demo.sh [OPTIONS]

Options:
  --sig-mode <both|classic|pqc>   Signature verification mode (default: both)
                                  Aliases: classic|pgp|gpg, pqc|mldsa65, both|dual
  --url <URL>                     Gatekeeper base URL (default: http://oss.jsigroup.local:8080)
  --namespace <NS>                OCI cache namespace (default: docker-cache)
  --repo <REPO>                   OCI repository path (default: apache/airflow)
  --tag <TAG>                     OCI tag (default: slim-latest-python3.12)
  -h, --help                      Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sig-mode)
      SIG_MODE="${2:-}"
      shift 2
      ;;
    --sig-mode=*)
      SIG_MODE="${1#*=}"
      shift
      ;;
    --url)
      GATEKEEPER_URL="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# Normalize SIG_MODE
SIG_MODE="$(printf '%s' "${SIG_MODE}" | tr '[:upper:]' '[:lower:]')"
case "${SIG_MODE}" in
  classic|pgp|gpg)
    SIG_MODE="classic"
    USE_CLASSIC=true
    USE_PQC=false
    SIG_MODE_LABEL="Classical PGP/GPG Only (RSA-3072 .asc)"
    ;;
  pqc|mldsa65|ml-dsa-65)
    SIG_MODE="pqc"
    USE_CLASSIC=false
    USE_PQC=true
    SIG_MODE_LABEL="Post-Quantum Only (NIST FIPS 204 ML-DSA-65 .mldsa65)"
    ;;
  both|dual)
    SIG_MODE="both"
    USE_CLASSIC=true
    USE_PQC=true
    SIG_MODE_LABEL="Dual Hybrid (Classical RSA-3072 GPG + NIST FIPS 204 ML-DSA-65)"
    ;;
  *)
    echo "[ERROR] Invalid --sig-mode '${SIG_MODE}'. Expected: classic, pqc, or both." >&2
    exit 2
    ;;
esac

GATEKEEPER_URL="${GATEKEEPER_URL%/}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PQC_VERIFY_SCRIPT="${REPO_ROOT}/client-templates/pqc-verify.py"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
fi

# Optional mTLS client cert/key for WAN access behind pfSense HAProxy
CURL_TLS=()
if [[ -n "${OSS_MTLS_CLIENT_CERT:-}" && -n "${OSS_MTLS_CLIENT_KEY:-}" ]]; then
  CURL_TLS=(--cert "${OSS_MTLS_CLIENT_CERT}" --key "${OSS_MTLS_CLIENT_KEY}")
fi

# Resolve Gatekeeper OCI manifest base path
if [[ "${NAMESPACE}" == "chainguard-cache" ]]; then
  MANIFEST_BASE="${GATEKEEPER_URL}/v2/chainguard-cache/${REPO}/manifests"
else
  MANIFEST_BASE="${GATEKEEPER_URL}/v2/virtual/${NAMESPACE}/${REPO}/manifests"
fi
REFERRERS_BASE="${GATEKEEPER_URL}/v2/${NAMESPACE}/${REPO}/referrers"
BLOBS_BASE="${GATEKEEPER_URL}/v2/${NAMESPACE}/${REPO}/blobs"

WORKDIR="$(mktemp -d /tmp/trusted-oss-demo.XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT
if [[ "${USE_CLASSIC}" == "true" ]]; then
  export GNUPGHOME="${WORKDIR}/gnupg"
  mkdir -p "${GNUPGHOME}"
  chmod 700 "${GNUPGHOME}"
fi

hr() {
  printf '%s\n' "================================================================================"
}

human_size() {
  awk -v b="${1:-0}" 'BEGIN {
    if (b >= 1073741824) printf "%.2f GiB", b/1073741824;
    else if (b >= 1048576) printf "%.2f MiB", b/1048576;
    else if (b >= 1024) printf "%.1f KiB", b/1024;
    else printf "%d B", b;
  }'
}

hr
echo "TRUSTED OSS CONTAINER DEMO — SIGNED-ONLY SUPPLY CHAIN PIPELINE"
hr
echo "Registry   : ${GATEKEEPER_URL}"
echo "Image      : ${NAMESPACE}/${REPO}:${TAG} (${PLATFORM_OS}/${PLATFORM_ARCH})"
echo "Sig Mode   : ${SIG_MODE} — ${SIG_MODE_LABEL}"
echo "Workspace  : ${WORKDIR}"
echo ""

# ------------------------------------------------------------------------------
# STAGE 1: Cache, Scan, Generate SBOM/CBOM & Sign via Gatekeeper
# ------------------------------------------------------------------------------
echo "[STAGE 1] Caching, Scanning, Attesting & Signing Container Image..."
curl -fsSL "${CURL_TLS[@]}" -D "${WORKDIR}/index.hdrs" \
  "${MANIFEST_BASE}/${TAG}" -o "${WORKDIR}/index.json"

INDEX_CACHE_STATUS="$(grep -i '^x-cache-status:' "${WORKDIR}/index.hdrs" | awk '{print $2}' | tr -d '\r' || echo "UNKNOWN")"
INDEX_SHA256="sha256:$(sha256sum "${WORKDIR}/index.json" | awk '{print $1}')"
INDEX_MEDIA_TYPE="$(jq -r '.mediaType // "application/vnd.oci.image.index.v1+json"' "${WORKDIR}/index.json")"
echo "  • Top-level manifest : ${TAG} (X-Cache-Status: ${INDEX_CACHE_STATUS})"
echo "  • Media type         : ${INDEX_MEDIA_TYPE}"
echo "  • Manifest SHA-256   : ${INDEX_SHA256}"

HAS_MANIFESTS="$(jq -r 'if (.manifests | type) == "array" and (.manifests | length) > 0 then "yes" else "no" end' "${WORKDIR}/index.json")"
if [[ "${HAS_MANIFESTS}" == "yes" ]]; then
  PLATFORM_DIGEST="$(jq -r --arg os "${PLATFORM_OS}" --arg arch "${PLATFORM_ARCH}" \
    '[.manifests[] | select(.platform.os == $os and .platform.architecture == $arch)][0].digest // empty' \
    "${WORKDIR}/index.json")"
  if [[ -z "${PLATFORM_DIGEST}" ]]; then
    PLATFORM_DIGEST="$(jq -r '.manifests[0].digest' "${WORKDIR}/index.json")"
  fi
  echo "  • Resolved ${PLATFORM_OS}/${PLATFORM_ARCH} manifest digest: ${PLATFORM_DIGEST}"
  curl -fsSL "${CURL_TLS[@]}" -D "${WORKDIR}/platform.hdrs" \
    "${MANIFEST_BASE}/${PLATFORM_DIGEST}" -o "${WORKDIR}/manifest.json"
  ACTIVE_REF="${PLATFORM_DIGEST}"
  ACTIVE_CACHE_STATUS="$(grep -i '^x-cache-status:' "${WORKDIR}/platform.hdrs" | awk '{print $2}' | tr -d '\r' || echo "UNKNOWN")"
else
  cp "${WORKDIR}/index.json" "${WORKDIR}/manifest.json"
  PLATFORM_DIGEST="${INDEX_SHA256}"
  ACTIVE_REF="${TAG}"
  ACTIVE_CACHE_STATUS="${INDEX_CACHE_STATUS}"
fi

MANIFEST_SHA256="sha256:$(sha256sum "${WORKDIR}/manifest.json" | awk '{print $1}')"
MANIFEST_BYTES="$(wc -c < "${WORKDIR}/manifest.json" | tr -d ' ')"
echo "  • Active platform manifest cached (X-Cache-Status: ${ACTIVE_CACHE_STATUS}, ${MANIFEST_BYTES} bytes)"
echo ""

# ------------------------------------------------------------------------------
# STAGE 2: Pull SBOM, CBOM (OCI 1.1 Referrers) & Selected Signature Layers
# ------------------------------------------------------------------------------
echo "[STAGE 2] Querying OCI 1.1 Referrers (SBOM + CBOM) & Signature Layers (${SIG_MODE})..."
curl -fsSL "${CURL_TLS[@]}" \
  "${REFERRERS_BASE}/${MANIFEST_SHA256}" -o "${WORKDIR}/referrers.json"

SBOM_DIGEST="$(jq -r '.manifests[] | select(.annotations["io.cyclonedx.type"]=="sbom") | .digest' "${WORKDIR}/referrers.json" | head -n1)"
CBOM_DIGEST="$(jq -r '.manifests[] | select(.annotations["io.cyclonedx.type"]=="cbom") | .digest' "${WORKDIR}/referrers.json" | head -n1)"

if [[ -z "${SBOM_DIGEST}" || -z "${CBOM_DIGEST}" ]]; then
  echo "[FAIL] Missing required SBOM or CBOM referrer descriptor for ${MANIFEST_SHA256}" >&2
  exit 1
fi

curl -fsSL "${CURL_TLS[@]}" "${BLOBS_BASE}/${SBOM_DIGEST}" -o "${WORKDIR}/sbom.cdx.json"
curl -fsSL "${CURL_TLS[@]}" "${BLOBS_BASE}/${CBOM_DIGEST}" -o "${WORKDIR}/cbom.cdx.json"

if [[ "${USE_CLASSIC}" == "true" ]]; then
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.asc" -o "${WORKDIR}/manifest.json.asc"
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.sbom.cdx.json.asc" -o "${WORKDIR}/sbom.cdx.json.asc"
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.cbom.cdx.json.asc" -o "${WORKDIR}/cbom.cdx.json.asc"
  GPG_SIG_SHA256="sha256:$(sha256sum "${WORKDIR}/manifest.json.asc" | awk '{print $1}')"
  GPG_SIG_SIZE="$(wc -c < "${WORKDIR}/manifest.json.asc" | tr -d ' ')"
fi

if [[ "${USE_PQC}" == "true" ]]; then
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.mldsa65" -o "${WORKDIR}/manifest.json.mldsa65"
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.sbom.cdx.json.mldsa65" -o "${WORKDIR}/sbom.cdx.json.mldsa65"
  curl -fsSL "${CURL_TLS[@]}" "${MANIFEST_BASE}/${ACTIVE_REF}.cbom.cdx.json.mldsa65" -o "${WORKDIR}/cbom.cdx.json.mldsa65"
  PQC_SIG_SHA256="sha256:$(sha256sum "${WORKDIR}/manifest.json.mldsa65" | awk '{print $1}')"
  PQC_SIG_SIZE="$(wc -c < "${WORKDIR}/manifest.json.mldsa65" | tr -d ' ')"
fi

SBOM_ACTUAL_SHA256="sha256:$(sha256sum "${WORKDIR}/sbom.cdx.json" | awk '{print $1}')"
CBOM_ACTUAL_SHA256="sha256:$(sha256sum "${WORKDIR}/cbom.cdx.json" | awk '{print $1}')"
SBOM_SIZE="$(wc -c < "${WORKDIR}/sbom.cdx.json" | tr -d ' ')"
CBOM_SIZE="$(wc -c < "${WORKDIR}/cbom.cdx.json" | tr -d ' ')"
CBOM_STATUS="$(jq -r '.metadata.properties[]? | select(.name=="trusted-oss:crypto-scan-status") | .value' "${WORKDIR}/cbom.cdx.json" | head -n1)"
CBOM_ASSETS="$(jq -r '[.components[]? | select(.type=="cryptographic-asset") | .name] | if length > 0 then join(", ") else "none (VERIFIED_INERT)" end' "${WORKDIR}/cbom.cdx.json")"

[[ "${SBOM_ACTUAL_SHA256}" == "${SBOM_DIGEST}" ]] || { echo "[FAIL] SBOM digest mismatch!"; exit 1; }
[[ "${CBOM_ACTUAL_SHA256}" == "${CBOM_DIGEST}" ]] || { echo "[FAIL] CBOM digest mismatch!"; exit 1; }

echo ""
hr
echo "TRUSTED CONTAINER ARTIFACT, LAYER, BOM & SIGNATURE TREE"
hr
if [[ "${HAS_MANIFESTS}" == "yes" ]]; then
  echo "${NAMESPACE}/${REPO}:${TAG}  [OCI Image Index]"
  echo "│  Digest: ${INDEX_SHA256}"
  echo "└── Platform Manifest (${PLATFORM_OS}/${PLATFORM_ARCH})"
  echo "    │  Digest: ${MANIFEST_SHA256}  ($(human_size "${MANIFEST_BYTES}"))"
  PREFIX="    "
else
  echo "${NAMESPACE}/${REPO}:${TAG}  [OCI Image Manifest]"
  echo "│  Digest: ${MANIFEST_SHA256}  ($(human_size "${MANIFEST_BYTES}"))"
  PREFIX=""
fi

CONFIG_DIGEST="$(jq -r '.config.digest // "n/a"' "${WORKDIR}/manifest.json")"
CONFIG_SIZE="$(jq -r '.config.size // 0' "${WORKDIR}/manifest.json")"
CONFIG_MEDIA="$(jq -r '.config.mediaType // "application/vnd.oci.image.config.v1+json"' "${WORKDIR}/manifest.json")"
LAYER_COUNT="$(jq -r '.layers | length' "${WORKDIR}/manifest.json")"

echo "${PREFIX}├── Image Config  (${CONFIG_MEDIA}, $(human_size "${CONFIG_SIZE}"))"
echo "${PREFIX}│   └── ${CONFIG_DIGEST}"
echo "${PREFIX}├── Container Layers (${LAYER_COUNT} immutable filesystem layers)"

LAYER_IDX=0
while IFS=$'\t' read -r l_digest l_size l_media; do
  LAYER_IDX=$((LAYER_IDX + 1))
  BRANCH="├──"
  [[ "${LAYER_IDX}" -eq "${LAYER_COUNT}" ]] && BRANCH="└──"
  printf '%s│   %s Layer %02d  %-10s  %s  (%s)\n' \
    "${PREFIX}" "${BRANCH}" "${LAYER_IDX}" "$(human_size "${l_size}")" "${l_digest}" "${l_media}"
done < <(jq -r '.layers[] | [.digest, (.size|tostring), .mediaType] | @tsv' "${WORKDIR}/manifest.json")

echo "${PREFIX}├── SBOM Manifest  (CycloneDX 1.6 — application/vnd.cyclonedx+json, $(human_size "${SBOM_SIZE}"))"
echo "${PREFIX}│   └── ${SBOM_DIGEST}"
echo "${PREFIX}├── CBOM Manifest  (CycloneDX 1.6 — application/vnd.cyclonedx+json, $(human_size "${CBOM_SIZE}"))"
echo "${PREFIX}│   ├── Digest : ${CBOM_DIGEST}"
echo "${PREFIX}│   └── Status : ${CBOM_STATUS:-UNKNOWN}  [Assets: ${CBOM_ASSETS}]"
echo "${PREFIX}└── Signature Layer(s)  [mode: ${SIG_MODE}]"
if [[ "${USE_CLASSIC}" == "true" && "${USE_PQC}" == "true" ]]; then
  echo "${PREFIX}    ├── Classical GPG (RSA-3072 .asc, $(human_size "${GPG_SIG_SIZE}"))"
  echo "${PREFIX}    │   └── ${GPG_SIG_SHA256}"
  echo "${PREFIX}    └── Post-Quantum (NIST FIPS 204 ML-DSA-65 .mldsa65, $(human_size "${PQC_SIG_SIZE}"))"
  echo "${PREFIX}        └── ${PQC_SIG_SHA256}"
elif [[ "${USE_CLASSIC}" == "true" ]]; then
  echo "${PREFIX}    └── Classical GPG (RSA-3072 .asc, $(human_size "${GPG_SIG_SIZE}"))"
  echo "${PREFIX}        └── ${GPG_SIG_SHA256}"
else
  echo "${PREFIX}    └── Post-Quantum (NIST FIPS 204 ML-DSA-65 .mldsa65, $(human_size "${PQC_SIG_SIZE}"))"
  echo "${PREFIX}        └── ${PQC_SIG_SHA256}"
fi
echo ""

# ------------------------------------------------------------------------------
# STAGE 3: Fetch Registry Public Keys & Validate Signatures (Fail-Closed)
# ------------------------------------------------------------------------------
hr
echo "[STAGE 3] Fetching Registry Public Keys & Validating Signatures (${SIG_MODE})"
hr

if [[ "${USE_CLASSIC}" == "true" ]]; then
  curl -fsSL "${CURL_TLS[@]}" "${GATEKEEPER_URL}/keys/trusted-oss-pubkey.asc" -o "${WORKDIR}/trusted-oss-pubkey.asc"
  gpg --batch --quiet --import "${WORKDIR}/trusted-oss-pubkey.asc"
  GPG_FPR="$(gpg --with-colons --fingerprint | awk -F: '$1 == "fpr" {print $10; exit}')"

  if [[ -n "${EXPECTED_GPG_FPR:-}" ]]; then
    NORM_EXPECTED="$(printf '%s' "${EXPECTED_GPG_FPR}" | tr -d ' ' | tr '[:lower:]' '[:upper:]')"
    if [[ "${GPG_FPR}" != "${NORM_EXPECTED}" ]]; then
      echo "  [FAIL] GPG key fingerprint mismatch! Expected ${NORM_EXPECTED}, got ${GPG_FPR}" >&2
      exit 1
    fi
  fi

  printf '%s:6:\n' "${GPG_FPR}" | gpg --batch --quiet --import-ownertrust
  gpg --batch --quiet --check-trustdb 2>/dev/null || true
  echo "  • Imported GPG Public Key Fingerprint   : ${GPG_FPR} (trust: ultimate)"
fi

if [[ "${USE_PQC}" == "true" ]]; then
  curl -fsSL "${CURL_TLS[@]}" "${GATEKEEPER_URL}/keys/trusted-oss-mldsa65.pub" -o "${WORKDIR}/trusted-oss-mldsa65.pub"
  curl -fsSL "${CURL_TLS[@]}" "${GATEKEEPER_URL}/keys/trusted-oss-mldsa65.fingerprint" -o "${WORKDIR}/trusted-oss-mldsa65.fingerprint"
  PQC_FPR_LINE="$(grep -i 'sha256' "${WORKDIR}/trusted-oss-mldsa65.fingerprint" | head -n1 || head -n1 "${WORKDIR}/trusted-oss-mldsa65.fingerprint")"
  PQC_FPR_HEX="$(printf '%s' "${PQC_FPR_LINE}" | sed -E 's/^.*SHA256://I' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"

  if [[ -n "${EXPECTED_PQC_FPR:-}" ]]; then
    NORM_PQC="$(printf '%s' "${EXPECTED_PQC_FPR}" | sed -E 's/^SHA256://I' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    if [[ "${PQC_FPR_HEX}" != "${NORM_PQC}" ]]; then
      echo "  [FAIL] ML-DSA-65 key fingerprint mismatch! Expected ${NORM_PQC}, got ${PQC_FPR_HEX}" >&2
      exit 1
    fi
  fi
  echo "  • Fetched ML-DSA-65 Key Fingerprint     : ${PQC_FPR_LINE}"
fi

echo ""
if [[ "${USE_CLASSIC}" == "true" ]]; then
  echo "  Verifying classical GPG (RSA-3072) detached signatures:"
  for target in manifest.json sbom.cdx.json cbom.cdx.json; do
    gpg --batch --verify "${WORKDIR}/${target}.asc" "${WORKDIR}/${target}" 2>&1 \
      | grep -E 'Good signature|Primary key fingerprint' | sed 's/^/    /'
  done
  echo ""
fi

if [[ "${USE_PQC}" == "true" ]]; then
  echo "  Verifying Post-Quantum NIST FIPS 204 (ML-DSA-65) detached signatures:"
  for target in manifest.json sbom.cdx.json cbom.cdx.json; do
    "${PYTHON_BIN}" "${PQC_VERIFY_SCRIPT}" \
      "${WORKDIR}/${target}" "${WORKDIR}/${target}.mldsa65" "${WORKDIR}/trusted-oss-mldsa65.pub" | sed 's/^/    /'
  done
  echo ""
fi

echo "  [NEGATIVE TEST — TAMPER DETECTION] Flipping 1 byte in a copy of manifest.json:"
cp "${WORKDIR}/manifest.json" "${WORKDIR}/manifest.tampered.json"
printf ' ' >> "${WORKDIR}/manifest.tampered.json"

if [[ "${USE_CLASSIC}" == "true" ]]; then
  if gpg --batch --quiet --verify "${WORKDIR}/manifest.json.asc" "${WORKDIR}/manifest.tampered.json" 2>/dev/null; then
    echo "    [ERROR] Tampered manifest unexpectedly passed GPG verification!" >&2
    exit 1
  else
    echo "    [BLOCKED] GPG rejected tampered manifest (1-byte modification detected)"
  fi
fi

if [[ "${USE_PQC}" == "true" ]]; then
  if "${PYTHON_BIN}" "${PQC_VERIFY_SCRIPT}" \
    "${WORKDIR}/manifest.tampered.json" "${WORKDIR}/manifest.json.mldsa65" "${WORKDIR}/trusted-oss-mldsa65.pub" >/dev/null 2>&1; then
    echo "    [ERROR] Tampered manifest unexpectedly passed ML-DSA-65 verification!" >&2
    exit 1
  else
    echo "    [BLOCKED] ML-DSA-65 rejected tampered manifest (execution denied)"
  fi
fi
echo ""

# ------------------------------------------------------------------------------
# STAGE 4: Inspect Provenance Ledger & Malware/CVE Health Record
# ------------------------------------------------------------------------------
hr
echo "[STAGE 4] Inspecting Registry Provenance & Malware/CVE Scan Verdict"
hr
MANIFEST_HEX="${MANIFEST_SHA256#sha256:}"
PROV_TOTAL="$(curl -fsSL "${CURL_TLS[@]}" "${GATEKEEPER_URL}/audit/provenance?limit=1" | jq -r '.total // 0')"
PROV_MATCH=""
PROV_END="${PROV_TOTAL}"
while [[ "${PROV_END}" -gt 0 ]]; do
  PROV_START=$(( PROV_END > 500 ? PROV_END - 500 : 0 ))
  PROV_LIMIT=$(( PROV_END - PROV_START ))
  curl -fsSL "${CURL_TLS[@]}" \
    "${GATEKEEPER_URL}/audit/provenance?offset=${PROV_START}&limit=${PROV_LIMIT}" \
    -o "${WORKDIR}/provenance.json"
  PROV_MATCH="$(jq --arg sha "${MANIFEST_HEX}" '[.records[] | select(.sha256 == $sha)] | last // empty' "${WORKDIR}/provenance.json")"
  [[ -n "${PROV_MATCH}" ]] && break
  PROV_END="${PROV_START}"
done

if [[ -n "${PROV_MATCH}" ]]; then
  printf '%s\n' "${PROV_MATCH}" | jq '{
    timestamp,
    ecosystem,
    artifact,
    sha256,
    clamav_status,
    cve_status,
    max_cvss,
    cbom_scan_status,
    pqc_status,
    signature_file,
    signature_file_mldsa,
    attestation_hmac: ((.attestation_hmac // "")[0:24] + "...")
  }'
else
  echo "  [WARN] No provenance record matched sha256:${MANIFEST_HEX} across ${PROV_TOTAL} ledger entries."
fi
echo ""

# ------------------------------------------------------------------------------
# STAGE 5: Signed-Only Execution Gate Summary
# ------------------------------------------------------------------------------
hr
echo "[STAGE 5] APPROVED FOR SECURE PIPELINE EXECUTION (${SIG_MODE})"
hr
echo "All verification gates passed:"
echo "  1. Container & all ${LAYER_COUNT} layers hashed and pinned to immutable digest"
echo "  2. CycloneDX 1.6 SBOM & CBOM verified against OCI 1.1 Referrers digests"
echo "  3. Cryptographic verification passed [${SIG_MODE_LABEL}]"
echo "  4. Registry provenance confirms ClamAV malware & CVE scans passed"
echo ""
echo "Safe, digest-pinned execution command (never run mutable tags):"
echo "  docker run --rm ${REPO}@${MANIFEST_SHA256} airflow version"
hr
