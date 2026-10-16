#!/usr/bin/env bash
# ==============================================================================
# Fetch Official GitHub Actions IPv4/IPv6 CIDR Ranges for pfSense Alias Table
# Source: https://api.github.com/meta (.actions)
# ==============================================================================
set -euo pipefail

OUTPUT_FILE="/tmp/github_actions_cidrs.txt"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -*)
      echo "[ERROR] Unknown option: $1" >&2
      exit 1
      ;;
    *)
      OUTPUT_FILE="$1"
      shift
      ;;
  esac
done

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

echo "[INFO] Fetching GitHub Actions CIDR list from https://api.github.com/meta..."
curl -fsSL -H "Accept: application/vnd.github+json" https://api.github.com/meta \
  | python3 -c "import sys, json; data = json.load(sys.stdin); print('\n'.join(data.get('actions', [])))" \
  > "${TMP_FILE}"

LINE_COUNT="$(wc -l < "${TMP_FILE}" | tr -d ' ')"
if [[ "${LINE_COUNT}" -lt 10 ]]; then
  echo "[ERROR] Unexpectedly small CIDR list (${LINE_COUNT} entries); aborting update." >&2
  exit 1
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Verified ${LINE_COUNT} GitHub Actions CIDRs (would write to ${OUTPUT_FILE})"
  exit 0
fi

mkdir -p "$(dirname -- "${OUTPUT_FILE}")"
mv "${TMP_FILE}" "${OUTPUT_FILE}"
chmod 0644 "${OUTPUT_FILE}"
echo "[OK] Wrote ${LINE_COUNT} GitHub Actions CIDRs to ${OUTPUT_FILE}"
