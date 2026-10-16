#!/usr/bin/env bash
# ==============================================================================
# Fetch Official GitHub Actions IPv4/IPv6 CIDR Ranges for pfSense Alias Table
# Source: https://api.github.com/meta (.actions)
# ==============================================================================
set -euo pipefail

OUTPUT_FILE="${1:-/tmp/github_actions_cidrs.txt}"
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

mkdir -p "$(dirname "${OUTPUT_FILE}")"
mv "${TMP_FILE}" "${OUTPUT_FILE}"
chmod 0644 "${OUTPUT_FILE}"
echo "[OK] Wrote ${LINE_COUNT} GitHub Actions CIDRs to ${OUTPUT_FILE}"
