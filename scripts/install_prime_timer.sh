#!/usr/bin/env bash
# Install and enable a systemd user timer that scans local projects and requests
# any new or missing OSS component versions from http://oss.jsigroup.local:8080.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_URL="${1:-http://oss.jsigroup.local:8080}"
UNIT_DIR="${HOME}/.config/systemd/user"
ENV_FILE="${HOME}/.config/trusted-oss-harbor/prime.env"

mkdir -p "${UNIT_DIR}" "$(dirname "${ENV_FILE}")"

if [[ ! -f "${ENV_FILE}" ]]; then
  cat > "${ENV_FILE}" <<EOF
# Set your TrueNAS Gatekeeper admin token before enabling live priming
GATEKEEPER_ADMIN_TOKEN=SomeLongRandomString123!
EOF
  chmod 0600 "${ENV_FILE}"
  echo "[INFO] Created ${ENV_FILE} (update GATEKEEPER_ADMIN_TOKEN if needed)"
fi

cat > "${UNIT_DIR}/trusted-oss-prime.service" <<EOF
[Unit]
Description=Trusted OSS Harbor Local Workspace Discovery & Cache Primer
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${REPO_DIR}
EnvironmentFile=-${REPO_DIR}/.env
EnvironmentFile=-${ENV_FILE}
ExecStart=/usr/bin/python3 ${REPO_DIR}/scripts/prime_cache.py --roots ${HOME} --url ${GATEWAY_URL} --wait
EOF

cat > "${UNIT_DIR}/trusted-oss-prime.timer" <<EOF
[Unit]
Description=Daily Trusted OSS Harbor Cache Primer (${GATEWAY_URL})

[Timer]
OnCalendar=*-*-* 06:00:00
RandomizedDelaySec=120
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now trusted-oss-prime.timer
systemctl --user list-timers trusted-oss-prime.timer --no-pager
