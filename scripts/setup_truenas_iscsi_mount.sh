#!/usr/bin/env bash
# ==============================================================================
# TrueNAS iSCSI External Block Storage Provisioning & Migration Script
# Connects the Linux host to a TrueNAS iSCSI LUN, formats/mounts XFS with
# _netdev persistence, and migrates /home/jsoehner/trusted-oss-data seamlessly.
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

PORTAL="${TRUENAS_ISCSI_PORTAL:-192.168.1.50:3260}"
TARGET_IQN="${TRUENAS_ISCSI_IQN:-iqn.2005-10.org.freenas.ctl:trusted-oss-harbor-lun0}"
MOUNTPOINT="${TRUENAS_ISCSI_MOUNTPOINT:-/mnt/truenas-iscsi-oss}"
SOURCE_DIR="${OSS_DATA_ROOT:-/home/jsoehner/trusted-oss-data}"
OWNER_USER="${SUDO_USER:-$(id -un)}"
OWNER_GROUP="$(id -gn "${OWNER_USER}")"
DRY_RUN="false"
DO_MIGRATE="false"

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --portal <IP:PORT>       TrueNAS iSCSI portal (default: ${PORTAL})
  --iqn <IQN>              TrueNAS iSCSI target IQN (default: ${TARGET_IQN})
  --mountpoint <PATH>      Host mountpoint for the iSCSI block device (default: ${MOUNTPOINT})
  --source-dir <PATH>      Existing OSS_DATA_ROOT to migrate from (default: ${SOURCE_DIR})
  --migrate                Rsync existing data from --source-dir and update .env OSS_DATA_ROOT
  --dry-run                Print planned commands without modifying the system
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --portal)
      PORTAL="$2"
      shift 2
      ;;
    --iqn)
      TARGET_IQN="$2"
      shift 2
      ;;
    --mountpoint)
      MOUNTPOINT="$2"
      shift 2
      ;;
    --source-dir)
      SOURCE_DIR="$2"
      shift 2
      ;;
    --migrate)
      DO_MIGRATE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

run_cmd() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] $*"
  else
    echo "[EXEC] $*"
    "$@"
  fi
}

echo "=============================================================================="
echo " TrueNAS iSCSI External Block Storage Setup"
echo "   Portal:      ${PORTAL}"
echo "   Target IQN:  ${TARGET_IQN}"
echo "   Mountpoint:  ${MOUNTPOINT}"
echo "   Source Dir:  ${SOURCE_DIR}"
echo "   Owner:       ${OWNER_USER}:${OWNER_GROUP}"
echo "   Migrate:     ${DO_MIGRATE}"
echo "   Dry Run:     ${DRY_RUN}"
echo "=============================================================================="

if [[ "${DRY_RUN}" != "true" && "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Please run with sudo (or use --dry-run to preview commands)." >&2
  exit 1
fi

# 1. Ensure open-iscsi & xfsprogs are installed
if ! command -v iscsiadm >/dev/null 2>&1; then
  run_cmd apt-get update
  run_cmd apt-get install -y open-iscsi xfsprogs
fi

run_cmd systemctl enable --now iscsid

# 2. Discover and log into the TrueNAS iSCSI target
run_cmd iscsiadm -m discovery -t sendtargets -p "${PORTAL}"
run_cmd iscsiadm -m node -T "${TARGET_IQN}" -p "${PORTAL}" --op update -n node.startup -v automatic
run_cmd iscsiadm -m node -T "${TARGET_IQN}" -p "${PORTAL}" --login || true

DISK_BY_PATH="/dev/disk/by-path/ip-${PORTAL}-iscsi-${TARGET_IQN}-lun-0"
echo "[INFO] Expected persistent block device path: ${DISK_BY_PATH}"

if [[ "${DRY_RUN}" != "true" ]]; then
  udevadm settle
  if [[ ! -b "${DISK_BY_PATH}" ]]; then
    echo "[ERROR] Block device ${DISK_BY_PATH} not found after iSCSI login." >&2
    exit 1
  fi
  if ! blkid "${DISK_BY_PATH}" >/dev/null 2>&1; then
    echo "[INFO] Formatting ${DISK_BY_PATH} with XFS (label=TRUSTED_OSS)..."
    mkfs.xfs -L TRUSTED_OSS "${DISK_BY_PATH}"
  else
    echo "[INFO] Existing filesystem detected on ${DISK_BY_PATH}; skipping mkfs."
  fi
else
  echo "[DRY-RUN] mkfs.xfs -L TRUSTED_OSS ${DISK_BY_PATH} (if unformatted)"
fi

# 3. Create mountpoint and configure /etc/fstab with _netdev
run_cmd mkdir -p "${MOUNTPOINT}"
FSTAB_ENTRY="LABEL=TRUSTED_OSS ${MOUNTPOINT} xfs _netdev,noatime,nodiratime,nofail 0 2"
if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[DRY-RUN] Append to /etc/fstab: ${FSTAB_ENTRY}"
  echo "[DRY-RUN] mount -a && chown -R ${OWNER_USER}:${OWNER_GROUP} ${MOUNTPOINT}"
else
  if ! grep -q "LABEL=TRUSTED_OSS" /etc/fstab; then
    echo "${FSTAB_ENTRY}" >> /etc/fstab
  fi
  mount "${MOUNTPOINT}" || mount -a
  chown "${OWNER_USER}:${OWNER_GROUP}" "${MOUNTPOINT}"
fi

# 4. Optional zero-downtime data migration from /home/jsoehner/trusted-oss-data
if [[ "${DO_MIGRATE}" == "true" ]]; then
  echo "[INFO] Migrating persistent OSS store from ${SOURCE_DIR} to ${MOUNTPOINT}..."
  run_cmd rsync -aHAX "${SOURCE_DIR}/" "${MOUNTPOINT}/"
  run_cmd chown -R "${OWNER_USER}:${OWNER_GROUP}" "${MOUNTPOINT}"
  if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    run_cmd sed -i "s|^OSS_DATA_ROOT=.*|OSS_DATA_ROOT=${MOUNTPOINT}|" "${PROJECT_ROOT}/.env"
  fi
  echo "[OK] Migration complete. OSS_DATA_ROOT is now ${MOUNTPOINT}."
fi
