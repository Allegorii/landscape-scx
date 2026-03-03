#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "please run as root"
  exit 1
fi

systemctl disable --now landscape-scx.service 2>/dev/null || true
rm -f /etc/systemd/system/landscape-scx.service
systemctl daemon-reload

rm -f /usr/local/bin/landscape-scx-agent
rm -f /usr/local/bin/landscape-scx

echo "uninstalled binaries and service (config kept at /etc/landscape-scx)"
