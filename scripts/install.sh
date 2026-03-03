#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="/etc/landscape-scx"
BIN_DIR="/usr/local/bin"
UNIT_DST="/etc/systemd/system/landscape-scx.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "please run as root"
  exit 1
fi

echo "[1/5] building binaries"
cd "$ROOT_DIR"
cargo build --release -p landscape-scx-agent -p landscape-scx-cli

echo "[2/5] installing binaries to $BIN_DIR"
install -m 0755 "$ROOT_DIR/target/release/landscape-scx-agent" "$BIN_DIR/landscape-scx-agent"
install -m 0755 "$ROOT_DIR/target/release/landscape-scx-cli" "$BIN_DIR/landscape-scx"

echo "[3/5] installing config to $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
  install -m 0644 "$ROOT_DIR/configs/landscape-scx.toml" "$CONFIG_DIR/config.toml"
else
  echo "config already exists, skip overwrite: $CONFIG_DIR/config.toml"
fi

echo "[4/5] installing systemd unit"
install -m 0644 "$ROOT_DIR/systemd/landscape-scx.service" "$UNIT_DST"

echo "[5/5] reload and enable service"
systemctl daemon-reload
systemctl enable --now landscape-scx.service

systemctl --no-pager --full status landscape-scx.service || true
echo "install finished"
