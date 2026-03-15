#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="/etc/landscape-scx"
BIN_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/landscape-scx"
BPF_SHARE_DIR="$SHARE_DIR/bpf"
BPF_SOURCE_DST="$BPF_SHARE_DIR/landscape_scx.bpf.c"
DEFAULT_CONFIG_SRC="$ROOT_DIR/configs/profiles/auto-discover-auto-partition.toml"
UNIT_DST="/etc/systemd/system/landscape-scx.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "please run as root"
  exit 1
fi

echo "[1/6] building binaries"
cd "$ROOT_DIR"
cargo build --release -p landscape-scx-agent -p landscape-scx-cli

echo "[2/6] installing binaries to $BIN_DIR"
install -m 0755 "$ROOT_DIR/target/release/landscape-scx-agent" "$BIN_DIR/landscape-scx-agent"
install -m 0755 "$ROOT_DIR/target/release/landscape-scx-cli" "$BIN_DIR/landscape-scx"

echo "[3/6] installing built-in scheduler source to $BPF_SHARE_DIR"
install -d "$BPF_SHARE_DIR"
install -m 0644 "$ROOT_DIR/bpf/landscape_scx.bpf.c" "$BPF_SOURCE_DST"

echo "[4/6] installing config to $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
  tmp_config="$(mktemp)"
  sed "s|^source_file = \".*\"|source_file = \"$BPF_SOURCE_DST\"|" \
    "$DEFAULT_CONFIG_SRC" > "$tmp_config"
  install -m 0644 "$tmp_config" "$CONFIG_DIR/config.toml"
  rm -f "$tmp_config"
else
  echo "config already exists, skip overwrite: $CONFIG_DIR/config.toml"
fi

echo "[5/6] installing systemd unit"
install -m 0644 "$ROOT_DIR/systemd/landscape-scx.service" "$UNIT_DST"

echo "[6/6] reload and enable service"
systemctl daemon-reload
systemctl enable --now landscape-scx.service

systemctl --no-pager --full status landscape-scx.service || true
echo "install finished"
