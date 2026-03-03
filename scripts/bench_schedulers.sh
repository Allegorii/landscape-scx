#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_CONFIG="$ROOT_DIR/configs/landscape-scx.toml"
AGENT_BIN_DEFAULT=""
DURATION_SECS=30
WARMUP_SECS=5
SCHEDULERS="scx_bpfland,scx_lavd,scx_rustland"
OUT_DIR="$ROOT_DIR/output/bench"

usage() {
  cat <<USAGE
Usage: sudo $0 [options]

Options:
  --config <path>         Base config file (default: $DEFAULT_CONFIG)
  --duration <sec>        Duration per scheduler (default: $DURATION_SECS)
  --warmup <sec>          Warmup before measurement (default: $WARMUP_SECS)
  --schedulers <list>     Comma-separated scheduler binaries
                          (default: $SCHEDULERS)
  --agent-bin <path>      landscape-scx-agent binary path
  --out-dir <path>        Output directory (default: $OUT_DIR)

Example:
  sudo $0 --config ./configs/profiles/throughput-16c.toml \
    --schedulers scx_bpfland,scx_lavd --duration 20 --warmup 5
USAGE
}

CONFIG_PATH="$DEFAULT_CONFIG"
AGENT_BIN="$AGENT_BIN_DEFAULT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_PATH="$2"; shift 2 ;;
    --duration) DURATION_SECS="$2"; shift 2 ;;
    --warmup) WARMUP_SECS="$2"; shift 2 ;;
    --schedulers) SCHEDULERS="$2"; shift 2 ;;
    --agent-bin) AGENT_BIN="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "please run as root"
  exit 1
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "config file not found: $CONFIG_PATH"
  exit 1
fi

if [[ -z "$AGENT_BIN" ]]; then
  if [[ -x "$ROOT_DIR/target/debug/landscape-scx-agent" ]]; then
    AGENT_BIN="$ROOT_DIR/target/debug/landscape-scx-agent"
  elif command -v landscape-scx-agent >/dev/null 2>&1; then
    AGENT_BIN="$(command -v landscape-scx-agent)"
  else
    echo "cannot find landscape-scx-agent; pass --agent-bin or build first"
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
CSV="$OUT_DIR/bench-$TS.csv"
LOG="$OUT_DIR/bench-$TS.log"

echo "scheduler,ok,sched_ext_state,cpu_util_pct,net_rx_softirq_delta,net_tx_softirq_delta,ctxt_delta" > "$CSV"

echo "== landscape-scx benchmark ==" | tee -a "$LOG"
echo "time: $(date -Is)" | tee -a "$LOG"
echo "config: $CONFIG_PATH" | tee -a "$LOG"
echo "agent: $AGENT_BIN" | tee -a "$LOG"
echo "duration_per_scheduler: ${DURATION_SECS}s, warmup: ${WARMUP_SECS}s" | tee -a "$LOG"
echo "schedulers: $SCHEDULERS" | tee -a "$LOG"

sum_softirq_line() {
  local name="$1"
  awk -v n="$name" '$1 ~ n":" {s=0; for(i=2;i<=NF;i++) s+=$i; print s; exit}' /proc/softirqs
}

read_cpu_stat() {
  # total busy idle_iowait
  awk '/^cpu / {total=0; for(i=2;i<=9;i++) total+=$i; busy=$2+$3+$4+$7+$8; idleio=$5+$6; print total, busy, idleio; exit}' /proc/stat
}

read_ctxt() {
  awk '/^ctxt / {print $2; exit}' /proc/stat
}

write_temp_config() {
  local scheduler_bin="$1"
  local tmp_cfg="$2"
  awk -v sched="$scheduler_bin" '
    BEGIN{in_scheduler=0}
    /^\[scheduler\]/{in_scheduler=1; print; next}
    /^\[/{if(in_scheduler==1){in_scheduler=0} }
    {
      if(in_scheduler==1 && $1=="start_command") {
        print "start_command = [\"" sched "\"]";
      } else {
        print;
      }
    }
  ' "$CONFIG_PATH" > "$tmp_cfg"
}

run_case() {
  local sched="$1"

  if ! command -v "$sched" >/dev/null 2>&1; then
    echo "[skip] scheduler not found in PATH: $sched" | tee -a "$LOG"
    echo "$sched,false,not_found,0,0,0,0" >> "$CSV"
    return 0
  fi

  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/landscape-scx-bench-XXXX.toml)"
  write_temp_config "$sched" "$tmp_cfg"

  echo "[case] $sched" | tee -a "$LOG"

  # Reset any previous scheduler started by agent.
  "$AGENT_BIN" unload-scheduler --config "$tmp_cfg" >/dev/null 2>&1 || true

  local ok="true"
  if ! "$AGENT_BIN" run --config "$tmp_cfg" --once >> "$LOG" 2>&1; then
    ok="false"
  fi

  # Warmup window is excluded from metrics.
  sleep "$WARMUP_SECS"

  if ! "$AGENT_BIN" run --config "$tmp_cfg" --once >> "$LOG" 2>&1; then
    ok="false"
  fi

  local cpu_before total_before busy_before idle_before
  read -r total_before busy_before idle_before < <(read_cpu_stat)
  local rx_before tx_before ctxt_before
  rx_before="$(sum_softirq_line NET_RX)"
  tx_before="$(sum_softirq_line NET_TX)"
  ctxt_before="$(read_ctxt)"

  sleep "$DURATION_SECS"

  local state
  state="$(cat /sys/kernel/sched_ext/state 2>/dev/null || echo unknown)"

  local total_after busy_after idle_after
  read -r total_after busy_after idle_after < <(read_cpu_stat)
  local rx_after tx_after ctxt_after
  rx_after="$(sum_softirq_line NET_RX)"
  tx_after="$(sum_softirq_line NET_TX)"
  ctxt_after="$(read_ctxt)"

  local total_delta busy_delta util
  total_delta=$((total_after - total_before))
  busy_delta=$((busy_after - busy_before))
  if [[ "$total_delta" -gt 0 ]]; then
    util="$(awk -v b="$busy_delta" -v t="$total_delta" 'BEGIN{printf "%.2f", (b*100.0)/t}')"
  else
    util="0.00"
  fi

  local rx_delta tx_delta ctxt_delta
  rx_delta=$((rx_after - rx_before))
  tx_delta=$((tx_after - tx_before))
  ctxt_delta=$((ctxt_after - ctxt_before))

  echo "$sched,$ok,$state,$util,$rx_delta,$tx_delta,$ctxt_delta" >> "$CSV"

  rm -f "$tmp_cfg"
}

IFS=',' read -r -a sched_arr <<< "$SCHEDULERS"
for sched in "${sched_arr[@]}"; do
  sched="${sched// /}"
  [[ -z "$sched" ]] && continue
  run_case "$sched"
done

echo
echo "Benchmark done."
echo "CSV: $CSV"
echo "Log: $LOG"
echo
echo "Quick view:"
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV"
else
  cat "$CSV"
fi
