#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_CONFIG="$ROOT_DIR/configs/profiles/archld-32c-dualwan-8q.toml"
CANDIDATE_CONFIG="$ROOT_DIR/configs/profiles/archld-32c-dualwan-8q-custom-bpf.toml"
BASELINE_LABEL="baseline"
CANDIDATE_LABEL="candidate"
DURATION_SECS=60
WARMUP_SECS=10
OUT_DIR="$ROOT_DIR/output/bench-ab"
IFACES=""
PING_TARGET=""
WORKLOAD_CMD=""
AGENT_BIN=""

usage() {
  cat <<USAGE
Usage: sudo $0 [options]

Options:
  --baseline-config <path>   Baseline config (default: $BASELINE_CONFIG)
  --candidate-config <path>  Candidate config (default: $CANDIDATE_CONFIG)
  --baseline-label <name>    Baseline case label (default: $BASELINE_LABEL)
  --candidate-label <name>   Candidate case label (default: $CANDIDATE_LABEL)
  --duration <sec>           Measure window per case (default: $DURATION_SECS)
  --warmup <sec>             Warmup before measurement (default: $WARMUP_SECS)
  --ifaces <list>            Comma-separated interfaces, e.g. ens27f0,ens16f1np1 (required)
  --ping-target <host>       Ping target for latency/loss (optional)
  --workload-cmd <cmd>       Workload command to run during each case (optional)
  --agent-bin <path>         landscape-scx-agent binary path
  --out-dir <path>           Output directory (default: $OUT_DIR)
  -h, --help                 Show help

Example:
  sudo $0 \
    --baseline-config ./configs/profiles/archld-32c-dualwan-8q.toml \
    --candidate-config ./configs/profiles/archld-32c-dualwan-8q-custom-bpf.toml \
    --baseline-label cosmos \
    --candidate-label custom_bpf \
    --ifaces ens27f0,ens16f1np1 \
    --duration 60 --warmup 10
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline-config) BASELINE_CONFIG="$2"; shift 2 ;;
    --candidate-config) CANDIDATE_CONFIG="$2"; shift 2 ;;
    --baseline-label) BASELINE_LABEL="$2"; shift 2 ;;
    --candidate-label) CANDIDATE_LABEL="$2"; shift 2 ;;
    --duration) DURATION_SECS="$2"; shift 2 ;;
    --warmup) WARMUP_SECS="$2"; shift 2 ;;
    --ifaces) IFACES="$2"; shift 2 ;;
    --ping-target) PING_TARGET="$2"; shift 2 ;;
    --workload-cmd) WORKLOAD_CMD="$2"; shift 2 ;;
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

if [[ ! -f "$BASELINE_CONFIG" ]]; then
  echo "baseline config not found: $BASELINE_CONFIG"
  exit 1
fi

if [[ ! -f "$CANDIDATE_CONFIG" ]]; then
  echo "candidate config not found: $CANDIDATE_CONFIG"
  exit 1
fi

if [[ -z "$IFACES" ]]; then
  echo "--ifaces is required"
  usage
  exit 1
fi

IFS=',' read -r -a IFACE_ARR <<< "$IFACES"
if [[ "${#IFACE_ARR[@]}" -eq 0 ]]; then
  echo "no interfaces parsed from --ifaces"
  exit 1
fi

for iface in "${IFACE_ARR[@]}"; do
  iface="${iface// /}"
  if [[ -z "$iface" ]]; then
    continue
  fi
  if [[ ! -d "/sys/class/net/$iface" ]]; then
    echo "iface not found: $iface"
    exit 1
  fi
done

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
CSV="$OUT_DIR/profile-ab-$TS.csv"
LOG="$OUT_DIR/profile-ab-$TS.log"

cleanup_pids=()
cleanup() {
  for p in "${cleanup_pids[@]:-}"; do
    kill "$p" >/dev/null 2>&1 || true
    wait "$p" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

PING_ENABLED=0
if [[ -n "$PING_TARGET" ]]; then
  PING_ENABLED=1
fi

echo "case,config,ok,sched_ext_state,sched_ext_ops,cpu_util_pct,rx_mbps_total,tx_mbps_total,net_rx_softirq_delta,net_tx_softirq_delta,ctxt_delta,ping_loss_pct,ping_avg_ms,ping_p95_ms,ping_max_ms,rx_mbps_by_iface,tx_mbps_by_iface,q0_7_delta_by_iface,q8plus_delta_by_iface" > "$CSV"

echo "== landscape-scx profile A/B benchmark ==" | tee -a "$LOG"
echo "time: $(date -Is)" | tee -a "$LOG"
echo "baseline_config: $BASELINE_CONFIG" | tee -a "$LOG"
echo "candidate_config: $CANDIDATE_CONFIG" | tee -a "$LOG"
echo "agent: $AGENT_BIN" | tee -a "$LOG"
echo "duration: ${DURATION_SECS}s, warmup: ${WARMUP_SECS}s" | tee -a "$LOG"
echo "ifaces: $IFACES, ping_target: ${PING_TARGET:-<disabled>}" | tee -a "$LOG"
echo "workload_cmd: ${WORKLOAD_CMD:-<none>}" | tee -a "$LOG"

sum_softirq_line() {
  local name="$1"
  awk -v n="$name" '$1 ~ n":" {s=0; for(i=2;i<=NF;i++) s+=$i; print s; exit}' /proc/softirqs
}

read_cpu_stat() {
  awk '/^cpu / {total=0; for(i=2;i<=9;i++) total+=$i; busy=$2+$3+$4+$7+$8; print total, busy; exit}' /proc/stat
}

read_ctxt() {
  awk '/^ctxt / {print $2; exit}' /proc/stat
}

collect_iface_bytes() {
  local -n out_rx="$1"
  local -n out_tx="$2"
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    out_rx["$iface"]="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
    out_tx["$iface"]="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
  done
}

collect_irq_buckets() {
  local -n out_low="$1"
  local -n out_high="$2"
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    local low high
    read -r low high < <(
      awk -v dev="$iface" '
        $0 ~ dev && match($NF, /TxRx-([0-9]+)/, m) {
          sum = 0
          for (i = 2; i <= NF - 2; i++) sum += $i
          if ((m[1] + 0) < 8) low += sum
          else high += sum
        }
        END { print low + 0, high + 0 }
      ' /proc/interrupts
    )
    out_low["$iface"]="$low"
    out_high["$iface"]="$high"
  done
}

mbps_by_iface() {
  local -n before="$1"
  local -n after="$2"
  local duration="$3"
  local parts=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    local delta=$((after[$iface] - before[$iface]))
    local mbps
    mbps="$(awk -v d="$duration" -v b="$delta" 'BEGIN{if (d > 0) printf "%.2f", (b * 8.0) / (d * 1000 * 1000); else print "0.00"}')"
    parts+=("$iface=$mbps")
  done
  local oldifs="$IFS"
  IFS=';'
  echo "${parts[*]}"
  IFS="$oldifs"
}

irq_delta_by_iface() {
  local -n before="$1"
  local -n after="$2"
  local parts=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    parts+=("$iface=$((after[$iface] - before[$iface]))")
  done
  local oldifs="$IFS"
  IFS=';'
  echo "${parts[*]}"
  IFS="$oldifs"
}

percentile_from_file() {
  local file="$1"
  local p="$2"
  awk -v p="$p" '
    {arr[NR] = $1}
    END {
      if (NR == 0) { print "0.00"; exit }
      n = asort(arr)
      idx = int((p / 100.0) * n)
      if (idx < 1) idx = 1
      if (idx > n) idx = n
      printf "%.2f", arr[idx]
    }
  ' "$file"
}

extract_ping_stats() {
  local ping_out="$1"
  local loss avg max p95

  loss="$(awk -F',' '/packet loss/ {gsub(/^[ \t]+|[ \t]+$/, "", $3); gsub(/% packet loss/, "", $3); print $3; exit}' "$ping_out" 2>/dev/null || true)"
  [[ -z "$loss" ]] && loss="100.00"

  avg="$(awk -F'=' '/rtt|round-trip/ {split($2,a,"/"); gsub(/^[ \t]+|[ \t]+$/, "", a[2]); print a[2]; exit}' "$ping_out" 2>/dev/null || true)"
  [[ -z "$avg" ]] && avg="0.00"

  max="$(awk -F'=' '/rtt|round-trip/ {split($2,a,"/"); gsub(/^[ \t]+|[ \t]+$/, "", a[3]); print a[3]; exit}' "$ping_out" 2>/dev/null || true)"
  [[ -z "$max" ]] && max="0.00"

  local samples
  samples="$(mktemp /tmp/landscape-scx-ab-ping-samples-XXXX.txt)"
  awk -F'time=' '/time=/{split($2,a," "); print a[1]}' "$ping_out" > "$samples"
  p95="$(percentile_from_file "$samples" 95)"
  rm -f "$samples"

  echo "$loss $avg $p95 $max"
}

run_case() {
  local case_label="$1"
  local config_path="$2"

  echo "[case] $case_label" | tee -a "$LOG"

  "$AGENT_BIN" unload-scheduler --config "$config_path" >> "$LOG" 2>&1 || true
  if ! "$AGENT_BIN" run --config "$config_path" --once >> "$LOG" 2>&1; then
    echo "$case_label,$config_path,false,setup_failed,unknown,0,0,0,0,0,0,100.00,0.00,0.00,0.00,,,," >> "$CSV"
    return 0
  fi

  sleep "$WARMUP_SECS"

  local workload_pid=""
  if [[ -n "$WORKLOAD_CMD" ]]; then
    bash -lc "$WORKLOAD_CMD" >> "$LOG" 2>&1 &
    workload_pid="$!"
    cleanup_pids+=("$workload_pid")
  fi

  local ping_out=""
  local ping_pid=""
  if [[ "$PING_ENABLED" -eq 1 ]]; then
    ping_out="$(mktemp /tmp/landscape-scx-profile-ab-ping-XXXX.log)"
    ping -n -i 0.2 -w "$DURATION_SECS" "$PING_TARGET" > "$ping_out" 2>&1 &
    ping_pid="$!"
    cleanup_pids+=("$ping_pid")
  fi

  local total_before busy_before rx_irq_before tx_irq_before ctxt_before
  read -r total_before busy_before < <(read_cpu_stat)
  rx_irq_before="$(sum_softirq_line NET_RX)"
  tx_irq_before="$(sum_softirq_line NET_TX)"
  ctxt_before="$(read_ctxt)"

  declare -A rx_before tx_before qlow_before qhigh_before
  declare -A rx_after tx_after qlow_after qhigh_after
  collect_iface_bytes rx_before tx_before
  collect_irq_buckets qlow_before qhigh_before

  sleep "$DURATION_SECS"

  local total_after busy_after rx_irq_after tx_irq_after ctxt_after
  read -r total_after busy_after < <(read_cpu_stat)
  rx_irq_after="$(sum_softirq_line NET_RX)"
  tx_irq_after="$(sum_softirq_line NET_TX)"
  ctxt_after="$(read_ctxt)"
  collect_iface_bytes rx_after tx_after
  collect_irq_buckets qlow_after qhigh_after

  if [[ -n "$ping_pid" ]]; then
    wait "$ping_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$workload_pid" ]]; then
    kill "$workload_pid" >/dev/null 2>&1 || true
    wait "$workload_pid" >/dev/null 2>&1 || true
  fi

  local state ops
  state="$(cat /sys/kernel/sched_ext/state 2>/dev/null || echo unknown)"
  ops="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo unknown)"

  local total_delta busy_delta util
  total_delta=$((total_after - total_before))
  busy_delta=$((busy_after - busy_before))
  if [[ "$total_delta" -gt 0 ]]; then
    util="$(awk -v b="$busy_delta" -v t="$total_delta" 'BEGIN{printf "%.2f", (b * 100.0) / t}')"
  else
    util="0.00"
  fi

  local rx_total_before=0
  local tx_total_before=0
  local rx_total_after=0
  local tx_total_after=0
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    rx_total_before=$((rx_total_before + rx_before[$iface]))
    tx_total_before=$((tx_total_before + tx_before[$iface]))
    rx_total_after=$((rx_total_after + rx_after[$iface]))
    tx_total_after=$((tx_total_after + tx_after[$iface]))
  done

  local rx_total_delta=$((rx_total_after - rx_total_before))
  local tx_total_delta=$((tx_total_after - tx_total_before))
  local rx_mbps_total tx_mbps_total
  rx_mbps_total="$(awk -v d="$DURATION_SECS" -v b="$rx_total_delta" 'BEGIN{if (d > 0) printf "%.2f", (b * 8.0) / (d * 1000 * 1000); else print "0.00"}')"
  tx_mbps_total="$(awk -v d="$DURATION_SECS" -v b="$tx_total_delta" 'BEGIN{if (d > 0) printf "%.2f", (b * 8.0) / (d * 1000 * 1000); else print "0.00"}')"

  local rx_by_iface tx_by_iface
  rx_by_iface="$(mbps_by_iface rx_before rx_after "$DURATION_SECS")"
  tx_by_iface="$(mbps_by_iface tx_before tx_after "$DURATION_SECS")"
  local qlow_by_iface qhigh_by_iface
  qlow_by_iface="$(irq_delta_by_iface qlow_before qlow_after)"
  qhigh_by_iface="$(irq_delta_by_iface qhigh_before qhigh_after)"

  local ping_loss="na"
  local ping_avg="na"
  local ping_p95="na"
  local ping_max="na"
  if [[ "$PING_ENABLED" -eq 1 && -n "$ping_out" ]]; then
    read -r ping_loss ping_avg ping_p95 ping_max < <(extract_ping_stats "$ping_out")
    rm -f "$ping_out"
  fi

  local rx_irq_delta=$((rx_irq_after - rx_irq_before))
  local tx_irq_delta=$((tx_irq_after - tx_irq_before))
  local ctxt_delta=$((ctxt_after - ctxt_before))
  echo "$case_label,$config_path,true,$state,$ops,$util,$rx_mbps_total,$tx_mbps_total,$rx_irq_delta,$tx_irq_delta,$ctxt_delta,$ping_loss,$ping_avg,$ping_p95,$ping_max,$rx_by_iface,$tx_by_iface,$qlow_by_iface,$qhigh_by_iface" >> "$CSV"
}

run_case "$BASELINE_LABEL" "$BASELINE_CONFIG"
run_case "$CANDIDATE_LABEL" "$CANDIDATE_CONFIG"

echo >> "$LOG"
echo "Benchmark done." | tee -a "$LOG"
echo "CSV: $CSV" | tee -a "$LOG"
echo "Log: $LOG" | tee -a "$LOG"

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
