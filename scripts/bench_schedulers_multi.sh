#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_CONFIG="$ROOT_DIR/configs/landscape-scx.toml"
DURATION_SECS=60
WARMUP_SECS=10
SCHEDULERS="native,scx_cosmos,scx_rusty"
OUT_DIR="$ROOT_DIR/output/bench-multi"
IFACES=""
PING_TARGET=""
WORKLOAD_CMD=""
AGENT_BIN=""

usage() {
  cat <<USAGE
Usage: sudo $0 [options]

Options:
  --config <path>         Base config file (default: $DEFAULT_CONFIG)
  --duration <sec>        Measure window per scheduler (default: $DURATION_SECS)
  --warmup <sec>          Warmup before measurement (default: $WARMUP_SECS)
  --schedulers <list>     Comma-separated scheduler binaries; supports 'native'
  --ifaces <list>         Comma-separated interfaces, e.g. ens18,ens19 (required)
  --ping-target <host>    Ping target for latency/loss (optional)
  --workload-cmd <cmd>    Workload command to run during each case (optional)
  --agent-bin <path>      landscape-scx-agent binary path
  --out-dir <path>        Output directory (default: $OUT_DIR)

Example:
  sudo $0 \
    --config ./configs/profiles/throughput-16c.toml \
    --schedulers native,scx_cosmos,scx_rusty \
    --ifaces ens18,ens19 --ping-target 192.168.15.10 \
    --duration 60 --warmup 10
USAGE
}

CONFIG_PATH="$DEFAULT_CONFIG"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_PATH="$2"; shift 2 ;;
    --duration) DURATION_SECS="$2"; shift 2 ;;
    --warmup) WARMUP_SECS="$2"; shift 2 ;;
    --schedulers) SCHEDULERS="$2"; shift 2 ;;
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

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "config file not found: $CONFIG_PATH"
  exit 1
fi

if [[ -z "$IFACES" ]]; then
  echo "--ifaces is required"
  usage
  exit 1
fi

IFS=',' read -r -a IFACE_ARR <<< "$IFACES"
if [[ "${#IFACE_ARR[@]}" -eq 0 ]]; then
  echo "no interface parsed from --ifaces"
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
CSV="$OUT_DIR/multi-bench-$TS.csv"
LOG="$OUT_DIR/multi-bench-$TS.log"
MD="$OUT_DIR/multi-bench-$TS.md"

cleanup_pids=()
cleanup() {
  for p in "${cleanup_pids[@]:-}"; do
    kill "$p" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

PING_ENABLED=0
if [[ -n "$PING_TARGET" ]]; then
  PING_ENABLED=1
fi

echo "scheduler,ok,sched_ext_state,cpu_util_pct,rx_mbps_total,tx_mbps_total,net_rx_softirq_delta,net_tx_softirq_delta,ctxt_delta,ping_loss_pct,ping_avg_ms,ping_p95_ms,ping_max_ms,rx_mbps_by_iface,tx_mbps_by_iface" > "$CSV"

echo "== landscape-scx multi-iface benchmark ==" | tee -a "$LOG"
echo "time: $(date -Is)" | tee -a "$LOG"
echo "config: $CONFIG_PATH" | tee -a "$LOG"
echo "agent: $AGENT_BIN" | tee -a "$LOG"
echo "duration: ${DURATION_SECS}s, warmup: ${WARMUP_SECS}s" | tee -a "$LOG"
echo "ifaces: $IFACES, ping_target: ${PING_TARGET:-<disabled>}" | tee -a "$LOG"
echo "schedulers: $SCHEDULERS" | tee -a "$LOG"
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
  for i in "${IFACE_ARR[@]}"; do
    local iface="${i// /}"
    out_rx["$iface"]="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
    out_tx["$iface"]="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
  done
}

sum_map() {
  local -n m="$1"
  local s=0
  for i in "${IFACE_ARR[@]}"; do
    local iface="${i// /}"
    s=$((s + m[$iface]))
  done
  echo "$s"
}

mbps_by_iface() {
  local -n before="$1"
  local -n after="$2"
  local duration="$3"
  local parts=()
  for i in "${IFACE_ARR[@]}"; do
    local iface="${i// /}"
    local delta=$((after[$iface]-before[$iface]))
    local mbps
    mbps="$(awk -v d="$duration" -v b="$delta" 'BEGIN{if(d>0) printf "%.2f", (b*8.0)/(d*1000*1000); else print "0.00"}')"
    parts+=("$iface=$mbps")
  done
  local oldifs="$IFS"
  IFS=';'
  echo "${parts[*]}"
  IFS="$oldifs"
}

write_temp_config() {
  local scheduler_bin="$1"
  local tmp_cfg="$2"
  awk -v sched="$scheduler_bin" '
    BEGIN{in_scheduler=0}
    /^\[scheduler\]/{in_scheduler=1; print; next}
    /^\[/{if(in_scheduler==1){in_scheduler=0}}
    {
      if(in_scheduler==1 && $1=="start_command") {
        print "start_command = [\"" sched "\"]";
      } else {
        print;
      }
    }
  ' "$CONFIG_PATH" > "$tmp_cfg"
}

percentile_from_file() {
  local file="$1"
  local p="$2"
  awk -v p="$p" '
    {arr[NR]=$1}
    END{
      if (NR==0) {print "0.00"; exit}
      n=asort(arr)
      idx=int((p/100.0)*n)
      if (idx < 1) idx=1
      if (idx > n) idx=n
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
  samples="$(mktemp /tmp/landscape-scx-ping-samples-XXXX.txt)"
  awk -F'time=' '/time=/{split($2,a," "); print a[1]}' "$ping_out" > "$samples"
  p95="$(percentile_from_file "$samples" 95)"
  rm -f "$samples"
  echo "$loss $avg $p95 $max"
}

run_case() {
  local sched="$1"
  local tmp_cfg=""
  local ping_out=""
  local ping_pid=""

  if [[ "$sched" == "native" ]]; then
    echo "[case] native (CFS baseline)" | tee -a "$LOG"
    "$AGENT_BIN" unload-scheduler --config "$CONFIG_PATH" >> "$LOG" 2>&1 || true
  else
    if ! command -v "$sched" >/dev/null 2>&1; then
      echo "[skip] scheduler not found: $sched" | tee -a "$LOG"
      echo "$sched,false,not_found,0,0,0,0,0,0,100.00,0.00,0.00,0.00,," >> "$CSV"
      return 0
    fi
    tmp_cfg="$(mktemp /tmp/landscape-scx-bench-multi-XXXX.toml)"
    write_temp_config "$sched" "$tmp_cfg"
    echo "[case] $sched" | tee -a "$LOG"
    "$AGENT_BIN" unload-scheduler --config "$tmp_cfg" >> "$LOG" 2>&1 || true
    if ! "$AGENT_BIN" run --config "$tmp_cfg" --once >> "$LOG" 2>&1; then
      echo "$sched,false,setup_failed,0,0,0,0,0,0,100.00,0.00,0.00,0.00,," >> "$CSV"
      rm -f "$tmp_cfg"
      return 0
    fi
  fi

  sleep "$WARMUP_SECS"

  local workload_pid=""
  if [[ -n "$WORKLOAD_CMD" ]]; then
    bash -lc "$WORKLOAD_CMD" >> "$LOG" 2>&1 &
    workload_pid="$!"
    cleanup_pids+=("$workload_pid")
  fi

  if [[ "$PING_ENABLED" -eq 1 ]]; then
    ping_out="$(mktemp /tmp/landscape-scx-bench-multi-ping-XXXX.log)"
    ping -n -i 0.2 -w "$DURATION_SECS" "$PING_TARGET" > "$ping_out" 2>&1 &
    ping_pid="$!"
    cleanup_pids+=("$ping_pid")
  fi

  local total_before busy_before rx_irq_before tx_irq_before ctxt_before
  read -r total_before busy_before < <(read_cpu_stat)
  rx_irq_before="$(sum_softirq_line NET_RX)"
  tx_irq_before="$(sum_softirq_line NET_TX)"
  ctxt_before="$(read_ctxt)"

  declare -A rx_before tx_before rx_after tx_after
  collect_iface_bytes rx_before tx_before
  local rx_sum_before tx_sum_before
  rx_sum_before="$(sum_map rx_before)"
  tx_sum_before="$(sum_map tx_before)"

  sleep "$DURATION_SECS"

  local total_after busy_after rx_irq_after tx_irq_after ctxt_after
  read -r total_after busy_after < <(read_cpu_stat)
  rx_irq_after="$(sum_softirq_line NET_RX)"
  tx_irq_after="$(sum_softirq_line NET_TX)"
  ctxt_after="$(read_ctxt)"

  collect_iface_bytes rx_after tx_after
  local rx_sum_after tx_sum_after
  rx_sum_after="$(sum_map rx_after)"
  tx_sum_after="$(sum_map tx_after)"

  if [[ -n "$ping_pid" ]]; then
    wait "$ping_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$workload_pid" ]]; then
    kill "$workload_pid" >/dev/null 2>&1 || true
    wait "$workload_pid" >/dev/null 2>&1 || true
  fi

  local state
  state="$(cat /sys/kernel/sched_ext/state 2>/dev/null || echo unknown)"

  local total_delta busy_delta util
  total_delta=$((total_after - total_before))
  busy_delta=$((busy_after - busy_before))
  if [[ "$total_delta" -gt 0 ]]; then
    util="$(awk -v b="$busy_delta" -v t="$total_delta" 'BEGIN{printf "%.2f", (b*100.0)/t}')"
  else
    util="0.00"
  fi

  local rx_mbps tx_mbps
  rx_mbps="$(awk -v d="$DURATION_SECS" -v b="$((rx_sum_after-rx_sum_before))" 'BEGIN{if(d>0) printf "%.2f", (b*8.0)/(d*1000*1000); else print "0.00"}')"
  tx_mbps="$(awk -v d="$DURATION_SECS" -v b="$((tx_sum_after-tx_sum_before))" 'BEGIN{if(d>0) printf "%.2f", (b*8.0)/(d*1000*1000); else print "0.00"}')"

  local rx_irq_delta tx_irq_delta ctxt_delta
  rx_irq_delta=$((rx_irq_after - rx_irq_before))
  tx_irq_delta=$((tx_irq_after - tx_irq_before))
  ctxt_delta=$((ctxt_after - ctxt_before))

  local loss avg p95 max
  if [[ "$PING_ENABLED" -eq 1 ]]; then
    read -r loss avg p95 max < <(extract_ping_stats "$ping_out")
  else
    loss="na"; avg="na"; p95="na"; max="na"
  fi

  local rx_by_iface tx_by_iface
  rx_by_iface="$(mbps_by_iface rx_before rx_after "$DURATION_SECS")"
  tx_by_iface="$(mbps_by_iface tx_before tx_after "$DURATION_SECS")"

  echo "$sched,true,$state,$util,$rx_mbps,$tx_mbps,$rx_irq_delta,$tx_irq_delta,$ctxt_delta,$loss,$avg,$p95,$max,\"$rx_by_iface\",\"$tx_by_iface\"" >> "$CSV"

  if [[ -n "$ping_out" ]]; then
    rm -f "$ping_out"
  fi
  rm -f "$tmp_cfg"
}

generate_markdown() {
  local csv="$1"
  local md="$2"
  local best_tx best_p95
  best_tx="$(awk -F',' 'NR>1 && $2=="true" {if($6+0 > max){max=$6; name=$1}} END{print name}' "$csv")"
  if [[ "$PING_ENABLED" -eq 1 ]]; then
    best_p95="$(awk -F',' 'NR>1 && $2=="true" {if(min=="" || $12+0 < min){min=$12; name=$1}} END{print name}' "$csv")"
  else
    best_p95="n/a"
  fi

  {
    echo "# Multi-Interface Benchmark Report"
    echo
    echo "- Generated at: $(date -Is)"
    echo "- Config: \`$CONFIG_PATH\`"
    echo "- Interfaces: \`$IFACES\`"
    echo "- Ping target: \`${PING_TARGET:-disabled}\`"
    echo "- Duration per scheduler: ${DURATION_SECS}s (warmup ${WARMUP_SECS}s)"
    echo
    echo "## Summary"
    echo
    echo "- Throughput-first winner: \`${best_tx:-n/a}\`"
    echo "- Latency-first winner (p95): \`${best_p95:-n/a}\`"
    echo
    echo "## Results"
    echo
    echo "| Scheduler | OK | State | CPU% | RX Mbps(total) | TX Mbps(total) | Loss % | Avg ms | p95 ms | Max ms | RX by iface | TX by iface |"
    echo "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|---|"
    awk -F',' 'NR>1 {
      printf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1,$2,$3,$4,$5,$6,$10,$11,$12,$13,$14,$15)
    }' "$csv"
  } > "$md"
}

IFS=',' read -r -a sched_arr <<< "$SCHEDULERS"
for sched in "${sched_arr[@]}"; do
  sched="${sched// /}"
  [[ -z "$sched" ]] && continue
  run_case "$sched"
done

generate_markdown "$CSV" "$MD"

echo
if command -v column >/dev/null 2>&1; then
  column -s, -t "$CSV"
else
  cat "$CSV"
fi

echo
echo "Multi-interface benchmark done."
echo "CSV: $CSV"
echo "LOG: $LOG"
echo "MD : $MD"
