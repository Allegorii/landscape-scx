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
PERF_EVENTS="cache-misses,cache-references,LLC-load-misses"
ENABLE_PERF=1
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

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
  --perf-events <list>       perf stat events (default: $PERF_EVENTS)
  --no-perf                  Disable perf stat collection
  --out-dir <path>           Output directory (default: $OUT_DIR)
  -h, --help                 Show help

Example:
  sudo $0 \
    --baseline-config ./configs/profiles/archld-32c-dualwan-8q.toml \
    --candidate-config ./configs/profiles/archld-32c-dualwan-8q-custom-bpf.toml \
    --baseline-label cosmos \
    --candidate-label custom_bpf \
    --ifaces ens27f0,ens16f1np1 \
    --duration 60 --warmup 10 \
    --perf-events cache-misses,cache-references,LLC-load-misses
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
    --perf-events) PERF_EVENTS="$2"; shift 2 ;;
    --no-perf) ENABLE_PERF=0; shift ;;
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

for iface_raw in "${IFACE_ARR[@]}"; do
  iface="${iface_raw// /}"
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

ensure_agent_bin_fresh() {
  local bin_path="$1"
  if [[ "$bin_path" != "$ROOT_DIR/target/debug/landscape-scx-agent" ]]; then
    return 0
  fi

  if find \
    "$ROOT_DIR/Cargo.toml" \
    "$ROOT_DIR/Cargo.lock" \
    "$ROOT_DIR/crates" \
    "$ROOT_DIR/bpf" \
    "$ROOT_DIR/configs" \
    -type f -newer "$bin_path" -print -quit | grep -q .; then
    echo "[info] rebuilding landscape-scx-agent because sources are newer than $bin_path" | tee -a "$LOG"
    (cd "$ROOT_DIR" && cargo build -p landscape-scx-agent) >> "$LOG" 2>&1
  fi
}

csv_row() {
  local oldifs="$IFS"
  IFS=,
  echo "$*"
  IFS="$oldifs"
}

log_header() {
  echo "== landscape-scx profile A/B benchmark ==" | tee -a "$LOG"
  echo "time: $(date -Is)" | tee -a "$LOG"
  echo "baseline_config: $BASELINE_CONFIG" | tee -a "$LOG"
  echo "candidate_config: $CANDIDATE_CONFIG" | tee -a "$LOG"
  echo "agent: $AGENT_BIN" | tee -a "$LOG"
  echo "duration: ${DURATION_SECS}s, warmup: ${WARMUP_SECS}s" | tee -a "$LOG"
  echo "ifaces: $IFACES, ping_target: ${PING_TARGET:-<disabled>}" | tee -a "$LOG"
  echo "workload_cmd: ${WORKLOAD_CMD:-<none>}" | tee -a "$LOG"
  echo "perf_events: $([[ "$ENABLE_PERF" -eq 1 ]] && echo "$PERF_EVENTS" || echo "<disabled>")" | tee -a "$LOG"
}

sum_softirq_line() {
  local name="$1"
  awk -v n="$name" '$1 ~ n":" {s=0; for(i=2;i<=NF;i++) s+=$i; print s + 0; found=1; exit} END{if(!found) print 0}' /proc/softirqs
}

read_sched_ext_state() {
  cat /sys/kernel/sched_ext/state 2>/dev/null || echo unknown
}

read_sched_ext_ops() {
  cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo unknown
}

config_scheduler_mode() {
  local config_path="$1"
  awk '
    BEGIN { in_scheduler = 0; mode = "" }
    /^\[scheduler\]/ { in_scheduler = 1; next }
    /^\[/ && in_scheduler == 1 { in_scheduler = 0 }
    in_scheduler == 1 && $1 == "mode" {
      gsub(/"/, "", $3)
      mode = $3
    }
    END {
      if (mode == "") print "external_command"
      else print mode
    }
  ' "$config_path"
}

read_cpu_stat() {
  awk '/^cpu / {total=0; for(i=2;i<=9;i++) total+=$i; busy=$2+$3+$4+$7+$8; print total, busy; exit}' /proc/stat
}

read_ctxt() {
  awk '/^ctxt / {print $2; exit}' /proc/stat
}

read_softnet_field() {
  local field_index="$1"
  awk -v idx="$field_index" '
    {
      if (NF >= idx) sum += strtonum("0x" $(idx))
    }
    END { print sum + 0 }
  ' /proc/net/softnet_stat
}

read_proc_ticks() {
  local pid="$1"
  awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0
}

ticks_to_seconds() {
  local ticks="$1"
  awk -v t="$ticks" -v hz="$CLK_TCK" 'BEGIN{if (hz > 0) printf "%.2f", t / hz; else print "0.00"}'
}

collect_iface_bytes() {
  local -n out_rx="$1"
  local -n out_tx="$2"
  out_rx=()
  out_tx=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    out_rx["$iface"]="$(cat "/sys/class/net/$iface/statistics/rx_bytes")"
    out_tx["$iface"]="$(cat "/sys/class/net/$iface/statistics/tx_bytes")"
  done
}

collect_irq_buckets() {
  local -n out_low="$1"
  local -n out_high="$2"
  out_low=()
  out_high=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    local low high
    read -r low high < <(
      awk -v dev="$iface" '
        $0 ~ dev {
          label = $NF
          queue = ""
          if (match(label, /TxRx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /txrx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /[-_]tx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /[-_]rx-([0-9]+)/, m)) queue = m[1]
          if (queue != "") {
            sum = 0
            for (i = 2; i <= NF - 2; i++) sum += $i
            if ((queue + 0) < 8) low += sum
            else high += sum
          }
        }
        END { print low + 0, high + 0 }
      ' /proc/interrupts
    )
    out_low["$iface"]="$low"
    out_high["$iface"]="$high"
  done
}

collect_irq_queue_totals() {
  local -n out="$1"
  out=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    while read -r queue sum; do
      [[ -z "$queue" ]] && continue
      out["$iface:$queue"]="$sum"
    done < <(
      awk -v dev="$iface" '
        $0 ~ dev {
          label = $NF
          queue = ""
          if (match(label, /TxRx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /txrx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /[-_]tx-([0-9]+)/, m)) queue = m[1]
          else if (match(label, /[-_]rx-([0-9]+)/, m)) queue = m[1]
          if (queue != "") {
            sum = 0
            for (i = 2; i <= NF - 2; i++) sum += $i
            bucket[queue] += sum
          }
        }
        END {
          for (q in bucket) print q, bucket[q] + 0
        }
      ' /proc/interrupts | sort -n
    )
  done
}

collect_ksoftirqd_ticks() {
  local -n out="$1"
  out=()
  while read -r pid comm; do
    [[ -z "$pid" || -z "$comm" ]] && continue
    out["$comm"]="$(read_proc_ticks "$pid")"
  done < <(ps -e -o pid= -o comm= | awk '$2 ~ /^ksoftirqd\// {print $1, $2}')
}

collect_irq_thread_ticks() {
  local -n out="$1"
  out=()
  while read -r pid comm; do
    [[ -z "$pid" || -z "$comm" ]] && continue
    out["$comm"]="$(read_proc_ticks "$pid")"
  done < <(
    ps -e -o pid= -o comm= | awk -v ifaces="$IFACES" '
      BEGIN {
        split(ifaces, raw, ",")
        count = 0
        for (i in raw) {
          gsub(/^[ \t]+|[ \t]+$/, "", raw[i])
          if (raw[i] != "") iface[++count] = raw[i]
        }
      }
      $2 ~ /^irq\// {
        for (i = 1; i <= count; i++) {
          if (index($2, iface[i]) > 0) {
            print $1, $2
            break
          }
        }
      }
    '
  )
}

mbps_by_iface() {
  local -n before="$1"
  local -n after="$2"
  local duration="$3"
  local parts=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    local delta=$(( ${after[$iface]:-0} - ${before[$iface]:-0} ))
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
    parts+=("$iface=$(( ${after[$iface]:-0} - ${before[$iface]:-0} ))")
  done
  local oldifs="$IFS"
  IFS=';'
  echo "${parts[*]}"
  IFS="$oldifs"
}

irq_queue_delta_by_iface() {
  local -n before="$1"
  local -n after="$2"
  local iface_parts=()
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    local queue_parts=()
    while read -r key; do
      [[ -z "$key" ]] && continue
      local queue="${key#${iface}:}"
      local delta=$(( ${after[$key]:-0} - ${before[$key]:-0} ))
      queue_parts+=("q${queue}:$delta")
    done < <(printf '%s\n' "${!before[@]}" "${!after[@]}" | awk -v prefix="${iface}:" 'index($0, prefix) == 1' | sort -u -t: -k2,2n)

    local joined=""
    if [[ "${#queue_parts[@]}" -gt 0 ]]; then
      local oldifs="$IFS"
      IFS='|'
      joined="${queue_parts[*]}"
      IFS="$oldifs"
    fi
    iface_parts+=("$iface=$joined")
  done

  local oldifs="$IFS"
  IFS=';'
  echo "${iface_parts[*]}"
  IFS="$oldifs"
}

sum_tick_delta() {
  local -n before="$1"
  local -n after="$2"
  local total=0
  while read -r key; do
    [[ -z "$key" ]] && continue
    total=$((total + ${after[$key]:-0} - ${before[$key]:-0}))
  done < <(printf '%s\n' "${!before[@]}" "${!after[@]}" | awk 'NF' | sort -u)
  echo "$total"
}

tick_delta_by_name() {
  local -n before="$1"
  local -n after="$2"
  local parts=()
  while read -r key; do
    [[ -z "$key" ]] && continue
    local delta=$(( ${after[$key]:-0} - ${before[$key]:-0} ))
    parts+=("$key=$(ticks_to_seconds "$delta")")
  done < <(printf '%s\n' "${!before[@]}" "${!after[@]}" | awk 'NF' | sort -u)

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

parse_perf_counter() {
  local perf_out="$1"
  local event_name="$2"
  awk -F',' -v name="$event_name" '
    $3 == name || $3 ~ ("^" name "([:@].*)?$") {
      value = $1
      gsub(/[[:space:]]/, "", value)
      if (value == "" || value ~ /^<.*>$/ || value == "notcounted") print "na"
      else print value
      found = 1
      exit
    }
    END {
      if (!found) print "na"
    }
  ' "$perf_out"
}

perf_available() {
  [[ "$ENABLE_PERF" -eq 1 ]] && command -v perf >/dev/null 2>&1 && [[ -n "$PERF_EVENTS" ]]
}

failure_row() {
  local case_label="$1"
  local config_path="$2"
  local state="$3"
  local ops="$4"
  csv_row \
    "$case_label" "$config_path" "false" "$state" "$ops" \
    "0" "0" "0" "0" "0" "0" "0" "0" "0.00" "0.00" "na" "na" "na" \
    "100.00" "0.00" "0.00" "0.00" \
    "" "" "" "" "" "" ""
}

reset_sched_ext_state() {
  "$AGENT_BIN" unload-scheduler --config "$CANDIDATE_CONFIG" >> "$LOG" 2>&1 || true
  "$AGENT_BIN" unload-scheduler --config "$BASELINE_CONFIG" >> "$LOG" 2>&1 || true

  local deadline=$((SECONDS + 10))
  while [[ "$SECONDS" -lt "$deadline" ]]; do
    if [[ "$(read_sched_ext_state)" != "enabled" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "[error] sched_ext still enabled after reset: ops=$(read_sched_ext_ops)" | tee -a "$LOG"
  return 1
}

run_case() {
  local case_label="$1"
  local config_path="$2"
  local scheduler_mode
  scheduler_mode="$(config_scheduler_mode "$config_path")"

  echo "[case] $case_label" | tee -a "$LOG"

  if ! reset_sched_ext_state; then
    failure_row "$case_label" "$config_path" "reset_failed" "$(read_sched_ext_ops)" >> "$CSV"
    return 0
  fi

  if ! "$AGENT_BIN" run --config "$config_path" --once >> "$LOG" 2>&1; then
    failure_row "$case_label" "$config_path" "setup_failed" "unknown" >> "$CSV"
    return 0
  fi

  local setup_state setup_ops
  setup_state="$(read_sched_ext_state)"
  setup_ops="$(read_sched_ext_ops)"
  if [[ "$scheduler_mode" == "custom_bpf" && "$setup_ops" != "landscape_scx" ]]; then
    echo "[error] $case_label expected landscape_scx, got ops=$setup_ops" | tee -a "$LOG"
    failure_row "$case_label" "$config_path" "$setup_state" "$setup_ops" >> "$CSV"
    return 0
  fi
  if [[ "$scheduler_mode" != "custom_bpf" && "$setup_ops" == "landscape_scx" ]]; then
    echo "[error] $case_label expected external scheduler, but ops stayed landscape_scx" | tee -a "$LOG"
    failure_row "$case_label" "$config_path" "$setup_state" "$setup_ops" >> "$CSV"
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

  local total_before busy_before rx_irq_before tx_irq_before softnet_drop_before softnet_sq_before ctxt_before
  read -r total_before busy_before < <(read_cpu_stat)
  rx_irq_before="$(sum_softirq_line NET_RX)"
  tx_irq_before="$(sum_softirq_line NET_TX)"
  softnet_drop_before="$(read_softnet_field 2)"
  softnet_sq_before="$(read_softnet_field 3)"
  ctxt_before="$(read_ctxt)"

  declare -A rx_before tx_before qlow_before qhigh_before irqq_before
  declare -A rx_after tx_after qlow_after qhigh_after irqq_after
  declare -A ksoft_before ksoft_after irqthr_before irqthr_after

  collect_iface_bytes rx_before tx_before
  collect_irq_buckets qlow_before qhigh_before
  collect_irq_queue_totals irqq_before
  collect_ksoftirqd_ticks ksoft_before
  collect_irq_thread_ticks irqthr_before

  local perf_out=""
  local perf_pid=""
  if perf_available; then
    perf_out="$(mktemp /tmp/landscape-scx-profile-ab-perf-XXXX.log)"
    perf stat -x, --no-big-num -a -e "$PERF_EVENTS" -o "$perf_out" sleep "$DURATION_SECS" >> "$LOG" 2>&1 &
    perf_pid="$!"
    cleanup_pids+=("$perf_pid")
  fi

  if [[ -n "$perf_pid" ]]; then
    wait "$perf_pid" >/dev/null 2>&1 || true
  else
    sleep "$DURATION_SECS"
  fi

  local total_after busy_after rx_irq_after tx_irq_after softnet_drop_after softnet_sq_after ctxt_after
  read -r total_after busy_after < <(read_cpu_stat)
  rx_irq_after="$(sum_softirq_line NET_RX)"
  tx_irq_after="$(sum_softirq_line NET_TX)"
  softnet_drop_after="$(read_softnet_field 2)"
  softnet_sq_after="$(read_softnet_field 3)"
  ctxt_after="$(read_ctxt)"

  collect_iface_bytes rx_after tx_after
  collect_irq_buckets qlow_after qhigh_after
  collect_irq_queue_totals irqq_after
  collect_ksoftirqd_ticks ksoft_after
  collect_irq_thread_ticks irqthr_after

  if [[ -n "$ping_pid" ]]; then
    wait "$ping_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$workload_pid" ]]; then
    kill "$workload_pid" >/dev/null 2>&1 || true
    wait "$workload_pid" >/dev/null 2>&1 || true
  fi

  local state ops
  state="$(read_sched_ext_state)"
  ops="$(read_sched_ext_ops)"

  local total_delta=$((total_after - total_before))
  local busy_delta=$((busy_after - busy_before))
  local util="0.00"
  if [[ "$total_delta" -gt 0 ]]; then
    util="$(awk -v b="$busy_delta" -v t="$total_delta" 'BEGIN{printf "%.2f", (b * 100.0) / t}')"
  fi

  local rx_total_before=0 tx_total_before=0 rx_total_after=0 tx_total_after=0
  for item in "${IFACE_ARR[@]}"; do
    local iface="${item// /}"
    rx_total_before=$((rx_total_before + ${rx_before[$iface]:-0}))
    tx_total_before=$((tx_total_before + ${tx_before[$iface]:-0}))
    rx_total_after=$((rx_total_after + ${rx_after[$iface]:-0}))
    tx_total_after=$((tx_total_after + ${tx_after[$iface]:-0}))
  done

  local rx_total_delta=$((rx_total_after - rx_total_before))
  local tx_total_delta=$((tx_total_after - tx_total_before))
  local rx_mbps_total tx_mbps_total
  rx_mbps_total="$(awk -v d="$DURATION_SECS" -v b="$rx_total_delta" 'BEGIN{if (d > 0) printf "%.2f", (b * 8.0) / (d * 1000 * 1000); else print "0.00"}')"
  tx_mbps_total="$(awk -v d="$DURATION_SECS" -v b="$tx_total_delta" 'BEGIN{if (d > 0) printf "%.2f", (b * 8.0) / (d * 1000 * 1000); else print "0.00"}')"

  local rx_by_iface tx_by_iface
  rx_by_iface="$(mbps_by_iface rx_before rx_after "$DURATION_SECS")"
  tx_by_iface="$(mbps_by_iface tx_before tx_after "$DURATION_SECS")"

  local irqq_by_iface qlow_by_iface qhigh_by_iface
  irqq_by_iface="$(irq_queue_delta_by_iface irqq_before irqq_after)"
  qlow_by_iface="$(irq_delta_by_iface qlow_before qlow_after)"
  qhigh_by_iface="$(irq_delta_by_iface qhigh_before qhigh_after)"

  local ping_loss="na" ping_avg="na" ping_p95="na" ping_max="na"
  if [[ "$PING_ENABLED" -eq 1 && -n "$ping_out" ]]; then
    read -r ping_loss ping_avg ping_p95 ping_max < <(extract_ping_stats "$ping_out")
    rm -f "$ping_out"
  fi

  local rx_irq_delta=$((rx_irq_after - rx_irq_before))
  local tx_irq_delta=$((tx_irq_after - tx_irq_before))
  local softnet_drop_delta=$((softnet_drop_after - softnet_drop_before))
  local softnet_sq_delta=$((softnet_sq_after - softnet_sq_before))
  local ctxt_delta=$((ctxt_after - ctxt_before))

  local ksoft_ticks irqthr_ticks
  ksoft_ticks="$(sum_tick_delta ksoft_before ksoft_after)"
  irqthr_ticks="$(sum_tick_delta irqthr_before irqthr_after)"
  local ksoft_secs irqthr_secs
  ksoft_secs="$(ticks_to_seconds "$ksoft_ticks")"
  irqthr_secs="$(ticks_to_seconds "$irqthr_ticks")"
  local ksoft_by_comm irqthr_by_comm
  ksoft_by_comm="$(tick_delta_by_name ksoft_before ksoft_after)"
  irqthr_by_comm="$(tick_delta_by_name irqthr_before irqthr_after)"

  local perf_cache_misses="na"
  local perf_cache_refs="na"
  local perf_llc_misses="na"
  if [[ -n "$perf_out" && -f "$perf_out" ]]; then
    perf_cache_misses="$(parse_perf_counter "$perf_out" "cache-misses")"
    perf_cache_refs="$(parse_perf_counter "$perf_out" "cache-references")"
    perf_llc_misses="$(parse_perf_counter "$perf_out" "LLC-load-misses")"
    rm -f "$perf_out"
  fi

  {
    echo "[detail][$case_label] softnet_dropped_delta=$softnet_drop_delta softnet_time_squeeze_delta=$softnet_sq_delta"
    echo "[detail][$case_label] irq_queue_delta_by_iface=$irqq_by_iface"
    echo "[detail][$case_label] ksoftirqd_cpu_secs_by_comm=$ksoft_by_comm"
    echo "[detail][$case_label] irq_thread_cpu_secs_by_comm=$irqthr_by_comm"
    echo "[detail][$case_label] perf_cache_misses=$perf_cache_misses perf_cache_references=$perf_cache_refs perf_llc_load_misses=$perf_llc_misses"
  } >> "$LOG"

  csv_row \
    "$case_label" "$config_path" "true" "$state" "$ops" "$util" "$rx_mbps_total" "$tx_mbps_total" \
    "$rx_irq_delta" "$tx_irq_delta" "$softnet_drop_delta" "$softnet_sq_delta" "$ctxt_delta" \
    "$ksoft_secs" "$irqthr_secs" "$perf_cache_misses" "$perf_cache_refs" "$perf_llc_misses" \
    "$ping_loss" "$ping_avg" "$ping_p95" "$ping_max" "$rx_by_iface" "$tx_by_iface" \
    "$irqq_by_iface" "$qlow_by_iface" "$qhigh_by_iface" "$ksoft_by_comm" "$irqthr_by_comm" >> "$CSV"
}

ensure_agent_bin_fresh "$AGENT_BIN"

csv_row \
  "case" "config" "ok" "sched_ext_state" "sched_ext_ops" "cpu_util_pct" "rx_mbps_total" "tx_mbps_total" \
  "net_rx_softirq_delta" "net_tx_softirq_delta" "softnet_dropped_delta" "softnet_time_squeeze_delta" \
  "ctxt_delta" "ksoftirqd_cpu_secs" "irq_thread_cpu_secs" "cache_misses" "cache_references" "llc_load_misses" \
  "ping_loss_pct" "ping_avg_ms" "ping_p95_ms" "ping_max_ms" "rx_mbps_by_iface" "tx_mbps_by_iface" \
  "irq_queue_delta_by_iface" "q0_7_delta_by_iface" "q8plus_delta_by_iface" "ksoftirqd_cpu_secs_by_comm" "irq_thread_cpu_secs_by_comm" > "$CSV"

log_header
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
