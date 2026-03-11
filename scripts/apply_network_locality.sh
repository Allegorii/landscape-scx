#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  apply_network_locality.sh <iface1,iface2,...> <cpu1,cpu2,...> [round_robin|full_mask] [cpus|rxqs] [active_queue_count]

Examples:
  ./scripts/apply_network_locality.sh ens27f0,ens16f1np1 0,2,3,6,7,8,9,10 round_robin cpus 16
  ./scripts/apply_network_locality.sh ens27f0 0,1,2,3 full_mask rxqs 4
EOF
}

if [[ $# -lt 2 || $# -gt 5 ]]; then
  usage >&2
  exit 1
fi

IFS=',' read -r -a ifaces <<<"$1"
IFS=',' read -r -a cpus <<<"$2"
mode="${3:-round_robin}"
xps_mode="${4:-cpus}"
active_queue_count="${5:-0}"

if [[ ${#ifaces[@]} -eq 0 || ${#cpus[@]} -eq 0 ]]; then
  echo "interfaces and cpus must be non-empty" >&2
  exit 1
fi

if ! [[ "$active_queue_count" =~ ^[0-9]+$ ]]; then
  echo "active_queue_count must be an integer" >&2
  exit 1
fi

cpu_mask() {
  local cpu="$1"
  printf '%x\n' "$((1 << cpu))"
}

full_mask() {
  local mask=0
  local cpu
  for cpu in "${cpus[@]}"; do
    mask=$((mask | (1 << cpu)))
  done
  printf '%x\n' "$mask"
}

assign_cpu() {
  local index="$1"
  echo "${cpus[$(( index % ${#cpus[@]} ))]}"
}

queue_mask() {
  local index="$1"
  local total="$2"
  case "$mode" in
    round_robin)
      printf '%x\n' "$((1 << index))"
      ;;
    full_mask)
      local mask=0
      local q
      for ((q=0; q<total; q++)); do
        mask=$((mask | (1 << q)))
      done
      printf '%x\n' "$mask"
      ;;
    *)
      echo "unsupported mode: $mode" >&2
      exit 1
      ;;
  esac
}

queue_is_active() {
  local index="$1"
  [[ "$active_queue_count" -eq 0 || "$index" -lt "$active_queue_count" ]]
}

for dev in "${ifaces[@]}"; do
  echo "== $dev =="

  rx_queue_total=$(find /sys/class/net/"$dev"/queues -maxdepth 1 -type d -name 'rx-*' | wc -l)
  effective_active_queue_count="$active_queue_count"
  if [[ "$effective_active_queue_count" -eq 0 ]]; then
    effective_active_queue_count="$rx_queue_total"
  fi

  xps_file="xps_cpus"
  if [[ "$xps_mode" == "rxqs" ]]; then
    xps_file="xps_rxqs"
  elif [[ "$xps_mode" != "cpus" ]]; then
    echo "unsupported xps mode: $xps_mode" >&2
    exit 1
  fi

  for f in /sys/class/net/"$dev"/queues/tx-*/"$xps_file"; do
    [[ -f "$f" ]] || continue
    q="${f%/$xps_file}"
    q="${q##*/tx-}"
    if ! queue_is_active "$q"; then
      echo "skip tx-$q (outside active_queue_count=$effective_active_queue_count)"
      continue
    fi
    case "$mode" in
      round_robin)
        if [[ "$xps_mode" == "cpus" ]]; then
          cpu="$(assign_cpu "$q")"
          cpu_mask "$cpu" >"$f"
          echo "xps_cpus tx-$q -> cpu $cpu"
        else
          queue_mask "$q" "$effective_active_queue_count" >"$f"
          echo "xps_rxqs tx-$q -> rxq $q"
        fi
        ;;
      full_mask)
        if [[ "$xps_mode" == "cpus" ]]; then
          full_mask >"$f"
          echo "xps_cpus tx-$q -> mask $(full_mask)"
        else
          queue_mask "$q" "$effective_active_queue_count" >"$f"
          echo "xps_rxqs tx-$q -> mask $(queue_mask "$q" "$effective_active_queue_count")"
        fi
        ;;
      *)
        echo "unsupported mode: $mode" >&2
        exit 1
        ;;
    esac
  done

  while read -r line; do
    irq="${line%%:*}"
    label="${line##* }"
    q="${label##*-}"
    if ! queue_is_active "$q"; then
      echo "skip irq $irq ($label) (outside active_queue_count=$effective_active_queue_count)"
      continue
    fi
    case "$mode" in
      round_robin)
        cpu="$(assign_cpu "$q")"
        if [[ -f "/proc/irq/$irq/smp_affinity_list" ]]; then
          echo "$cpu" >"/proc/irq/$irq/smp_affinity_list"
        else
          cpu_mask "$cpu" >"/proc/irq/$irq/smp_affinity"
        fi
        echo "irq $irq ($label) -> cpu $cpu"
        ;;
      full_mask)
        if [[ -f "/proc/irq/$irq/smp_affinity" ]]; then
          full_mask >"/proc/irq/$irq/smp_affinity"
        fi
        echo "irq $irq ($label) -> mask $(full_mask)"
        ;;
    esac
  done < <(grep -E "$dev.*TxRx-[0-9]+|$dev.*txrx-[0-9]+|$dev.*[-_]tx-[0-9]+|$dev.*[-_]rx-[0-9]+" /proc/interrupts || true)
done
