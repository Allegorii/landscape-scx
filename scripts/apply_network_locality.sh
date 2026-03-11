#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  apply_network_locality.sh <iface1,iface2,...> <cpu1,cpu2,...> [round_robin|full_mask]

Examples:
  ./scripts/apply_network_locality.sh ens27f0,ens16f1np1 0,2,3,6,7,8,9,10 round_robin
  ./scripts/apply_network_locality.sh ens27f0 0,1,2,3 full_mask
EOF
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage >&2
  exit 1
fi

IFS=',' read -r -a ifaces <<<"$1"
IFS=',' read -r -a cpus <<<"$2"
mode="${3:-round_robin}"

if [[ ${#ifaces[@]} -eq 0 || ${#cpus[@]} -eq 0 ]]; then
  echo "interfaces and cpus must be non-empty" >&2
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

for dev in "${ifaces[@]}"; do
  echo "== $dev =="

  for f in /sys/class/net/"$dev"/queues/tx-*/xps_cpus; do
    [[ -f "$f" ]] || continue
    q="${f%/xps_cpus}"
    q="${q##*/tx-}"
    case "$mode" in
      round_robin)
        cpu="$(assign_cpu "$q")"
        cpu_mask "$cpu" >"$f"
        echo "xps tx-$q -> cpu $cpu"
        ;;
      full_mask)
        full_mask >"$f"
        echo "xps tx-$q -> mask $(full_mask)"
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
  done < <(grep -E "$dev.*TxRx|$dev.*txrx|$dev.*rx|$dev.*tx" /proc/interrupts || true)
done
