# TRex LAN Full-Switch Evaluation

This document records the current evaluation boundary for the built-in
`custom_bpf` full-switch scheduler on `archld` using a pure LAN L3 forwarding
topology.

## Scope

This is a validation of:

- full-switch scheduler stability
- steady-state scheduler overhead under small-packet forwarding
- pure kernel L3 forwarding on `ens28f0` and `ens28f1`

This is not a validation of:

- PPPoE / `pppd` forwarding
- WAN uplink performance
- high-pressure rescue behavior under 10G / 25G class load

## Topology

- DUT interfaces:
  - `ens28f0`: `100.100.100.1/24`
  - `ens28f1`: `192.168.88.1/24`
- TRex interfaces:
  - port0: `100.100.100.2/24`
  - port1: `192.168.88.2/24`
- Routed test prefixes:
  - `16.0.0.0/24` via `100.100.100.2`
  - `48.0.0.0/24` via `192.168.88.2`
- DUT queue layout:
  - `ens28f0`: 8 active combined queues
  - `ens28f1`: 8 active combined queues

The test traffic traverses the DUT's kernel L3 forwarding path. It does not
exercise the `pppd` userspace dataplane.

## Profiles

- Baseline:
  - [`configs/profiles/archld-32c-trex-lan-8q.toml`](/home/haolan/landscape/landscape-scx/configs/profiles/archld-32c-trex-lan-8q.toml)
- Candidate:
  - [`configs/profiles/archld-32c-trex-lan-8q-custom-bpf-full.toml`](/home/haolan/landscape/landscape-scx/configs/profiles/archld-32c-trex-lan-8q-custom-bpf-full.toml)

Both profiles use the same queue count, CPU island layout, IRQ affinity, RSS,
and XPS placement. The only intended scheduler difference is `scx_cosmos`
versus built-in `custom_bpf` full-switch.

## Load Model

- TRex generator with 1G NICs
- `64B` small packets
- bidirectional traffic
- observed load: about `2.47 Mpps` aggregate bidirectional

At this load level, the test is close to the practical 1G small-packet limit,
so the traffic generator and link speed materially constrain the result.

## Stability Outcome

The full-switch scheduler was not stable in the initial form. The final
stabilized version required:

- urgent rescue queues for dataplane work
- explicit handling for unknown per-CPU kthreads
- removing unused housekeeping-map pinning
- less aggressive preempt/kick behavior in the steady state

After those fixes, the candidate profile remained:

- `sched_ext_state=enabled`
- `sched_ext_ops=landscape_scx`

under sustained TRex LAN forwarding load, without watchdog fallback.

## A/B Results

Representative result from the final `64B` bidirectional runs:

### Against `scx_cosmos`

| Metric | `scx_cosmos` baseline | `custom_bpf` full-switch |
| --- | ---: | ---: |
| CPU util % | 15.87 | 14.73 |
| RX Mbps total | 1184.23 | 1184.17 |
| TX Mbps total | 1184.15 | 1184.10 |
| `softnet_dropped_delta` | 0 | 0 |
| `softnet_time_squeeze_delta` | 2 | 2 |
| `ctxt_delta` | 171,963 | 164,609 |
| `ksoftirqd_cpu_secs` | 0.04 | 0.03 |
| `pressure_elevated_queues` | 0 | 0 |
| `pressure_high_queues` | 0 | 0 |

### Against pure CFS

| Metric | `CFS` baseline | `custom_bpf` full-switch |
| --- | ---: | ---: |
| CPU util % | 14.58 | 14.56 |
| RX Mbps total | 1184.88 | 1185.98 |
| TX Mbps total | 1184.84 | 1185.93 |
| `softnet_dropped_delta` | 0 | 0 |
| `softnet_time_squeeze_delta` | 1 | 2 |
| `ctxt_delta` | 149,111 | 154,852 |
| `ksoftirqd_cpu_secs` | 0.04 | 0.00 |
| `pressure_elevated_queues` | 0 | 0 |
| `pressure_high_queues` | 0 | 0 |

Interpretation:

- throughput is effectively identical across all three schedulers
- no queue-pressure or `softnet` saturation signal was triggered
- compared with `scx_cosmos`, the candidate is at steady-state overhead parity
  and slightly better on CPU utilization, context switches, and `ksoftirqd`
- compared with pure CFS, the candidate is also effectively at parity:
  throughput is negligibly higher, CPU is flat, `ksoftirqd` time is lower, but
  context switches and `time_squeeze` are not better

## What This Proves

- the built-in full-switch scheduler can now run stably on this host in a pure
  LAN L3 forwarding setup
- the current steady-state overhead is at the same order as both
  `scx_cosmos` and pure CFS in a practical 1G small-packet test

## What This Does Not Prove

- that the built-in scheduler improves throughput in this environment
- that the pressure-aware rescue path is beneficial under true saturation
- that PPPoE / `pppd` forwarding benefits from this scheduler

The reason is straightforward: under 1G TRex load, the DUT never entered a
clear queue-pressure or `softnet` backlog regime. The setup is sufficient to
validate stability and overhead parity, but not to demonstrate a material
performance win.

## Recommended Next Step

To continue performance validation, use at least one of:

- a higher-bandwidth or higher-PPS generator such as 10G / 25G TRex
- a workload that actually drives queue pressure, `softnet time_squeeze`, or
  `ksoftirqd` backlog
- a separate PPPoE-path topology if the target is `pppd` dataplane behavior

Without that higher-pressure environment, further benchmark iteration on this
1G LAN setup is unlikely to produce additional signal.
