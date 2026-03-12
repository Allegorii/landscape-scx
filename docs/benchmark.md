# Benchmark Different sched_ext Schedulers

Use the helper script to rotate scheduler binaries and compare basic kernel metrics.

## What it records

- `sched_ext_state`
- overall CPU utilization percentage (delta over window)
- `NET_RX` softirq delta
- `NET_TX` softirq delta
- context switch delta (`ctxt`)

## Run

```bash
sudo ./scripts/bench_schedulers.sh \
  --config ./configs/profiles/throughput-16c.toml \
  --schedulers native,scx_bpfland,scx_lavd,scx_rustland \
  --duration 30 --warmup 5
```

## Full report mode

```bash
sudo ./scripts/bench_schedulers_full.sh \
  --config ./configs/profiles/throughput-16c.toml \
  --schedulers native,scx_bpfland,scx_lavd,scx_rustland \
  --duration 60 --warmup 10 \
  --iface eth0 --ping-target 1.1.1.1 \
  --workload-cmd \"iperf3 -c 192.168.1.2 -t 60 -P 4\"
```

This mode also outputs:

- latency metrics (`loss`, `avg`, `p95`, `max`) from ping samples
- interface throughput estimate (`rx_mbps`, `tx_mbps`)
- markdown report with quick winner summary
  - throughput-first recommendation
  - latency-first recommendation (guards against high max latency outliers)

`native` in scheduler list means CFS baseline (sched_ext unloaded).
`--ping-target` is optional; if omitted, latency fields are marked as `na`.

## Multi-interface summary mode

```bash
sudo ./scripts/bench_schedulers_multi.sh \
  --config ./configs/profiles/throughput-16c.toml \
  --schedulers native,scx_cosmos,scx_rusty \
  --duration 60 --warmup 10 \
  --ifaces ens18,ens19
```

This mode aggregates throughput across multiple interfaces and also outputs
per-interface throughput breakdown fields in CSV/Markdown.

## Profile A/B mode

Use the profile A/B helper when you want to compare two full agent configs
directly, such as `scx_cosmos` vs the built-in `custom_bpf` scheduler on the
same host.

```bash
sudo ./scripts/bench_profile_ab.sh \
  --baseline-config ./configs/profiles/archld-32c-dualwan-8q.toml \
  --candidate-config ./configs/profiles/archld-32c-dualwan-8q-custom-bpf.toml \
  --baseline-label cosmos \
  --candidate-label custom_bpf \
  --ifaces ens27f0,ens16f1np1 \
  --duration 60 --warmup 10
```

This mode records:

- `sched_ext_state` and `sched_ext_ops`
- overall CPU utilization percentage
- aggregate interface throughput and per-interface throughput
- `NET_RX` / `NET_TX` softirq deltas
- `softnet_stat` dropped / time_squeeze deltas
- context switch delta (`ctxt`)
- per-interface per-queue IRQ deltas
- `ksoftirqd/*` CPU time delta
- dataplane `irq/*` thread CPU time delta
- optional `perf stat` counters (`cache-misses`, `cache-references`, `LLC-load-misses`)
- optional ping loss/latency
- per-interface `q0-7` and `q8+` IRQ deltas

Output:

- CSV: `output/bench-ab/profile-ab-<timestamp>.csv`
- Log: `output/bench-ab/profile-ab-<timestamp>.log`

Optional knobs:

- `--perf-events cache-misses,cache-references,LLC-load-misses`
- `--no-perf`

The CSV keeps aggregate fields compact enough for quick comparison, while the
log also records detailed locality diagnostics such as:

- `irq_queue_delta_by_iface`
- `ksoftirqd_cpu_secs_by_comm`
- `irq_thread_cpu_secs_by_comm`
- `softnet_dropped_delta` / `softnet_time_squeeze_delta`

## Output

- CSV: `output/bench/bench-<timestamp>.csv`
- Log: `output/bench/bench-<timestamp>.log`
- Full CSV: `output/bench-full/full-bench-<timestamp>.csv`
- Full Log: `output/bench-full/full-bench-<timestamp>.log`
- Full Report: `output/bench-full/full-bench-<timestamp>.md`

## Notes

- Run on stable traffic and equal workload windows.
- These metrics are intended to explain *why* a profile wins or loses:
  - `softnet_dropped_delta` / `time_squeeze` point to RX backlog pressure
  - per-queue IRQ deltas show whether traffic stays on the intended queue set
  - `ksoftirqd` / `irq/*` CPU time show where dataplane CPU time moved
  - cache / LLC miss counters help spot locality regressions
- Combine them with your own p95/p99 latency and workload-native throughput
  tooling for final decisions.
