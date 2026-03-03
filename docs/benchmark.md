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
  --schedulers scx_bpfland,scx_lavd,scx_rustland \
  --duration 30 --warmup 5
```

## Full report mode

```bash
sudo ./scripts/bench_schedulers_full.sh \
  --config ./configs/profiles/throughput-16c.toml \
  --schedulers scx_bpfland,scx_lavd,scx_rustland \
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

## Output

- CSV: `output/bench/bench-<timestamp>.csv`
- Log: `output/bench/bench-<timestamp>.log`
- Full CSV: `output/bench-full/full-bench-<timestamp>.csv`
- Full Log: `output/bench-full/full-bench-<timestamp>.log`
- Full Report: `output/bench-full/full-bench-<timestamp>.md`

## Notes

- Run on stable traffic and equal workload windows.
- This script provides coarse-grained system metrics; combine with your own
  p95/p99 latency and throughput tooling for final decisions.
