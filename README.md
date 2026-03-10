# landscape-scx

A standalone `sched_ext` project tailored for [landscape](../README.md) deployments.

## Goals

- Improve forwarding consistency by reducing CPU migration and run-queue contention.
- Keep integration low-coupling: no direct code changes in `landscape` are required.
- Provide safe fallback to CFS when `sched_ext` is unavailable.

## Workspace Layout

- `crates/common`: shared config, process/thread discovery, scheduler syscalls.
- `crates/scx-bpf`: scheduler loader/unloader and `sched_ext` state handling.
- `crates/agent`: long-running daemon for discovery + policy application.
- `crates/cli`: operator-facing command wrapper.
- `configs/landscape-scx.toml`: default policy template.
- `systemd/landscape-scx.service`: service unit example.
- `bpf/landscape_scx.bpf.c`: placeholder for future SCX BPF scheduler.

## Current State

This initial version implements:

- landscape-oriented thread discovery (process names + cmdline keywords)
- scheduler lifecycle (`load/unload`) via external scx command
- partial switch for matched threads (`SCHED_EXT` + CPU affinity)
- dry-run and status modes

## Build

```bash
cd landscape-scx
cargo check
```

## Run (dry-run first)

`cargo run -p landscape-scx-agent -- run --config ./configs/landscape-scx.toml --dry-run --once`

## Run with apply

`sudo cargo run -p landscape-scx-agent -- run --config ./configs/landscape-scx.toml`

## Thread-Class CPU placement

You can pin different thread groups to different CPU sets by prefix matching,
and override whether each class should apply `SCHED_EXT` or CPU affinity:

```toml
[policy]
thread_cpu_classes = [
  { thread_name_prefix = "tokio-runtime-w", cpus = [2, 3], apply_sched_ext = true, apply_affinity = true },
  { thread_name_prefix = "sqlx-sqlite-wor", cpus = [4], apply_sched_ext = false, apply_affinity = true },
  { thread_name_prefix = "r2d2-worker-", cpus = [5], apply_sched_ext = false, apply_affinity = true },
]
```

Resolution order is first-match wins.

- `cpus = []` means "inherit the default CPU set for this thread kind".
- `apply_sched_ext` overrides `policy.apply_sched_ext` for that class only.
- `apply_affinity` lets you keep a class on CFS while still pinning it, or skip pinning entirely.

If no class matches, fallback is:
- `ksoftirqd/N` -> CPU `N` (only for CPUs allowed by `policy.ksoftirqd_cpus` or `forwarding_cpus`)
- others -> `control_cpus`

You can also filter threads inside a matched process before any class policy is applied:

```toml
[discovery]
thread_include_prefixes = ["tokio-runtime-w", "sqlx-sqlite-wor", "r2d2-worker-"]
thread_exclude_prefixes = ["tokio-runtime-worker-blocking"]
```

## Scheduler lifecycle

`sudo cargo run -p landscape-scx-agent -- load-scheduler --config ./configs/landscape-scx.toml`

`sudo cargo run -p landscape-scx-agent -- unload-scheduler --config ./configs/landscape-scx.toml`

## Validate config

`cargo run -p landscape-scx-agent -- validate --config ./configs/landscape-scx.toml`

## Health check

`cargo run -p landscape-scx-agent -- health --config ./configs/landscape-scx.toml`

By default `scheduler.start_command = ["scx_cosmos"]`.
You can set another explicit scheduler command if needed.

## Integration With Landscape

Default discovery targets:

- `landscape-webserver`
- `ksoftirqd/N` for CPUs selected by `policy.ksoftirqd_cpus` or `policy.forwarding_cpus`
- optional command-line keyword matching for deployment-specific workers

You can scope by cgroup path to avoid touching unrelated system tasks.

## Install as service

`sudo ./scripts/install.sh`

This installs:

- `/usr/local/bin/landscape-scx-agent`
- `/usr/local/bin/landscape-scx`
- `/etc/landscape-scx/config.toml`
- `/etc/systemd/system/landscape-scx.service`

## Benchmark schedulers

Use the benchmark helper to compare different `scx_*` schedulers quickly:

`sudo ./scripts/bench_schedulers.sh --config ./configs/profiles/throughput-16c.toml --schedulers native,scx_bpfland,scx_lavd --duration 30 --warmup 5`

See `docs/benchmark.md` for details.

For full report mode (throughput + latency + markdown summary):

`sudo ./scripts/bench_schedulers_full.sh --config ./configs/profiles/throughput-16c.toml --schedulers native,scx_bpfland,scx_lavd,scx_rustland --duration 60 --iface eth0 --workload-cmd \"iperf3 -c 192.168.1.2 -t 60 -P 4\"`

For dual/multi-port aggregation mode:

`sudo ./scripts/bench_schedulers_multi.sh --config ./configs/profiles/throughput-16c.toml --schedulers native,scx_cosmos,scx_rusty --duration 60 --warmup 10 --ifaces ens18,ens19`

## Prebuilt Profiles

Common profile templates are available under:

- `configs/profiles/conservative-any.toml`
- `configs/profiles/balanced-4c.toml`
- `configs/profiles/balanced-8c.toml`
- `configs/profiles/low-latency-8c.toml`
- `configs/profiles/landscape-forwarding-8c.toml`
- `configs/profiles/landscape-forwarding-16c.toml`
- `configs/profiles/throughput-16c.toml`

See `configs/profiles/README.md` for selection guidance.
