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
- `bpf/landscape_scx.bpf.c`: queue-island SCX skeleton for the future in-process scheduler.

## Current State

This initial version implements:

- landscape-oriented thread discovery (process names + cmdline keywords)
- scheduler lifecycle (`load/unload`) via external scx command
- partial switch for matched threads (`SCHED_EXT` + CPU affinity)
- optional interface-driven IRQ affinity + XPS placement
- experimental built-in `custom_bpf` scheduler path:
  - generates per-run queue/task intent
  - renders an auto-generated scheduler header
  - compiles `bpf/landscape_scx.bpf.c`
  - registers `landscape_scx` through `bpftool struct_ops`
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

## Network locality

You can also manage IRQ affinity and `xps_cpus` / `xps_rxqs` for selected
interfaces. The simple string form reuses `policy.forwarding_cpus`:

```toml
[network]
interfaces = ["ens27f0", "ens16f1np1"]
apply_irq_affinity = true
apply_xps = true
apply_rss_equal = true
apply_combined_channels = true
clear_inactive_xps = true
queue_mapping_mode = "round_robin"
xps_mode = "cpus"
active_queue_count = 16
```

For per-interface CPU islands or queue-count caps, use table entries:

```toml
[network]
apply_irq_affinity = true
apply_xps = true
apply_rss_equal = true
apply_combined_channels = true
clear_inactive_xps = true
interfaces = [
  { name = "ens27f0", forwarding_cpus = [2, 3, 4, 5], active_queue_count = 4, xps_mode = "cpus" },
  { name = "ens16f1np1", forwarding_cpus = [6, 7, 8, 9], active_queue_count = 4, xps_mode = "rxqs" },
]
```

Supported queue mapping modes:

- `round_robin`: queue `N` maps to `forwarding_cpus[N % len]`
- `full_mask`: every queue gets the full forwarding CPU mask

Supported XPS modes:

- `cpus`: manage `tx-*/xps_cpus`
- `rxqs`: manage `tx-*/xps_rxqs` with queue-index bitmasks

`active_queue_count = 0` means "manage all usable queues"; any positive value
limits management to the first `N` queue IRQs / TX queues for that interface.
When enabled, `apply_rss_equal = true` runs `ethtool -X <iface> equal <N>`,
`apply_combined_channels = true` runs `ethtool -L <iface> combined <N>`, and
`clear_inactive_xps = true` zeros any `tx-*` XPS files above the active queue
limit so old full-queue mappings do not leak traffic back into higher queues.

`status` will print current IRQ/XPS values alongside expected values, and `validate`
will fail if a managed interface or its queue/IRQ files are missing.

For manual fallback outside the agent, use `./scripts/apply_network_locality.sh`.
That helper currently mirrors IRQ/XPS placement only; `ethtool -X/-L` and inactive XPS cleanup are handled by the agent.

## Scheduler lifecycle

`sudo cargo run -p landscape-scx-agent -- load-scheduler --config ./configs/landscape-scx.toml`

`sudo cargo run -p landscape-scx-agent -- unload-scheduler --config ./configs/landscape-scx.toml`

## Validate config

`cargo run -p landscape-scx-agent -- validate --config ./configs/landscape-scx.toml`

When `scheduler.mode = "custom_bpf"`, `validate` also checks the local build
toolchain and compiles the scheduler source into a temporary object. That
surfaces missing `clang`, missing `bpftool`, missing kernel BTF, or broken
`source_file` paths before you try to `run`.

## Health check

`cargo run -p landscape-scx-agent -- health --config ./configs/landscape-scx.toml`

By default `scheduler.start_command = ["scx_cosmos"]`.
You can set another explicit scheduler command if needed.

## Built-in scheduler skeleton

You can also switch `scheduler.mode` to `custom_bpf` to inspect the generated
queue/task intent and drive the experimental built-in loader:

```toml
[scheduler]
mode = "custom_bpf"

[scheduler.custom_bpf]
switch_mode = "partial"
housekeeping_cpus = [0, 1]
forwarding_thread_prefixes = ["landscape-forwarder", "pppoe-rx-"]
source_file = "./bpf/landscape_scx.bpf.c"
build_dir = "/run/landscape-scx/custom-bpf"
link_dir = "/run/landscape-scx/custom-bpf/links"
```

Current limitations:

- the built-in scheduler is still an MVP and defaults to `switch_mode = "partial"`
- only dataplane tasks present in the generated intent are switched into `SCHED_EXT`
- `load-scheduler` now preloads the built-in scheduler with the current
  generated intent, but it does not switch any tasks into `SCHED_EXT`
- the runtime loader requires local `clang`, `bpftool`, kernel BTF, and root privileges
- `validate` checks compile-time prerequisites, but the actual `run` path still
  needs root and `bpftool struct_ops` support from the running kernel

The stable path remains `mode = "external_command"`. Use `custom_bpf` only when
you explicitly want to iterate on the built-in queue-island scheduler.

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
- `configs/profiles/archld-32c-dualwan.toml`
- `configs/profiles/archld-32c-dualwan-8q.toml`
- `configs/profiles/throughput-16c.toml`

See `configs/profiles/README.md` for selection guidance.
