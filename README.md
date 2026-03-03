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

## Scheduler lifecycle

`sudo cargo run -p landscape-scx-agent -- load-scheduler --config ./configs/landscape-scx.toml`

`sudo cargo run -p landscape-scx-agent -- unload-scheduler --config ./configs/landscape-scx.toml`

By default `scheduler.start_command = []`, and agent auto-detects a scheduler binary
from PATH (`scx_bpfland`, `scx_lavd`, `scx_rustland`, ...). You can also set an explicit command.

## Integration With Landscape

Default discovery targets:

- `landscape-webserver`
- `ksoftirqd/*`
- optional command-line keyword matching for deployment-specific workers

You can scope by cgroup path to avoid touching unrelated system tasks.

## Install as service

`sudo ./scripts/install.sh`

This installs:

- `/usr/local/bin/landscape-scx-agent`
- `/usr/local/bin/landscape-scx`
- `/etc/landscape-scx/config.toml`
- `/etc/systemd/system/landscape-scx.service`
