# Profile Templates

These templates are designed for common hardware layouts.

## Profiles

- `conservative-any.toml`
  - safest startup profile for unknown CPU topology
  - disables `ksoftirqd` management and avoids aggressive pinning

- `balanced-4c.toml`
  - for 4-core hosts
  - balanced forwarding vs control-plane split

- `balanced-8c.toml`
  - for 8-core hosts
  - balanced split with dedicated DB worker cores

- `low-latency-8c.toml`
  - for 8-core hosts prioritizing forwarding latency
  - more forwarding cores and faster re-apply interval

- `landscape-forwarding-8c.toml`
  - for 8-core `landscape-webserver` deployments
  - thread-aware profile: opts only `ksoftirqd/N` and named PPPoE worker into `SCHED_EXT`
  - pins Tokio / DB / unnamed helper threads to control cores

- `landscape-forwarding-16c.toml`
  - for 16-core `landscape-webserver` deployments
  - same strategy as above with wider forwarding and control domains

- `archld-32c-dualwan.toml`
  - host-tuned profile for the observed `archld` deployment with `ens27f0` and `ens16f1np1` as WAN
  - forwarding CPUs are chosen from measured WAN IRQ hotspots, so re-check IRQ/XPS layout before reusing elsewhere

- `archld-32c-dualwan-8q.toml`
  - host-tuned 8-queue-per-WAN variant for the same `archld` deployment
  - manages `ethtool -X/-L`, inactive XPS cleanup, and queue-locality so queues `0-7` become the dataplane baseline

- `archld-32c-dualwan-8q-custom-bpf.toml`
  - built-in `custom_bpf` variant of the same `archld` 8-queue profile
  - intended for validating queue/task intent with real qids instead of the minimal local loader-only profile
  - includes PPPoE / forwarding-worker prefixes so interface-local WAN workers can join the generated dataplane intent

- `archld-32c-dualwan-autoq-custom-bpf.toml`
  - built-in `custom_bpf` variant for validating topology-aware `active_queue_count = 0`
  - keeps the same WAN CPU islands, but lets the agent auto-size active queues from usable queues and dataplane physical cores
  - also exercises `xps_mode = "auto"` and `rps_mode = "auto"` on the target NIC
  - validated on the `archld` target host: both WAN interfaces resolved to `active_queues=8/8`, `xps_mode=Cpus`, and `rps_zeroed=8/8`
  - on that host this confirms the auto-sizing path ran, but it does not produce a different queue count than the fixed `8q` profile because each WAN already exposes `8` usable queues backed by `8` dataplane physical cores

- `archld-32c-dualwan-8q-custom-bpf-full.toml`
  - full-switch built-in `custom_bpf` variant for dedicated router-host testing
  - keeps the same 8-queue WAN locality but routes non-dataplane tasks through housekeeping CPUs/DSQ instead of leaving the machine in partial mode

- `auto-discover-auto-partition.toml`
  - automatic built-in `custom_bpf` full-switch profile
  - discovers all manageable physical NICs automatically, groups bridge slaves by `master`, and auto-partitions forwarding vs control CPUs from topology
  - supports `auto_discover_include_prefixes` / `auto_discover_exclude_prefixes` when "all manageable NICs" is too broad for the host

- `custom-bpf-local-test.toml`
  - minimal local validation profile for the built-in `custom_bpf` loader
  - does not manage NIC locality or switch any workload threads; it is only for verifying compile/register flow

- `throughput-16c.toml`
  - for 16-core hosts prioritizing forwarding throughput
  - wider forwarding domain with more isolated worker pools

## Which One To Start With

- For real `landscape-webserver` deployments, prefer `landscape-forwarding-8c.toml` or `landscape-forwarding-16c.toml`
  - these profiles are thread-aware and keep most control-plane workers on control CPUs
  - they only opt selected forwarding-adjacent threads into `SCHED_EXT`

- For first bootstrapping on an unknown machine, start with `conservative-any.toml`
  - use this when you want to verify `sched_ext`, permissions, and basic matching before tuning harder

- For dedicated router hosts that should move beyond partial mode, start from `archld-32c-dualwan-8q-custom-bpf-full.toml`
  - this is the aggressive path for evaluating a full `sched_ext` takeover with explicit housekeeping CPUs
  - validate it only after the partial `archld-32c-dualwan-8q-custom-bpf.toml` path is already stable on the target host

- If you want one profile that discovers interfaces and derives CPU islands automatically, start from `auto-discover-auto-partition.toml`
  - this is the least manual path for hosts that should let the agent manage all discoverable dataplane NICs
  - add `auto_discover_include_prefixes` or `auto_discover_exclude_prefixes` when only a subset of interfaces should be managed

- Use `balanced-4c.toml`, `balanced-8c.toml`, `low-latency-8c.toml`, and `throughput-16c.toml` as generic baselines or benchmark comparisons
  - these are still useful, but they are broader scheduling templates rather than Landscape-specific defaults
  - they are good A/B candidates when comparing a generic policy against the Landscape-aware profiles

- If your `landscape` instance has extra named threads such as PPPoE or Wi-Fi helpers, treat the Landscape-specific profiles as a starting point, not a final answer
  - refine `thread_include_prefixes`, `thread_exclude_prefixes`, and `thread_cpu_classes` based on the actual thread list from `status` or `ps -eLo pid,tid,comm,cmd`
  - host-tuned profiles like `archld-32c-dualwan.toml` should only be reused after checking WAN IRQ affinity, XPS/RPS masks, and service cgroup layout
- queue-capped profiles like `archld-32c-dualwan-8q.toml` can now drive RSS / combined queue count directly, but still need validation on the target NIC before production rollout
- auto-sized profiles like `archld-32c-dualwan-autoq-custom-bpf.toml` are useful for checking topology-aware defaults
  - on hosts without SMT or without queue/core asymmetry, `active_queue_count = 0` may legitimately resolve to the same queue count as a hand-tuned fixed profile
  - the real confirmation is that `status` shows resolved `active_queues`, `xps_mode`, and `rps_zeroed` values coming from the agent, not just from static template literals

## Usage

```bash
cargo run -p landscape-scx-agent -- run --config ./configs/profiles/balanced-8c.toml --once
```

For a Landscape-specific starting point, prefer:

```bash
cargo run -p landscape-scx-agent -- run --config ./configs/profiles/landscape-forwarding-8c.toml --once --dry-run
```

For persistent service usage, copy one profile to `/etc/landscape-scx/config.toml`.
