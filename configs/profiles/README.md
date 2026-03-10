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

- `throughput-16c.toml`
  - for 16-core hosts prioritizing forwarding throughput
  - wider forwarding domain with more isolated worker pools

## Which One To Start With

- For real `landscape-webserver` deployments, prefer `landscape-forwarding-8c.toml` or `landscape-forwarding-16c.toml`
  - these profiles are thread-aware and keep most control-plane workers on control CPUs
  - they only opt selected forwarding-adjacent threads into `SCHED_EXT`

- For first bootstrapping on an unknown machine, start with `conservative-any.toml`
  - use this when you want to verify `sched_ext`, permissions, and basic matching before tuning harder

- Use `balanced-4c.toml`, `balanced-8c.toml`, `low-latency-8c.toml`, and `throughput-16c.toml` as generic baselines or benchmark comparisons
  - these are still useful, but they are broader scheduling templates rather than Landscape-specific defaults
  - they are good A/B candidates when comparing a generic policy against the Landscape-aware profiles

- If your `landscape` instance has extra named threads such as PPPoE or Wi-Fi helpers, treat the Landscape-specific profiles as a starting point, not a final answer
  - refine `thread_include_prefixes`, `thread_exclude_prefixes`, and `thread_cpu_classes` based on the actual thread list from `status` or `ps -eLo pid,tid,comm,cmd`
  - host-tuned profiles like `archld-32c-dualwan.toml` should only be reused after checking WAN IRQ affinity, XPS/RPS masks, and service cgroup layout

## Usage

```bash
cargo run -p landscape-scx-agent -- run --config ./configs/profiles/balanced-8c.toml --once
```

For a Landscape-specific starting point, prefer:

```bash
cargo run -p landscape-scx-agent -- run --config ./configs/profiles/landscape-forwarding-8c.toml --once --dry-run
```

For persistent service usage, copy one profile to `/etc/landscape-scx/config.toml`.
