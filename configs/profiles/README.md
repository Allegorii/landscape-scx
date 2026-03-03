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

- `throughput-16c.toml`
  - for 16-core hosts prioritizing forwarding throughput
  - wider forwarding domain with more isolated worker pools

## Usage

```bash
cargo run -p landscape-scx-agent -- run --config ./configs/profiles/balanced-8c.toml --once
```

For persistent service usage, copy one profile to `/etc/landscape-scx/config.toml`.
