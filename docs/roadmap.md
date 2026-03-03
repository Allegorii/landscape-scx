# Roadmap

## Phase 1 (done)
- Independent workspace
- landscape-oriented task discovery
- best-effort SCHED_EXT policy assignment
- systemd integration template

## Phase 2
- Add `landscape-scx-bpf` crate and loader (done, external mode)
- Partial switch rollout and rollback path (done)
- Implement builtin SCX scheduler in BPF C (next)

## Phase 3
- Integrate policy feedback loop (softirq + queue depth + packet rate)
- Optional API integration with landscape for dynamic flow-aware scheduling
