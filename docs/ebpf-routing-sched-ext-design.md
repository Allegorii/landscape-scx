# High-Performance `sched_ext` Design for eBPF Routing

## 1. Scope

This design targets router hosts where the data plane is dominated by:

- RX/TX queue IRQs
- NAPI / softirq packet processing
- `ksoftirqd/N` fallback execution
- userspace forwarding workers such as PPPoE handlers, AF_XDP workers, or route/control-plane helpers

The goal is to improve forwarding throughput and stability by reducing CPU
migration, LLC misses, and run-queue contention around the packet path.

## 2. Hard Constraints

`sched_ext` does not schedule hard IRQ handlers and does not directly schedule
softirq execution in interrupt context. For eBPF routing, this means:

- the biggest wins come from scheduling `ksoftirqd`, threaded IRQ workers, and
  userspace forwarding tasks well
- queue locality must still be established with RSS, IRQ affinity, XPS, and RPS
- the scheduler should treat the network queue layout as the source of truth

This is why the current project already couples queue ownership, IRQ affinity,
and per-thread CPU placement instead of trying to replace NIC locality with a
pure CPU scheduler policy.

## 3. Performance Goals

The scheduler should optimize for:

1. Higher sustained throughput under multi-queue forwarding load
2. Lower packet-path CPU migration and context-switch rates
3. Lower `ksoftirqd` spillover caused by queue-owner CPU interference
4. Lower LLC miss rate by keeping queue-related work on the same CPU island
5. Predictable tail latency during bursts without collapsing fairness for
   housekeeping tasks

The primary success metrics should remain aligned with the existing benchmark
tooling:

- interface throughput
- `NET_RX` / `NET_TX` softirq deltas
- `softnet_stat` drops and `time_squeeze`
- per-queue IRQ deltas
- `ksoftirqd/*` CPU time
- context-switch deltas
- optional LLC/cache miss counters

## 4. Workload Model

For a typical eBPF router, the useful scheduling unit is not the process. It is
the queue pipeline:

`RX queue -> IRQ/NAPI -> eBPF/XDP/tc path -> ksoftirqd fallback or userspace worker -> TX queue`

The scheduler should therefore model each active queue as a queue island:

- one queue island owns one logical queue identifier (`qid`)
- each `qid` has an owner CPU
- all schedulable tasks derived from that queue should stay on the same owner
  CPU by default
- housekeeping and unrelated control-plane work should not run on dataplane
  CPUs unless explicitly allowed

## 5. Core Scheduling Model

### 5.1 Queue Islands

Keep the current per-queue DSQ model and make it the central abstraction:

- one DSQ per active queue
- one shared housekeeping DSQ
- optional one overflow DSQ per LLC domain for controlled work sharing

The existing implementation already has the right foundation in
`bpf/landscape_scx.bpf.c`:

- `qid_owner_map` for queue-to-owner mapping
- `task_ctx_map` for task-to-queue mapping
- a housekeeping CPU map

That should remain the fast path because the lookup cost is stable and the
dispatch decision is simple.

### 5.2 Task Classes

Tasks should be classified into four scheduling classes:

1. `DATAPLANE_STRICT`
   Used for `ksoftirqd/N`, AF_XDP workers, PPPoE RX/TX workers, or other
   queue-bound forwarding threads. These must stay on the owner CPU.
2. `DATAPLANE_SHARED`
   Used for per-interface helpers that are dataplane-related but not tied to a
   single queue. These may run inside the queue's LLC domain.
3. `CONTROL_PLANE`
   Routing daemons, health checks, BGP, stats, and agent threads. These should
   stay on housekeeping CPUs.
4. `BACKGROUND`
   Everything else when `switch_mode = full`. These should go to housekeeping
   DSQs and never preempt queue-owner CPUs unless the dataplane is idle.

The current project already discovers `ksoftirqd` and forwarding workers. The
next step is to represent the class explicitly in the task context map so the
kernel scheduler can make different decisions per class without recompilation.

### 5.3 Owner CPU First

Default rule:

- if the task is `DATAPLANE_STRICT`, `select_cpu` returns `owner_cpu`
- `enqueue` inserts the task into the queue DSQ derived from `qid`
- `dispatch` only consumes the local queue DSQ on that CPU

This keeps the hottest cache lines local:

- socket and skb metadata
- per-queue BPF map state
- route cache / neighbor state touched by the same flow distribution
- userspace ring metadata for AF_XDP-like workloads

### 5.4 Housekeeping Isolation

Reserve a housekeeping CPU set for:

- control plane
- storage
- logging
- watchdogs
- service managers
- transient shell / admin work

For dedicated router hosts, this should be mandatory. For mixed-use hosts, it
should remain configurable but still default away from forwarding CPUs.

## 6. Bounded Sharing Instead of Free Balancing

Pure fairness hurts forwarding locality. Pure pinning can underutilize CPUs when
traffic skews hard to a small queue subset. The design should therefore use
bounded sharing:

- no cross-queue stealing in the normal case
- allow stealing only after queue pressure exceeds a threshold for a sustained
  interval
- only steal within the same LLC domain first
- only expand across NUMA nodes as a last resort

Suggested policy:

- `pressure_level = 0`: strict owner-only execution
- `pressure_level = 1`: allow sibling CPU steal within the same LLC
- `pressure_level = 2`: temporarily widen `DATAPLANE_SHARED` tasks across the
  interface CPU island
- `pressure_level = 3`: operator-visible overload state; keep strict tasks
  local, but move control/background fully off dataplane CPUs

This preserves the main fast path while still giving the system a controlled
escape hatch during bursts or skewed queue distributions.

## 7. Feedback Loop

The roadmap already calls for a policy feedback loop. For routing workloads,
that loop should drive queue pressure rather than generic CPU utilization.

### 7.1 Signals

User space should periodically aggregate:

- `/proc/softirqs` deltas for `NET_RX` and `NET_TX`
- `/proc/net/softnet_stat` dropped and `time_squeeze`
- per-interface per-queue IRQ deltas
- `ksoftirqd/*` runtime deltas
- interface throughput
- optional LLC miss counters

### 7.2 Derived Pressure Indicators

For each queue island, compute:

- `irq_load`
- `ksoftirqd_ratio`
- `drop_rate`
- `time_squeeze_rate`
- `worker_run_ratio`
- `imbalance_score` against peer queues in the same interface

Then write a compact per-queue pressure record into a BPF map. The scheduler
should not perform expensive calculations in-kernel; user space should reduce
the data to a small integer state per queue or per LLC island.

### 7.3 Dynamic Response

Based on pressure state:

- keep strict pinning when queues are healthy
- shorten slices for control-plane work when dataplane pressure rises
- enable same-LLC work sharing only for the overloaded queue island
- if `ksoftirqd_ratio` rises on a queue owner CPU, move non-dataplane tasks off
  that CPU before widening dataplane sharing

That ordering matters because queue-owner interference is often cheaper to fix
than turning on broader balancing.

## 8. Hook Behavior

### 8.1 `select_cpu`

Recommended logic:

- `DATAPLANE_STRICT`: return `owner_cpu`
- `DATAPLANE_SHARED`: return preferred CPU inside `llc_mask[qid]`
- `CONTROL_PLANE` and `BACKGROUND`: choose housekeeping CPU, preferably the
  previous CPU if it is already housekeeping
- fall back to `scx_bpf_select_cpu_dfl()` only for unclassified tasks

### 8.2 `enqueue`

Recommended logic:

- queue-bound dataplane tasks -> `DSQ[qid]`
- shared dataplane tasks -> `DSQ[llc_id]` or the interface-local overflow DSQ
- housekeeping tasks -> housekeeping DSQ
- background tasks in full-switch mode -> housekeeping DSQ with lower priority

### 8.3 `dispatch`

Recommended logic:

1. consume the local queue DSQ
2. if local queue is empty and the CPU is a dataplane CPU, optionally consume
   same-LLC overflow DSQ when pressure sharing is enabled
3. otherwise consume housekeeping DSQ only if this CPU is marked housekeeping

Dataplane CPUs should not regularly drain general-purpose work. That defeats the
point of queue islands.

### 8.4 `init`

Pre-create:

- one queue DSQ per active `qid`
- one housekeeping DSQ
- optional one per-LLC overflow DSQ

Topology maps such as `cpu -> llc_id` should be loaded from user space once and
updated only when topology or configuration changes.

## 9. Required Map Extensions

To support the design above, extend the current BPF data model with:

- `task_ctx.class`
- `task_ctx.llc_id`
- `queue_pressure_map[qid]`
- `cpu_topology_map[cpu] = { llc_id, numa_id, flags }`
- optional `llc_overflow_map[llc_id]`

Keep all runtime-driven values in maps so queue churn, process churn, and policy
updates do not require recompiling the BPF object.

## 10. Integration with the Existing Agent

The current agent already does three useful things:

- builds queue ownership from interface locality plans
- maps `ksoftirqd/N` to queue owners
- maps forwarding workers to interface owners or explicit CPU classes

The next iteration should add:

1. explicit task-class assignment in the generated scheduler intent
2. LLC and NUMA topology discovery
3. pressure-state reduction from benchmark metrics into runtime BPF maps
4. a feedback reconcile loop that can widen or tighten sharing without
   reloading the scheduler

This keeps the control plane in Rust and the dataplane decision path in BPF.

## 11. Deployment Modes

### 11.1 Dedicated Router Host

Use `switch_mode = full` with:

- fixed housekeeping CPUs
- fixed forwarding CPU islands
- aggressive IRQ/XPS locality
- strict dataplane pinning
- bounded same-LLC stealing only under pressure

This should deliver the best throughput and cache locality.

### 11.2 Mixed-Use Host

Use `switch_mode = partial` with:

- only queue-bound dataplane tasks in `SCHED_EXT`
- all other tasks left on CFS or confined to housekeeping
- no cross-island stealing by default

This minimizes blast radius and is the safer rollout mode.

## 12. What Not to Do

Do not design this like a generic desktop or server scheduler:

- do not optimize for global fairness first
- do not round-robin dataplane tasks across all forwarding CPUs
- do not let housekeeping work opportunistically occupy dataplane CPUs
- do not rely on CPU utilization alone as the control signal

For eBPF routing, preserving packet-path locality is usually worth more than
perfect fairness.

## 13. Recommended Implementation Order

1. Keep the current queue-owner fast path unchanged
2. Add explicit task classes to `task_ctx_map`
3. Add LLC-aware overflow DSQs and topology maps
4. Add agent-side queue pressure reduction and runtime map updates
5. Benchmark strict mode versus bounded-sharing mode with the existing A/B
   scripts

This sequence limits risk while exposing the main performance gains early.
