/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal queue-island sched_ext scheduler for landscape.
 *
 * The generated header landscape_scx.autogen.h now only carries static
 * scheduler flags. Runtime queue ownership and dataplane task identity are
 * synchronized through BPF maps so queue/task churn doesn't require rebuilding
 * or reloading the scheduler.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LANDSCAPE_MAX_QIDS 128
#define LANDSCAPE_MAX_TASKS 4096
#define LANDSCAPE_DSQ_BASE 0x1000ULL
#define LANDSCAPE_HOUSEKEEPING_DSQ 0x2000ULL
#define LANDSCAPE_SOFTIRQ_DSQ_BASE 0x3000ULL
#define LANDSCAPE_URGENT_DSQ_BASE 0x4000ULL
#define LANDSCAPE_TASK_F_DATAPLANE (1U << 0)
#define LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT 0U
#define LANDSCAPE_TASK_CLASS_DATAPLANE_SHARED 1U
#define LANDSCAPE_TASK_CLASS_CONTROL_PLANE 2U
#define LANDSCAPE_TASK_CLASS_BACKGROUND 3U
#define LANDSCAPE_PRESSURE_LEVEL_NONE 0U
#define LANDSCAPE_PRESSURE_LEVEL_ELEVATED 1U
#define LANDSCAPE_PRESSURE_LEVEL_HIGH 2U
#define LANDSCAPE_HOUSEKEEPING_SLICE (SCX_SLICE_DFL / 4)
#define LANDSCAPE_BACKGROUND_SLICE (SCX_SLICE_DFL / 8)
#define LANDSCAPE_URGENT_WAIT_NS 1000000ULL
#define LANDSCAPE_STRICT_RUN_BUDGET_NS 2000000ULL
#define LANDSCAPE_SOFTIRQ_RUN_BUDGET_NS 1000000ULL
#define PF_KTHREAD 0x00200000
#define SCX_KICK_PREEMPT (1LLU << 1)

#define BPF_STRUCT_OPS(name, args...) SEC("struct_ops/" #name) BPF_PROG(name, ##args)
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) SEC("struct_ops.s/" #name) BPF_PROG(name, ##args)

struct landscape_task_key {
	__u32 pid;
	__u32 tid;
	__u64 start_time_ns;
};

struct landscape_task_ctx {
	__u32 qid;
	__u32 owner_cpu;
	__u32 flags;
	__u32 class;
};

struct landscape_queue_owner_ctx {
	__u32 qid;
	__u32 owner_cpu;
	__u64 dsq_id;
};

struct landscape_queue_pressure_ctx {
	__u32 pressure_level;
	__u32 reserved0;
	__u64 reserved1;
};

struct landscape_task_runtime_ctx {
	__u64 runnable_at_ns;
	__u64 started_at_ns;
	__u64 last_wait_ns;
	__u64 last_run_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LANDSCAPE_MAX_QIDS);
	__type(key, __u32);
	__type(value, struct landscape_queue_owner_ctx);
} qid_owner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LANDSCAPE_MAX_TASKS);
	__type(key, struct landscape_task_key);
	__type(value, struct landscape_task_ctx);
} task_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LANDSCAPE_MAX_QIDS);
	__type(key, __u32);
	__type(value, struct landscape_queue_pressure_ctx);
} qpress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LANDSCAPE_MAX_TASKS);
	__type(key, struct landscape_task_key);
	__type(value, struct landscape_task_runtime_ctx);
} task_runtime_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} hk_cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} hk_defcpu_map SEC(".maps");

#include "landscape_scx.autogen.h"

static __always_inline __u32 task_pid(struct task_struct *p)
{
	return BPF_CORE_READ(p, tgid);
}

static __always_inline __u32 task_tid(struct task_struct *p)
{
	return BPF_CORE_READ(p, pid);
}

static __always_inline __u64 task_start_time_ns(struct task_struct *p)
{
	return BPF_CORE_READ(p, start_time);
}

static __always_inline __u64 dsq_for_qid(__u32 qid)
{
	return LANDSCAPE_DSQ_BASE + qid;
}

static __always_inline __u64 softirq_dsq_for_qid(__u32 qid)
{
	return LANDSCAPE_SOFTIRQ_DSQ_BASE + qid;
}

static __always_inline __u64 urgent_dsq_for_qid(__u32 qid)
{
	return LANDSCAPE_URGENT_DSQ_BASE + qid;
}

static __always_inline bool task_class_is_dataplane(__u32 task_class)
{
	return task_class == LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT ||
	       task_class == LANDSCAPE_TASK_CLASS_DATAPLANE_SHARED;
}

static __always_inline bool task_is_dataplane(const struct landscape_task_ctx *task)
{
	if (!task)
		return false;

	return task_class_is_dataplane(task->class) ||
	       (task->flags & LANDSCAPE_TASK_F_DATAPLANE);
}

static __always_inline bool task_is_percpu_kthread(struct task_struct *p)
{
	return (BPF_CORE_READ(p, flags) & PF_KTHREAD) &&
	       BPF_CORE_READ(p, nr_cpus_allowed) == 1;
}

static __always_inline bool is_housekeeping_cpu(__u32 cpu)
{
	__u8 *value;

	value = bpf_map_lookup_elem(&hk_cpu_map, &cpu);
	return value && *value;
}

static __always_inline bool default_housekeeping_cpu(__u32 *cpu)
{
	__u32 key = 0;
	__u32 *value;

	if (!cpu)
		return false;

	value = bpf_map_lookup_elem(&hk_defcpu_map, &key);
	if (!value)
		return false;

	*cpu = *value;
	return true;
}

static __always_inline __u32 queue_pressure_level(__u32 qid)
{
	struct landscape_queue_pressure_ctx *pressure;

	pressure = bpf_map_lookup_elem(&qpress_map, &qid);
	if (!pressure)
		return LANDSCAPE_PRESSURE_LEVEL_NONE;

	return pressure->pressure_level;
}

static __always_inline __u64 dataplane_slice(__u32 qid)
{
	__u32 pressure = queue_pressure_level(qid);

	if (pressure >= LANDSCAPE_PRESSURE_LEVEL_HIGH)
		return SCX_SLICE_DFL * 4;
	if (pressure >= LANDSCAPE_PRESSURE_LEVEL_ELEVATED)
		return SCX_SLICE_DFL * 2;
	return SCX_SLICE_DFL;
}

static __always_inline __u64 housekeeping_slice(__u32 task_class)
{
	if (task_class == LANDSCAPE_TASK_CLASS_BACKGROUND)
		return LANDSCAPE_BACKGROUND_SLICE;
	return LANDSCAPE_HOUSEKEEPING_SLICE;
}

static __always_inline bool lookup_task_ctx(struct task_struct *p, struct landscape_task_ctx *out)
{
	struct landscape_task_key key = {};
	struct landscape_task_ctx *ctx;

	if (!out)
		return false;

	key.pid = task_pid(p);
	key.tid = task_tid(p);
	key.start_time_ns = task_start_time_ns(p);
	ctx = bpf_map_lookup_elem(&task_ctx_map, &key);
	if (!ctx)
		return false;

	*out = *ctx;
	return true;
}

static __always_inline bool fill_task_key(struct task_struct *p, struct landscape_task_key *out)
{
	if (!out)
		return false;

	out->pid = task_pid(p);
	out->tid = task_tid(p);
	out->start_time_ns = task_start_time_ns(p);
	return true;
}

static __always_inline struct landscape_task_runtime_ctx *
lookup_task_runtime_ctx(const struct landscape_task_key *key)
{
	if (!key)
		return NULL;

	return bpf_map_lookup_elem(&task_runtime_map, key);
}

static __always_inline struct landscape_task_runtime_ctx *
ensure_task_runtime_ctx(struct task_struct *p, struct landscape_task_key *key)
{
	struct landscape_task_runtime_ctx init = {};
	struct landscape_task_runtime_ctx *runtime;

	if (!fill_task_key(p, key))
		return NULL;

	runtime = bpf_map_lookup_elem(&task_runtime_map, key);
	if (runtime)
		return runtime;

	bpf_map_update_elem(&task_runtime_map, key, &init, BPF_NOEXIST);
	return bpf_map_lookup_elem(&task_runtime_map, key);
}

static __always_inline bool task_should_use_urgent_dsq(
	const struct landscape_task_ctx *task,
	const struct landscape_task_runtime_ctx *runtime,
	__u64 now_ns)
{
	if (!task)
		return false;

	if (queue_pressure_level(task->qid) >= LANDSCAPE_PRESSURE_LEVEL_HIGH)
		return true;

	if (!runtime)
		return false;

	if (runtime->last_wait_ns >= LANDSCAPE_URGENT_WAIT_NS)
		return true;

	if (runtime->runnable_at_ns &&
	    now_ns > runtime->runnable_at_ns &&
	    now_ns - runtime->runnable_at_ns >= LANDSCAPE_URGENT_WAIT_NS)
		return true;

	return false;
}

static __always_inline __u64 dataplane_run_budget_ns(
	const struct landscape_task_ctx *task,
	struct task_struct *p)
{
	if (task_is_percpu_kthread(p))
		return LANDSCAPE_SOFTIRQ_RUN_BUDGET_NS;
	if (task && task->class == LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT)
		return LANDSCAPE_STRICT_RUN_BUDGET_NS;
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct landscape_task_ctx task = {};
	__u32 housekeeping_cpu = 0;
	bool is_idle = false;

	if (lookup_task_ctx(p, &task)) {
		switch (task.class) {
		case LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT:
			return task.owner_cpu;
		case LANDSCAPE_TASK_CLASS_DATAPLANE_SHARED:
			if (prev_cpu >= 0 && !is_housekeeping_cpu((__u32)prev_cpu))
				return prev_cpu;
			return task.owner_cpu;
		case LANDSCAPE_TASK_CLASS_CONTROL_PLANE:
		case LANDSCAPE_TASK_CLASS_BACKGROUND:
			break;
		default:
			if (task_is_dataplane(&task))
				return task.owner_cpu;
			break;
		}
	}

	if (prev_cpu >= 0 && is_housekeeping_cpu((__u32)prev_cpu))
		return prev_cpu;

	if (default_housekeeping_cpu(&housekeeping_cpu))
		return housekeeping_cpu;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

s32 BPF_STRUCT_OPS(landscape_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct landscape_task_ctx task = {};
	struct landscape_task_key key = {};
	struct landscape_task_runtime_ctx *runtime;
	__u64 now_ns = bpf_ktime_get_ns();

	if (lookup_task_ctx(p, &task)) {
		if (task_is_dataplane(&task)) {
			runtime = ensure_task_runtime_ctx(p, &key);
			if (runtime && !runtime->runnable_at_ns)
				runtime->runnable_at_ns = now_ns;

			/*
			 * Per-CPU kthreads such as ksoftirqd need a separate
			 * queue from forwarding workers. Sharing a FIFO DSQ lets
			 * queue-bound userspace workers starve softirq progress
			 * long enough to trip sched_ext's watchdog.
			 */
			if (task_is_percpu_kthread(p)) {
				__u64 softirq_dsq = task_should_use_urgent_dsq(&task, runtime, now_ns) ?
					urgent_dsq_for_qid(task.qid) : softirq_dsq_for_qid(task.qid);
				__u64 softirq_flags = enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT;

				scx_bpf_dsq_insert(p, softirq_dsq, SCX_SLICE_DFL, softirq_flags);
				scx_bpf_kick_cpu((s32)task.owner_cpu, SCX_KICK_PREEMPT);
				return 0;
			}

			if (task.class == LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT) {
				__u64 worker_dsq = task_should_use_urgent_dsq(&task, runtime, now_ns) ?
					urgent_dsq_for_qid(task.qid) : dsq_for_qid(task.qid);

				scx_bpf_dsq_insert(p, worker_dsq, dataplane_slice(task.qid),
						 enq_flags | SCX_ENQ_PREEMPT);
				scx_bpf_kick_cpu((s32)task.owner_cpu, SCX_KICK_PREEMPT);
				return 0;
			}

			scx_bpf_dsq_insert(p, dsq_for_qid(task.qid), dataplane_slice(task.qid),
					 enq_flags);
			return 0;
		}

		scx_bpf_dsq_insert(p, LANDSCAPE_HOUSEKEEPING_DSQ,
				 housekeeping_slice(task.class), enq_flags);
		return 0;
	}

	scx_bpf_dsq_insert(p, LANDSCAPE_HOUSEKEEPING_DSQ, LANDSCAPE_HOUSEKEEPING_SLICE,
			 enq_flags);
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_tick, struct task_struct *p)
{
	struct landscape_task_ctx task = {};
	struct landscape_task_key key = {};
	struct landscape_task_runtime_ctx *runtime;
	__u64 now_ns;
	__u64 budget_ns;

	if (!lookup_task_ctx(p, &task) || !task_is_dataplane(&task))
		return 0;

	if (!fill_task_key(p, &key))
		return 0;

	runtime = lookup_task_runtime_ctx(&key);
	if (!runtime || !runtime->started_at_ns)
		return 0;

	budget_ns = dataplane_run_budget_ns(&task, p);
	if (!budget_ns)
		return 0;

	now_ns = bpf_ktime_get_ns();
	if (now_ns <= runtime->started_at_ns ||
	    now_ns - runtime->started_at_ns < budget_ns)
		return 0;

	scx_bpf_kick_cpu((s32)task.owner_cpu, SCX_KICK_PREEMPT);
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_running, struct task_struct *p)
{
	struct landscape_task_ctx task = {};
	struct landscape_task_key key = {};
	struct landscape_task_runtime_ctx *runtime;
	__u64 now_ns;

	if (!lookup_task_ctx(p, &task) || !task_is_dataplane(&task))
		return 0;

	runtime = ensure_task_runtime_ctx(p, &key);
	if (!runtime)
		return 0;

	now_ns = bpf_ktime_get_ns();
	if (runtime->runnable_at_ns && now_ns > runtime->runnable_at_ns)
		runtime->last_wait_ns = now_ns - runtime->runnable_at_ns;
	else
		runtime->last_wait_ns = 0;

	runtime->started_at_ns = now_ns;
	runtime->runnable_at_ns = 0;
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_stopping, struct task_struct *p, bool runnable)
{
	struct landscape_task_ctx task = {};
	struct landscape_task_key key = {};
	struct landscape_task_runtime_ctx *runtime;
	__u64 now_ns;

	if (!lookup_task_ctx(p, &task) || !task_is_dataplane(&task))
		return 0;

	if (!fill_task_key(p, &key))
		return 0;

	runtime = lookup_task_runtime_ctx(&key);
	if (!runtime)
		return 0;

	now_ns = bpf_ktime_get_ns();
	if (runtime->started_at_ns && now_ns > runtime->started_at_ns)
		runtime->last_run_ns = now_ns - runtime->started_at_ns;
	runtime->started_at_ns = 0;
	if (runnable && !runtime->runnable_at_ns)
		runtime->runnable_at_ns = now_ns;

	return 0;
}

s32 BPF_STRUCT_OPS(landscape_dispatch, s32 cpu, struct task_struct *prev)
{
	__u32 owner_cpu = cpu;
	struct landscape_queue_owner_ctx *queue;

	queue = bpf_map_lookup_elem(&qid_owner_map, &owner_cpu);
	if (queue) {
		if (scx_bpf_dsq_move_to_local(urgent_dsq_for_qid(queue->qid)))
			return 0;

		if (scx_bpf_dsq_move_to_local(softirq_dsq_for_qid(queue->qid)))
			return 0;

		if (scx_bpf_dsq_move_to_local(queue->dsq_id))
			return 0;
	}

	if (queue && queue_pressure_level(queue->qid) >= LANDSCAPE_PRESSURE_LEVEL_ELEVATED)
		return 0;

	if (!is_housekeeping_cpu(owner_cpu))
		return 0;

	/*
	 * During full-switch bootstrap the runtime ownership maps are populated
	 * by user space immediately after registration. Until then, fall back to
	 * the housekeeping DSQ so the scheduler can stay alive long enough for the
	 * first map sync to land.
	 */
	if (scx_bpf_dsq_move_to_local(LANDSCAPE_HOUSEKEEPING_DSQ))
		return 0;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(landscape_init)
{
	__u32 qid;

#pragma clang loop unroll(disable)
	for (qid = 0; qid < LANDSCAPE_MAX_QIDS; qid++) {
		scx_bpf_create_dsq(dsq_for_qid(qid), -1);
		scx_bpf_create_dsq(softirq_dsq_for_qid(qid), -1);
		scx_bpf_create_dsq(urgent_dsq_for_qid(qid), -1);
	}
	scx_bpf_create_dsq(LANDSCAPE_HOUSEKEEPING_DSQ, -1);

	return 0;
}

s32 BPF_STRUCT_OPS(landscape_exit, struct scx_exit_info *ei)
{
	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops landscape_scx_ops = {
	.select_cpu		= (void *)landscape_select_cpu,
	.enqueue		= (void *)landscape_enqueue,
	.dispatch		= (void *)landscape_dispatch,
	.tick			= (void *)landscape_tick,
	.running		= (void *)landscape_running,
	.stopping		= (void *)landscape_stopping,
	.init			= (void *)landscape_init,
	.exit			= (void *)landscape_exit,
	.dispatch_max_batch	= 64,
	.flags			= LANDSCAPE_GEN_SCX_FLAGS,
	.name			= "landscape_scx",
};

char LICENSE[] SEC("license") = "GPL";
