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
#define LANDSCAPE_TASK_F_DATAPLANE (1U << 0)

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
	__u32 reserved;
};

struct landscape_queue_owner_ctx {
	__u32 qid;
	__u32 owner_cpu;
	__u64 dsq_id;
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

static __always_inline bool lookup_task_ctx(struct task_struct *p, struct landscape_task_ctx *out)
{
	struct landscape_task_key key = {
		.pid = task_pid(p),
		.tid = task_tid(p),
		.start_time_ns = task_start_time_ns(p),
	};
	struct landscape_task_ctx *ctx;

	if (!out)
		return false;

	ctx = bpf_map_lookup_elem(&task_ctx_map, &key);
	if (!ctx)
		return false;

	*out = *ctx;
	return true;
}

s32 BPF_STRUCT_OPS(landscape_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct landscape_task_ctx task = {};
	bool is_idle = false;

	if (lookup_task_ctx(p, &task) && (task.flags & LANDSCAPE_TASK_F_DATAPLANE))
		return task.owner_cpu;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

s32 BPF_STRUCT_OPS(landscape_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct landscape_task_ctx task = {};

	if (lookup_task_ctx(p, &task) && (task.flags & LANDSCAPE_TASK_F_DATAPLANE)) {
		scx_bpf_dsq_insert(p, dsq_for_qid(task.qid), SCX_SLICE_DFL, enq_flags);
		return 0;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_dispatch, s32 cpu, struct task_struct *prev)
{
	__u32 owner_cpu = cpu;
	struct landscape_queue_owner_ctx *queue;

	queue = bpf_map_lookup_elem(&qid_owner_map, &owner_cpu);
	if (queue && scx_bpf_dsq_move_to_local(queue->dsq_id))
		return 0;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(landscape_init)
{
	__u32 qid;

#pragma clang loop unroll(disable)
	for (qid = 0; qid < LANDSCAPE_MAX_QIDS; qid++)
		scx_bpf_create_dsq(dsq_for_qid(qid), -1);

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
	.init			= (void *)landscape_init,
	.exit			= (void *)landscape_exit,
	.dispatch_max_batch	= 64,
	.flags			= LANDSCAPE_GEN_SCX_FLAGS,
	.name			= "landscape_scx",
};

char LICENSE[] SEC("license") = "GPL";
