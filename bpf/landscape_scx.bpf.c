/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal queue-island sched_ext scheduler for landscape.
 *
 * The generated header landscape_scx.autogen.h is emitted by user space from
 * the current queue/task intent. The first runnable version intentionally keeps
 * the dataplane set small and relies on partial switch:
 *
 * - qid -> owner_cpu comes from generated queue owner arrays
 * - tid -> qid/owner_cpu comes from generated dataplane task table
 * - all non-dataplane tasks fall back to SCX_DSQ_GLOBAL
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LANDSCAPE_MAX_QIDS 128
#define LANDSCAPE_DSQ_BASE 0x1000ULL
#define LANDSCAPE_TASK_F_DATAPLANE (1U << 0)

#define BPF_STRUCT_OPS(name, args...) SEC("struct_ops/" #name) BPF_PROG(name, ##args)
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) SEC("struct_ops.s/" #name) BPF_PROG(name, ##args)

struct landscape_boot_task_ctx {
	__u32 tid;
	__u32 qid;
	__u32 owner_cpu;
	__u32 flags;
};

#include "landscape_scx.autogen.h"

static __always_inline __u32 task_tid(struct task_struct *p)
{
	return BPF_CORE_READ(p, pid);
}

static __always_inline bool lookup_boot_task(__u32 tid, struct landscape_boot_task_ctx *out)
{
	__u32 i;

	if (!out)
		return false;

#pragma clang loop unroll(disable)
	for (i = 0; i < LANDSCAPE_GEN_TASK_COUNT; i++) {
		if (landscape_gen_tasks[i].tid != tid)
			continue;

		*out = landscape_gen_tasks[i];
		return true;
	}

	return false;
}

static __always_inline __u64 dsq_for_qid(__u32 qid)
{
	return LANDSCAPE_DSQ_BASE + qid;
}

s32 BPF_STRUCT_OPS(landscape_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct landscape_boot_task_ctx task = {};
	bool is_idle = false;

	if (lookup_boot_task(task_tid(p), &task) && (task.flags & LANDSCAPE_TASK_F_DATAPLANE))
		return task.owner_cpu;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

s32 BPF_STRUCT_OPS(landscape_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct landscape_boot_task_ctx task = {};

	if (lookup_boot_task(task_tid(p), &task) && (task.flags & LANDSCAPE_TASK_F_DATAPLANE)) {
		scx_bpf_dsq_insert(p, dsq_for_qid(task.qid), SCX_SLICE_DFL, enq_flags);
		return 0;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	return 0;
}

s32 BPF_STRUCT_OPS(landscape_dispatch, s32 cpu, struct task_struct *prev)
{
	__u32 qid;

#pragma clang loop unroll(disable)
	for (qid = 0; qid < LANDSCAPE_GEN_QUEUE_COUNT; qid++) {
		if ((__s32)landscape_gen_queue_owner_cpus[qid] != cpu)
			continue;

		if (scx_bpf_dsq_move_to_local(dsq_for_qid(qid)))
			return 0;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(landscape_init)
{
	__u32 qid;

#pragma clang loop unroll(disable)
	for (qid = 0; qid < LANDSCAPE_GEN_QUEUE_COUNT; qid++)
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
