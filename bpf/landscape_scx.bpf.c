/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal queue-island SCX skeleton for landscape.
 *
 * This file is intentionally not wired into the current cargo build yet. The
 * user-space side still launches external sched_ext schedulers by default, and
 * the future in-process loader will be responsible for:
 *
 * - loading this struct_ops program
 * - creating qid_to_cpu / cpu_to_qid / task_to_qid contents
 * - toggling SCX_OPS_SWITCH_PARTIAL vs full switch
 *
 * First intended rollout:
 * - single NIC or small fixed queue set
 * - one DSQ per queue-id
 * - ksoftirqd/<cpu> and explicitly tagged forwarding workers only
 * - partial switch first, full switch later
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * The exact scx helper/header wiring depends on the kernel/libbpf environment
 * used by the future loader. Keep this file as a source-of-truth skeleton for
 * the hook layout and map contract even before the build glue lands.
 */

#define LANDSCAPE_DSQ_BASE 0x1000ULL
#define LANDSCAPE_MAX_QIDS 128
#define LANDSCAPE_TASK_F_DATAPLANE (1U << 0)

struct landscape_queue_ctx {
    __u32 qid;
    __u32 owner_cpu;
    __u64 dsq_id;
};

struct landscape_task_ctx {
    __u32 qid;
    __u32 owner_cpu;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LANDSCAPE_MAX_QIDS);
    __type(key, __u32);
    __type(value, struct landscape_queue_ctx);
} qid_to_cpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} cpu_to_qid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct landscape_task_ctx);
} task_to_qid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} housekeeping_cpus SEC(".maps");

static __always_inline bool landscape_task_is_dataplane(__u32 pid)
{
    struct landscape_task_ctx *task = bpf_map_lookup_elem(&task_to_qid, &pid);

    return task && (task->flags & LANDSCAPE_TASK_F_DATAPLANE);
}

static __always_inline struct landscape_task_ctx *landscape_lookup_task(__u32 pid)
{
    return bpf_map_lookup_elem(&task_to_qid, &pid);
}

static __always_inline struct landscape_queue_ctx *landscape_lookup_queue(__u32 qid)
{
    return bpf_map_lookup_elem(&qid_to_cpu, &qid);
}

/*
 * Hook skeletons:
 *
 * select_cpu()
 *   - dataplane tasks: return owner_cpu[qid]
 *   - housekeeping/other tasks: keep prev_cpu or fall back to generic policy
 *
 * enqueue()
 *   - dataplane tasks: insert into DSQ[qid]
 *   - others: insert into global / housekeeping DSQ
 *
 * dispatch()
 *   - dataplane CPU: consume its queue DSQ first
 *   - housekeeping CPU: consume housekeeping/global DSQ
 *
 * init()
 *   - create DSQ[qid] for all queue ids pre-populated by user space
 *
 * exit()
 *   - export debug/teardown state later
 */

/*
 * Pseudocode only. The final implementation should use the exact helper set
 * provided by the target kernel's sched_ext headers, for example:
 *
 *   scx_bpf_create_dsq()
 *   scx_bpf_dsq_insert()
 *   scx_bpf_move_to_local()
 *   scx_bpf_select_cpu_dfl()
 */

SEC(".struct_ops")
int landscape_select_cpu(void *p, int prev_cpu, unsigned long wake_flags)
{
    /*
     * TODO:
     * 1. lookup task_to_qid[pid]
     * 2. if dataplane, return owner_cpu
     * 3. otherwise fall back to default CPU selection
     */
    return prev_cpu;
}

SEC(".struct_ops")
void landscape_enqueue(void *p, unsigned long enq_flags)
{
    /*
     * TODO:
     * 1. resolve qid from task_to_qid[pid]
     * 2. dataplane -> scx_bpf_dsq_insert(..., LANDSCAPE_DSQ_BASE + qid, ...)
     * 3. non-dataplane -> global/housekeeping DSQ
     */
}

SEC(".struct_ops")
void landscape_dispatch(int cpu, void *prev)
{
    /*
     * TODO:
     * 1. cpu_to_qid[cpu] decides whether this CPU owns a dataplane DSQ
     * 2. dataplane CPU pulls its own DSQ into local DSQ
     * 3. housekeeping CPU pulls housekeeping/global work
     */
}

SEC(".struct_ops")
int landscape_init(void)
{
    /*
     * TODO:
     * iterate qid_to_cpu and create DSQ[ qid ] = LANDSCAPE_DSQ_BASE + qid
     */
    return 0;
}

SEC(".struct_ops")
void landscape_exit(void *ei)
{
    /* TODO: emit exit diagnostics once the loader supports it. */
}

/*
 * Final struct_ops registration will look roughly like:
 *
 * struct sched_ext_ops landscape_scx_ops = {
 *   .select_cpu = (void *)landscape_select_cpu,
 *   .enqueue    = (void *)landscape_enqueue,
 *   .dispatch   = (void *)landscape_dispatch,
 *   .init       = (void *)landscape_init,
 *   .exit       = (void *)landscape_exit,
 *   .name       = "landscape_scx",
 *   .flags      = SCX_OPS_SWITCH_PARTIAL,
 * };
 *
 * The first operational version should keep SCX_OPS_SWITCH_PARTIAL enabled.
 * Full switch belongs to a later milestone after housekeeping/global DSQs are
 * proven out for ordinary SCHED_NORMAL tasks.
 */

char LICENSE[] SEC("license") = "GPL";
