/*
 * Default generated scheduler header.
 *
 * The real file is emitted into the custom_bpf build directory and included
 * before this one through the compiler include path. Keep this checked-in copy
 * valid so the source remains buildable even before the runtime generator runs.
 */

#ifndef LANDSCAPE_GEN_TASK_COUNT
#define LANDSCAPE_GEN_TASK_COUNT 0
#endif

#ifndef LANDSCAPE_GEN_QUEUE_COUNT
#define LANDSCAPE_GEN_QUEUE_COUNT 0
#endif

#ifndef LANDSCAPE_GEN_SCX_FLAGS
#define LANDSCAPE_GEN_SCX_FLAGS SCX_OPS_SWITCH_PARTIAL
#endif

#if LANDSCAPE_GEN_QUEUE_COUNT == 0
static const volatile __u32 landscape_gen_queue_owner_cpus[1] = { 0 };
#endif

#if LANDSCAPE_GEN_TASK_COUNT == 0
static const volatile struct landscape_boot_task_ctx landscape_gen_tasks[1] = {
	{ .tid = 0, .qid = 0, .owner_cpu = 0, .flags = 0 },
};
#endif
