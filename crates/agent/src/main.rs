use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::{collections::BTreeMap, collections::BTreeSet};

use anyhow::Result;
use clap::{Parser, Subcommand};
use landscape_scx_bpf::{
    describe_landscape_scheduler_intent, ensure_landscape_scheduler, ensure_scheduler,
    read_sched_ext_ops, read_sched_ext_state, sched_ext_enabled, unload_scheduler,
    validate_custom_bpf_runtime,
};
use landscape_scx_common::{
    affinity_list_matches, apply_ethtool_combined_channels, apply_ethtool_rss_equal,
    build_network_locality_plans, desired_locality_cpus, discover_candidates, get_sched_policy,
    irqbalance_conflicts, load_config, parse_ksoftirqd_cpu, read_online_cpus, rss_equal_matches,
    sched_policy_name, try_set_cpu_affinity, try_set_sched_ext, validate_cpu_config,
    write_irq_affinity, write_rps_cpus, write_xps_cpus, xps_mask_matches, InterfaceLocalityPlan,
    LandscapeQueueIntent, LandscapeSchedulerIntent, LandscapeTaskIntent, LandscapeTaskKind,
    SchedulerMode, ScxConfig, ThreadCandidate, ThreadCpuClass, LANDSCAPE_DSQ_BASE,
};
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "landscape-scx-agent", version, about = "sched_ext agent for landscape")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    Status {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
    },
    LoadScheduler {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
    },
    UnloadScheduler {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
    },
    Validate {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
    },
    Health {
        #[arg(long, default_value = "/etc/landscape-scx/config.toml")]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "landscape_scx_agent=info".to_string()),
        )
        .init();

    let args = Args::parse();
    match args.cmd {
        Command::Run { config, dry_run, once } => run(config, dry_run, once),
        Command::Status { config } => status(config),
        Command::LoadScheduler { config } => load_scheduler(config),
        Command::UnloadScheduler { config } => unload_scheduler_cmd(config),
        Command::Validate { config } => validate(config),
        Command::Health { config } => health(config),
    }
}

fn status(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    let prepared = if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        Some(prepare_builtin_scheduler_runtime(&cfg)?)
    } else {
        None
    };
    let list = if let Some(prepared) = &prepared {
        prepared.candidates.clone()
    } else {
        let self_pid = std::process::id() as i32;
        discover_candidates(&cfg)?.into_iter().filter(|c| c.pid != self_pid).collect()
    };
    info!(
        "sched_ext state={} enabled={} matched_threads={}",
        read_sched_ext_state(),
        sched_ext_enabled(),
        list.len()
    );
    for c in &list {
        println!(
            "pid={} tid={} comm={} cgroup={} cmdline={}",
            c.pid,
            c.tid,
            c.comm,
            c.cgroup.replace('\n', ";"),
            c.cmdline
        );
    }
    print_network_status(&cfg)?;
    if let Some(prepared) = &prepared {
        print!("{}", describe_landscape_scheduler_intent(&prepared.intent));
    }
    Ok(())
}

fn load_scheduler(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        let prepared = prepare_builtin_scheduler_runtime(&cfg)?;
        info!(
            "builtin scheduler load prepared: queues={} tasks={}",
            prepared.intent.queues.len(),
            prepared.intent.tasks.len()
        );
        ensure_landscape_scheduler_with_fallback(&cfg, &prepared.intent)?;
        apply_builtin_switch_to_candidates(&cfg, &prepared.intent, &prepared.selected, false)
    } else {
        ensure_scheduler_with_fallback(&cfg)
    }
}

fn unload_scheduler_cmd(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    unload_scheduler(&cfg.scheduler)
}

fn validate(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;
    validate_custom_bpf_runtime(&cfg.scheduler)?;
    if irqbalance_conflicts(&cfg) {
        warn!("irqbalance is active while network.apply_irq_affinity=true; it may overwrite manual IRQ affinity");
    }
    let online = read_online_cpus()?;
    info!("config validation passed; online_cpus={:?}", online);
    Ok(())
}

fn run(config: PathBuf, dry_run: bool, once: bool) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;

    if !dry_run && !matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        ensure_scheduler_with_fallback(&cfg)?;
    }

    loop {
        apply_network_locality(&cfg, dry_run)?;
        if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
            run_custom_bpf_cycle(&cfg, dry_run)?;
        } else {
            apply_partial_switch(&cfg, dry_run)?;
        }
        if once {
            break;
        }
        thread::sleep(Duration::from_secs(cfg.agent.apply_interval_secs));
    }

    Ok(())
}

fn print_network_status(cfg: &ScxConfig) -> Result<()> {
    let plans = build_network_locality_plans(cfg)?;
    if plans.is_empty() {
        return Ok(());
    }

    println!("network_locality:");
    if irqbalance_conflicts(cfg) {
        println!("irqbalance=active status=warning");
    }
    for plan in plans {
        println!(
            "iface={} forwarding_cpus={} queue_mapping_mode={:?} xps_mode={:?} rps_mode={:?} active_queues={}/{} irqs={}/{} rxqs={}/{}",
            plan.interface,
            landscape_scx_common::cpu_list_string(&plan.forwarding_cpus),
            plan.queue_mapping_mode,
            plan.xps_mode,
            plan.rps_mode,
            plan.active_queue_count,
            plan.total_tx_queues,
            plan.irq_actions.len(),
            plan.total_irqs,
            plan.active_queue_count.min(plan.total_rx_queues),
            plan.total_rx_queues,
        );

        if let Some(action) = &plan.channel_action {
            println!(
                "  combined_channels={} expected={} max={} status={}",
                action.current_combined,
                action.expected_combined,
                action.max_combined,
                if action.current_combined == action.expected_combined { "ok" } else { "mismatch" }
            );
        }

        if let Some(action) = &plan.rss_action {
            let expected = (0..action.expected_queue_count).collect::<Vec<_>>();
            println!(
                "  rss_equal ring_count={} queues={} expected={} status={}",
                action.current_ring_count,
                landscape_scx_common::cpu_list_string(&action.current_used_queues),
                landscape_scx_common::cpu_list_string(&expected),
                if rss_equal_matches(&action.current_used_queues, action.expected_queue_count) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        if !plan.inactive_xps_actions.is_empty() {
            let zeroed = plan
                .inactive_xps_actions
                .iter()
                .filter(|action| xps_mask_matches(&action.current_value, &action.indices))
                .count();
            println!(
                "  inactive_xps_zeroed={}/{} status={}",
                zeroed,
                plan.inactive_xps_actions.len(),
                if zeroed == plan.inactive_xps_actions.len() { "ok" } else { "mismatch" }
            );
        }

        for action in &plan.irq_actions {
            println!(
                "  irq={} label={} affinity={} expected={} status={}",
                action.irq,
                action.label,
                action.current_affinity_list,
                action.affinity_list,
                if affinity_list_matches(&action.current_affinity_list, &action.cpus) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        for action in &plan.xps_actions {
            println!(
                "  tx_queue={} {}={} expected={} status={}",
                action.queue_name,
                if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                    "xps_cpus"
                } else {
                    "xps_rxqs"
                },
                action.current_value,
                action.mask,
                if xps_mask_matches(&action.current_value, &action.indices) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        if !plan.rps_actions.is_empty() {
            let zeroed = plan
                .rps_actions
                .iter()
                .filter(|action| xps_mask_matches(&action.current_value, &action.indices))
                .count();
            println!(
                "  rps_zeroed={}/{} status={}",
                zeroed,
                plan.rps_actions.len(),
                if zeroed == plan.rps_actions.len() { "ok" } else { "mismatch" }
            );
        }

        for queue in &plan.status.rx_queues {
            println!("  rx_queue={} rps={}", queue.name, queue.value);
        }
    }

    Ok(())
}

fn apply_network_locality(cfg: &ScxConfig, dry_run: bool) -> Result<()> {
    let plans = build_network_locality_plans(cfg)?;
    if plans.is_empty() {
        return Ok(());
    }

    if irqbalance_conflicts(cfg) {
        warn!("irqbalance is active while network.apply_irq_affinity=true; it may overwrite manual IRQ affinity");
    }

    if dry_run {
        for plan in plans {
            if let Some(action) = &plan.channel_action {
                println!(
                    "[DRY][NET] iface={} combined_channels={} -> {}",
                    action.interface, action.current_combined, action.expected_combined
                );
            }
            if let Some(action) = &plan.rss_action {
                println!(
                    "[DRY][NET] iface={} rss_equal={} -> 0-{}",
                    action.interface,
                    landscape_scx_common::cpu_list_string(&action.current_used_queues),
                    action.expected_queue_count.saturating_sub(1)
                );
            }
            for action in &plan.irq_actions {
                println!(
                    "[DRY][NET] iface={} irq={} label={} affinity={} -> {}",
                    action.interface,
                    action.irq,
                    action.label,
                    action.current_affinity_list,
                    action.affinity_list
                );
            }
            for action in &plan.xps_actions {
                println!(
                    "[DRY][NET] iface={} tx_queue={} {}={} -> {}",
                    action.interface,
                    action.queue_name,
                    if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                        "xps_cpus"
                    } else {
                        "xps_rxqs"
                    },
                    action.current_value,
                    action.mask
                );
            }
            for action in &plan.rps_actions {
                println!(
                    "[DRY][NET] iface={} rx_queue={} rps_cpus={} -> {}",
                    action.interface, action.queue_name, action.current_value, action.mask
                );
            }
            for action in &plan.inactive_xps_actions {
                println!(
                    "[DRY][NET] iface={} inactive_tx_queue={} {}={} -> {}",
                    action.interface,
                    action.queue_name,
                    if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                        "xps_cpus"
                    } else {
                        "xps_rxqs"
                    },
                    action.current_value,
                    action.mask
                );
            }
        }
        return Ok(());
    }

    let mut channel_ok = 0usize;
    let mut channel_fail = 0usize;
    let mut channel_skip = 0usize;
    let mut rss_ok = 0usize;
    let mut rss_fail = 0usize;
    let mut rss_skip = 0usize;
    let mut irq_ok = 0usize;
    let mut irq_fail = 0usize;
    let mut irq_skip = 0usize;
    let mut xps_ok = 0usize;
    let mut xps_fail = 0usize;
    let mut xps_skip = 0usize;
    let mut rps_ok = 0usize;
    let mut rps_fail = 0usize;
    let mut rps_skip = 0usize;
    let mut inactive_xps_ok = 0usize;
    let mut inactive_xps_fail = 0usize;
    let mut inactive_xps_skip = 0usize;
    let mut plans = plans;

    // Restore RSS indirection before reducing combined queue count; some drivers
    // reject `ethtool -L combined N` while the indirection table still references
    // queues outside the target range.
    let mut refresh_after_rss = false;
    for plan in &plans {
        if let Some(action) = &plan.rss_action {
            if rss_equal_matches(&action.current_used_queues, action.expected_queue_count) {
                rss_skip += 1;
            } else if let Err(e) = apply_ethtool_rss_equal(action) {
                rss_fail += 1;
                warn!(
                    "rss equal update failed iface={} target={} err={}",
                    action.interface, action.expected_queue_count, e
                );
            } else {
                rss_ok += 1;
                refresh_after_rss = true;
            }
        }
    }

    if refresh_after_rss {
        plans = build_network_locality_plans(cfg)?;
    }

    let mut refresh_after_channels = false;
    for plan in &plans {
        if let Some(action) = &plan.channel_action {
            if action.current_combined == action.expected_combined {
                channel_skip += 1;
            } else if let Err(e) = apply_ethtool_combined_channels(action) {
                channel_fail += 1;
                warn!(
                    "combined queue update failed iface={} current={} target={} err={}",
                    action.interface, action.current_combined, action.expected_combined, e
                );
            } else {
                channel_ok += 1;
                refresh_after_channels = true;
            }
        }
    }

    if refresh_after_channels {
        plans = build_network_locality_plans(cfg)?;
    }

    for plan in plans {
        for action in plan.irq_actions {
            if affinity_list_matches(&action.current_affinity_list, &action.cpus) {
                irq_skip += 1;
                continue;
            }

            if let Err(e) = write_irq_affinity(&action) {
                irq_fail += 1;
                warn!(
                    "irq affinity failed iface={} irq={} label={} err={}",
                    action.interface, action.irq, action.label, e
                );
            } else {
                irq_ok += 1;
            }
        }

        for action in plan.xps_actions {
            if xps_mask_matches(&action.current_value, &action.indices) {
                xps_skip += 1;
                continue;
            }

            if let Err(e) = write_xps_cpus(&action) {
                xps_fail += 1;
                warn!(
                    "xps update failed iface={} tx_queue={} err={}",
                    action.interface, action.queue_name, e
                );
            } else {
                xps_ok += 1;
            }
        }

        for action in plan.rps_actions {
            if xps_mask_matches(&action.current_value, &action.indices) {
                rps_skip += 1;
                continue;
            }

            if let Err(e) = write_rps_cpus(&action) {
                rps_fail += 1;
                warn!(
                    "rps update failed iface={} rx_queue={} err={}",
                    action.interface, action.queue_name, e
                );
            } else {
                rps_ok += 1;
            }
        }

        for action in plan.inactive_xps_actions {
            if xps_mask_matches(&action.current_value, &action.indices) {
                inactive_xps_skip += 1;
                continue;
            }

            if let Err(e) = write_xps_cpus(&action) {
                inactive_xps_fail += 1;
                warn!(
                    "inactive xps cleanup failed iface={} tx_queue={} err={}",
                    action.interface, action.queue_name, e
                );
            } else {
                inactive_xps_ok += 1;
            }
        }
    }

    info!(
        "network locality apply finished: channel_success={} channel_failed={} channel_skipped={} rss_success={} rss_failed={} rss_skipped={} irq_success={} irq_failed={} irq_skipped={} xps_success={} xps_failed={} xps_skipped={} rps_success={} rps_failed={} rps_skipped={} inactive_xps_success={} inactive_xps_failed={} inactive_xps_skipped={}",
        channel_ok,
        channel_fail,
        channel_skip,
        rss_ok,
        rss_fail,
        rss_skip,
        irq_ok,
        irq_fail,
        irq_skip,
        xps_ok,
        xps_fail,
        xps_skip,
        rps_ok,
        rps_fail,
        rps_skip,
        inactive_xps_ok,
        inactive_xps_fail,
        inactive_xps_skip
    );
    if channel_fail > 0
        || rss_fail > 0
        || irq_fail > 0
        || xps_fail > 0
        || rps_fail > 0
        || inactive_xps_fail > 0
    {
        warn!("some network locality updates failed, verify root permission, ethtool support, and interface state");
    }

    Ok(())
}

fn health(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    let self_pid = std::process::id() as i32;
    let list: Vec<_> =
        discover_candidates(&cfg)?.into_iter().filter(|c| c.pid != self_pid).collect();

    let state = std::fs::read_to_string("/sys/kernel/sched_ext/state")
        .unwrap_or_else(|_| "unknown".to_string());
    let ops = std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .unwrap_or_else(|_| "unknown".to_string());

    let mut counts = std::collections::BTreeMap::<i32, usize>::new();
    let mut failed = 0usize;
    for c in &list {
        match get_sched_policy(c.tid) {
            Ok(p) => {
                *counts.entry(p).or_insert(0) += 1;
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    println!("sched_ext_state={}", state.trim());
    println!("sched_ext_ops={}", ops.trim());
    println!("matched_threads={}", list.len());
    println!("policy_distribution:");
    for (policy, cnt) in &counts {
        println!("  {} ({}) = {}", policy, sched_policy_name(*policy), cnt);
    }
    if failed > 0 {
        println!("  read_failed = {}", failed);
    }

    let ext_count = *counts.get(&7).unwrap_or(&0usize);
    println!("sched_ext_threads={}", ext_count);

    if ext_count == 0 {
        warn!("no matched thread is currently in SCHED_EXT");
    } else {
        info!("health check passed: {} matched threads in SCHED_EXT", ext_count);
    }

    Ok(())
}

fn apply_partial_switch(cfg: &ScxConfig, dry_run: bool) -> Result<()> {
    let self_pid = std::process::id() as i32;
    let list: Vec<_> =
        discover_candidates(cfg)?.into_iter().filter(|c| c.pid != self_pid).collect();

    apply_partial_switch_to_candidates(cfg, &list, dry_run)
}

fn run_custom_bpf_cycle(cfg: &ScxConfig, dry_run: bool) -> Result<()> {
    let prepared = prepare_builtin_scheduler_runtime(cfg)?;

    info!(
        "builtin scheduler intent prepared: ops={} queues={} tasks={}",
        read_sched_ext_ops(),
        prepared.intent.queues.len(),
        prepared.intent.tasks.len()
    );
    if dry_run {
        print!("{}", describe_landscape_scheduler_intent(&prepared.intent));
    } else {
        ensure_landscape_scheduler_with_fallback(cfg, &prepared.intent)?;
    }

    apply_builtin_switch_to_candidates(cfg, &prepared.intent, &prepared.selected, dry_run)
}

#[derive(Debug, Clone)]
struct BuiltinSchedulerPrepared {
    candidates: Vec<ThreadCandidate>,
    intent: LandscapeSchedulerIntent,
    selected: Vec<ThreadCandidate>,
}

fn prepare_builtin_scheduler_runtime(cfg: &ScxConfig) -> Result<BuiltinSchedulerPrepared> {
    let self_pid = std::process::id() as i32;
    let candidates: Vec<_> =
        discover_candidates(cfg)?.into_iter().filter(|c| c.pid != self_pid).collect();
    let plans = build_network_locality_plans(cfg)?;
    let intent = build_landscape_scheduler_intent(cfg, &plans, &candidates);
    let selected = select_builtin_scheduler_candidates(&intent, &candidates);

    Ok(BuiltinSchedulerPrepared { candidates, intent, selected })
}

fn apply_partial_switch_to_candidates(
    cfg: &ScxConfig,
    list: &[ThreadCandidate],
    dry_run: bool,
) -> Result<()> {
    info!("discovered {} candidate threads", list.len());

    if dry_run {
        info!("dry-run mode, no scheduler syscalls will be issued");
        for c in list {
            let action = thread_policy_action(cfg, &c.comm);
            println!(
                "[DRY] tid={} comm={} cpus={:?} sched_ext={} affinity={}",
                c.tid,
                c.comm,
                action.cpus,
                if action.apply_sched_ext { "apply" } else { "skip" },
                if action.apply_affinity { "apply" } else { "skip" }
            );
        }
        return Ok(());
    }

    let mut sched_ok = 0usize;
    let mut sched_fail = 0usize;
    let mut sched_skip = 0usize;
    let mut affinity_ok = 0usize;
    let mut affinity_fail = 0usize;
    let mut affinity_skip = 0usize;

    for c in list {
        let action = thread_policy_action(cfg, &c.comm);

        if action.apply_affinity {
            if let Err(e) = try_set_cpu_affinity(c.tid, &action.cpus) {
                affinity_fail += 1;
                warn!("affinity failed tid={} comm={} err={}", c.tid, c.comm, e);
            } else {
                affinity_ok += 1;
            }
        } else {
            affinity_skip += 1;
        }

        if action.apply_sched_ext {
            match try_set_sched_ext(c.tid) {
                Ok(_) => {
                    sched_ok += 1;
                }
                Err(e) => {
                    sched_fail += 1;
                    warn!("failed tid={} comm={} err={}", c.tid, c.comm, e);
                }
            }
        } else {
            sched_skip += 1;
        }
    }

    info!(
        "partial switch apply finished: sched_ext_success={} sched_ext_failed={} sched_ext_skipped={} affinity_success={} affinity_failed={} affinity_skipped={}",
        sched_ok,
        sched_fail,
        sched_skip,
        affinity_ok,
        affinity_fail,
        affinity_skip
    );
    if sched_fail > 0 || affinity_fail > 0 {
        warn!("some threads were not switched, verify root permission and sched_ext state");
    }
    Ok(())
}

fn apply_builtin_switch_to_candidates(
    cfg: &ScxConfig,
    intent: &LandscapeSchedulerIntent,
    list: &[ThreadCandidate],
    dry_run: bool,
) -> Result<()> {
    let intent_actions = intent
        .tasks
        .iter()
        .map(|task| (task.key(), builtin_task_policy_action(task)))
        .collect::<BTreeMap<_, _>>();

    info!("discovered {} candidate threads", list.len());

    if dry_run {
        info!("dry-run mode, no scheduler syscalls will be issued");
        for c in list {
            let action = intent_actions
                .get(&c.task_key())
                .cloned()
                .unwrap_or_else(|| thread_policy_action(cfg, &c.comm));
            println!(
                "[DRY] tid={} comm={} cpus={:?} sched_ext={} affinity={}",
                c.tid,
                c.comm,
                action.cpus,
                if action.apply_sched_ext { "apply" } else { "skip" },
                if action.apply_affinity { "apply" } else { "skip" }
            );
        }
        return Ok(());
    }

    let mut sched_ok = 0usize;
    let mut sched_fail = 0usize;
    let mut sched_skip = 0usize;
    let mut affinity_ok = 0usize;
    let mut affinity_fail = 0usize;
    let mut affinity_skip = 0usize;

    for c in list {
        let action = intent_actions
            .get(&c.task_key())
            .cloned()
            .unwrap_or_else(|| thread_policy_action(cfg, &c.comm));

        if action.apply_affinity {
            if let Err(e) = try_set_cpu_affinity(c.tid, &action.cpus) {
                affinity_fail += 1;
                warn!("affinity failed tid={} comm={} err={}", c.tid, c.comm, e);
            } else {
                affinity_ok += 1;
            }
        } else {
            affinity_skip += 1;
        }

        if action.apply_sched_ext {
            match try_set_sched_ext(c.tid) {
                Ok(_) => {
                    sched_ok += 1;
                }
                Err(e) => {
                    sched_fail += 1;
                    warn!("failed tid={} comm={} err={}", c.tid, c.comm, e);
                }
            }
        } else {
            sched_skip += 1;
        }
    }

    info!(
        "partial switch apply finished: sched_ext_success={} sched_ext_failed={} sched_ext_skipped={} affinity_success={} affinity_failed={} affinity_skipped={}",
        sched_ok,
        sched_fail,
        sched_skip,
        affinity_ok,
        affinity_fail,
        affinity_skip
    );
    if sched_fail > 0 || affinity_fail > 0 {
        warn!("some threads were not switched, verify root permission and sched_ext state");
    }
    Ok(())
}

fn build_landscape_scheduler_intent(
    cfg: &ScxConfig,
    plans: &[InterfaceLocalityPlan],
    candidates: &[ThreadCandidate],
) -> LandscapeSchedulerIntent {
    let housekeeping_cpus = effective_housekeeping_cpus(cfg);
    let mut queues = Vec::new();
    let mut owner_cpu_to_qid = BTreeMap::new();
    let mut interface_first_qid = BTreeMap::new();
    let mut qid = 0u32;

    for plan in plans {
        for queue_index in 0..plan.active_queue_count {
            let Some(owner_cpu) =
                desired_locality_cpus(&plan.forwarding_cpus, &plan.queue_mapping_mode, queue_index)
                    .into_iter()
                    .next()
            else {
                continue;
            };

            owner_cpu_to_qid.insert(owner_cpu, qid);
            interface_first_qid.entry(plan.interface.clone()).or_insert((qid, owner_cpu));
            queues.push(LandscapeQueueIntent {
                qid,
                interface: plan.interface.clone(),
                queue_index,
                owner_cpu,
                dsq_id: LANDSCAPE_DSQ_BASE + qid as u64,
            });
            qid += 1;
        }
    }

    let mut seen = BTreeSet::new();
    let mut tasks = Vec::new();
    for candidate in candidates {
        let task = if let Some(cpu) = parse_ksoftirqd_cpu(&candidate.comm) {
            owner_cpu_to_qid.get(&cpu).copied().map(|qid| LandscapeTaskIntent {
                pid: candidate.pid,
                tid: candidate.tid,
                start_time_ns: candidate.start_time_ns,
                comm: candidate.comm.clone(),
                kind: LandscapeTaskKind::Ksoftirqd,
                qid,
                owner_cpu: cpu,
            })
        } else if matches_forwarding_worker(cfg, &candidate.comm) {
            resolve_forwarding_worker_intent(
                cfg,
                candidate,
                &owner_cpu_to_qid,
                &interface_first_qid,
            )
        } else {
            None
        };

        let Some(task) = task else {
            continue;
        };
        if seen.insert(task.key()) {
            tasks.push(task);
        }
    }

    tasks.sort_by(|a, b| a.qid.cmp(&b.qid).then_with(|| a.key().cmp(&b.key())));

    LandscapeSchedulerIntent {
        switch_mode: cfg.scheduler.custom_bpf.switch_mode.clone(),
        housekeeping_cpus,
        queues,
        tasks,
    }
}

fn effective_housekeeping_cpus(cfg: &ScxConfig) -> Vec<usize> {
    if !cfg.scheduler.custom_bpf.housekeeping_cpus.is_empty() {
        return cfg.scheduler.custom_bpf.housekeeping_cpus.clone();
    }
    if !cfg.policy.control_cpus.is_empty() {
        return cfg.policy.control_cpus.clone();
    }
    cfg.policy.forwarding_cpus.clone()
}

fn matches_forwarding_worker(cfg: &ScxConfig, comm: &str) -> bool {
    cfg.scheduler
        .custom_bpf
        .forwarding_thread_prefixes
        .iter()
        .any(|prefix| !prefix.is_empty() && comm.starts_with(prefix))
}

fn forwarding_worker_requires_interface(comm: &str) -> bool {
    matches!(comm, "pppd") || comm.starts_with("landscape_pppoe") || comm.starts_with("pppoe-rx-")
}

fn resolve_forwarding_worker_interface_owner(
    candidate: &ThreadCandidate,
    interface_first_qid: &BTreeMap<String, (u32, usize)>,
) -> Option<(u32, usize)> {
    interface_first_qid.iter().find_map(|(iface, mapping)| {
        if candidate.cmdline.contains(iface) || candidate.comm.contains(iface) {
            Some(*mapping)
        } else {
            None
        }
    })
}

fn resolve_forwarding_worker_intent(
    cfg: &ScxConfig,
    candidate: &ThreadCandidate,
    owner_cpu_to_qid: &BTreeMap<usize, u32>,
    interface_first_qid: &BTreeMap<String, (u32, usize)>,
) -> Option<LandscapeTaskIntent> {
    if let Some((qid, owner_cpu)) =
        resolve_forwarding_worker_interface_owner(candidate, interface_first_qid)
    {
        return Some(LandscapeTaskIntent {
            pid: candidate.pid,
            tid: candidate.tid,
            start_time_ns: candidate.start_time_ns,
            comm: candidate.comm.clone(),
            kind: LandscapeTaskKind::ForwardingWorker,
            qid,
            owner_cpu,
        });
    }

    // PPP/PPPoE workers are interface-scoped. If their cmdline/comm no longer
    // exposes the attach interface, treat them as stale residual processes
    // instead of falling back to an unrelated owner CPU.
    if forwarding_worker_requires_interface(&candidate.comm) {
        return None;
    }

    let action = thread_policy_action(cfg, &candidate.comm);
    if action.cpus.len() != 1 {
        return None;
    }

    let owner_cpu = action.cpus[0];
    owner_cpu_to_qid.get(&owner_cpu).copied().map(|qid| LandscapeTaskIntent {
        pid: candidate.pid,
        tid: candidate.tid,
        start_time_ns: candidate.start_time_ns,
        comm: candidate.comm.clone(),
        kind: LandscapeTaskKind::ForwardingWorker,
        qid,
        owner_cpu,
    })
}

#[derive(Debug, Clone)]
struct ThreadPolicyAction {
    cpus: Vec<usize>,
    apply_sched_ext: bool,
    apply_affinity: bool,
}

fn builtin_task_policy_action(task: &LandscapeTaskIntent) -> ThreadPolicyAction {
    match task.kind {
        LandscapeTaskKind::Ksoftirqd => ThreadPolicyAction {
            cpus: vec![task.owner_cpu],
            apply_sched_ext: true,
            apply_affinity: false,
        },
        LandscapeTaskKind::ForwardingWorker => ThreadPolicyAction {
            cpus: vec![task.owner_cpu],
            apply_sched_ext: true,
            apply_affinity: true,
        },
    }
}

fn thread_policy_action(cfg: &ScxConfig, comm: &str) -> ThreadPolicyAction {
    let default = default_thread_policy_action(cfg, comm);
    let Some(class) = matching_thread_class(cfg, comm) else {
        return default;
    };

    ThreadPolicyAction {
        cpus: if class.cpus.is_empty() { default.cpus } else { class.cpus.clone() },
        apply_sched_ext: class.apply_sched_ext.unwrap_or(default.apply_sched_ext),
        apply_affinity: class.apply_affinity.unwrap_or(default.apply_affinity),
    }
}

fn default_thread_policy_action(cfg: &ScxConfig, comm: &str) -> ThreadPolicyAction {
    ThreadPolicyAction {
        cpus: default_cpu_set(cfg, comm),
        apply_sched_ext: cfg.policy.apply_sched_ext,
        apply_affinity: parse_ksoftirqd_cpu(comm).is_none(),
    }
}

fn default_cpu_set(cfg: &ScxConfig, comm: &str) -> Vec<usize> {
    if let Some(cpu) = parse_ksoftirqd_cpu(comm) {
        return vec![cpu];
    }

    if cfg.policy.control_cpus.is_empty() {
        return cfg.policy.forwarding_cpus.clone();
    }

    cfg.policy.control_cpus.clone()
}

fn matching_thread_class<'a>(cfg: &'a ScxConfig, comm: &str) -> Option<&'a ThreadCpuClass> {
    cfg.policy.thread_cpu_classes.iter().find(|class| {
        !class.thread_name_prefix.is_empty() && comm.starts_with(&class.thread_name_prefix)
    })
}

fn select_builtin_scheduler_candidates(
    intent: &LandscapeSchedulerIntent,
    candidates: &[ThreadCandidate],
) -> Vec<ThreadCandidate> {
    let task_keys = intent.tasks.iter().map(|task| task.key()).collect::<BTreeSet<_>>();
    candidates.iter().filter(|c| task_keys.contains(&c.task_key())).cloned().collect()
}

fn ensure_scheduler_with_fallback(cfg: &ScxConfig) -> Result<()> {
    match ensure_scheduler(&cfg.scheduler) {
        Ok(()) => {
            info!("scheduler ensure success, sched_ext state={}", read_sched_ext_state());
            Ok(())
        }
        Err(e) => {
            if cfg.scheduler.fallback_on_error {
                warn!("scheduler ensure failed but fallback enabled: {}", e);
                Ok(())
            } else {
                error!("scheduler ensure failed: {}", e);
                Err(e)
            }
        }
    }
}

fn ensure_landscape_scheduler_with_fallback(
    cfg: &ScxConfig,
    intent: &LandscapeSchedulerIntent,
) -> Result<()> {
    match ensure_landscape_scheduler(&cfg.scheduler, intent) {
        Ok(()) => {
            info!(
                "builtin scheduler ensure success, sched_ext state={} ops={}",
                read_sched_ext_state(),
                read_sched_ext_ops()
            );
            Ok(())
        }
        Err(e) => {
            if cfg.scheduler.fallback_on_error {
                warn!("builtin scheduler ensure failed but fallback enabled: {}", e);
                Ok(())
            } else {
                error!("builtin scheduler ensure failed: {}", e);
                Err(e)
            }
        }
    }
}

fn load_or_default(path: PathBuf) -> Result<ScxConfig> {
    if path.exists() {
        load_config(&path)
    } else {
        warn!("config file not found at {}, fallback to built-in defaults", path.display());
        Ok(ScxConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_landscape_scheduler_intent, builtin_task_policy_action, thread_policy_action,
        ScxConfig, ThreadCpuClass,
    };
    use landscape_scx_common::{
        InterfaceLocalityPlan, InterfaceLocalityStatus, LandscapeTaskIntent, LandscapeTaskKind,
        QueueMappingMode, ThreadCandidate, XpsMode,
    };

    #[test]
    fn class_can_disable_sched_ext_without_disabling_affinity() {
        let mut cfg = ScxConfig::default();
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "tokio-runtime-w".into(),
            cpus: vec![6, 7],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let action = thread_policy_action(&cfg, "tokio-runtime-worker");
        assert_eq!(action.cpus, vec![6, 7]);
        assert!(action.apply_affinity);
        assert!(!action.apply_sched_ext);
    }

    #[test]
    fn ksoftirqd_defaults_to_its_own_cpu_and_no_affinity_change() {
        let cfg = ScxConfig::default();
        let action = thread_policy_action(&cfg, "ksoftirqd/3");

        assert_eq!(action.cpus, vec![3]);
        assert!(action.apply_sched_ext);
        assert!(!action.apply_affinity);
    }

    #[test]
    fn builtin_intent_maps_ksoftirqd_cpu_to_queue_owner() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.housekeeping_cpus = vec![6, 7];

        let plan = InterfaceLocalityPlan {
            interface: "eth0".into(),
            forwarding_cpus: vec![2, 3],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "eth0".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        };
        let candidates = vec![
            ThreadCandidate {
                pid: 15,
                tid: 15,
                start_time_ns: 1_500,
                comm: "ksoftirqd/2".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 16,
                tid: 16,
                start_time_ns: 1_600,
                comm: "ksoftirqd/3".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &[plan], &candidates);
        assert_eq!(intent.housekeeping_cpus, vec![6, 7]);
        assert_eq!(intent.queues.len(), 2);
        assert_eq!(intent.tasks.len(), 2);
        assert_eq!(intent.tasks[0].kind, LandscapeTaskKind::Ksoftirqd);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 2);
        assert_eq!(intent.tasks[1].qid, 1);
        assert_eq!(intent.tasks[1].owner_cpu, 3);
    }

    #[test]
    fn builtin_intent_maps_pppd_to_interface_queue_owner() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["pppd".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "pppd".into(),
            cpus: vec![20],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![
            InterfaceLocalityPlan {
                interface: "ens27f0".into(),
                forwarding_cpus: vec![0, 2],
                queue_mapping_mode: QueueMappingMode::RoundRobin,
                xps_mode: XpsMode::Cpus,
                rps_mode: landscape_scx_common::RpsMode::Auto,
                apply_rss_equal: false,
                apply_combined_channels: false,
                clear_inactive_xps: false,
                active_queue_count: 2,
                total_tx_queues: 2,
                total_rx_queues: 2,
                total_irqs: 2,
                status: InterfaceLocalityStatus {
                    interface: "ens27f0".into(),
                    tx_xps_cpus: Vec::new(),
                    tx_xps_rxqs: Vec::new(),
                    rx_queues: Vec::new(),
                    irqs: Vec::new(),
                    channel_status: None,
                    rss_status: None,
                },
                channel_action: None,
                rss_action: None,
                xps_actions: Vec::new(),
                rps_actions: Vec::new(),
                inactive_xps_actions: Vec::new(),
                irq_actions: Vec::new(),
            },
            InterfaceLocalityPlan {
                interface: "ens16f1np1".into(),
                forwarding_cpus: vec![11, 16],
                queue_mapping_mode: QueueMappingMode::RoundRobin,
                xps_mode: XpsMode::Cpus,
                rps_mode: landscape_scx_common::RpsMode::Auto,
                apply_rss_equal: false,
                apply_combined_channels: false,
                clear_inactive_xps: false,
                active_queue_count: 2,
                total_tx_queues: 2,
                total_rx_queues: 2,
                total_irqs: 2,
                status: InterfaceLocalityStatus {
                    interface: "ens16f1np1".into(),
                    tx_xps_cpus: Vec::new(),
                    tx_xps_rxqs: Vec::new(),
                    rx_queues: Vec::new(),
                    irqs: Vec::new(),
                    channel_status: None,
                    rss_status: None,
                },
                channel_action: None,
                rss_action: None,
                xps_actions: Vec::new(),
                rps_actions: Vec::new(),
                inactive_xps_actions: Vec::new(),
                irq_actions: Vec::new(),
            },
        ];
        let candidates = vec![
            ThreadCandidate {
                pid: 200,
                tid: 200,
                start_time_ns: 20_000,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens27f0-h8a".into(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 201,
                tid: 201,
                start_time_ns: 20_100,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens16f1np1-uplink".into(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 2);
        assert_eq!(intent.tasks[0].kind, LandscapeTaskKind::ForwardingWorker);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 0);
        assert_eq!(intent.tasks[1].qid, 2);
        assert_eq!(intent.tasks[1].owner_cpu, 11);
    }

    #[test]
    fn builtin_forwarding_worker_action_forces_sched_ext_on_owner_cpu() {
        let action = builtin_task_policy_action(&LandscapeTaskIntent {
            pid: 15630,
            tid: 15630,
            start_time_ns: 123_456,
            comm: "pppd".into(),
            kind: LandscapeTaskKind::ForwardingWorker,
            qid: 8,
            owner_cpu: 11,
        });

        assert_eq!(action.cpus, vec![11]);
        assert!(action.apply_sched_ext);
        assert!(action.apply_affinity);
    }

    #[test]
    fn builtin_intent_filters_stale_pppd_without_interface_binding() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["pppd".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "pppd".into(),
            cpus: vec![20],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![InterfaceLocalityPlan {
            interface: "ens27f0".into(),
            forwarding_cpus: vec![0, 2],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "ens27f0".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        }];
        let candidates = vec![
            ThreadCandidate {
                pid: 200,
                tid: 200,
                start_time_ns: 20_000,
                comm: "pppd".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 201,
                tid: 201,
                start_time_ns: 20_100,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens27f0-h8a".into(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 1);
        assert_eq!(intent.tasks[0].tid, 201);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 0);
    }

    #[test]
    fn builtin_intent_allows_generic_forwarder_single_cpu_fallback() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["landscape-forwarder".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "landscape-forwarder".into(),
            cpus: vec![11],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![InterfaceLocalityPlan {
            interface: "ens16f1np1".into(),
            forwarding_cpus: vec![11, 16],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "ens16f1np1".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        }];
        let candidates = vec![ThreadCandidate {
            pid: 300,
            tid: 301,
            start_time_ns: 42_000,
            comm: "landscape-forwarder".into(),
            cmdline: String::new(),
            cgroup: String::new(),
        }];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 1);
        assert_eq!(intent.tasks[0].tid, 301);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 11);
    }
}
