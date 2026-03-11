use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use landscape_scx_bpf::{
    ensure_scheduler, read_sched_ext_state, sched_ext_enabled, unload_scheduler,
};
use landscape_scx_common::{
    affinity_list_matches, build_network_locality_plans, discover_candidates, get_sched_policy,
    load_config, parse_ksoftirqd_cpu, read_online_cpus, sched_policy_name, try_set_cpu_affinity,
    try_set_sched_ext, validate_cpu_config, write_irq_affinity, write_xps_cpus, xps_mask_matches,
    ScxConfig, ThreadCpuClass,
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
    let self_pid = std::process::id() as i32;
    let list: Vec<_> =
        discover_candidates(&cfg)?.into_iter().filter(|c| c.pid != self_pid).collect();
    info!(
        "sched_ext state={} enabled={} matched_threads={}",
        read_sched_ext_state(),
        sched_ext_enabled(),
        list.len()
    );
    for c in list {
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
    Ok(())
}

fn load_scheduler(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    ensure_scheduler_with_fallback(&cfg)
}

fn unload_scheduler_cmd(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    unload_scheduler(&cfg.scheduler)
}

fn validate(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;
    let online = read_online_cpus()?;
    info!("config validation passed; online_cpus={:?}", online);
    Ok(())
}

fn run(config: PathBuf, dry_run: bool, once: bool) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;

    if !dry_run {
        ensure_scheduler_with_fallback(&cfg)?;
    }

    loop {
        apply_network_locality(&cfg, dry_run)?;
        apply_partial_switch(&cfg, dry_run)?;
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
    for plan in plans {
        println!(
            "iface={} queue_mapping_mode={:?}",
            plan.interface, cfg.network.queue_mapping_mode
        );

        for irq in &plan.status.irqs {
            let expected = plan.irq_actions.iter().find(|action| action.irq == irq.irq);
            if let Some(expected) = expected {
                println!(
                    "  irq={} label={} affinity={} expected={} status={}",
                    irq.irq,
                    irq.label,
                    irq.affinity_list,
                    expected.affinity_list,
                    if affinity_list_matches(&irq.affinity_list, &expected.cpus) {
                        "ok"
                    } else {
                        "mismatch"
                    }
                );
            } else {
                println!("  irq={} label={} affinity={}", irq.irq, irq.label, irq.affinity_list);
            }
        }

        for queue in &plan.status.tx_queues {
            let expected = plan.xps_actions.iter().find(|action| action.queue_name == queue.name);
            if let Some(expected) = expected {
                println!(
                    "  tx_queue={} xps={} expected={} status={}",
                    queue.name,
                    queue.value,
                    expected.mask,
                    if xps_mask_matches(&queue.value, &expected.cpus) { "ok" } else { "mismatch" }
                );
            } else {
                println!("  tx_queue={} xps={}", queue.name, queue.value);
            }
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

    if dry_run {
        for plan in plans {
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
                    "[DRY][NET] iface={} tx_queue={} xps={} -> {}",
                    action.interface, action.queue_name, action.current_value, action.mask
                );
            }
        }
        return Ok(());
    }

    let mut irq_ok = 0usize;
    let mut irq_fail = 0usize;
    let mut irq_skip = 0usize;
    let mut xps_ok = 0usize;
    let mut xps_fail = 0usize;
    let mut xps_skip = 0usize;

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
            if xps_mask_matches(&action.current_value, &action.cpus) {
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
    }

    info!(
        "network locality apply finished: irq_success={} irq_failed={} irq_skipped={} xps_success={} xps_failed={} xps_skipped={}",
        irq_ok, irq_fail, irq_skip, xps_ok, xps_fail, xps_skip
    );
    if irq_fail > 0 || xps_fail > 0 {
        warn!("some IRQ/XPS locality updates failed, verify root permission and interface state");
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

#[derive(Debug, Clone)]
struct ThreadPolicyAction {
    cpus: Vec<usize>,
    apply_sched_ext: bool,
    apply_affinity: bool,
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
    use super::{thread_policy_action, ScxConfig, ThreadCpuClass};

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
}
