use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use landscape_scx_bpf::{
    ensure_scheduler, read_sched_ext_state, sched_ext_enabled, unload_scheduler,
};
use landscape_scx_common::{
    discover_candidates, load_config, try_set_cpu_affinity, try_set_sched_ext, ScxConfig,
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

fn run(config: PathBuf, dry_run: bool, once: bool) -> Result<()> {
    let cfg = load_or_default(config)?;

    if !dry_run {
        ensure_scheduler_with_fallback(&cfg)?;
    }

    loop {
        apply_partial_switch(&cfg, dry_run)?;
        if once {
            break;
        }
        thread::sleep(Duration::from_secs(cfg.agent.apply_interval_secs));
    }

    Ok(())
}

fn apply_partial_switch(cfg: &ScxConfig, dry_run: bool) -> Result<()> {
    let self_pid = std::process::id() as i32;
    let raw_list = discover_candidates(cfg)?;
    let list: Vec<_> = raw_list
        .into_iter()
        .filter(|c| c.pid != self_pid)
        .filter(|c| cfg.policy.manage_ksoftirqd || !c.comm.starts_with("ksoftirqd/"))
        .collect();
    info!("discovered {} candidate threads", list.len());

    if dry_run || !cfg.policy.apply_sched_ext {
        info!("dry-run mode, no sched_setattr syscall will be issued");
        for c in list {
            let affinity_note =
                if should_skip_affinity(&c.comm) { "affinity=skip" } else { "affinity=apply" };
            println!(
                "[DRY] apply SCHED_EXT tid={} comm={} cpus={:?} {}",
                c.tid,
                c.comm,
                target_cpu_set(cfg, &c.comm),
                affinity_note
            );
        }
        return Ok(());
    }

    let mut ok = 0usize;
    let mut fail = 0usize;

    for c in list {
        let cpus = target_cpu_set(cfg, &c.comm);
        if !should_skip_affinity(&c.comm) {
            if let Err(e) = try_set_cpu_affinity(c.tid, &cpus) {
                warn!("affinity failed tid={} comm={} err={}", c.tid, c.comm, e);
            }
        }
        match try_set_sched_ext(c.tid) {
            Ok(_) => {
                ok += 1;
            }
            Err(e) => {
                fail += 1;
                warn!("failed tid={} comm={} err={}", c.tid, c.comm, e);
            }
        }
    }

    info!("partial switch apply finished: success={} failed={}", ok, fail);
    if fail > 0 {
        warn!("some threads were not switched, verify root permission and sched_ext state");
    }
    Ok(())
}

fn target_cpu_set(cfg: &ScxConfig, comm: &str) -> Vec<usize> {
    if comm.starts_with("ksoftirqd/") {
        if cfg.policy.forwarding_cpus.is_empty() {
            return cfg.policy.control_cpus.clone();
        }
        return cfg.policy.forwarding_cpus.clone();
    }
    if cfg.policy.control_cpus.is_empty() {
        return cfg.policy.forwarding_cpus.clone();
    }
    cfg.policy.control_cpus.clone()
}

fn should_skip_affinity(comm: &str) -> bool {
    comm.starts_with("ksoftirqd/")
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
