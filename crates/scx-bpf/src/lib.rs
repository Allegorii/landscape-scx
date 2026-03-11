use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use landscape_scx_common::{
    LandscapeSchedulerIntent, LandscapeTaskKind, SchedulerConfig, SchedulerMode,
};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub fn read_sched_ext_state() -> String {
    fs::read_to_string("/sys/kernel/sched_ext/state")
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn sched_ext_enabled() -> bool {
    read_sched_ext_state() == "enabled"
}

pub fn ensure_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    match cfg.mode {
        SchedulerMode::Disabled => Ok(()),
        SchedulerMode::ExternalCommand => ensure_external_scheduler(cfg),
        SchedulerMode::CustomBpf => ensure_custom_bpf_scheduler(cfg),
    }
}

pub fn unload_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    match cfg.mode {
        SchedulerMode::Disabled => Ok(()),
        SchedulerMode::ExternalCommand => unload_external_scheduler(cfg),
        SchedulerMode::CustomBpf => unload_custom_bpf_scheduler(),
    }
}

pub fn load_landscape_scheduler(_intent: &LandscapeSchedulerIntent) -> Result<()> {
    anyhow::bail!(
        "custom_bpf scheduler loader is not wired yet; use `status` to inspect the generated intent and implement BPF struct_ops loading in crates/scx-bpf next"
    )
}

pub fn sync_landscape_scheduler_maps(_intent: &LandscapeSchedulerIntent) -> Result<()> {
    anyhow::bail!(
        "custom_bpf map syncing is not wired yet; the generated intent is available from the agent for future qid_to_cpu/cpu_to_qid/task_to_qid updates"
    )
}

pub fn describe_landscape_scheduler_intent(intent: &LandscapeSchedulerIntent) -> String {
    let mut out = String::new();
    out.push_str("builtin_scheduler_intent:\n");
    out.push_str(&format!("  switch_mode={:?}\n", intent.switch_mode));
    out.push_str(&format!(
        "  housekeeping_cpus={}\n",
        landscape_scx_common::cpu_list_string(&intent.housekeeping_cpus)
    ));
    out.push_str(&format!("  queues={}\n", intent.queues.len()));
    for queue in &intent.queues {
        out.push_str(&format!(
            "    qid={} iface={} queue={} owner_cpu={} dsq=0x{:x}\n",
            queue.qid, queue.interface, queue.queue_index, queue.owner_cpu, queue.dsq_id
        ));
    }

    let ksoftirqd = intent
        .tasks
        .iter()
        .filter(|task| matches!(task.kind, LandscapeTaskKind::Ksoftirqd))
        .count();
    let forwarding = intent
        .tasks
        .iter()
        .filter(|task| matches!(task.kind, LandscapeTaskKind::ForwardingWorker))
        .count();
    out.push_str(&format!(
        "  tasks={} ksoftirqd={} forwarding_workers={}\n",
        intent.tasks.len(),
        ksoftirqd,
        forwarding
    ));
    for task in &intent.tasks {
        out.push_str(&format!(
            "    tid={} pid={} kind={:?} comm={} qid={} owner_cpu={}\n",
            task.tid, task.pid, task.kind, task.comm, task.qid, task.owner_cpu
        ));
    }

    out
}

fn ensure_external_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    if sched_ext_enabled() {
        return Ok(());
    }

    let (program, args) = resolve_start_command(cfg)?;
    let mut cmd = Command::new(&program);
    if !args.is_empty() {
        cmd.args(&args);
    }

    let child = cmd.spawn().with_context(|| {
        format!("failed to spawn scheduler command: program={} args={:?}", program, args)
    })?;

    if let Some(parent) = cfg.pid_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid file dir: {}", parent.display()))?;
    }
    fs::write(&cfg.pid_file, child.id().to_string())
        .with_context(|| format!("failed to write pid file: {}", cfg.pid_file.display()))?;

    wait_for_sched_ext(cfg.ready_timeout_ms)
}

fn ensure_custom_bpf_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    anyhow::bail!(
        "scheduler.mode=custom_bpf is configured with switch_mode={:?}, but the in-process BPF loader is not implemented yet; keep using external_command or inspect the generated intent via `status`",
        cfg.custom_bpf.switch_mode
    )
}

fn resolve_start_command(cfg: &SchedulerConfig) -> Result<(String, Vec<String>)> {
    if !cfg.start_command.is_empty() {
        let program = cfg.start_command[0].clone();
        let args = cfg.start_command[1..].to_vec();
        return Ok((program, args));
    }

    // Auto-detect common sched-ext schedulers shipped by recent scx packages.
    let candidates = [
        "scx_bpfland",
        "scx_lavd",
        "scx_rustland",
        "scx_rlfifo",
        "scx_central",
        "scx_flatcg",
        "scx_nest",
        "scx_pair",
        "scx_qmap",
    ];

    for bin in candidates {
        if executable_in_path(bin) {
            return Ok((bin.to_string(), Vec::new()));
        }
    }

    anyhow::bail!(
        "no scheduler command configured and no known scx binary found in PATH; set scheduler.start_command explicitly"
    )
}

fn executable_in_path(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).exists();
    }

    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|p| p.join(bin).exists())
}

fn unload_external_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    if !cfg.stop_command.is_empty() {
        let mut cmd = Command::new(&cfg.stop_command[0]);
        if cfg.stop_command.len() > 1 {
            cmd.args(&cfg.stop_command[1..]);
        }
        let status = cmd
            .status()
            .with_context(|| format!("failed to execute stop command: {:?}", cfg.stop_command))?;
        if !status.success() {
            anyhow::bail!("stop command failed with status: {status}");
        }
    } else if let Some(pid) = read_pid_file(&cfg.pid_file)? {
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .with_context(|| format!("failed to SIGTERM scheduler pid={pid}"))?;
    }

    let _ = fs::remove_file(&cfg.pid_file);

    // Best-effort wait for state to flip.
    let deadline = Instant::now() + Duration::from_millis(cfg.ready_timeout_ms);
    while Instant::now() < deadline {
        if !sched_ext_enabled() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

fn unload_custom_bpf_scheduler() -> Result<()> {
    anyhow::bail!(
        "custom_bpf unload is not implemented yet; once the struct_ops loader exists, this path should detach the landscape_scx_ops link"
    )
}

fn wait_for_sched_ext(timeout_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if sched_ext_enabled() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!(
        "sched_ext was not enabled within timeout (current state: {})",
        read_sched_ext_state()
    )
}

fn read_pid_file(path: &Path) -> Result<Option<i32>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read pid file: {}", path.display()))?;
    let pid = raw
        .trim()
        .parse::<i32>()
        .with_context(|| format!("invalid pid in {}: {}", path.display(), raw.trim()))?;
    Ok(Some(pid))
}
