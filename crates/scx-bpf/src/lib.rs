use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use landscape_scx_common::{SchedulerConfig, SchedulerMode};
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
    }
}

pub fn unload_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    match cfg.mode {
        SchedulerMode::Disabled => Ok(()),
        SchedulerMode::ExternalCommand => unload_external_scheduler(cfg),
    }
}

fn ensure_external_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    if sched_ext_enabled() {
        return Ok(());
    }

    if cfg.start_command.is_empty() {
        anyhow::bail!("scheduler.start_command is empty");
    }

    let mut cmd = Command::new(&cfg.start_command[0]);
    if cfg.start_command.len() > 1 {
        cmd.args(&cfg.start_command[1..]);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn scheduler command: {:?}", cfg.start_command))?;

    if let Some(parent) = cfg.pid_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid file dir: {}", parent.display()))?;
    }
    fs::write(&cfg.pid_file, child.id().to_string())
        .with_context(|| format!("failed to write pid file: {}", cfg.pid_file.display()))?;

    wait_for_sched_ext(cfg.ready_timeout_ms)
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
