use std::path::PathBuf;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "landscape-scx", version, about = "CLI wrapper for landscape-scx-agent")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,

    #[arg(long, global = true, default_value = "landscape-scx-agent")]
    agent_bin: String,
}

#[derive(Debug, Subcommand)]
enum Cmd {
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
}

fn main() -> ExitCode {
    let args = Args::parse();
    let agent_bin = resolve_agent_bin(&args.agent_bin);

    let mut cmd = Command::new(&agent_bin);
    match args.cmd {
        Cmd::Run { config, dry_run, once } => {
            cmd.arg("run").arg("--config").arg(config);
            if dry_run {
                cmd.arg("--dry-run");
            }
            if once {
                cmd.arg("--once");
            }
        }
        Cmd::Status { config } => {
            cmd.arg("status").arg("--config").arg(config);
        }
        Cmd::LoadScheduler { config } => {
            cmd.arg("load-scheduler").arg("--config").arg(config);
        }
        Cmd::UnloadScheduler { config } => {
            cmd.arg("unload-scheduler").arg("--config").arg(config);
        }
        Cmd::Validate { config } => {
            cmd.arg("validate").arg("--config").arg(config);
        }
    }

    match cmd.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => {
            eprintln!("agent exited with status: {status}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("failed to run {}: {}", agent_bin, e);
            ExitCode::from(1)
        }
    }
}

fn resolve_agent_bin(configured: &str) -> String {
    if std::path::Path::new(configured).exists() {
        return configured.to_string();
    }

    if configured == "landscape-scx-agent" {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("landscape-scx-agent");
                if candidate.exists() {
                    return candidate.to_string_lossy().to_string();
                }
            }
        }
        let local_debug = std::path::Path::new("target/debug/landscape-scx-agent");
        if local_debug.exists() {
            return local_debug.to_string_lossy().to_string();
        }
    }

    configured.to_string()
}
