use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use landscape_scx_common::{
    LandscapeSchedulerIntent, LandscapeTaskKind, ScxSwitchMode, SchedulerConfig, SchedulerMode,
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

pub fn read_sched_ext_ops() -> String {
    fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn ensure_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    match cfg.mode {
        SchedulerMode::Disabled => Ok(()),
        SchedulerMode::ExternalCommand => ensure_external_scheduler(cfg),
        SchedulerMode::CustomBpf => ensure_custom_bpf_scheduler(cfg),
    }
}

pub fn validate_custom_bpf_runtime(cfg: &SchedulerConfig) -> Result<()> {
    if !matches!(cfg.mode, SchedulerMode::CustomBpf) {
        return Ok(());
    }

    let source_file = &cfg.custom_bpf.source_file;
    if !source_file.exists() {
        anyhow::bail!(
            "scheduler.custom_bpf.source_file does not exist: {}",
            source_file.display()
        );
    }
    if !source_file.is_file() {
        anyhow::bail!(
            "scheduler.custom_bpf.source_file is not a file: {}",
            source_file.display()
        );
    }
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        anyhow::bail!("missing /sys/kernel/btf/vmlinux; kernel BTF is required for custom_bpf");
    }
    if !Path::new("/usr/include/bpf").exists() {
        anyhow::bail!("missing /usr/include/bpf; install libbpf headers");
    }
    if !command_in_path("bpftool") {
        anyhow::bail!("bpftool not found in PATH");
    }
    if !command_in_path("clang") {
        anyhow::bail!("clang not found in PATH");
    }

    let temp_root = std::env::temp_dir().join(format!(
        "landscape-scx-validate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    let paths = BuiltinSchedulerPaths {
        build_dir: temp_root.clone(),
        link_dir: temp_root.join("links"),
        source_file: source_file.clone(),
        object_file_path: temp_root.join("landscape_scx.bpf.o"),
        vmlinux_header_path: temp_root.join("vmlinux.h"),
        autogen_header_path: temp_root.join("landscape_scx.autogen.h"),
        intent_state_path: temp_root.join("intent.toml"),
    };

    fs::create_dir_all(&paths.build_dir)
        .with_context(|| format!("failed to create {}", paths.build_dir.display()))?;
    let validate_result = (|| {
        write_vmlinux_header(&paths.vmlinux_header_path)?;
        let empty_intent = LandscapeSchedulerIntent {
            switch_mode: cfg.custom_bpf.switch_mode.clone(),
            housekeeping_cpus: cfg.custom_bpf.housekeeping_cpus.clone(),
            queues: Vec::new(),
            tasks: Vec::new(),
        };
        fs::write(&paths.autogen_header_path, render_autogen_header(&empty_intent))
            .with_context(|| format!("failed to write {}", paths.autogen_header_path.display()))?;
        compile_landscape_scheduler_object(&paths)
    })();
    let _ = fs::remove_dir_all(&paths.build_dir);
    validate_result
}

pub fn unload_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    match cfg.mode {
        SchedulerMode::Disabled => Ok(()),
        SchedulerMode::ExternalCommand => unload_external_scheduler(cfg),
        SchedulerMode::CustomBpf => unload_custom_bpf_scheduler(),
    }
}

pub fn load_landscape_scheduler(_intent: &LandscapeSchedulerIntent) -> Result<()> {
    anyhow::bail!("load_landscape_scheduler now requires SchedulerConfig; call ensure_landscape_scheduler() from the agent path")
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

pub fn ensure_landscape_scheduler(
    cfg: &SchedulerConfig,
    intent: &LandscapeSchedulerIntent,
) -> Result<()> {
    if !matches!(cfg.mode, SchedulerMode::CustomBpf) {
        anyhow::bail!("ensure_landscape_scheduler requires scheduler.mode=custom_bpf");
    }

    let paths = builtin_paths(cfg);
    fs::create_dir_all(&paths.build_dir)
        .with_context(|| format!("failed to create {}", paths.build_dir.display()))?;
    fs::create_dir_all(&paths.link_dir)
        .with_context(|| format!("failed to create {}", paths.link_dir.display()))?;

    let intent_state = toml::to_string(intent).context("failed to serialize scheduler intent")?;
    let needs_reload = read_intent_state(&paths.intent_state_path).as_deref() != Some(intent_state.as_str())
        || read_sched_ext_ops() != "landscape_scx"
        || !sched_ext_enabled();

    if !needs_reload {
        return Ok(());
    }

    write_vmlinux_header(&paths.vmlinux_header_path)?;
    fs::write(&paths.autogen_header_path, render_autogen_header(intent))
        .with_context(|| format!("failed to write {}", paths.autogen_header_path.display()))?;
    compile_landscape_scheduler_object(&paths)?;

    let current_ops = read_sched_ext_ops();
    if current_ops == "landscape_scx" {
        unload_custom_bpf_scheduler_by_name()?;
    } else if sched_ext_enabled() {
        anyhow::bail!(
            "sched_ext is already enabled by {}, unload it before loading landscape_scx",
            current_ops
        );
    }
    cleanup_custom_bpf_link_dir(&paths.link_dir)?;

    register_landscape_scheduler_object(&paths)?;
    wait_for_landscape_scheduler(cfg.ready_timeout_ms)?;
    fs::write(&paths.intent_state_path, intent_state)
        .with_context(|| format!("failed to write {}", paths.intent_state_path.display()))?;
    Ok(())
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
        "scheduler.mode=custom_bpf is configured with switch_mode={:?}; this path now requires the agent to provide a scheduler intent, so use `run` / `status` instead of load-scheduler",
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
    command_in_path(bin)
}

fn command_in_path(bin: &str) -> bool {
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
    unload_custom_bpf_scheduler_by_name()
}

fn unload_custom_bpf_scheduler_by_name() -> Result<()> {
    let output = Command::new("bpftool")
        .args(["struct_ops", "unregister", "name", "landscape_scx_ops"])
        .output()
        .context("failed to execute bpftool struct_ops unregister")?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file") || stderr.contains("not found") || stderr.contains("invalid name") {
        return Ok(());
    }

    anyhow::bail!(
        "bpftool struct_ops unregister failed: {}",
        stderr.trim()
    )
}

fn cleanup_custom_bpf_link_dir(link_dir: &Path) -> Result<()> {
    if !link_dir.exists() {
        return Ok(());
    }

    // Best effort: if a previous pinned struct_ops link remains after the
    // scheduler has already exited, bpftool register will fail with EEXIST.
    for entry in fs::read_dir(link_dir)
        .with_context(|| format!("failed to read {}", link_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let _ = fs::remove_file(&path);
        }
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

fn wait_for_landscape_scheduler(timeout_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if sched_ext_enabled() && read_sched_ext_ops() == "landscape_scx" {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    anyhow::bail!(
        "landscape_scx did not become the active sched_ext ops within timeout (state={}, ops={})",
        read_sched_ext_state(),
        read_sched_ext_ops()
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

#[derive(Debug, Clone)]
struct BuiltinSchedulerPaths {
    build_dir: PathBuf,
    link_dir: PathBuf,
    source_file: PathBuf,
    object_file_path: PathBuf,
    vmlinux_header_path: PathBuf,
    autogen_header_path: PathBuf,
    intent_state_path: PathBuf,
}

fn builtin_paths(cfg: &SchedulerConfig) -> BuiltinSchedulerPaths {
    let build_dir = cfg.custom_bpf.build_dir.clone();
    BuiltinSchedulerPaths {
        link_dir: cfg.custom_bpf.link_dir.clone(),
        source_file: cfg.custom_bpf.source_file.clone(),
        object_file_path: build_dir.join("landscape_scx.bpf.o"),
        vmlinux_header_path: build_dir.join("vmlinux.h"),
        autogen_header_path: build_dir.join("landscape_scx.autogen.h"),
        intent_state_path: build_dir.join("intent.toml"),
        build_dir,
    }
}

fn read_intent_state(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn write_vmlinux_header(path: &Path) -> Result<()> {
    let output = Command::new("bpftool")
        .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        .output()
        .context("failed to execute bpftool btf dump")?;
    if !output.status.success() {
        anyhow::bail!(
            "bpftool btf dump failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    fs::write(path, output.stdout)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn compile_landscape_scheduler_object(paths: &BuiltinSchedulerPaths) -> Result<()> {
    let include_bpf = if Path::new("/usr/include/bpf").exists() {
        PathBuf::from("/usr/include/bpf")
    } else {
        anyhow::bail!("missing /usr/include/bpf; install libbpf headers");
    };
    let source_dir = paths.source_file.parent().unwrap_or_else(|| Path::new("."));

    let output = Command::new("clang")
        .arg("-target")
        .arg("bpf")
        .arg(format!("-D__TARGET_ARCH_{}", target_arch_define()))
        .arg("-O2")
        .arg("-g")
        .arg("-I")
        .arg(&paths.build_dir)
        .arg("-I")
        .arg(source_dir)
        .arg("-I")
        .arg(include_bpf)
        .arg("-c")
        .arg(&paths.source_file)
        .arg("-o")
        .arg(&paths.object_file_path)
        .output()
        .with_context(|| format!("failed to execute clang for {}", paths.source_file.display()))?;

    if !output.status.success() {
        anyhow::bail!(
            "clang failed to compile {}: {}",
            paths.source_file.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn register_landscape_scheduler_object(paths: &BuiltinSchedulerPaths) -> Result<()> {
    let output = Command::new("bpftool")
        .args(["struct_ops", "register"])
        .arg(&paths.object_file_path)
        .arg(&paths.link_dir)
        .output()
        .context("failed to execute bpftool struct_ops register")?;

    if !output.status.success() {
        anyhow::bail!(
            "bpftool struct_ops register failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn render_autogen_header(intent: &LandscapeSchedulerIntent) -> String {
    let mut out = String::new();
    out.push_str("/* Auto-generated by landscape-scx-agent. */\n");
    out.push_str(&format!("#define LANDSCAPE_GEN_TASK_COUNT {}\n", intent.tasks.len()));
    out.push_str(&format!("#define LANDSCAPE_GEN_QUEUE_COUNT {}\n", intent.queues.len()));
    out.push_str(&format!(
        "#define LANDSCAPE_GEN_SCX_FLAGS {}\n\n",
        match intent.switch_mode {
            ScxSwitchMode::Partial => "SCX_OPS_SWITCH_PARTIAL",
            ScxSwitchMode::Full => "0",
        }
    ));

    if intent.queues.is_empty() {
        out.push_str("static const volatile __u32 landscape_gen_queue_owner_cpus[1] = { 0 };\n\n");
    } else {
        out.push_str("static const volatile __u32 landscape_gen_queue_owner_cpus[LANDSCAPE_GEN_QUEUE_COUNT] = {\n");
        for queue in &intent.queues {
            out.push_str(&format!("    {},\n", queue.owner_cpu));
        }
        out.push_str("};\n\n");
    }

    if intent.tasks.is_empty() {
        out.push_str("static const volatile struct landscape_boot_task_ctx landscape_gen_tasks[1] = {\n");
        out.push_str("    { .tid = 0, .qid = 0, .owner_cpu = 0, .flags = 0 },\n");
        out.push_str("};\n");
        return out;
    }

    out.push_str(
        "static const volatile struct landscape_boot_task_ctx landscape_gen_tasks[LANDSCAPE_GEN_TASK_COUNT] = {\n",
    );
    for task in &intent.tasks {
        out.push_str(&format!(
            "    {{ .tid = {}, .qid = {}, .owner_cpu = {}, .flags = {} }},\n",
            task.tid,
            task.qid,
            task.owner_cpu,
            match task.kind {
                LandscapeTaskKind::Ksoftirqd | LandscapeTaskKind::ForwardingWorker => {
                    "LANDSCAPE_TASK_F_DATAPLANE"
                }
            }
        ));
    }
    out.push_str("};\n");
    out
}

fn target_arch_define() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "s390x" => "s390",
        "powerpc64" | "powerpc64le" => "powerpc",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::render_autogen_header;
    use landscape_scx_common::{
        LandscapeQueueIntent, LandscapeSchedulerIntent, LandscapeTaskIntent, LandscapeTaskKind,
        ScxSwitchMode,
    };

    #[test]
    fn autogen_header_renders_queue_and_task_tables() {
        let intent = LandscapeSchedulerIntent {
            switch_mode: ScxSwitchMode::Partial,
            housekeeping_cpus: vec![0, 1],
            queues: vec![LandscapeQueueIntent {
                qid: 0,
                interface: "eth0".into(),
                queue_index: 0,
                owner_cpu: 2,
                dsq_id: 0x1000,
            }],
            tasks: vec![LandscapeTaskIntent {
                pid: 1,
                tid: 42,
                comm: "ksoftirqd/2".into(),
                kind: LandscapeTaskKind::Ksoftirqd,
                qid: 0,
                owner_cpu: 2,
            }],
        };

        let header = render_autogen_header(&intent);
        assert!(header.contains("#define LANDSCAPE_GEN_QUEUE_COUNT 1"));
        assert!(header.contains("#define LANDSCAPE_GEN_TASK_COUNT 1"));
        assert!(header.contains("LANDSCAPE_TASK_F_DATAPLANE"));
        assert!(header.contains("{ .tid = 42, .qid = 0, .owner_cpu = 2"));
    }
}
