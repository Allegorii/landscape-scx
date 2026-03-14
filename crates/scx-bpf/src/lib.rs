use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use landscape_scx_common::{
    LandscapeSchedulerIntent, LandscapeTaskClass, LandscapeTaskIntent, LandscapeTaskKey,
    LandscapeTaskKind, SchedulerConfig, SchedulerMode, ScxSwitchMode,
};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

const LANDSCAPE_TASK_F_DATAPLANE: u32 = 1;
const LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT: u32 = 0;
const LANDSCAPE_TASK_CLASS_DATAPLANE_SHARED: u32 = 1;
const LANDSCAPE_TASK_CLASS_CONTROL_PLANE: u32 = 2;
const LANDSCAPE_TASK_CLASS_BACKGROUND: u32 = 3;
const QID_OWNER_MAP_NAME: &str = "qid_owner_map";
const TASK_CTX_MAP_NAME: &str = "task_ctx_map";
const QUEUE_PRESSURE_MAP_NAME: &str = "queue_pressure_map";
const HOUSEKEEPING_CPU_MAP_NAME: &str = "hk_cpu_map";
const HOUSEKEEPING_DEFAULT_CPU_MAP_NAME: &str = "hk_defcpu_map";
const LANDSCAPE_SCHEDULER_SCHEMA_VERSION: u32 = 3;
const ACTIVE_CUSTOM_BPF_STATE_PATH: &str = "/run/landscape-scx/custom-bpf-active.toml";
const CUSTOM_BPF_BPFFS_PREFIX: &str = "landscape-scx-";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct LandscapeSchedulerStaticState {
    schema_version: u32,
    switch_mode: ScxSwitchMode,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct ActiveCustomBpfState {
    build_dir: PathBuf,
    link_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueOwnerMapValue {
    qid: u32,
    owner_cpu: u32,
    dsq_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskCtxMapValue {
    qid: u32,
    owner_cpu: u32,
    flags: u32,
    class: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueuePressureMapValue {
    pressure_level: u32,
    reserved0: u32,
    reserved1: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HousekeepingDefaultCpuValue {
    cpu: u32,
}

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
        anyhow::bail!("scheduler.custom_bpf.source_file does not exist: {}", source_file.display());
    }
    if !source_file.is_file() {
        anyhow::bail!("scheduler.custom_bpf.source_file is not a file: {}", source_file.display());
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
        source_copy_path: temp_root.join("landscape_scx.bpf.c"),
        object_file_path: temp_root.join("landscape_scx.bpf.o"),
        vmlinux_header_path: temp_root.join("vmlinux.h"),
        autogen_header_path: temp_root.join("landscape_scx.autogen.h"),
        intent_state_path: temp_root.join("intent.toml"),
        runtime_state_path: temp_root.join("runtime.toml"),
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
        SchedulerMode::CustomBpf => unload_custom_bpf_scheduler(cfg),
    }
}

pub fn load_landscape_scheduler(_intent: &LandscapeSchedulerIntent) -> Result<()> {
    anyhow::bail!("load_landscape_scheduler now requires SchedulerConfig; call ensure_landscape_scheduler() from the agent path")
}

pub fn sync_landscape_scheduler_maps(
    cfg: &SchedulerConfig,
    intent: &LandscapeSchedulerIntent,
) -> Result<()> {
    if !matches!(cfg.mode, SchedulerMode::CustomBpf) {
        anyhow::bail!("sync_landscape_scheduler_maps requires scheduler.mode=custom_bpf");
    }

    let paths = builtin_paths(cfg);
    let previous_intent =
        read_intent_state(&paths.intent_state_path).and_then(|raw| toml::from_str(&raw).ok());
    sync_landscape_scheduler_maps_with_previous(&paths, previous_intent.as_ref(), intent)?;
    fs::write(
        &paths.intent_state_path,
        toml::to_string(intent).context("failed to serialize scheduler intent")?,
    )
    .with_context(|| format!("failed to write {}", paths.intent_state_path.display()))?;
    Ok(())
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
            "    qid={} iface={} queue={} owner_cpu={} dsq=0x{:x} pressure={}\n",
            queue.qid,
            queue.interface,
            queue.queue_index,
            queue.owner_cpu,
            queue.dsq_id,
            queue.pressure_level
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
            "    tid={} pid={} start_time_ns={} kind={:?} class={:?} comm={} qid={} owner_cpu={}\n",
            task.tid,
            task.pid,
            task.start_time_ns,
            task.kind,
            task.class,
            task.comm,
            task.qid,
            task.owner_cpu
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

    let runtime_state = LandscapeSchedulerStaticState {
        schema_version: LANDSCAPE_SCHEDULER_SCHEMA_VERSION,
        switch_mode: intent.switch_mode.clone(),
    };
    let previous_intent =
        read_intent_state(&paths.intent_state_path).and_then(|raw| toml::from_str(&raw).ok());
    let needs_reload = read_runtime_state(&paths.runtime_state_path).as_ref()
        != Some(&runtime_state)
        || !builtin_map_pins_ready(&paths)
        || read_sched_ext_ops() != "landscape_scx"
        || !sched_ext_enabled();

    if !needs_reload {
        sync_landscape_scheduler_maps_with_previous(&paths, previous_intent.as_ref(), intent)?;
        write_intent_state(&paths.intent_state_path, intent)?;
        write_active_custom_bpf_state(&paths)?;
        return Ok(());
    }

    write_vmlinux_header(&paths.vmlinux_header_path)?;
    fs::write(&paths.autogen_header_path, render_autogen_header(intent))
        .with_context(|| format!("failed to write {}", paths.autogen_header_path.display()))?;
    compile_landscape_scheduler_object(&paths)?;

    let current_ops = read_sched_ext_ops();
    if current_ops == "landscape_scx" {
        unload_custom_bpf_scheduler_by_name()?;
        cleanup_custom_bpf_active_paths(&paths)?;
        wait_for_landscape_scheduler_unloaded(cfg.ready_timeout_ms)?;
    } else if sched_ext_enabled() {
        anyhow::bail!(
            "sched_ext is already enabled by {}, unload it before loading landscape_scx",
            current_ops
        );
    }
    if current_ops != "landscape_scx" {
        cleanup_custom_bpf_link_dir(&paths.link_dir)?;
    }

    register_landscape_scheduler_object(&paths)?;
    pin_landscape_scheduler_maps(&paths)?;
    sync_landscape_scheduler_maps_with_previous(&paths, previous_intent.as_ref(), intent)?;
    wait_for_landscape_scheduler(cfg.ready_timeout_ms)?;
    write_runtime_state(&paths.runtime_state_path, &runtime_state)?;
    write_intent_state(&paths.intent_state_path, intent)?;
    write_active_custom_bpf_state(&paths)?;
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

fn unload_custom_bpf_scheduler(cfg: &SchedulerConfig) -> Result<()> {
    let paths = builtin_paths(cfg);

    unload_custom_bpf_scheduler_by_name()?;
    cleanup_custom_bpf_active_paths(&paths)?;
    let _ = fs::remove_file(&paths.intent_state_path);
    let _ = fs::remove_file(&paths.runtime_state_path);
    clear_active_custom_bpf_state();

    if !sched_ext_enabled() || read_sched_ext_ops() != "landscape_scx" {
        return Ok(());
    }

    wait_for_landscape_scheduler_unloaded(cfg.ready_timeout_ms)
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
    if stderr.contains("No such file")
        || stderr.contains("not found")
        || stderr.contains("no struct_ops found")
        || stderr.contains("invalid name")
    {
        return Ok(());
    }

    anyhow::bail!("bpftool struct_ops unregister failed: {}", stderr.trim())
}

fn cleanup_custom_bpf_link_dir(link_dir: &Path) -> Result<()> {
    if !link_dir.exists() {
        return Ok(());
    }

    // Best effort: if previous pinned struct_ops links or map pins remain after
    // the scheduler has already exited, bpftool register/pin will fail with
    // EEXIST.
    for entry in
        fs::read_dir(link_dir).with_context(|| format!("failed to read {}", link_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let _ = fs::remove_file(&path);
        } else if path.is_dir() {
            let _ = fs::remove_dir_all(&path);
        }
    }

    Ok(())
}

fn cleanup_custom_bpf_active_paths(current_paths: &BuiltinSchedulerPaths) -> Result<()> {
    if let Some(active) = read_active_custom_bpf_state() {
        cleanup_custom_bpf_link_dir(&active.link_dir)?;
        let _ = fs::remove_file(active.build_dir.join("intent.toml"));
        let _ = fs::remove_file(active.build_dir.join("runtime.toml"));
        if active.link_dir != current_paths.link_dir {
            cleanup_custom_bpf_link_dir(&current_paths.link_dir)?;
        }
    } else {
        cleanup_known_custom_bpf_link_dirs()?;
        cleanup_custom_bpf_link_dir(&current_paths.link_dir)?;
    }
    Ok(())
}

fn cleanup_known_custom_bpf_link_dirs() -> Result<()> {
    let bpffs_root = Path::new("/sys/fs/bpf");
    if !bpffs_root.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(bpffs_root)
        .with_context(|| format!("failed to read {}", bpffs_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(CUSTOM_BPF_BPFFS_PREFIX) || !path.is_dir() {
            continue;
        }
        cleanup_custom_bpf_link_dir(&path)?;
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

fn wait_for_landscape_scheduler_unloaded(timeout_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if !sched_ext_enabled() || read_sched_ext_ops() != "landscape_scx" {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    anyhow::bail!(
        "landscape_scx did not unload within timeout (state={}, ops={})",
        read_sched_ext_state(),
        read_sched_ext_ops()
    )
}

fn sync_landscape_scheduler_maps_with_previous(
    paths: &BuiltinSchedulerPaths,
    previous_intent: Option<&LandscapeSchedulerIntent>,
    intent: &LandscapeSchedulerIntent,
) -> Result<()> {
    let qid_owner_path = builtin_qid_owner_map_path(paths);
    let task_ctx_path = builtin_task_ctx_map_path(paths);
    let queue_pressure_path = builtin_queue_pressure_map_path(paths);
    let housekeeping_cpu_path = builtin_housekeeping_cpu_map_path(paths);
    let housekeeping_default_path = builtin_housekeeping_default_cpu_map_path(paths);
    let current_qid_owners = qid_owner_entries_from_intent(intent)?;
    let previous_qid_owners =
        previous_intent.map(qid_owner_entries_from_intent).transpose()?.unwrap_or_default();
    let current_task_ctx = task_ctx_entries_from_intent(intent)?;
    let previous_task_ctx =
        previous_intent.map(task_ctx_entries_from_intent).transpose()?.unwrap_or_default();
    let current_queue_pressure = queue_pressure_entries_from_intent(intent);
    let previous_queue_pressure =
        previous_intent.map(queue_pressure_entries_from_intent).unwrap_or_default();
    let current_housekeeping_cpus = housekeeping_cpu_entries_from_intent(intent)?;
    let previous_housekeeping_cpus =
        previous_intent.map(housekeeping_cpu_entries_from_intent).transpose()?.unwrap_or_default();
    let current_housekeeping_default = housekeeping_default_cpu_from_intent(intent)?;

    for (owner_cpu, value) in &current_qid_owners {
        bpftool_map_update_pinned(
            &qid_owner_path,
            &owner_cpu.to_ne_bytes(),
            &queue_owner_value_bytes(*value),
        )?;
    }
    for owner_cpu in previous_qid_owners.keys() {
        if !current_qid_owners.contains_key(owner_cpu) {
            bpftool_map_delete_pinned(&qid_owner_path, &owner_cpu.to_ne_bytes())?;
        }
    }

    for (task_key, value) in &current_task_ctx {
        bpftool_map_update_pinned(
            &task_ctx_path,
            &task_key_bytes(task_key)?,
            &task_ctx_value_bytes(*value),
        )?;
    }
    for task_key in previous_task_ctx.keys() {
        if !current_task_ctx.contains_key(task_key) {
            bpftool_map_delete_pinned(&task_ctx_path, &task_key_bytes(task_key)?)?;
        }
    }

    for (qid, value) in &current_queue_pressure {
        bpftool_map_update_pinned(
            &queue_pressure_path,
            &qid.to_ne_bytes(),
            &queue_pressure_value_bytes(*value),
        )?;
    }
    for qid in previous_queue_pressure.keys() {
        if !current_queue_pressure.contains_key(qid) {
            bpftool_map_delete_pinned(&queue_pressure_path, &qid.to_ne_bytes())?;
        }
    }

    for (cpu, value) in &current_housekeeping_cpus {
        bpftool_map_update_pinned(&housekeeping_cpu_path, &cpu.to_ne_bytes(), &[*value])?;
    }
    for cpu in previous_housekeeping_cpus.keys() {
        if !current_housekeeping_cpus.contains_key(cpu) {
            bpftool_map_delete_pinned(&housekeeping_cpu_path, &cpu.to_ne_bytes())?;
        }
    }

    bpftool_map_update_pinned(
        &housekeeping_default_path,
        &0u32.to_ne_bytes(),
        &housekeeping_default_cpu_value_bytes(current_housekeeping_default),
    )?;

    Ok(())
}

fn qid_owner_entries_from_intent(
    intent: &LandscapeSchedulerIntent,
) -> Result<BTreeMap<u32, QueueOwnerMapValue>> {
    let mut entries = BTreeMap::new();
    for queue in &intent.queues {
        let owner_cpu =
            u32::try_from(queue.owner_cpu).context("queue owner_cpu does not fit into u32")?;
        entries.insert(
            owner_cpu,
            QueueOwnerMapValue { qid: queue.qid, owner_cpu, dsq_id: queue.dsq_id },
        );
    }
    Ok(entries)
}

fn task_ctx_entries_from_intent(
    intent: &LandscapeSchedulerIntent,
) -> Result<BTreeMap<LandscapeTaskKey, TaskCtxMapValue>> {
    let mut entries = BTreeMap::new();
    for task in &intent.tasks {
        let owner_cpu =
            u32::try_from(task.owner_cpu).context("task owner_cpu does not fit into u32")?;
        entries.insert(
            task.key(),
            TaskCtxMapValue {
                qid: task.qid,
                owner_cpu,
                flags: task_flags(task),
                class: task_class(task),
            },
        );
    }
    Ok(entries)
}

fn queue_pressure_entries_from_intent(
    intent: &LandscapeSchedulerIntent,
) -> BTreeMap<u32, QueuePressureMapValue> {
    intent
        .queues
        .iter()
        .map(|queue| {
            (
                queue.qid,
                QueuePressureMapValue {
                    pressure_level: queue.pressure_level,
                    reserved0: 0,
                    reserved1: 0,
                },
            )
        })
        .collect()
}

fn housekeeping_cpu_entries_from_intent(
    intent: &LandscapeSchedulerIntent,
) -> Result<BTreeMap<u32, u8>> {
    let mut entries = BTreeMap::new();
    for cpu in &intent.housekeeping_cpus {
        let cpu = u32::try_from(*cpu).context("housekeeping cpu does not fit into u32")?;
        entries.insert(cpu, 1u8);
    }
    Ok(entries)
}

fn housekeeping_default_cpu_from_intent(
    intent: &LandscapeSchedulerIntent,
) -> Result<HousekeepingDefaultCpuValue> {
    let Some(cpu) = intent.housekeeping_cpus.first() else {
        anyhow::bail!("built-in scheduler intent requires at least one housekeeping cpu");
    };
    Ok(HousekeepingDefaultCpuValue {
        cpu: u32::try_from(*cpu).context("housekeeping default cpu does not fit into u32")?,
    })
}

fn task_flags(task: &LandscapeTaskIntent) -> u32 {
    match task.class {
        LandscapeTaskClass::DataplaneStrict | LandscapeTaskClass::DataplaneShared => {
            LANDSCAPE_TASK_F_DATAPLANE
        }
        LandscapeTaskClass::ControlPlane | LandscapeTaskClass::Background => 0,
    }
}

fn task_class(task: &LandscapeTaskIntent) -> u32 {
    match task.class {
        LandscapeTaskClass::DataplaneStrict => LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT,
        LandscapeTaskClass::DataplaneShared => LANDSCAPE_TASK_CLASS_DATAPLANE_SHARED,
        LandscapeTaskClass::ControlPlane => LANDSCAPE_TASK_CLASS_CONTROL_PLANE,
        LandscapeTaskClass::Background => LANDSCAPE_TASK_CLASS_BACKGROUND,
    }
}

fn pin_landscape_scheduler_maps(paths: &BuiltinSchedulerPaths) -> Result<()> {
    let map_dir = builtin_map_dir(paths);
    fs::create_dir_all(&map_dir)
        .with_context(|| format!("failed to create {}", map_dir.display()))?;

    pin_landscape_scheduler_map_by_name(QID_OWNER_MAP_NAME, &builtin_qid_owner_map_path(paths))?;
    pin_landscape_scheduler_map_by_name(TASK_CTX_MAP_NAME, &builtin_task_ctx_map_path(paths))?;
    pin_landscape_scheduler_map_by_name(
        QUEUE_PRESSURE_MAP_NAME,
        &builtin_queue_pressure_map_path(paths),
    )?;
    pin_landscape_scheduler_map_by_name(
        HOUSEKEEPING_CPU_MAP_NAME,
        &builtin_housekeeping_cpu_map_path(paths),
    )?;
    pin_landscape_scheduler_map_by_name(
        HOUSEKEEPING_DEFAULT_CPU_MAP_NAME,
        &builtin_housekeeping_default_cpu_map_path(paths),
    )?;
    Ok(())
}

fn pin_landscape_scheduler_map_by_name(name: &str, pin_path: &Path) -> Result<()> {
    if pin_path.exists() {
        let _ = fs::remove_file(pin_path);
    }

    let Some(map_id) = find_loaded_map_id_by_name(name)? else {
        anyhow::bail!("failed to find loaded BPF map named {}", name);
    };

    let output = Command::new("bpftool")
        .args(["map", "pin", "id", &map_id.to_string()])
        .arg(pin_path)
        .output()
        .with_context(|| format!("failed to pin BPF map {} to {}", name, pin_path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "bpftool map pin failed for {}: {}",
            name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn find_loaded_map_id_by_name(name: &str) -> Result<Option<u32>> {
    let output = Command::new("bpftool")
        .args(["map", "show"])
        .output()
        .context("failed to execute bpftool map show")?;
    if !output.status.success() {
        anyhow::bail!(
            "bpftool map show failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut match_id = None;
    for line in stdout.lines() {
        let Some((id_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(id) = id_raw.trim().parse::<u32>() else {
            continue;
        };
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        let Some(name_index) = fields.iter().position(|field| *field == "name") else {
            continue;
        };
        if fields.get(name_index + 1) == Some(&name) {
            match_id = Some(id);
        }
    }

    Ok(match_id)
}

fn bpftool_map_update_pinned(pin_path: &Path, key_bytes: &[u8], value_bytes: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".to_string(),
        "update".to_string(),
        "pinned".to_string(),
        pin_path.display().to_string(),
        "key".to_string(),
        "hex".to_string(),
    ];
    args.extend(hex_byte_args(key_bytes));
    args.push("value".to_string());
    args.push("hex".to_string());
    args.extend(hex_byte_args(value_bytes));
    args.push("any".to_string());

    let output = Command::new("bpftool")
        .args(&args)
        .output()
        .with_context(|| format!("failed to update pinned BPF map {}", pin_path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "bpftool map update failed for {}: {}",
            pin_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn bpftool_map_delete_pinned(pin_path: &Path, key_bytes: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".to_string(),
        "delete".to_string(),
        "pinned".to_string(),
        pin_path.display().to_string(),
        "key".to_string(),
        "hex".to_string(),
    ];
    args.extend(hex_byte_args(key_bytes));

    let output = Command::new("bpftool")
        .args(&args)
        .output()
        .with_context(|| format!("failed to delete from pinned BPF map {}", pin_path.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file or directory")
        || stderr.contains("not found")
        || stderr.contains("element not found")
    {
        return Ok(());
    }

    anyhow::bail!("bpftool map delete failed for {}: {}", pin_path.display(), stderr.trim())
}

fn queue_owner_value_bytes(value: QueueOwnerMapValue) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.qid.to_ne_bytes());
    bytes.extend_from_slice(&value.owner_cpu.to_ne_bytes());
    bytes.extend_from_slice(&value.dsq_id.to_ne_bytes());
    bytes
}

fn task_ctx_value_bytes(value: TaskCtxMapValue) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.qid.to_ne_bytes());
    bytes.extend_from_slice(&value.owner_cpu.to_ne_bytes());
    bytes.extend_from_slice(&value.flags.to_ne_bytes());
    bytes.extend_from_slice(&value.class.to_ne_bytes());
    bytes
}

fn queue_pressure_value_bytes(value: QueuePressureMapValue) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&value.pressure_level.to_ne_bytes());
    bytes.extend_from_slice(&value.reserved0.to_ne_bytes());
    bytes.extend_from_slice(&value.reserved1.to_ne_bytes());
    bytes
}

fn housekeeping_default_cpu_value_bytes(value: HousekeepingDefaultCpuValue) -> Vec<u8> {
    value.cpu.to_ne_bytes().to_vec()
}

fn task_key_bytes(task_key: &LandscapeTaskKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(
        &u32::try_from(task_key.pid).context("task key pid does not fit into u32")?.to_ne_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(task_key.tid).context("task key tid does not fit into u32")?.to_ne_bytes(),
    );
    bytes.extend_from_slice(&task_key.start_time_ns.to_ne_bytes());
    Ok(bytes)
}

fn hex_byte_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn builtin_map_dir(paths: &BuiltinSchedulerPaths) -> PathBuf {
    paths.link_dir.join("maps")
}

fn builtin_map_pins_ready(paths: &BuiltinSchedulerPaths) -> bool {
    builtin_qid_owner_map_path(paths).exists()
        && builtin_task_ctx_map_path(paths).exists()
        && builtin_queue_pressure_map_path(paths).exists()
        && builtin_housekeeping_cpu_map_path(paths).exists()
        && builtin_housekeeping_default_cpu_map_path(paths).exists()
}

fn builtin_qid_owner_map_path(paths: &BuiltinSchedulerPaths) -> PathBuf {
    builtin_map_dir(paths).join(QID_OWNER_MAP_NAME)
}

fn builtin_task_ctx_map_path(paths: &BuiltinSchedulerPaths) -> PathBuf {
    builtin_map_dir(paths).join(TASK_CTX_MAP_NAME)
}

fn builtin_queue_pressure_map_path(paths: &BuiltinSchedulerPaths) -> PathBuf {
    builtin_map_dir(paths).join(QUEUE_PRESSURE_MAP_NAME)
}

fn builtin_housekeeping_cpu_map_path(paths: &BuiltinSchedulerPaths) -> PathBuf {
    builtin_map_dir(paths).join(HOUSEKEEPING_CPU_MAP_NAME)
}

fn builtin_housekeeping_default_cpu_map_path(paths: &BuiltinSchedulerPaths) -> PathBuf {
    builtin_map_dir(paths).join(HOUSEKEEPING_DEFAULT_CPU_MAP_NAME)
}

fn write_runtime_state(path: &Path, state: &LandscapeSchedulerStaticState) -> Result<()> {
    fs::write(path, toml::to_string(state).context("failed to serialize runtime state")?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_runtime_state(path: &Path) -> Option<LandscapeSchedulerStaticState> {
    fs::read_to_string(path).ok().and_then(|raw| toml::from_str(&raw).ok())
}

fn write_active_custom_bpf_state(paths: &BuiltinSchedulerPaths) -> Result<()> {
    let state = ActiveCustomBpfState {
        build_dir: paths.build_dir.clone(),
        link_dir: paths.link_dir.clone(),
    };
    let path = Path::new(ACTIVE_CUSTOM_BPF_STATE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(
        path,
        toml::to_string(&state).context("failed to serialize active custom_bpf state")?,
    )
    .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_active_custom_bpf_state() -> Option<ActiveCustomBpfState> {
    fs::read_to_string(ACTIVE_CUSTOM_BPF_STATE_PATH).ok().and_then(|raw| toml::from_str(&raw).ok())
}

fn clear_active_custom_bpf_state() {
    let _ = fs::remove_file(ACTIVE_CUSTOM_BPF_STATE_PATH);
}

fn write_intent_state(path: &Path, intent: &LandscapeSchedulerIntent) -> Result<()> {
    fs::write(path, toml::to_string(intent).context("failed to serialize scheduler intent")?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
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
    source_copy_path: PathBuf,
    object_file_path: PathBuf,
    vmlinux_header_path: PathBuf,
    autogen_header_path: PathBuf,
    intent_state_path: PathBuf,
    runtime_state_path: PathBuf,
}

fn builtin_paths(cfg: &SchedulerConfig) -> BuiltinSchedulerPaths {
    let build_dir = cfg.custom_bpf.build_dir.clone();
    BuiltinSchedulerPaths {
        link_dir: cfg.custom_bpf.link_dir.clone(),
        source_file: cfg.custom_bpf.source_file.clone(),
        source_copy_path: build_dir.join("landscape_scx.bpf.c"),
        object_file_path: build_dir.join("landscape_scx.bpf.o"),
        vmlinux_header_path: build_dir.join("vmlinux.h"),
        autogen_header_path: build_dir.join("landscape_scx.autogen.h"),
        intent_state_path: build_dir.join("intent.toml"),
        runtime_state_path: build_dir.join("runtime.toml"),
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
    fs::copy(&paths.source_file, &paths.source_copy_path).with_context(|| {
        format!(
            "failed to copy {} to {}",
            paths.source_file.display(),
            paths.source_copy_path.display()
        )
    })?;

    let output = Command::new("clang")
        .arg("-target")
        .arg("bpf")
        .arg(format!("-D__TARGET_ARCH_{}", target_arch_define()))
        .arg("-O2")
        .arg("-g")
        .arg("-I")
        .arg(&paths.build_dir)
        .arg("-I")
        .arg(include_bpf)
        .arg("-c")
        .arg(&paths.source_copy_path)
        .arg("-o")
        .arg(&paths.object_file_path)
        .output()
        .with_context(|| {
            format!("failed to execute clang for {}", paths.source_copy_path.display())
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "clang failed to compile {}: {}",
            paths.source_copy_path.display(),
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
    out.push_str(&format!(
        "#define LANDSCAPE_GEN_SCX_FLAGS {}\n",
        match intent.switch_mode {
            ScxSwitchMode::Partial => "SCX_OPS_SWITCH_PARTIAL",
            ScxSwitchMode::Full => "0",
        }
    ));
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
    use super::{
        queue_pressure_entries_from_intent, render_autogen_header, task_class,
        task_ctx_entries_from_intent, LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT,
    };
    use landscape_scx_common::{
        LandscapeQueueIntent, LandscapeSchedulerIntent, LandscapeTaskClass, LandscapeTaskIntent,
        LandscapeTaskKind, ScxSwitchMode,
    };

    #[test]
    fn autogen_header_renders_scheduler_flags_only() {
        let intent = LandscapeSchedulerIntent {
            switch_mode: ScxSwitchMode::Partial,
            housekeeping_cpus: vec![0, 1],
            queues: vec![LandscapeQueueIntent {
                qid: 0,
                interface: "eth0".into(),
                queue_index: 0,
                owner_cpu: 2,
                dsq_id: 0x1000,
                pressure_level: 2,
            }],
            tasks: vec![LandscapeTaskIntent {
                pid: 1,
                tid: 42,
                start_time_ns: 123,
                comm: "ksoftirqd/2".into(),
                kind: LandscapeTaskKind::Ksoftirqd,
                class: LandscapeTaskClass::DataplaneStrict,
                qid: 0,
                owner_cpu: 2,
            }],
        };

        let header = render_autogen_header(&intent);
        assert!(header.contains("#define LANDSCAPE_GEN_SCX_FLAGS SCX_OPS_SWITCH_PARTIAL"));
        assert!(!header.contains("LANDSCAPE_GEN_QUEUE_COUNT"));
        assert!(!header.contains("LANDSCAPE_GEN_TASK_COUNT"));
        assert!(!header.contains("LANDSCAPE_TASK_F_DATAPLANE"));
    }

    #[test]
    fn task_ctx_entries_encode_class() {
        let intent = LandscapeSchedulerIntent {
            switch_mode: ScxSwitchMode::Partial,
            housekeeping_cpus: vec![0],
            queues: vec![LandscapeQueueIntent {
                qid: 7,
                interface: "eth0".into(),
                queue_index: 0,
                owner_cpu: 3,
                dsq_id: 0x1007,
                pressure_level: 0,
            }],
            tasks: vec![LandscapeTaskIntent {
                pid: 10,
                tid: 11,
                start_time_ns: 12,
                comm: "worker".into(),
                kind: LandscapeTaskKind::ForwardingWorker,
                class: LandscapeTaskClass::DataplaneStrict,
                qid: 7,
                owner_cpu: 3,
            }],
        };

        let entries = task_ctx_entries_from_intent(&intent).expect("task ctx entries");
        let value = entries.values().next().expect("task ctx value");
        assert_eq!(value.class, LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT);
        assert_eq!(task_class(&intent.tasks[0]), LANDSCAPE_TASK_CLASS_DATAPLANE_STRICT);
    }

    #[test]
    fn queue_pressure_entries_follow_queue_intent() {
        let intent = LandscapeSchedulerIntent {
            switch_mode: ScxSwitchMode::Partial,
            housekeeping_cpus: vec![0],
            queues: vec![LandscapeQueueIntent {
                qid: 9,
                interface: "eth1".into(),
                queue_index: 1,
                owner_cpu: 4,
                dsq_id: 0x1009,
                pressure_level: 3,
            }],
            tasks: Vec::new(),
        };

        let entries = queue_pressure_entries_from_intent(&intent);
        assert_eq!(entries.get(&9).expect("pressure entry").pressure_level, 3);
    }
}
