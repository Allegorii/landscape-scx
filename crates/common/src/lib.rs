use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const SCHED_EXT_POLICY: u32 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScxConfig {
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    #[serde(default)]
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_process_names")]
    pub process_names: Vec<String>,
    #[serde(default = "default_cmdline_keywords")]
    pub cmdline_keywords: Vec<String>,
    #[serde(default)]
    pub cgroup_prefixes: Vec<String>,
    #[serde(default)]
    pub thread_include_prefixes: Vec<String>,
    #[serde(default)]
    pub thread_exclude_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_forwarding_cpus")]
    pub forwarding_cpus: Vec<usize>,
    #[serde(default = "default_control_cpus")]
    pub control_cpus: Vec<usize>,
    #[serde(default = "default_enable_ksoftirqd")]
    pub manage_ksoftirqd: bool,
    #[serde(default)]
    pub ksoftirqd_cpus: Vec<usize>,
    #[serde(default = "default_enable_sched_ext")]
    pub apply_sched_ext: bool,
    #[serde(default)]
    pub thread_cpu_classes: Vec<ThreadCpuClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadCpuClass {
    pub thread_name_prefix: String,
    #[serde(default)]
    pub cpus: Vec<usize>,
    #[serde(default)]
    pub apply_sched_ext: Option<bool>,
    #[serde(default)]
    pub apply_affinity: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub apply_irq_affinity: bool,
    #[serde(default)]
    pub apply_xps: bool,
    #[serde(default = "default_queue_mapping_mode")]
    pub queue_mapping_mode: QueueMappingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueueMappingMode {
    RoundRobin,
    FullMask,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerMode {
    Disabled,
    ExternalCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    #[serde(default = "default_scheduler_mode")]
    pub mode: SchedulerMode,
    #[serde(default = "default_scheduler_start_command")]
    pub start_command: Vec<String>,
    #[serde(default)]
    pub stop_command: Vec<String>,
    #[serde(default = "default_scheduler_pid_file")]
    pub pid_file: PathBuf,
    #[serde(default = "default_ready_timeout_ms")]
    pub ready_timeout_ms: u64,
    #[serde(default = "default_fallback_on_error")]
    pub fallback_on_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_apply_interval_secs")]
    pub apply_interval_secs: u64,
}

impl Default for ScxConfig {
    fn default() -> Self {
        Self {
            discovery: DiscoveryConfig::default(),
            policy: PolicyConfig::default(),
            network: NetworkConfig::default(),
            scheduler: SchedulerConfig::default(),
            agent: AgentConfig::default(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            process_names: default_process_names(),
            cmdline_keywords: default_cmdline_keywords(),
            cgroup_prefixes: Vec::new(),
            thread_include_prefixes: Vec::new(),
            thread_exclude_prefixes: Vec::new(),
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            forwarding_cpus: default_forwarding_cpus(),
            control_cpus: default_control_cpus(),
            manage_ksoftirqd: default_enable_ksoftirqd(),
            ksoftirqd_cpus: Vec::new(),
            apply_sched_ext: default_enable_sched_ext(),
            thread_cpu_classes: Vec::new(),
        }
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            mode: default_scheduler_mode(),
            start_command: default_scheduler_start_command(),
            stop_command: Vec::new(),
            pid_file: default_scheduler_pid_file(),
            ready_timeout_ms: default_ready_timeout_ms(),
            fallback_on_error: default_fallback_on_error(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self { apply_interval_secs: default_apply_interval_secs() }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            apply_irq_affinity: false,
            apply_xps: false,
            queue_mapping_mode: default_queue_mapping_mode(),
        }
    }
}

fn default_process_names() -> Vec<String> {
    vec!["landscape-webserver".to_string()]
}

fn default_cmdline_keywords() -> Vec<String> {
    vec!["landscape-webserver".to_string()]
}

fn default_forwarding_cpus() -> Vec<usize> {
    vec![0, 1]
}

fn default_control_cpus() -> Vec<usize> {
    vec![2, 3]
}

const fn default_enable_ksoftirqd() -> bool {
    true
}

const fn default_enable_sched_ext() -> bool {
    true
}

fn default_scheduler_mode() -> SchedulerMode {
    SchedulerMode::ExternalCommand
}

fn default_scheduler_start_command() -> Vec<String> {
    vec!["scx_cosmos".to_string()]
}

fn default_scheduler_pid_file() -> PathBuf {
    PathBuf::from("/run/landscape-scx/scheduler.pid")
}

const fn default_ready_timeout_ms() -> u64 {
    3000
}

const fn default_fallback_on_error() -> bool {
    true
}

const fn default_apply_interval_secs() -> u64 {
    10
}

fn default_queue_mapping_mode() -> QueueMappingMode {
    QueueMappingMode::RoundRobin
}

pub fn load_config(path: impl AsRef<Path>) -> Result<ScxConfig> {
    let path_ref = path.as_ref();
    let raw = fs::read_to_string(path_ref)
        .with_context(|| format!("failed to read config file: {}", path_ref.display()))?;
    let cfg: ScxConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse TOML config: {}", path_ref.display()))?;
    Ok(cfg)
}

#[derive(Debug, Clone)]
pub struct ThreadCandidate {
    pub pid: i32,
    pub tid: i32,
    pub comm: String,
    pub cmdline: String,
    pub cgroup: String,
}

pub fn discover_candidates(cfg: &ScxConfig) -> Result<Vec<ThreadCandidate>> {
    let mut out = Vec::new();

    for proc_entry in fs::read_dir("/proc").context("read /proc")? {
        let proc_entry = match proc_entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = proc_entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let proc_dir = proc_entry.path();
        let cmdline = read_cmdline(pid).unwrap_or_default();
        let cgroup = read_cgroup(pid).unwrap_or_default();

        let thread_dir = proc_dir.join("task");
        let task_entries = match fs::read_dir(&thread_dir) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for task in task_entries {
            let task = match task {
                Ok(v) => v,
                Err(_) => continue,
            };
            let tid: i32 = match task.file_name().to_string_lossy().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let comm = match fs::read_to_string(task.path().join("comm")) {
                Ok(v) => v.trim().to_string(),
                Err(_) => continue,
            };

            if !matches_target(&comm, &cmdline, &cgroup, cfg) {
                continue;
            }

            out.push(ThreadCandidate {
                pid,
                tid,
                comm,
                cmdline: cmdline.clone(),
                cgroup: cgroup.clone(),
            });
        }
    }

    out.sort_by_key(|v| (v.pid, v.tid));
    out.dedup_by_key(|v| (v.pid, v.tid));
    Ok(out)
}

fn matches_target(comm: &str, cmdline: &str, cgroup: &str, cfg: &ScxConfig) -> bool {
    if let Some(cpu) = parse_ksoftirqd_cpu(comm) {
        return matches_ksoftirqd(comm, cpu, cfg);
    }

    let process_match =
        cfg.discovery.process_names.iter().any(|name| comm == name || comm.starts_with(name));
    let cmdline_match =
        cfg.discovery.cmdline_keywords.iter().any(|kw| !kw.is_empty() && cmdline.contains(kw));
    let cgroup_match = if cfg.discovery.cgroup_prefixes.is_empty() {
        true
    } else {
        cfg.discovery.cgroup_prefixes.iter().any(|prefix| cgroup.contains(prefix))
    };

    (process_match || cmdline_match) && cgroup_match && matches_thread_filters(comm, &cfg.discovery)
}

fn matches_ksoftirqd(comm: &str, cpu: usize, cfg: &ScxConfig) -> bool {
    if !cfg.policy.manage_ksoftirqd {
        return false;
    }

    if !effective_ksoftirqd_cpus(&cfg.policy).contains(&cpu) {
        return false;
    }

    matches_thread_filters(comm, &cfg.discovery)
}

fn matches_thread_filters(comm: &str, cfg: &DiscoveryConfig) -> bool {
    let include_match = if cfg.thread_include_prefixes.is_empty() {
        true
    } else {
        prefix_matches_any(comm, &cfg.thread_include_prefixes)
    };
    include_match && !prefix_matches_any(comm, &cfg.thread_exclude_prefixes)
}

fn prefix_matches_any(comm: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| !prefix.is_empty() && comm.starts_with(prefix))
}

fn effective_ksoftirqd_cpus(policy: &PolicyConfig) -> Vec<usize> {
    if !policy.ksoftirqd_cpus.is_empty() {
        return policy.ksoftirqd_cpus.clone();
    }
    policy.forwarding_cpus.clone()
}

pub fn parse_ksoftirqd_cpu(comm: &str) -> Option<usize> {
    let suffix = comm.strip_prefix("ksoftirqd/")?;
    suffix.parse().ok()
}

fn read_cmdline(pid: i32) -> io::Result<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|seg| !seg.is_empty())
        .map(|seg| String::from_utf8_lossy(seg).to_string())
        .collect();
    Ok(parts.join(" "))
}

fn read_cgroup(pid: i32) -> io::Result<String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
    sched_util_min: u32,
    sched_util_max: u32,
}

pub fn try_set_sched_ext(tid: i32) -> Result<()> {
    let attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        sched_policy: SCHED_EXT_POLICY,
        sched_flags: 0,
        sched_nice: 0,
        sched_priority: 0,
        sched_runtime: 0,
        sched_deadline: 0,
        sched_period: 0,
        sched_util_min: 0,
        sched_util_max: 1024,
    };

    let ret = unsafe { libc::syscall(libc::SYS_sched_setattr, tid, &attr as *const SchedAttr, 0) };

    if ret == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    Err(anyhow::anyhow!("sched_setattr tid={} policy=SCHED_EXT failed: {}", tid, err))
}

pub fn try_set_cpu_affinity(tid: i32, cpus: &[usize]) -> Result<()> {
    if cpus.is_empty() {
        return Ok(());
    }

    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            libc::CPU_SET(cpu, &mut set);
        }
        let ret = libc::sched_setaffinity(
            tid,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set as *const libc::cpu_set_t,
        );
        if ret == 0 {
            return Ok(());
        }
    }

    let err = io::Error::last_os_error();
    Err(anyhow::anyhow!("sched_setaffinity tid={} cpus={:?} failed: {}", tid, cpus, err))
}

pub fn get_sched_policy(tid: i32) -> Result<i32> {
    let policy = unsafe { libc::sched_getscheduler(tid) };
    if policy >= 0 {
        return Ok(policy);
    }
    let err = io::Error::last_os_error();
    Err(anyhow::anyhow!("sched_getscheduler tid={} failed: {}", tid, err))
}

pub fn sched_policy_name(policy: i32) -> &'static str {
    match policy {
        0 => "SCHED_OTHER",
        1 => "SCHED_FIFO",
        2 => "SCHED_RR",
        3 => "SCHED_BATCH",
        5 => "SCHED_IDLE",
        6 => "SCHED_DEADLINE",
        7 => "SCHED_EXT",
        _ => "UNKNOWN",
    }
}

pub fn read_online_cpus() -> Result<BTreeSet<usize>> {
    let raw = fs::read_to_string("/sys/devices/system/cpu/online")
        .context("failed to read /sys/devices/system/cpu/online")?;
    parse_cpu_list(raw.trim())
}

#[derive(Debug, Clone)]
pub struct InterfaceLocalityStatus {
    pub interface: String,
    pub tx_queues: Vec<QueueLocalityState>,
    pub rx_queues: Vec<QueueLocalityState>,
    pub irqs: Vec<IrqLocalityState>,
}

#[derive(Debug, Clone)]
pub struct QueueLocalityState {
    pub name: String,
    pub path: PathBuf,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct IrqLocalityState {
    pub irq: u32,
    pub label: String,
    pub queue_index: Option<usize>,
    pub affinity_list_path: PathBuf,
    pub affinity_mask_path: PathBuf,
    pub affinity_list: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceLocalityPlan {
    pub interface: String,
    pub status: InterfaceLocalityStatus,
    pub xps_actions: Vec<XpsAction>,
    pub irq_actions: Vec<IrqAffinityAction>,
}

#[derive(Debug, Clone)]
pub struct XpsAction {
    pub interface: String,
    pub queue_name: String,
    pub path: PathBuf,
    pub cpus: Vec<usize>,
    pub mask: String,
    pub current_value: String,
}

#[derive(Debug, Clone)]
pub struct IrqAffinityAction {
    pub interface: String,
    pub irq: u32,
    pub label: String,
    pub list_path: PathBuf,
    pub mask_path: PathBuf,
    pub cpus: Vec<usize>,
    pub affinity_list: String,
    pub current_affinity_list: String,
}

pub fn build_network_locality_plans(cfg: &ScxConfig) -> Result<Vec<InterfaceLocalityPlan>> {
    let mut plans = Vec::new();

    for iface in &cfg.network.interfaces {
        let status = read_interface_locality_status(iface)?;
        let xps_actions = if cfg.network.apply_xps {
            build_interface_xps_actions(cfg, &status)?
        } else {
            Vec::new()
        };
        let irq_actions = if cfg.network.apply_irq_affinity {
            build_interface_irq_actions(cfg, &status)?
        } else {
            Vec::new()
        };

        plans.push(InterfaceLocalityPlan {
            interface: iface.clone(),
            status,
            xps_actions,
            irq_actions,
        });
    }

    Ok(plans)
}

fn read_interface_locality_status(iface: &str) -> Result<InterfaceLocalityStatus> {
    let iface_root = PathBuf::from(format!("/sys/class/net/{iface}"));
    if !iface_root.exists() {
        anyhow::bail!(
            "network.interfaces contains {iface}, but {} does not exist",
            iface_root.display()
        );
    }

    Ok(InterfaceLocalityStatus {
        interface: iface.to_string(),
        tx_queues: read_queue_locality_states(iface, "tx-", "xps_cpus")?,
        rx_queues: read_queue_locality_states(iface, "rx-", "rps_cpus")?,
        irqs: read_irq_locality_states(iface)?,
    })
}

fn read_queue_locality_states(
    iface: &str,
    prefix: &str,
    value_file: &str,
) -> Result<Vec<QueueLocalityState>> {
    let queue_root = PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    if !queue_root.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(&queue_root)
        .with_context(|| format!("failed to read queue dir for interface {iface}"))?
    {
        let entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(prefix) {
            continue;
        }
        let path = entry.path().join(value_file);
        if !path.exists() {
            continue;
        }
        let value = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .trim()
            .to_string();
        out.push(QueueLocalityState { name, path, value });
    }

    out.sort_by_key(|queue| queue_index(&queue.name, prefix).unwrap_or(usize::MAX));
    Ok(out)
}

fn read_irq_locality_states(iface: &str) -> Result<Vec<IrqLocalityState>> {
    let raw = fs::read_to_string("/proc/interrupts").context("failed to read /proc/interrupts")?;
    let mut out = Vec::new();

    for line in raw.lines() {
        let Some((irq_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let label = rest.split_whitespace().last().unwrap_or_default();
        if !label.contains(iface) {
            continue;
        }

        let irq = match irq_raw.trim().parse::<u32>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let affinity_list_path = PathBuf::from(format!("/proc/irq/{irq}/smp_affinity_list"));
        let affinity_mask_path = PathBuf::from(format!("/proc/irq/{irq}/smp_affinity"));
        let affinity_list = match fs::read_to_string(&affinity_list_path) {
            Ok(v) => v.trim().to_string(),
            Err(_) => {
                let mask = fs::read_to_string(&affinity_mask_path).with_context(|| {
                    format!(
                        "failed to read IRQ affinity for {iface} irq={irq} ({})",
                        affinity_mask_path.display()
                    )
                })?;
                let cpus = parse_cpu_mask(mask.trim())?.into_iter().collect::<Vec<_>>();
                cpu_list_string(&cpus)
            }
        };

        let Some(queue_index) = parse_irq_queue_index(label) else {
            continue;
        };

        out.push(IrqLocalityState {
            irq,
            label: label.to_string(),
            queue_index: Some(queue_index),
            affinity_list_path,
            affinity_mask_path,
            affinity_list,
        });
    }

    out.sort_by_key(|irq| (irq.queue_index.unwrap_or(usize::MAX), irq.irq));
    Ok(out)
}

fn build_interface_xps_actions(
    cfg: &ScxConfig,
    status: &InterfaceLocalityStatus,
) -> Result<Vec<XpsAction>> {
    if status.tx_queues.is_empty() {
        anyhow::bail!(
            "network.apply_xps is enabled, but interface {} has no tx-*/xps_cpus entries",
            status.interface
        );
    }

    let mut out = Vec::new();
    for (ordinal, queue) in status.tx_queues.iter().enumerate() {
        let index = queue_index(&queue.name, "tx-").unwrap_or(ordinal);
        let cpus = desired_locality_cpus(
            &cfg.policy.forwarding_cpus,
            &cfg.network.queue_mapping_mode,
            index,
        );
        out.push(XpsAction {
            interface: status.interface.clone(),
            queue_name: queue.name.clone(),
            path: queue.path.clone(),
            mask: cpu_mask_string(&cpus),
            cpus,
            current_value: queue.value.clone(),
        });
    }

    Ok(out)
}

fn build_interface_irq_actions(
    cfg: &ScxConfig,
    status: &InterfaceLocalityStatus,
) -> Result<Vec<IrqAffinityAction>> {
    if status.irqs.is_empty() {
        anyhow::bail!(
            "network.apply_irq_affinity is enabled, but no IRQ labels containing interface {} were found in /proc/interrupts",
            status.interface
        );
    }

    let mut out = Vec::new();
    for (ordinal, irq) in status.irqs.iter().enumerate() {
        let index = irq.queue_index.unwrap_or(ordinal);
        let cpus = desired_locality_cpus(
            &cfg.policy.forwarding_cpus,
            &cfg.network.queue_mapping_mode,
            index,
        );
        out.push(IrqAffinityAction {
            interface: status.interface.clone(),
            irq: irq.irq,
            label: irq.label.clone(),
            list_path: irq.affinity_list_path.clone(),
            mask_path: irq.affinity_mask_path.clone(),
            affinity_list: cpu_list_string(&cpus),
            cpus,
            current_affinity_list: irq.affinity_list.clone(),
        });
    }

    Ok(out)
}

fn desired_locality_cpus(
    forwarding_cpus: &[usize],
    mode: &QueueMappingMode,
    index: usize,
) -> Vec<usize> {
    match mode {
        QueueMappingMode::RoundRobin => vec![forwarding_cpus[index % forwarding_cpus.len()]],
        QueueMappingMode::FullMask => forwarding_cpus.to_vec(),
    }
}

fn queue_index(name: &str, prefix: &str) -> Option<usize> {
    name.strip_prefix(prefix)?.parse().ok()
}

fn parse_irq_queue_index(label: &str) -> Option<usize> {
    let (prefix, suffix) = label.rsplit_once('-')?;
    if !prefix.contains("TxRx")
        && !prefix.contains("txrx")
        && !prefix.contains("-tx")
        && !prefix.contains("-rx")
        && !prefix.contains("_tx")
        && !prefix.contains("_rx")
    {
        return None;
    }
    suffix.parse().ok()
}

pub fn cpu_mask_string(cpus: &[usize]) -> String {
    let unique = cpus.iter().copied().collect::<BTreeSet<_>>();
    if unique.is_empty() {
        return "0".to_string();
    }

    let groups = unique.iter().copied().max().unwrap_or(0) / 32 + 1;
    let mut words = vec![0u32; groups];
    for cpu in unique {
        words[cpu / 32] |= 1u32 << (cpu % 32);
    }

    let mut parts = Vec::with_capacity(words.len());
    for idx in (0..words.len()).rev() {
        let word = words[idx];
        if idx == words.len() - 1 {
            parts.push(format!("{word:x}"));
        } else {
            parts.push(format!("{word:08x}"));
        }
    }
    parts.join(",")
}

pub fn cpu_list_string(cpus: &[usize]) -> String {
    let sorted = cpus.iter().copied().collect::<BTreeSet<_>>();
    let values = sorted.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        return String::new();
    }

    let mut out = Vec::new();
    let mut start = values[0];
    let mut prev = values[0];

    for cpu in values.into_iter().skip(1) {
        if cpu == prev + 1 {
            prev = cpu;
            continue;
        }

        out.push(format_cpu_range(start, prev));
        start = cpu;
        prev = cpu;
    }
    out.push(format_cpu_range(start, prev));

    out.join(",")
}

fn format_cpu_range(start: usize, end: usize) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

pub fn parse_cpu_mask(raw: &str) -> Result<BTreeSet<usize>> {
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!("cpu mask is empty");
    }

    let mut out = BTreeSet::new();
    let parts = token.split(',').map(str::trim).collect::<Vec<_>>();
    for (word_idx, part) in parts.iter().rev().enumerate() {
        let value = u32::from_str_radix(part, 16)
            .with_context(|| format!("invalid cpu mask word: {part}"))?;
        for bit in 0..32 {
            if (value & (1u32 << bit)) != 0 {
                out.insert(word_idx * 32 + bit);
            }
        }
    }

    Ok(out)
}

pub fn xps_mask_matches(raw: &str, cpus: &[usize]) -> bool {
    parse_cpu_mask(raw)
        .map(|current| current == cpus.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or(false)
}

pub fn affinity_list_matches(raw: &str, cpus: &[usize]) -> bool {
    parse_cpu_list(raw.trim())
        .map(|current| current == cpus.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or(false)
}

pub fn write_xps_cpus(action: &XpsAction) -> Result<()> {
    write_trimmed(&action.path, &action.mask)
}

pub fn write_irq_affinity(action: &IrqAffinityAction) -> Result<()> {
    if action.list_path.exists() {
        return write_trimmed(&action.list_path, &action.affinity_list);
    }
    write_trimmed(&action.mask_path, &cpu_mask_string(&action.cpus))
}

fn write_trimmed(path: &Path, value: &str) -> Result<()> {
    fs::write(path, format!("{value}\n"))
        .with_context(|| format!("failed to write {} -> {}", value, path.display()))
}

pub fn validate_cpu_config(cfg: &ScxConfig) -> Result<()> {
    let online = read_online_cpus()?;

    validate_cpu_set("policy.forwarding_cpus", &cfg.policy.forwarding_cpus, &online)?;
    validate_cpu_set("policy.control_cpus", &cfg.policy.control_cpus, &online)?;
    if !cfg.policy.ksoftirqd_cpus.is_empty() {
        validate_optional_cpu_set("policy.ksoftirqd_cpus", &cfg.policy.ksoftirqd_cpus, &online)?;
    }

    for (idx, class) in cfg.policy.thread_cpu_classes.iter().enumerate() {
        if class.thread_name_prefix.trim().is_empty() {
            anyhow::bail!("policy.thread_cpu_classes[{idx}].thread_name_prefix is empty");
        }
        if !class.cpus.is_empty() {
            validate_optional_cpu_set(
                &format!("policy.thread_cpu_classes[{idx}].cpus"),
                &class.cpus,
                &online,
            )?;
        }
    }

    validate_network_config(cfg)?;

    Ok(())
}

fn validate_cpu_set(name: &str, cpus: &[usize], online: &BTreeSet<usize>) -> Result<()> {
    if cpus.is_empty() {
        anyhow::bail!("{name} is empty");
    }
    validate_optional_cpu_set(name, cpus, online)
}

fn validate_optional_cpu_set(name: &str, cpus: &[usize], online: &BTreeSet<usize>) -> Result<()> {
    for cpu in cpus {
        if !online.contains(cpu) {
            anyhow::bail!(
                "{name} contains cpu {} which is not online; online cpus are {:?}",
                cpu,
                online
            );
        }
    }
    Ok(())
}

fn validate_network_config(cfg: &ScxConfig) -> Result<()> {
    let network = &cfg.network;
    if !network.apply_irq_affinity && !network.apply_xps && network.interfaces.is_empty() {
        return Ok(());
    }

    if network.interfaces.is_empty() {
        anyhow::bail!(
            "network.interfaces is empty, but network.apply_irq_affinity or network.apply_xps is enabled"
        );
    }

    for iface in &network.interfaces {
        let iface_root = PathBuf::from(format!("/sys/class/net/{iface}"));
        if !iface_root.exists() {
            anyhow::bail!(
                "network.interfaces contains {iface}, but {} does not exist",
                iface_root.display()
            );
        }

        if network.apply_xps {
            let tx_queues = read_queue_locality_states(iface, "tx-", "xps_cpus")?;
            if tx_queues.is_empty() {
                anyhow::bail!(
                    "network.apply_xps is enabled, but interface {iface} has no tx-*/xps_cpus entries"
                );
            }
        }

        if network.apply_irq_affinity {
            let irqs = read_irq_locality_states(iface)?;
            if irqs.is_empty() {
                anyhow::bail!(
                    "network.apply_irq_affinity is enabled, but no IRQ labels containing interface {iface} were found in /proc/interrupts"
                );
            }
        }
    }

    Ok(())
}

fn parse_cpu_list(raw: &str) -> Result<BTreeSet<usize>> {
    let mut out = BTreeSet::new();
    for part in raw.split(',').filter(|s| !s.trim().is_empty()) {
        let token = part.trim();
        if let Some((start_s, end_s)) = token.split_once('-') {
            let start: usize =
                start_s.parse().with_context(|| format!("invalid cpu range: {token}"))?;
            let end: usize =
                end_s.parse().with_context(|| format!("invalid cpu range: {token}"))?;
            if start > end {
                anyhow::bail!("invalid cpu range: {token}");
            }
            for c in start..=end {
                out.insert(c);
            }
        } else {
            let cpu: usize = token.parse().with_context(|| format!("invalid cpu id: {token}"))?;
            out.insert(cpu);
        }
    }
    if out.is_empty() {
        anyhow::bail!("parsed online cpu list is empty from input: {raw}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        affinity_list_matches, cpu_list_string, cpu_mask_string, matches_target, parse_cpu_mask,
        parse_irq_queue_index, parse_ksoftirqd_cpu, xps_mask_matches, DiscoveryConfig,
        NetworkConfig, PolicyConfig, QueueMappingMode, SchedulerConfig, SchedulerMode, ScxConfig,
    };

    fn test_config() -> ScxConfig {
        ScxConfig {
            discovery: DiscoveryConfig {
                process_names: vec!["landscape-webserver".into()],
                cmdline_keywords: vec!["landscape-webserver".into()],
                cgroup_prefixes: Vec::new(),
                thread_include_prefixes: Vec::new(),
                thread_exclude_prefixes: Vec::new(),
            },
            policy: PolicyConfig {
                forwarding_cpus: vec![0, 1],
                control_cpus: vec![2, 3],
                manage_ksoftirqd: true,
                ksoftirqd_cpus: Vec::new(),
                apply_sched_ext: true,
                thread_cpu_classes: Vec::new(),
            },
            network: NetworkConfig {
                interfaces: Vec::new(),
                apply_irq_affinity: false,
                apply_xps: false,
                queue_mapping_mode: QueueMappingMode::RoundRobin,
            },
            scheduler: SchedulerConfig {
                mode: SchedulerMode::Disabled,
                start_command: Vec::new(),
                stop_command: Vec::new(),
                pid_file: "/tmp/landscape-scx-test.pid".into(),
                ready_timeout_ms: 1000,
                fallback_on_error: false,
            },
            agent: super::AgentConfig { apply_interval_secs: 10 },
        }
    }

    #[test]
    fn parse_ksoftirqd_thread_name() {
        assert_eq!(parse_ksoftirqd_cpu("ksoftirqd/0"), Some(0));
        assert_eq!(parse_ksoftirqd_cpu("ksoftirqd/31"), Some(31));
        assert_eq!(parse_ksoftirqd_cpu("ksoftirqd/not-a-cpu"), None);
        assert_eq!(parse_ksoftirqd_cpu("tokio-runtime-w"), None);
    }

    #[test]
    fn discovery_honors_thread_include_and_exclude_prefixes() {
        let mut cfg = test_config();
        cfg.discovery.thread_include_prefixes = vec!["tokio-runtime-w".into()];
        cfg.discovery.thread_exclude_prefixes = vec!["tokio-runtime-worker-blocking".into()];

        assert!(matches_target(
            "tokio-runtime-w",
            "landscape-webserver --config /etc/landscape.toml",
            "",
            &cfg
        ));
        assert!(!matches_target(
            "axum-http-worker",
            "landscape-webserver --config /etc/landscape.toml",
            "",
            &cfg
        ));
        assert!(!matches_target(
            "tokio-runtime-worker-blocking",
            "landscape-webserver --config /etc/landscape.toml",
            "",
            &cfg
        ));
    }

    #[test]
    fn ksoftirqd_is_scoped_to_effective_cpu_set() {
        let mut cfg = test_config();
        assert!(matches_target("ksoftirqd/0", "", "", &cfg));
        assert!(matches_target("ksoftirqd/1", "", "", &cfg));
        assert!(!matches_target("ksoftirqd/2", "", "", &cfg));

        cfg.policy.ksoftirqd_cpus = vec![3];
        assert!(!matches_target("ksoftirqd/0", "", "", &cfg));
        assert!(matches_target("ksoftirqd/3", "", "", &cfg));
    }

    #[test]
    fn cpu_list_string_compacts_ranges() {
        assert_eq!(cpu_list_string(&[0, 2, 3, 4, 7, 8, 9]), "0,2-4,7-9");
    }

    #[test]
    fn cpu_mask_string_formats_multiword_masks() {
        assert_eq!(cpu_mask_string(&[0, 2, 35]), "8,00000005");
    }

    #[test]
    fn parse_cpu_mask_round_trips() {
        let mask = "8,00000005";
        let parsed = parse_cpu_mask(mask).unwrap().into_iter().collect::<Vec<_>>();
        assert_eq!(parsed, vec![0, 2, 35]);
        assert!(xps_mask_matches(mask, &[0, 2, 35]));
        assert!(affinity_list_matches("0,2,35", &[0, 2, 35]));
    }

    #[test]
    fn irq_queue_index_requires_queue_style_label() {
        assert_eq!(parse_irq_queue_index("ens27f0-TxRx-0"), Some(0));
        assert_eq!(parse_irq_queue_index("i40e-ens16f1np1-TxRx-31"), Some(31));
        assert_eq!(parse_irq_queue_index("mlx5e-tx-7"), Some(7));
        assert_eq!(parse_irq_queue_index("mlx5e-rx-9"), Some(9));
        assert_eq!(parse_irq_queue_index("ens27f0"), None);
        assert_eq!(parse_irq_queue_index("i40e-ens16f1np1"), None);
    }
}
