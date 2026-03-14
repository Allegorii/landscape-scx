use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const SCHED_EXT_POLICY: u32 = 7;
pub const LANDSCAPE_DSQ_BASE: u64 = 0x1000;

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
    #[serde(default)]
    pub auto_partition_cpus: bool,
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
    pub interfaces: Vec<NetworkInterfaceSpec>,
    #[serde(default)]
    pub auto_discover: bool,
    #[serde(default)]
    pub auto_discover_include_prefixes: Vec<String>,
    #[serde(default)]
    pub auto_discover_exclude_prefixes: Vec<String>,
    #[serde(default)]
    pub apply_irq_affinity: bool,
    #[serde(default)]
    pub apply_xps: bool,
    #[serde(default)]
    pub apply_rss_equal: bool,
    #[serde(default)]
    pub apply_combined_channels: bool,
    #[serde(default)]
    pub clear_inactive_xps: bool,
    #[serde(default = "default_queue_mapping_mode")]
    pub queue_mapping_mode: QueueMappingMode,
    #[serde(default = "default_xps_mode")]
    pub xps_mode: XpsMode,
    #[serde(default = "default_rps_mode")]
    pub rps_mode: RpsMode,
    #[serde(default)]
    pub active_queue_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NetworkInterfaceSpec {
    Name(String),
    Config(NetworkInterfacePolicy),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfacePolicy {
    pub name: String,
    #[serde(default)]
    pub forwarding_cpus: Vec<usize>,
    #[serde(default)]
    pub active_queue_count: usize,
    #[serde(default)]
    pub apply_rss_equal: Option<bool>,
    #[serde(default)]
    pub apply_combined_channels: Option<bool>,
    #[serde(default)]
    pub clear_inactive_xps: Option<bool>,
    #[serde(default)]
    pub queue_mapping_mode: Option<QueueMappingMode>,
    #[serde(default)]
    pub xps_mode: Option<XpsMode>,
    #[serde(default)]
    pub rps_mode: Option<RpsMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueueMappingMode {
    RoundRobin,
    FullMask,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XpsMode {
    Auto,
    Cpus,
    Rxqs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpsMode {
    Auto,
    Off,
    Preserve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerMode {
    Disabled,
    ExternalCommand,
    CustomBpf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScxSwitchMode {
    Partial,
    Full,
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
    #[serde(default)]
    pub custom_bpf: CustomBpfSchedulerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomBpfSchedulerConfig {
    #[serde(default = "default_scx_switch_mode")]
    pub switch_mode: ScxSwitchMode,
    #[serde(default)]
    pub housekeeping_cpus: Vec<usize>,
    #[serde(default)]
    pub forwarding_thread_prefixes: Vec<String>,
    #[serde(default = "default_custom_bpf_source_file")]
    pub source_file: PathBuf,
    #[serde(default = "default_custom_bpf_build_dir")]
    pub build_dir: PathBuf,
    #[serde(default = "default_custom_bpf_link_dir")]
    pub link_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_apply_interval_secs")]
    pub apply_interval_secs: u64,
    #[serde(default = "default_event_driven")]
    pub event_driven: bool,
    #[serde(default = "default_event_debounce_ms")]
    pub event_debounce_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LandscapeSchedulerIntent {
    pub switch_mode: ScxSwitchMode,
    pub housekeeping_cpus: Vec<usize>,
    pub queues: Vec<LandscapeQueueIntent>,
    pub tasks: Vec<LandscapeTaskIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct LandscapeTaskKey {
    pub pid: i32,
    pub tid: i32,
    pub start_time_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LandscapeQueueIntent {
    pub qid: u32,
    pub interface: String,
    pub queue_index: usize,
    pub owner_cpu: usize,
    pub dsq_id: u64,
    #[serde(default)]
    pub pressure_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LandscapeTaskKind {
    Ksoftirqd,
    ForwardingWorker,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LandscapeTaskClass {
    DataplaneStrict,
    DataplaneShared,
    ControlPlane,
    Background,
}

impl Default for LandscapeTaskClass {
    fn default() -> Self {
        Self::DataplaneStrict
    }
}

impl LandscapeTaskKind {
    pub fn default_class(&self) -> LandscapeTaskClass {
        match self {
            Self::Ksoftirqd | Self::ForwardingWorker => LandscapeTaskClass::DataplaneStrict,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LandscapeTaskIntent {
    pub pid: i32,
    pub tid: i32,
    pub start_time_ns: u64,
    pub comm: String,
    pub kind: LandscapeTaskKind,
    #[serde(default)]
    pub class: LandscapeTaskClass,
    pub qid: u32,
    pub owner_cpu: usize,
}

impl LandscapeTaskIntent {
    pub fn key(&self) -> LandscapeTaskKey {
        LandscapeTaskKey {
            pid: self.pid,
            tid: self.tid,
            start_time_ns: self.start_time_ns,
        }
    }
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
            auto_partition_cpus: false,
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
            custom_bpf: CustomBpfSchedulerConfig::default(),
        }
    }
}

impl Default for CustomBpfSchedulerConfig {
    fn default() -> Self {
        Self {
            switch_mode: default_scx_switch_mode(),
            housekeeping_cpus: Vec::new(),
            forwarding_thread_prefixes: Vec::new(),
            source_file: default_custom_bpf_source_file(),
            build_dir: default_custom_bpf_build_dir(),
            link_dir: default_custom_bpf_link_dir(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            apply_interval_secs: default_apply_interval_secs(),
            event_driven: default_event_driven(),
            event_debounce_ms: default_event_debounce_ms(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            auto_discover: false,
            auto_discover_include_prefixes: Vec::new(),
            auto_discover_exclude_prefixes: Vec::new(),
            apply_irq_affinity: false,
            apply_xps: false,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            queue_mapping_mode: default_queue_mapping_mode(),
            xps_mode: default_xps_mode(),
            rps_mode: default_rps_mode(),
            active_queue_count: 0,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPolicyCpuSets {
    forwarding_cpus: Vec<usize>,
    control_cpus: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AutoDiscoveredInterfaceGroup {
    key: String,
    members: Vec<String>,
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

fn default_scx_switch_mode() -> ScxSwitchMode {
    ScxSwitchMode::Partial
}

fn default_custom_bpf_source_file() -> PathBuf {
    PathBuf::from("./bpf/landscape_scx.bpf.c")
}

fn default_custom_bpf_build_dir() -> PathBuf {
    PathBuf::from("/run/landscape-scx/custom-bpf")
}

fn default_custom_bpf_link_dir() -> PathBuf {
    PathBuf::from("/run/landscape-scx/custom-bpf/links")
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
    5
}

const fn default_event_driven() -> bool {
    true
}

const fn default_event_debounce_ms() -> u64 {
    250
}

fn default_queue_mapping_mode() -> QueueMappingMode {
    QueueMappingMode::RoundRobin
}

fn default_xps_mode() -> XpsMode {
    XpsMode::Auto
}

fn default_rps_mode() -> RpsMode {
    RpsMode::Auto
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
    pub start_time_ns: u64,
    pub comm: String,
    pub cmdline: String,
    pub cgroup: String,
}

impl ThreadCandidate {
    pub fn task_key(&self) -> LandscapeTaskKey {
        LandscapeTaskKey {
            pid: self.pid,
            tid: self.tid,
            start_time_ns: self.start_time_ns,
        }
    }
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
            let start_time_ns = match read_task_start_time_ns(pid, tid) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !matches_target(&comm, &cmdline, &cgroup, cfg) {
                continue;
            }

            out.push(ThreadCandidate {
                pid,
                tid,
                start_time_ns,
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

    let Ok(ksoftirqd_cpus) = effective_ksoftirqd_cpus(cfg) else {
        return false;
    };
    if !ksoftirqd_cpus.contains(&cpu) {
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

pub fn effective_forwarding_cpus(cfg: &ScxConfig) -> Result<Vec<usize>> {
    Ok(resolve_policy_cpu_sets(cfg)?.forwarding_cpus)
}

pub fn effective_control_cpus(cfg: &ScxConfig) -> Result<Vec<usize>> {
    Ok(resolve_policy_cpu_sets(cfg)?.control_cpus)
}

pub fn effective_ksoftirqd_cpus(cfg: &ScxConfig) -> Result<Vec<usize>> {
    if !cfg.policy.ksoftirqd_cpus.is_empty() {
        return Ok(cfg.policy.ksoftirqd_cpus.clone());
    }
    effective_forwarding_cpus(cfg)
}

fn resolve_policy_cpu_sets(cfg: &ScxConfig) -> Result<ResolvedPolicyCpuSets> {
    if !cfg.policy.auto_partition_cpus {
        return Ok(ResolvedPolicyCpuSets {
            forwarding_cpus: cfg.policy.forwarding_cpus.clone(),
            control_cpus: cfg.policy.control_cpus.clone(),
        });
    }

    let online = read_online_cpus()?;
    let groups = online_cpu_core_groups(&online)?;
    let (forwarding_cpus, control_cpus) = auto_partition_cpu_sets_from_core_groups(&groups);

    Ok(ResolvedPolicyCpuSets { forwarding_cpus, control_cpus })
}

fn online_cpu_core_groups(online: &BTreeSet<usize>) -> Result<Vec<Vec<usize>>> {
    let mut seen = BTreeSet::new();
    let mut groups = Vec::new();

    for cpu in online.iter().copied() {
        if seen.contains(&cpu) {
            continue;
        }

        let mut group = read_cpu_thread_siblings(cpu)
            .unwrap_or_else(|_| BTreeSet::from([cpu]))
            .into_iter()
            .filter(|sibling| online.contains(sibling))
            .collect::<Vec<_>>();
        if group.is_empty() {
            group.push(cpu);
        }
        group.sort_unstable();

        for sibling in &group {
            seen.insert(*sibling);
        }
        groups.push(group);
    }

    groups.sort_by_key(|group| group[0]);
    Ok(groups)
}

fn auto_partition_cpu_sets_from_core_groups(core_groups: &[Vec<usize>]) -> (Vec<usize>, Vec<usize>) {
    if core_groups.is_empty() {
        return (Vec::new(), Vec::new());
    }

    if core_groups.len() == 1 {
        let forwarding_cpus = core_groups[0].first().copied().into_iter().collect::<Vec<_>>();
        let mut control_cpus = core_groups[0].iter().skip(1).copied().collect::<Vec<_>>();
        if control_cpus.is_empty() {
            control_cpus = forwarding_cpus.clone();
        }
        return (forwarding_cpus, control_cpus);
    }

    let reserve_groups = if core_groups.len() <= 1 { 0 } else { (core_groups.len() / 4).max(1) };
    let split_at = core_groups.len().saturating_sub(reserve_groups);

    // Keep forwarding and control on separate physical cores by default. On SMT
    // systems forwarding uses one sibling per core and leaves the paired sibling
    // unused unless that whole core is assigned to housekeeping/control.
    let mut forwarding_cpus = core_groups
        .iter()
        .take(split_at)
        .filter_map(|group| group.first().copied())
        .collect::<Vec<_>>();
    let mut control_cpus = core_groups
        .iter()
        .skip(split_at)
        .flat_map(|group| group.iter().copied())
        .collect::<Vec<_>>();

    if forwarding_cpus.is_empty() {
        forwarding_cpus = core_groups
            .iter()
            .take(1)
            .filter_map(|group| group.first().copied())
            .collect::<Vec<_>>();
    }
    if control_cpus.is_empty() {
        control_cpus = forwarding_cpus.clone();
    }

    (forwarding_cpus, control_cpus)
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

fn read_task_start_time_ns(pid: i32, tid: i32) -> io::Result<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))?;
    let Some(comm_end) = raw.rfind(") ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing task stat comm terminator",
        ));
    };
    let fields = raw[comm_end + 2..].split_whitespace().collect::<Vec<_>>();
    let Some(start_ticks_raw) = fields.get(19) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing task stat start time"));
    };
    let start_ticks = start_ticks_raw
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let ticks_per_sec = task_clock_ticks_per_sec()?;
    Ok(start_ticks.saturating_mul(1_000_000_000u64) / ticks_per_sec)
}

fn task_clock_ticks_per_sec() -> io::Result<u64> {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value <= 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value as u64)
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

pub fn try_set_sched_other(tid: i32) -> Result<()> {
    let attr = SchedAttr {
        size: std::mem::size_of::<SchedAttr>() as u32,
        sched_policy: libc::SCHED_OTHER as u32,
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
    Err(anyhow::anyhow!("sched_setattr tid={} policy=SCHED_OTHER failed: {}", tid, err))
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
    pub tx_xps_cpus: Vec<QueueLocalityState>,
    pub tx_xps_rxqs: Vec<QueueLocalityState>,
    pub rx_queues: Vec<QueueLocalityState>,
    pub irqs: Vec<IrqLocalityState>,
    pub channel_status: Option<ChannelStatus>,
    pub rss_status: Option<RssStatus>,
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
    pub total_count: u64,
    pub affinity_list_path: PathBuf,
    pub affinity_mask_path: PathBuf,
    pub affinity_list: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceLocalityPlan {
    pub interface: String,
    pub forwarding_cpus: Vec<usize>,
    pub queue_mapping_mode: QueueMappingMode,
    pub xps_mode: XpsMode,
    pub rps_mode: RpsMode,
    pub apply_rss_equal: bool,
    pub apply_combined_channels: bool,
    pub clear_inactive_xps: bool,
    pub active_queue_count: usize,
    pub total_tx_queues: usize,
    pub total_rx_queues: usize,
    pub total_irqs: usize,
    pub status: InterfaceLocalityStatus,
    pub channel_action: Option<ChannelAction>,
    pub rss_action: Option<RssEqualAction>,
    pub xps_actions: Vec<XpsAction>,
    pub rps_actions: Vec<RpsAction>,
    pub inactive_xps_actions: Vec<XpsAction>,
    pub irq_actions: Vec<IrqAffinityAction>,
}

#[derive(Debug, Clone)]
pub struct XpsAction {
    pub interface: String,
    pub queue_name: String,
    pub path: PathBuf,
    pub mode: XpsMode,
    pub indices: Vec<usize>,
    pub mask: String,
    pub current_value: String,
}

#[derive(Debug, Clone)]
pub struct RpsAction {
    pub interface: String,
    pub queue_name: String,
    pub path: PathBuf,
    pub mask: String,
    pub indices: Vec<usize>,
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

#[derive(Debug, Clone)]
struct ResolvedNetworkInterface {
    name: String,
    auto_discovered: bool,
    forwarding_cpus: Vec<usize>,
    active_queue_count: usize,
    apply_rss_equal: bool,
    apply_combined_channels: bool,
    clear_inactive_xps: bool,
    queue_mapping_mode: QueueMappingMode,
    requested_xps_mode: XpsMode,
    xps_mode: XpsMode,
    rps_mode: RpsMode,
}

#[derive(Debug, Clone)]
pub struct ChannelStatus {
    pub current_combined: usize,
    pub max_combined: usize,
}

#[derive(Debug, Clone)]
pub struct RssStatus {
    pub ring_count: usize,
    pub used_queues: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct ChannelAction {
    pub interface: String,
    pub current_combined: usize,
    pub max_combined: usize,
    pub expected_combined: usize,
}

#[derive(Debug, Clone)]
pub struct RssEqualAction {
    pub interface: String,
    pub current_ring_count: usize,
    pub current_used_queues: Vec<usize>,
    pub expected_queue_count: usize,
}

impl NetworkInterfaceSpec {
    fn resolve(&self, cfg: &ScxConfig) -> Result<ResolvedNetworkInterface> {
        let network = &cfg.network;
        let forwarding_cpus = effective_forwarding_cpus(cfg)?;
        match self {
            NetworkInterfaceSpec::Name(name) => {
                let mut resolved = ResolvedNetworkInterface {
                    name: name.clone(),
                    auto_discovered: false,
                    forwarding_cpus,
                    active_queue_count: network.active_queue_count,
                    apply_rss_equal: network.apply_rss_equal,
                    apply_combined_channels: network.apply_combined_channels,
                    clear_inactive_xps: network.clear_inactive_xps,
                    queue_mapping_mode: network.queue_mapping_mode.clone(),
                    requested_xps_mode: network.xps_mode.clone(),
                    xps_mode: network.xps_mode.clone(),
                    rps_mode: network.rps_mode.clone(),
                };
                resolved.xps_mode = effective_xps_mode(cfg, &resolved);
                Ok(resolved)
            }
            NetworkInterfaceSpec::Config(iface_cfg) => {
                let mut resolved = ResolvedNetworkInterface {
                    name: iface_cfg.name.clone(),
                    auto_discovered: false,
                    forwarding_cpus: if iface_cfg.forwarding_cpus.is_empty() {
                        forwarding_cpus
                    } else {
                        iface_cfg.forwarding_cpus.clone()
                    },
                    active_queue_count: if iface_cfg.active_queue_count == 0 {
                        network.active_queue_count
                    } else {
                        iface_cfg.active_queue_count
                    },
                    apply_rss_equal: iface_cfg.apply_rss_equal.unwrap_or(network.apply_rss_equal),
                    apply_combined_channels: iface_cfg
                        .apply_combined_channels
                        .unwrap_or(network.apply_combined_channels),
                    clear_inactive_xps: iface_cfg
                        .clear_inactive_xps
                        .unwrap_or(network.clear_inactive_xps),
                    queue_mapping_mode: iface_cfg
                        .queue_mapping_mode
                        .clone()
                        .unwrap_or_else(|| network.queue_mapping_mode.clone()),
                    requested_xps_mode: iface_cfg
                        .xps_mode
                        .clone()
                        .unwrap_or_else(|| network.xps_mode.clone()),
                    xps_mode: iface_cfg
                        .xps_mode
                        .clone()
                        .unwrap_or_else(|| network.xps_mode.clone()),
                    rps_mode: iface_cfg
                        .rps_mode
                        .clone()
                        .unwrap_or_else(|| network.rps_mode.clone()),
                };
                resolved.xps_mode = effective_xps_mode(cfg, &resolved);
                Ok(resolved)
            }
        }
    }
}

fn resolved_network_interfaces(cfg: &ScxConfig) -> Result<Vec<ResolvedNetworkInterface>> {
    resolved_network_interfaces_at(cfg, Path::new("/sys/class/net"))
}

fn resolved_network_interfaces_at(
    cfg: &ScxConfig,
    sys_class_net: &Path,
) -> Result<Vec<ResolvedNetworkInterface>> {
    if !cfg.network.interfaces.is_empty() {
        return cfg.network.interfaces.iter().map(|iface| iface.resolve(cfg)).collect();
    }

    if !cfg.network.auto_discover {
        return Ok(Vec::new());
    }

    auto_discovered_network_interfaces(cfg, sys_class_net)
}

fn auto_discovered_network_interfaces(
    cfg: &ScxConfig,
    sys_class_net: &Path,
) -> Result<Vec<ResolvedNetworkInterface>> {
    let groups = discover_auto_network_interface_groups(cfg, sys_class_net)?;
    if groups.is_empty() {
        return Ok(Vec::new());
    }

    let forwarding_cpu_sets =
        split_forwarding_cpus_across_interfaces(&effective_forwarding_cpus(cfg)?, groups.len())?;
    let network = &cfg.network;
    let mut out = Vec::new();

    for (group, group_forwarding_cpus) in groups.into_iter().zip(forwarding_cpu_sets.into_iter()) {
        let compatible_members = auto_discovered_compatible_group_members(
            cfg,
            &group.members,
            network,
            &group_forwarding_cpus,
            sys_class_net,
        );
        let member_cpu_sets =
            split_group_forwarding_cpus_across_members(&group_forwarding_cpus, compatible_members.len());
        for (name, forwarding_cpus) in compatible_members.into_iter().zip(member_cpu_sets.into_iter()) {
            let mut resolved = ResolvedNetworkInterface {
                name,
                auto_discovered: true,
                forwarding_cpus,
                active_queue_count: network.active_queue_count,
                apply_rss_equal: network.apply_rss_equal,
                apply_combined_channels: network.apply_combined_channels,
                clear_inactive_xps: network.clear_inactive_xps,
                queue_mapping_mode: network.queue_mapping_mode.clone(),
                requested_xps_mode: network.xps_mode.clone(),
                xps_mode: network.xps_mode.clone(),
                rps_mode: network.rps_mode.clone(),
            };
            resolved.xps_mode = effective_xps_mode(cfg, &resolved);
            out.push(resolved);
        }
    }

    Ok(out)
}

fn auto_discovered_compatible_group_members(
    cfg: &ScxConfig,
    members: &[String],
    network: &NetworkConfig,
    group_forwarding_cpus: &[usize],
    sys_class_net: &Path,
) -> Vec<String> {
    members
        .iter()
        .filter_map(|name| {
            let mut resolved = ResolvedNetworkInterface {
                name: name.clone(),
                auto_discovered: true,
                forwarding_cpus: group_forwarding_cpus.to_vec(),
                active_queue_count: network.active_queue_count,
                apply_rss_equal: network.apply_rss_equal,
                apply_combined_channels: network.apply_combined_channels,
                clear_inactive_xps: network.clear_inactive_xps,
                queue_mapping_mode: network.queue_mapping_mode.clone(),
                requested_xps_mode: network.xps_mode.clone(),
                xps_mode: network.xps_mode.clone(),
                rps_mode: network.rps_mode.clone(),
            };
            resolved.xps_mode = effective_xps_mode(cfg, &resolved);

            if auto_discovered_interface_supports_queue_mode(cfg, sys_class_net, &resolved) {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect()
}

fn auto_discovered_interface_supports_queue_mode(
    cfg: &ScxConfig,
    sys_class_net: &Path,
    iface: &ResolvedNetworkInterface,
) -> bool {
    let iface_root = sys_class_net.join(&iface.name);
    let tx_count = queue_value_file_count_at(&iface_root, "tx-", "xps_cpus");
    let tx_rxqs_count = queue_value_file_count_at(&iface_root, "tx-", "xps_rxqs");
    let any_tx_count = queue_entry_count_at(&iface_root, "tx-");

    if any_tx_count == 0 {
        return false;
    }

    if !matches!(iface.rps_mode, RpsMode::Preserve) && queue_entry_count_at(&iface_root, "rx-") == 0 {
        return false;
    }
    if cfg.network.apply_irq_affinity {
        let interrupts = match fs::read_to_string("/proc/interrupts") {
            Ok(v) => v,
            Err(_) => return false,
        };
        if irq_label_count_in_interrupts(&interrupts, &iface.name) == 0 {
            return false;
        }
    }

    match iface.xps_mode {
        XpsMode::Auto => tx_count > 0 || tx_rxqs_count > 0,
        XpsMode::Cpus => tx_count > 0,
        XpsMode::Rxqs => tx_rxqs_count > 0,
    }
}

fn discover_auto_network_interface_groups(
    cfg: &ScxConfig,
    sys_class_net: &Path,
) -> Result<Vec<AutoDiscoveredInterfaceGroup>> {
    let mut groups = BTreeMap::<String, Vec<String>>::new();

    for entry in fs::read_dir(sys_class_net)
        .with_context(|| format!("failed to read {}", sys_class_net.display()))?
    {
        let entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if !auto_discover_name_matches_filters(&cfg.network, &name) {
            continue;
        }
        if interface_is_auto_discoverable(&name, &entry.path())? {
            let key = auto_discover_group_key(&name, &entry.path())?;
            groups.entry(key).or_default().push(name);
        }
    }

    let mut out = groups
        .into_iter()
        .map(|(key, mut members)| {
            members.sort();
            AutoDiscoveredInterfaceGroup { key, members }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

fn auto_discover_name_matches_filters(network: &NetworkConfig, name: &str) -> bool {
    if network
        .auto_discover_exclude_prefixes
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return false;
    }

    if network.auto_discover_include_prefixes.is_empty() {
        return true;
    }

    network
        .auto_discover_include_prefixes
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn auto_discover_group_key(name: &str, iface_root: &Path) -> Result<String> {
    let master_path = iface_root.join("master");
    if !master_path.exists() {
        return Ok(name.to_string());
    }

    let target = fs::read_link(&master_path)
        .with_context(|| format!("failed to read {}", master_path.display()))?;
    let Some(master_name) = target.file_name().and_then(|value| value.to_str()) else {
        return Ok(name.to_string());
    };
    Ok(master_name.to_string())
}

fn interface_is_auto_discoverable(name: &str, iface_root: &Path) -> Result<bool> {
    if name == "lo" {
        return Ok(false);
    }
    if !iface_root.join("device").exists() {
        return Ok(false);
    }
    if iface_root.join("bridge").exists() {
        return Ok(false);
    }
    if !interface_has_carrier(iface_root)? {
        return Ok(false);
    }

    interface_has_queue_entries(iface_root)
}

fn interface_has_carrier(iface_root: &Path) -> Result<bool> {
    let carrier_path = iface_root.join("carrier");
    if !carrier_path.exists() {
        return Ok(true);
    }

    let carrier = fs::read_to_string(&carrier_path)
        .with_context(|| format!("failed to read {}", carrier_path.display()))?;
    Ok(carrier.trim() != "0")
}

fn interface_has_queue_entries(iface_root: &Path) -> Result<bool> {
    let queue_root = iface_root.join("queues");
    if !queue_root.exists() {
        return Ok(false);
    }

    for entry in fs::read_dir(&queue_root)
        .with_context(|| format!("failed to read {}", queue_root.display()))?
    {
        let entry = match entry {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("tx-") || name.starts_with("rx-") {
            return Ok(true);
        }
    }

    Ok(false)
}

fn queue_entry_count_at(iface_root: &Path, prefix: &str) -> usize {
    let queue_root = iface_root.join("queues");
    if !queue_root.exists() {
        return 0;
    }

    fs::read_dir(&queue_root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .count()
}

fn queue_value_file_count_at(iface_root: &Path, prefix: &str, value_file: &str) -> usize {
    let queue_root = iface_root.join("queues");
    if !queue_root.exists() {
        return 0;
    }

    fs::read_dir(&queue_root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .filter(|entry| entry.path().join(value_file).exists())
        .count()
}

fn split_forwarding_cpus_across_interfaces(
    forwarding_cpus: &[usize],
    interface_count: usize,
) -> Result<Vec<Vec<usize>>> {
    if interface_count == 0 {
        return Ok(Vec::new());
    }
    if forwarding_cpus.len() < interface_count {
        anyhow::bail!(
            "network.auto_discover found {} interfaces, but only {} forwarding CPUs are available",
            interface_count,
            forwarding_cpus.len()
        );
    }

    let base = forwarding_cpus.len() / interface_count;
    let remainder = forwarding_cpus.len() % interface_count;
    let mut start = 0usize;
    let mut out = Vec::with_capacity(interface_count);

    for idx in 0..interface_count {
        let len = base + usize::from(idx < remainder);
        out.push(forwarding_cpus[start..start + len].to_vec());
        start += len;
    }

    Ok(out)
}

fn split_group_forwarding_cpus_across_members(
    forwarding_cpus: &[usize],
    member_count: usize,
) -> Vec<Vec<usize>> {
    if member_count == 0 {
        return Vec::new();
    }
    if forwarding_cpus.is_empty() {
        return vec![Vec::new(); member_count];
    }
    if forwarding_cpus.len() >= member_count {
        return split_forwarding_cpus_across_interfaces(forwarding_cpus, member_count)
            .unwrap_or_else(|_| forwarding_cpus.iter().copied().map(|cpu| vec![cpu]).collect());
    }

    (0..member_count)
        .map(|idx| vec![forwarding_cpus[idx % forwarding_cpus.len()]])
        .collect()
}

fn effective_xps_mode(cfg: &ScxConfig, iface: &ResolvedNetworkInterface) -> XpsMode {
    match iface.requested_xps_mode {
        XpsMode::Cpus | XpsMode::Rxqs => iface.requested_xps_mode.clone(),
        XpsMode::Auto => {
            if strict_forwarding_thread_pinning(cfg) {
                XpsMode::Cpus
            } else {
                XpsMode::Rxqs
            }
        }
    }
}

fn adapt_xps_mode_to_interface_support(
    mut iface: ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
) -> ResolvedNetworkInterface {
    if !matches!(iface.requested_xps_mode, XpsMode::Auto) {
        return iface;
    }

    iface.xps_mode = match iface.xps_mode {
        XpsMode::Rxqs if status.tx_xps_rxqs.is_empty() && !status.tx_xps_cpus.is_empty() => {
            XpsMode::Cpus
        }
        XpsMode::Cpus if status.tx_xps_cpus.is_empty() && !status.tx_xps_rxqs.is_empty() => {
            XpsMode::Rxqs
        }
        mode => mode,
    };
    iface
}

fn strict_forwarding_thread_pinning(cfg: &ScxConfig) -> bool {
    if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        return true;
    }

    let mut saw_forwarding_class = false;
    for class in &cfg.policy.thread_cpu_classes {
        if !looks_like_forwarding_prefix(&class.thread_name_prefix) {
            continue;
        }
        saw_forwarding_class = true;
        if !class.apply_affinity.unwrap_or(true) || class.cpus.len() != 1 {
            return false;
        }
    }

    saw_forwarding_class
}

fn looks_like_forwarding_prefix(prefix: &str) -> bool {
    matches!(prefix, "pppd" | "landscape-forwarder")
        || prefix.starts_with("landscape_pppoe")
        || prefix.starts_with("pppoe-rx-")
}

fn physical_core_capacity(cpus: &[usize]) -> usize {
    let mut unique_cores = BTreeSet::new();

    for cpu in cpus {
        let siblings = read_cpu_thread_siblings(*cpu).unwrap_or_else(|_| {
            let mut out = BTreeSet::new();
            out.insert(*cpu);
            out
        });
        let canonical =
            siblings.into_iter().map(|entry| entry.to_string()).collect::<Vec<_>>().join(",");
        unique_cores.insert(canonical);
    }

    unique_cores.len().max(1)
}

fn read_cpu_thread_siblings(cpu: usize) -> Result<BTreeSet<usize>> {
    let path =
        PathBuf::from(format!("/sys/devices/system/cpu/cpu{}/topology/thread_siblings_list", cpu));
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read cpu topology siblings from {}", path.display()))?;
    parse_cpu_list(raw.trim())
}

pub fn build_network_locality_plans(cfg: &ScxConfig) -> Result<Vec<InterfaceLocalityPlan>> {
    let mut plans = Vec::new();

    for iface in resolved_network_interfaces(cfg)? {
        let initial_mode = iface.xps_mode.clone();
        let initial_status = match read_interface_locality_status(&iface) {
            Ok(status) => status,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        let iface = adapt_xps_mode_to_interface_support(iface, &initial_status);
        let status = if iface.xps_mode == initial_mode {
            initial_status
        } else {
            match read_interface_locality_status(&iface) {
                Ok(status) => status,
                Err(_err) if iface.auto_discovered => continue,
                Err(err) => return Err(err),
            }
        };
        let active_queue_count = match effective_active_queue_count(cfg, &iface, &status) {
            Ok(count) => count,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        let channel_action = match build_channel_action(&iface, &status, active_queue_count) {
            Ok(action) => action,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        let rss_action = match build_rss_equal_action(&iface, &status, active_queue_count) {
            Ok(action) => action,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        let rps_actions = match build_interface_rps_actions(&iface, &status, active_queue_count) {
            Ok(actions) => actions,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        let xps_actions = if cfg.network.apply_xps {
            match build_interface_xps_actions(&iface, &status, active_queue_count) {
                Ok(actions) => actions,
                Err(_err) if iface.auto_discovered => continue,
                Err(err) => return Err(err),
            }
        } else {
            Vec::new()
        };
        let inactive_xps_actions = if iface.clear_inactive_xps {
            match build_inactive_xps_actions(&status, active_queue_count) {
                Ok(actions) => actions,
                Err(_err) if iface.auto_discovered => continue,
                Err(err) => return Err(err),
            }
        } else {
            Vec::new()
        };
        let irq_actions = if cfg.network.apply_irq_affinity {
            match build_interface_irq_actions(&iface, &status, active_queue_count) {
                Ok(actions) => actions,
                Err(_err) if iface.auto_discovered => continue,
                Err(err) => return Err(err),
            }
        } else {
            Vec::new()
        };

        plans.push(InterfaceLocalityPlan {
            interface: iface.name.clone(),
            forwarding_cpus: iface.forwarding_cpus.clone(),
            queue_mapping_mode: iface.queue_mapping_mode.clone(),
            xps_mode: iface.xps_mode.clone(),
            rps_mode: iface.rps_mode.clone(),
            apply_rss_equal: iface.apply_rss_equal,
            apply_combined_channels: iface.apply_combined_channels,
            clear_inactive_xps: iface.clear_inactive_xps,
            active_queue_count,
            total_tx_queues: status_tx_queue_count(&status, &iface.xps_mode),
            total_rx_queues: status.rx_queues.len(),
            total_irqs: status.irqs.len(),
            channel_action,
            rss_action,
            status,
            xps_actions,
            rps_actions,
            inactive_xps_actions,
            irq_actions,
        });
    }

    Ok(plans)
}

fn read_interface_locality_status(
    iface: &ResolvedNetworkInterface,
) -> Result<InterfaceLocalityStatus> {
    let iface_root = PathBuf::from(format!("/sys/class/net/{}", iface.name));
    if !iface_root.exists() {
        anyhow::bail!(
            "network.interfaces contains {}, but {} does not exist",
            iface.name,
            iface_root.display()
        );
    }

    Ok(InterfaceLocalityStatus {
        interface: iface.name.clone(),
        tx_xps_cpus: read_queue_locality_states(&iface.name, "tx-", "xps_cpus")?,
        tx_xps_rxqs: read_queue_locality_states(&iface.name, "tx-", "xps_rxqs")?,
        rx_queues: read_queue_locality_states(&iface.name, "rx-", "rps_cpus")?,
        irqs: read_irq_locality_states(&iface.name)?,
        channel_status: if iface.apply_combined_channels {
            Some(read_ethtool_channels_status(&iface.name)?)
        } else {
            None
        },
        rss_status: if iface.apply_rss_equal || matches!(iface.rps_mode, RpsMode::Auto) {
            Some(read_ethtool_rss_status(&iface.name)?)
        } else {
            None
        },
    })
}

fn run_ethtool(args: &[&str]) -> Result<String> {
    let output = Command::new("ethtool")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute ethtool {}", args.join(" ")))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };
    anyhow::bail!("ethtool {} failed: {}", args.join(" "), details);
}

pub fn irqbalance_conflicts(cfg: &ScxConfig) -> bool {
    cfg.network.apply_irq_affinity && irqbalance_active()
}

pub fn irqbalance_active() -> bool {
    if let Ok(output) = Command::new("systemctl").args(["is-active", "irqbalance"]).output() {
        if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active" {
            return true;
        }
    }

    Command::new("pgrep")
        .args(["-x", "irqbalance"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn parse_ethtool_channels_status(raw: &str) -> Result<ChannelStatus> {
    let mut max_combined = None;
    let mut current_combined = None;
    let mut in_preset = false;
    let mut in_current = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        match trimmed {
            "Pre-set maximums:" => {
                in_preset = true;
                in_current = false;
                continue;
            }
            "Current hardware settings:" => {
                in_preset = false;
                in_current = true;
                continue;
            }
            _ => {}
        }

        if let Some(value) = trimmed.strip_prefix("Combined:") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("invalid ethtool combined value: {trimmed}"))?;
            if in_preset {
                max_combined = Some(parsed);
            } else if in_current {
                current_combined = Some(parsed);
            }
        }
    }

    let Some(current_combined) = current_combined else {
        anyhow::bail!("failed to parse current combined channels from ethtool -l output");
    };
    let Some(max_combined) = max_combined else {
        anyhow::bail!("failed to parse max combined channels from ethtool -l output");
    };

    Ok(ChannelStatus { current_combined, max_combined })
}

fn read_ethtool_channels_status(iface: &str) -> Result<ChannelStatus> {
    parse_ethtool_channels_status(&run_ethtool(&["-l", iface])?)
}

fn parse_ethtool_rss_status(raw: &str) -> Result<RssStatus> {
    let mut ring_count = None;
    let mut used_queues = BTreeSet::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("RX flow hash indirection table") {
            if let Some(start) = trimmed.find("with ") {
                let rest = &trimmed[start + 5..];
                if let Some(end) = rest.find(" RX ring(s)") {
                    ring_count = Some(
                        rest[..end]
                            .trim()
                            .parse::<usize>()
                            .with_context(|| format!("invalid RSS ring count in: {trimmed}"))?,
                    );
                }
            }
            continue;
        }

        let Some((head, tail)) = trimmed.split_once(':') else {
            continue;
        };
        if !head.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        for token in tail.split_whitespace() {
            if let Ok(queue) = token.parse::<usize>() {
                used_queues.insert(queue);
            }
        }
    }

    let Some(ring_count) = ring_count else {
        anyhow::bail!("failed to parse RSS ring count from ethtool -x output");
    };

    Ok(RssStatus {
        ring_count,
        used_queues: used_queues.into_iter().collect(),
    })
}

fn read_ethtool_rss_status(iface: &str) -> Result<RssStatus> {
    parse_ethtool_rss_status(&run_ethtool(&["-x", iface])?)
}

fn build_channel_action(
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Option<ChannelAction>> {
    if !iface.apply_combined_channels {
        return Ok(None);
    }

    let Some(channel_status) = &status.channel_status else {
        anyhow::bail!("missing ethtool channel status for {}", iface.name);
    };

    Ok(Some(ChannelAction {
        interface: iface.name.clone(),
        current_combined: channel_status.current_combined,
        max_combined: channel_status.max_combined,
        expected_combined: active_queue_count,
    }))
}

fn build_rss_equal_action(
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Option<RssEqualAction>> {
    if !iface.apply_rss_equal {
        return Ok(None);
    }

    let Some(rss_status) = &status.rss_status else {
        anyhow::bail!("missing ethtool RSS status for {}", iface.name);
    };

    Ok(Some(RssEqualAction {
        interface: iface.name.clone(),
        current_ring_count: rss_status.ring_count,
        current_used_queues: rss_status.used_queues.clone(),
        expected_queue_count: active_queue_count,
    }))
}

fn build_interface_rps_actions(
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Vec<RpsAction>> {
    let should_disable = match iface.rps_mode {
        RpsMode::Preserve => false,
        RpsMode::Off => true,
        RpsMode::Auto => {
            let Some(rss_status) = &status.rss_status else {
                return Ok(Vec::new());
            };
            rss_status.ring_count == active_queue_count
                && rss_equal_matches(&rss_status.used_queues, active_queue_count)
        }
    };

    if !should_disable {
        return Ok(Vec::new());
    }

    Ok(status
        .rx_queues
        .iter()
        .map(|queue| RpsAction {
            interface: status.interface.clone(),
            queue_name: queue.name.clone(),
            path: queue.path.clone(),
            mask: "0".to_string(),
            indices: Vec::new(),
            current_value: queue.value.clone(),
        })
        .collect())
}

fn effective_active_queue_count(
    cfg: &ScxConfig,
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
) -> Result<usize> {
    let mut capacities = Vec::new();

    if cfg.network.apply_irq_affinity {
        capacities.push(("irqs", status.irqs.len()));
    }
    if cfg.network.apply_xps {
        capacities.push(("tx", status_tx_queue_count(status, &iface.xps_mode)));
        if iface.xps_mode == XpsMode::Rxqs {
            capacities.push(("rx", status.rx_queues.len()));
        }
    }
    if capacities.is_empty() {
        capacities.push(("tx", status_tx_queue_count(status, &iface.xps_mode)));
    }

    let available = capacities.iter().map(|(_, count)| *count).filter(|count| *count > 0).min();
    let Some(available) = available else {
        anyhow::bail!(
            "interface {} has no active queue/IRQ data for the requested network locality mode",
            iface.name
        );
    };

    if iface.active_queue_count == 0 {
        let physical_capacity = physical_core_capacity(&iface.forwarding_cpus);
        return Ok(available.min(physical_capacity));
    }

    if iface.active_queue_count > available {
        let summary = capacities
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "network interface {} requests active_queue_count={}, but only {} queues are usable ({})",
            iface.name,
            iface.active_queue_count,
            available,
            summary
        );
    }

    Ok(iface.active_queue_count)
}

fn status_tx_queue_count(status: &InterfaceLocalityStatus, xps_mode: &XpsMode) -> usize {
    match xps_mode {
        XpsMode::Auto => status.tx_xps_cpus.len(),
        XpsMode::Cpus => status.tx_xps_cpus.len(),
        XpsMode::Rxqs => status.tx_xps_rxqs.len(),
    }
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
    let cpu_columns = interrupt_cpu_column_count(&raw);
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
        let total_count = parse_interrupt_total_count(rest, cpu_columns);
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
            total_count,
            affinity_list_path,
            affinity_mask_path,
            affinity_list,
        });
    }

    out.sort_by_key(|irq| (irq.queue_index.unwrap_or(usize::MAX), irq.irq));
    Ok(out)
}

fn interrupt_cpu_column_count(raw: &str) -> usize {
    raw.lines()
        .next()
        .map(|line| line.split_whitespace().filter(|field| field.starts_with("CPU")).count())
        .unwrap_or(0)
}

fn parse_interrupt_total_count(rest: &str, cpu_columns: usize) -> u64 {
    rest.split_whitespace().take(cpu_columns).filter_map(|field| field.parse::<u64>().ok()).sum()
}

fn irq_label_count_in_interrupts(raw: &str, iface: &str) -> usize {
    raw.lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once(':')?;
            let label = rest.split_whitespace().last().unwrap_or_default();
            if label.contains(iface) && parse_irq_queue_index(label).is_some() {
                Some(())
            } else {
                None
            }
        })
        .count()
}

fn build_interface_xps_actions(
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Vec<XpsAction>> {
    let queues = match iface.xps_mode {
        XpsMode::Auto => &status.tx_xps_cpus,
        XpsMode::Cpus => &status.tx_xps_cpus,
        XpsMode::Rxqs => &status.tx_xps_rxqs,
    };
    if queues.is_empty() {
        anyhow::bail!(
            "network.apply_xps is enabled, but interface {} has no tx-* entries for {:?}",
            status.interface,
            iface.xps_mode
        );
    }

    let mut out = Vec::new();
    for (ordinal, queue) in queues.iter().take(active_queue_count).enumerate() {
        let indices = match iface.xps_mode {
            XpsMode::Auto => {
                desired_locality_cpus(&iface.forwarding_cpus, &iface.queue_mapping_mode, ordinal)
            }
            XpsMode::Cpus => {
                desired_locality_cpus(&iface.forwarding_cpus, &iface.queue_mapping_mode, ordinal)
            }
            XpsMode::Rxqs => {
                desired_locality_rxqs(active_queue_count, &iface.queue_mapping_mode, ordinal)
            }
        };
        out.push(XpsAction {
            interface: status.interface.clone(),
            queue_name: queue.name.clone(),
            path: queue.path.clone(),
            mode: iface.xps_mode.clone(),
            mask: cpu_mask_string(&indices),
            indices,
            current_value: queue.value.clone(),
        });
    }

    Ok(out)
}

fn build_inactive_xps_actions(
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Vec<XpsAction>> {
    let mut out = Vec::new();

    for queue in status.tx_xps_cpus.iter().skip(active_queue_count) {
        out.push(XpsAction {
            interface: status.interface.clone(),
            queue_name: queue.name.clone(),
            path: queue.path.clone(),
            mode: XpsMode::Cpus,
            indices: Vec::new(),
            mask: "0".to_string(),
            current_value: queue.value.clone(),
        });
    }

    for queue in status.tx_xps_rxqs.iter().skip(active_queue_count) {
        out.push(XpsAction {
            interface: status.interface.clone(),
            queue_name: queue.name.clone(),
            path: queue.path.clone(),
            mode: XpsMode::Rxqs,
            indices: Vec::new(),
            mask: "0".to_string(),
            current_value: queue.value.clone(),
        });
    }

    out.sort_by(|a, b| a.queue_name.cmp(&b.queue_name).then_with(|| a.path.cmp(&b.path)));
    Ok(out)
}

fn build_interface_irq_actions(
    iface: &ResolvedNetworkInterface,
    status: &InterfaceLocalityStatus,
    active_queue_count: usize,
) -> Result<Vec<IrqAffinityAction>> {
    if status.irqs.is_empty() {
        anyhow::bail!(
            "network.apply_irq_affinity is enabled, but no IRQ labels containing interface {} were found in /proc/interrupts",
            status.interface
        );
    }

    let mut out = Vec::new();
    for (ordinal, irq) in status.irqs.iter().take(active_queue_count).enumerate() {
        let cpus =
            desired_locality_cpus(&iface.forwarding_cpus, &iface.queue_mapping_mode, ordinal);
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

pub fn desired_locality_cpus(
    forwarding_cpus: &[usize],
    mode: &QueueMappingMode,
    index: usize,
) -> Vec<usize> {
    match mode {
        QueueMappingMode::RoundRobin => vec![forwarding_cpus[index % forwarding_cpus.len()]],
        QueueMappingMode::FullMask => forwarding_cpus.to_vec(),
    }
}

fn desired_locality_rxqs(
    active_queue_count: usize,
    mode: &QueueMappingMode,
    index: usize,
) -> Vec<usize> {
    match mode {
        QueueMappingMode::RoundRobin => vec![index % active_queue_count],
        QueueMappingMode::FullMask => (0..active_queue_count).collect(),
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

pub fn rss_equal_matches(current_used_queues: &[usize], expected_queue_count: usize) -> bool {
    current_used_queues == (0..expected_queue_count).collect::<Vec<_>>().as_slice()
}

pub fn affinity_list_matches(raw: &str, cpus: &[usize]) -> bool {
    parse_cpu_list(raw.trim())
        .map(|current| current == cpus.iter().copied().collect::<BTreeSet<_>>())
        .unwrap_or(false)
}

pub fn write_xps_cpus(action: &XpsAction) -> Result<()> {
    write_trimmed(&action.path, &action.mask)
}

pub fn write_rps_cpus(action: &RpsAction) -> Result<()> {
    write_trimmed(&action.path, &action.mask)
}

pub fn apply_ethtool_combined_channels(action: &ChannelAction) -> Result<()> {
    let output = Command::new("ethtool")
        .args(["-L", &action.interface, "combined", &action.expected_combined.to_string()])
        .output()
        .with_context(|| format!("failed to execute ethtool -L for {}", action.interface))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };
    anyhow::bail!(
        "ethtool -L {} combined {} failed: {}",
        action.interface,
        action.expected_combined,
        details
    );
}

pub fn apply_ethtool_rss_equal(action: &RssEqualAction) -> Result<()> {
    let output = Command::new("ethtool")
        .args(["-X", &action.interface, "equal", &action.expected_queue_count.to_string()])
        .output()
        .with_context(|| format!("failed to execute ethtool -X for {}", action.interface))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };
    anyhow::bail!(
        "ethtool -X {} equal {} failed: {}",
        action.interface,
        action.expected_queue_count,
        details
    );
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
    let forwarding_cpus = effective_forwarding_cpus(cfg)?;
    let control_cpus = effective_control_cpus(cfg)?;

    validate_cpu_set("policy.forwarding_cpus", &forwarding_cpus, &online)?;
    validate_cpu_set("policy.control_cpus", &control_cpus, &online)?;
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
    let manages_network_locality = network.apply_irq_affinity
        || network.apply_xps
        || network.apply_rss_equal
        || network.apply_combined_channels;

    if !manages_network_locality && network.interfaces.is_empty() && !network.auto_discover {
        return Ok(());
    }

    if network.interfaces.is_empty() && !network.auto_discover {
        anyhow::bail!(
            "network.interfaces is empty and network.auto_discover=false, but network locality management is enabled"
        );
    }

    let online = read_online_cpus()?;
    let resolved = resolved_network_interfaces(cfg)?;

    if manages_network_locality && resolved.is_empty() {
        anyhow::bail!("network.auto_discover is enabled, but no manageable interfaces were found");
    }

    let mut validated_interfaces = 0usize;
    for iface in resolved {
        validate_optional_cpu_set(
            &format!("network.interfaces[{}].forwarding_cpus", iface.name),
            &iface.forwarding_cpus,
            &online,
        )?;

        let iface_root = PathBuf::from(format!("/sys/class/net/{}", iface.name));
        if !iface_root.exists() {
            anyhow::bail!(
                "network.interfaces contains {}, but {} does not exist",
                iface.name,
                iface_root.display()
            );
        }

        let status = match read_interface_locality_status(&iface) {
            Ok(status) => status,
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        };
        match effective_active_queue_count(cfg, &iface, &status) {
            Ok(_) => {
                validated_interfaces += 1;
            }
            Err(_err) if iface.auto_discovered => continue,
            Err(err) => return Err(err),
        }
    }

    if manages_network_locality && validated_interfaces == 0 {
        anyhow::bail!(
            "network locality management is enabled, but auto-discovery found no interfaces compatible with the requested locality mode"
        );
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
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        affinity_list_matches, auto_partition_cpu_sets_from_core_groups, build_interface_rps_actions,
        cpu_list_string, cpu_mask_string, discover_auto_network_interface_groups,
        effective_active_queue_count, interface_is_auto_discoverable, matches_target, parse_cpu_mask,
        irq_label_count_in_interrupts, parse_ethtool_channels_status, parse_ethtool_rss_status, parse_irq_queue_index,
        parse_ksoftirqd_cpu, resolved_network_interfaces, resolved_network_interfaces_at,
        rss_equal_matches, split_forwarding_cpus_across_interfaces, xps_mask_matches,
        ChannelStatus, CustomBpfSchedulerConfig, DiscoveryConfig, InterfaceLocalityStatus,
        NetworkConfig, PolicyConfig, QueueLocalityState, QueueMappingMode,
        ResolvedNetworkInterface, RpsMode, RssStatus, SchedulerConfig, SchedulerMode, ScxConfig,
        ScxSwitchMode, ThreadCpuClass, XpsMode,
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
                auto_partition_cpus: false,
                manage_ksoftirqd: true,
                ksoftirqd_cpus: Vec::new(),
                apply_sched_ext: true,
                thread_cpu_classes: Vec::new(),
            },
            network: NetworkConfig {
                interfaces: Vec::new(),
                auto_discover: false,
                auto_discover_include_prefixes: Vec::new(),
                auto_discover_exclude_prefixes: Vec::new(),
                apply_irq_affinity: false,
                apply_xps: false,
                apply_rss_equal: false,
                apply_combined_channels: false,
                clear_inactive_xps: false,
                queue_mapping_mode: QueueMappingMode::RoundRobin,
                xps_mode: XpsMode::Auto,
                rps_mode: RpsMode::Auto,
                active_queue_count: 0,
            },
            scheduler: SchedulerConfig {
                mode: SchedulerMode::Disabled,
                start_command: Vec::new(),
                stop_command: Vec::new(),
                pid_file: "/tmp/landscape-scx-test.pid".into(),
                ready_timeout_ms: 1000,
                fallback_on_error: false,
                custom_bpf: CustomBpfSchedulerConfig::default(),
            },
            agent: super::AgentConfig {
                apply_interval_secs: 5,
                event_driven: true,
                event_debounce_ms: 250,
            },
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

    #[test]
    fn irq_label_count_in_interrupts_filters_queue_style_labels() {
        let raw = r#"
           CPU0       CPU1
 97:          1          2  PCI-MSI  ens16f0np0-TxRx-0
 98:          3          4  PCI-MSI  ens16f0np0-TxRx-1
 99:          5          6  PCI-MSI  ens18
100:          7          8  PCI-MSI  i40e-ens16f1np1-TxRx-0
"#;

        assert_eq!(irq_label_count_in_interrupts(raw, "ens16f0np0"), 2);
        assert_eq!(irq_label_count_in_interrupts(raw, "ens18"), 0);
        assert_eq!(irq_label_count_in_interrupts(raw, "ens16f1np1"), 1);
    }

    #[test]
    fn network_interfaces_accept_string_and_table_forms() {
        let cfg: ScxConfig = toml::from_str(
            r#"
[policy]
forwarding_cpus = [0, 1, 2, 3]
control_cpus = [4, 5]

[network]
apply_irq_affinity = true
apply_xps = true
apply_rss_equal = true
apply_combined_channels = true
clear_inactive_xps = true
active_queue_count = 8
xps_mode = "cpus"
queue_mapping_mode = "round_robin"
interfaces = [
  "eth0",
  { name = "eth1", forwarding_cpus = [6, 7], active_queue_count = 4, apply_rss_equal = false, clear_inactive_xps = false, xps_mode = "rxqs", queue_mapping_mode = "full_mask" }
]
"#,
        )
        .unwrap();

        let resolved = resolved_network_interfaces(&cfg).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "eth0");
        assert_eq!(resolved[0].forwarding_cpus, vec![0, 1, 2, 3]);
        assert_eq!(resolved[0].active_queue_count, 8);
        assert!(resolved[0].apply_rss_equal);
        assert!(resolved[0].apply_combined_channels);
        assert!(resolved[0].clear_inactive_xps);
        assert_eq!(resolved[0].xps_mode, XpsMode::Cpus);
        assert_eq!(resolved[1].name, "eth1");
        assert_eq!(resolved[1].forwarding_cpus, vec![6, 7]);
        assert_eq!(resolved[1].active_queue_count, 4);
        assert!(!resolved[1].apply_rss_equal);
        assert!(resolved[1].apply_combined_channels);
        assert!(!resolved[1].clear_inactive_xps);
        assert_eq!(resolved[1].xps_mode, XpsMode::Rxqs);
        assert_eq!(resolved[1].queue_mapping_mode, QueueMappingMode::FullMask);
    }

    #[test]
    fn parse_ethtool_channel_status() {
        let status = parse_ethtool_channels_status(
            r#"
Channel parameters for ens27f0:
Pre-set maximums:
RX:             n/a
TX:             n/a
Other:          1
Combined:       32
Current hardware settings:
RX:             n/a
TX:             n/a
Other:          1
Combined:       8
"#,
        )
        .unwrap();

        assert_eq!(status.max_combined, 32);
        assert_eq!(status.current_combined, 8);
    }

    #[test]
    fn parse_ethtool_rss_status_and_match_equal_range() {
        let status = parse_ethtool_rss_status(
            r#"
RX flow hash indirection table for ens16f1np1 with 8 RX ring(s):
    0:      0     1     2     3     4     5     6     7
    8:      0     1     2     3     4     5     6     7
RSS hash key:
dead:beef
"#,
        )
        .unwrap();

        assert_eq!(status.ring_count, 8);
        assert_eq!(status.used_queues, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert!(rss_equal_matches(&status.used_queues, 8));
        assert!(!rss_equal_matches(&status.used_queues, 4));
    }

    #[test]
    fn auto_xps_mode_prefers_cpus_for_custom_bpf_scheduler() {
        let mut cfg = test_config();
        cfg.scheduler.mode = SchedulerMode::CustomBpf;
        cfg.network.interfaces = vec![super::NetworkInterfaceSpec::Name("eth0".into())];

        let resolved = resolved_network_interfaces(&cfg).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].requested_xps_mode, XpsMode::Auto);
        assert_eq!(resolved[0].xps_mode, XpsMode::Cpus);
    }

    #[test]
    fn auto_xps_mode_prefers_rxqs_without_strict_forwarder_pinning() {
        let mut cfg = test_config();
        cfg.network.interfaces = vec![super::NetworkInterfaceSpec::Name("eth0".into())];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "pppd".into(),
            cpus: vec![0, 1],
            apply_sched_ext: Some(true),
            apply_affinity: Some(true),
        }];

        let resolved = resolved_network_interfaces(&cfg).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].requested_xps_mode, XpsMode::Auto);
        assert_eq!(resolved[0].xps_mode, XpsMode::Rxqs);
    }

    #[test]
    fn auto_discoverable_interfaces_require_physical_queue_backing() {
        let root = unique_test_dir("auto-discover-eligible");
        let phys = root.join("ens1");
        let loopback = root.join("lo");
        let bridge_member = root.join("ens2");
        let bridge_master = root.join("br_lan");
        let virtual_iface = root.join("veth0");

        fs::create_dir_all(phys.join("device")).unwrap();
        fs::create_dir_all(phys.join("queues/tx-0")).unwrap();
        fs::write(phys.join("carrier"), "1\n").unwrap();
        fs::create_dir_all(loopback.join("queues/tx-0")).unwrap();
        fs::create_dir_all(bridge_member.join("device")).unwrap();
        fs::create_dir_all(bridge_member.join("queues/tx-0")).unwrap();
        fs::write(bridge_member.join("carrier"), "1\n").unwrap();
        fs::create_dir_all(bridge_master.join("device")).unwrap();
        fs::create_dir_all(bridge_master.join("bridge")).unwrap();
        fs::create_dir_all(bridge_master.join("queues/tx-0")).unwrap();
        fs::create_dir_all(virtual_iface.join("queues/tx-0")).unwrap();

        assert!(interface_is_auto_discoverable("ens1", &phys).unwrap());
        assert!(!interface_is_auto_discoverable("lo", &loopback).unwrap());
        assert!(interface_is_auto_discoverable("ens2", &bridge_member).unwrap());
        assert!(!interface_is_auto_discoverable("br_lan", &bridge_master).unwrap());
        assert!(!interface_is_auto_discoverable("veth0", &virtual_iface).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_discover_splits_forwarding_cpus_per_interface() {
        let root = unique_test_dir("auto-discover-resolve");
        let ens1 = root.join("ens1");
        let ens2 = root.join("ens2");
        let ignored = root.join("veth0");

        fs::create_dir_all(ens1.join("device")).unwrap();
        fs::create_dir_all(ens1.join("queues/tx-0")).unwrap();
        fs::write(ens1.join("queues/tx-0/xps_cpus"), "0\n").unwrap();
        fs::create_dir_all(ens1.join("queues/rx-0")).unwrap();
        fs::create_dir_all(ens2.join("device")).unwrap();
        fs::create_dir_all(ens2.join("queues/tx-0")).unwrap();
        fs::write(ens2.join("queues/tx-0/xps_cpus"), "0\n").unwrap();
        fs::create_dir_all(ens2.join("queues/rx-0")).unwrap();
        fs::create_dir_all(ignored.join("queues/tx-0")).unwrap();

        let mut cfg = test_config();
        cfg.network.auto_discover = true;
        cfg.network.apply_xps = true;
        cfg.network.xps_mode = XpsMode::Cpus;
        cfg.policy.forwarding_cpus = vec![0, 2, 4, 6];

        let resolved = resolved_network_interfaces_at(&cfg, &root).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "ens1");
        assert_eq!(resolved[0].forwarding_cpus, vec![0, 2]);
        assert_eq!(resolved[1].name, "ens2");
        assert_eq!(resolved[1].forwarding_cpus, vec![4, 6]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_discover_reclaims_bridge_group_cpus_from_incompatible_members() {
        let root = unique_test_dir("auto-discover-bridge-compatible");
        let br_lan = root.join("br_lan");
        let ens18 = root.join("ens18");
        let ens27f1 = root.join("ens27f1");
        let ens28f0 = root.join("ens28f0");

        fs::create_dir_all(&br_lan).unwrap();

        for iface in [&ens18, &ens27f1, &ens28f0] {
            fs::create_dir_all(iface.join("device")).unwrap();
            fs::create_dir_all(iface.join("queues/tx-0")).unwrap();
            fs::create_dir_all(iface.join("queues/rx-0")).unwrap();
            fs::write(iface.join("carrier"), "1\n").unwrap();
        }
        fs::write(ens27f1.join("queues/tx-0/xps_cpus"), "0\n").unwrap();
        fs::write(ens28f0.join("queues/tx-0/xps_cpus"), "0\n").unwrap();
        symlink(&br_lan, ens18.join("master")).unwrap();
        symlink(&br_lan, ens27f1.join("master")).unwrap();

        let mut cfg = test_config();
        cfg.network.auto_discover = true;
        cfg.network.apply_xps = true;
        cfg.network.xps_mode = XpsMode::Cpus;
        cfg.policy.forwarding_cpus = vec![0, 1, 2, 3];

        let resolved = resolved_network_interfaces_at(&cfg, &root).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "ens27f1");
        assert_eq!(resolved[0].forwarding_cpus, vec![0, 1]);
        assert_eq!(resolved[1].name, "ens28f0");
        assert_eq!(resolved[1].forwarding_cpus, vec![2, 3]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_discover_requires_enough_forwarding_cpus() {
        let err = split_forwarding_cpus_across_interfaces(&[0, 1], 3).unwrap_err().to_string();
        assert!(err.contains("network.auto_discover found 3 interfaces"));
    }

    #[test]
    fn auto_discover_groups_bridge_members_and_skips_no_carrier_slaves() {
        let root = unique_test_dir("auto-discover-bridge-group");
        let br_lan = root.join("br_lan");
        let ens18 = root.join("ens18");
        let ens27f1 = root.join("ens27f1");
        let ens17 = root.join("ens17");
        let ens28f0 = root.join("ens28f0");

        fs::create_dir_all(&br_lan).unwrap();

        for iface in [&ens18, &ens27f1, &ens17, &ens28f0] {
            fs::create_dir_all(iface.join("device")).unwrap();
            fs::create_dir_all(iface.join("queues/tx-0")).unwrap();
        }
        fs::write(ens18.join("carrier"), "1\n").unwrap();
        fs::write(ens27f1.join("carrier"), "1\n").unwrap();
        fs::write(ens17.join("carrier"), "0\n").unwrap();
        fs::write(ens28f0.join("carrier"), "1\n").unwrap();
        symlink(&br_lan, ens18.join("master")).unwrap();
        symlink(&br_lan, ens27f1.join("master")).unwrap();
        symlink(&br_lan, ens17.join("master")).unwrap();

        let cfg = test_config();
        let groups = discover_auto_network_interface_groups(&cfg, &root).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].key, "br_lan");
        assert_eq!(groups[0].members, vec!["ens18".to_string(), "ens27f1".to_string()]);
        assert_eq!(groups[1].key, "ens28f0");
        assert_eq!(groups[1].members, vec!["ens28f0".to_string()]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_discover_honors_include_and_exclude_prefix_filters() {
        let root = unique_test_dir("auto-discover-prefix-filters");
        let ens16f1np1 = root.join("ens16f1np1");
        let ens27f0 = root.join("ens27f0");
        let ens28f0 = root.join("ens28f0");
        let ens28f1 = root.join("ens28f1");

        for iface in [&ens16f1np1, &ens27f0, &ens28f0, &ens28f1] {
            fs::create_dir_all(iface.join("device")).unwrap();
            fs::create_dir_all(iface.join("queues/tx-0")).unwrap();
            fs::write(iface.join("queues/tx-0/xps_cpus"), "0\n").unwrap();
            fs::create_dir_all(iface.join("queues/rx-0")).unwrap();
            fs::write(iface.join("carrier"), "1\n").unwrap();
        }

        let mut cfg = test_config();
        cfg.network.auto_discover = true;
        cfg.network.apply_xps = true;
        cfg.network.xps_mode = XpsMode::Cpus;
        cfg.network.auto_discover_include_prefixes = vec!["ens28".into(), "ens16".into()];
        cfg.network.auto_discover_exclude_prefixes = vec!["ens16".into()];
        cfg.policy.forwarding_cpus = vec![0, 1, 2, 3];

        let resolved = resolved_network_interfaces_at(&cfg, &root).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "ens28f0");
        assert_eq!(resolved[1].name, "ens28f1");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn auto_partition_keeps_forwarding_and_control_on_separate_smt_cores() {
        let groups = vec![vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7]];
        let (forwarding, control) = auto_partition_cpu_sets_from_core_groups(&groups);
        assert_eq!(forwarding, vec![0, 2, 4]);
        assert_eq!(control, vec![6, 7]);
    }

    #[test]
    fn auto_partition_reserves_a_fraction_of_non_smt_cores_for_control() {
        let groups = vec![vec![0], vec![1], vec![2], vec![3]];
        let (forwarding, control) = auto_partition_cpu_sets_from_core_groups(&groups);
        assert_eq!(forwarding, vec![0, 1, 2]);
        assert_eq!(control, vec![3]);
    }

    #[test]
    fn auto_partition_single_smt_core_falls_back_to_split_siblings() {
        let groups = vec![vec![0, 1]];
        let (forwarding, control) = auto_partition_cpu_sets_from_core_groups(&groups);
        assert_eq!(forwarding, vec![0]);
        assert_eq!(control, vec![1]);
    }

    #[test]
    fn active_queue_count_auto_caps_to_physical_core_capacity() {
        let cfg = test_config();
        let iface = ResolvedNetworkInterface {
            name: "eth0".into(),
            auto_discovered: false,
            forwarding_cpus: vec![9000, 9001, 9002],
            active_queue_count: 0,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            requested_xps_mode: XpsMode::Auto,
            xps_mode: XpsMode::Cpus,
            rps_mode: RpsMode::Auto,
        };
        let status = InterfaceLocalityStatus {
            interface: "eth0".into(),
            tx_xps_cpus: (0..8)
                .map(|idx| QueueLocalityState {
                    name: format!("tx-{idx}"),
                    path: PathBuf::from(format!("/tmp/tx-{idx}")),
                    value: "0".into(),
                })
                .collect(),
            tx_xps_rxqs: Vec::new(),
            rx_queues: Vec::new(),
            irqs: Vec::new(),
            channel_status: None,
            rss_status: None,
        };

        let active = effective_active_queue_count(&cfg, &iface, &status).unwrap();
        assert_eq!(active, 3);
    }

    #[test]
    fn auto_rps_mode_disables_rps_when_rss_is_aligned() {
        let iface = ResolvedNetworkInterface {
            name: "eth0".into(),
            auto_discovered: false,
            forwarding_cpus: vec![0, 1],
            active_queue_count: 0,
            apply_rss_equal: true,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            requested_xps_mode: XpsMode::Auto,
            xps_mode: XpsMode::Cpus,
            rps_mode: RpsMode::Auto,
        };
        let status = InterfaceLocalityStatus {
            interface: "eth0".into(),
            tx_xps_cpus: Vec::new(),
            tx_xps_rxqs: Vec::new(),
            rx_queues: vec![
                QueueLocalityState {
                    name: "rx-0".into(),
                    path: PathBuf::from("/tmp/rx-0"),
                    value: "3".into(),
                },
                QueueLocalityState {
                    name: "rx-1".into(),
                    path: PathBuf::from("/tmp/rx-1"),
                    value: "c".into(),
                },
            ],
            irqs: Vec::new(),
            channel_status: Some(ChannelStatus { max_combined: 8, current_combined: 2 }),
            rss_status: Some(RssStatus { ring_count: 2, used_queues: vec![0, 1] }),
        };

        let actions = build_interface_rps_actions(&iface, &status, 2).unwrap();
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().all(|action| action.mask == "0"));
    }

    #[test]
    fn scheduler_config_accepts_custom_bpf_mode() {
        let cfg: ScxConfig = toml::from_str(
            r#"
[scheduler]
mode = "custom_bpf"

[scheduler.custom_bpf]
switch_mode = "full"
housekeeping_cpus = [0, 1]
forwarding_thread_prefixes = ["landscape-forwarder", "pppoe-rx-"]
"#,
        )
        .unwrap();

        assert!(matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf));
        assert_eq!(cfg.scheduler.custom_bpf.switch_mode, ScxSwitchMode::Full);
        assert_eq!(cfg.scheduler.custom_bpf.housekeeping_cpus, vec![0, 1]);
        assert_eq!(
            cfg.scheduler.custom_bpf.forwarding_thread_prefixes,
            vec!["landscape-forwarder".to_string(), "pppoe-rx-".to_string()]
        );
        assert_eq!(
            cfg.scheduler.custom_bpf.source_file,
            PathBuf::from("./bpf/landscape_scx.bpf.c")
        );
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("landscape-scx-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
