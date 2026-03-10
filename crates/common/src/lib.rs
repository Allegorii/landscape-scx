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
        matches_target, parse_ksoftirqd_cpu, DiscoveryConfig, PolicyConfig, SchedulerConfig,
        SchedulerMode, ScxConfig,
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
}
