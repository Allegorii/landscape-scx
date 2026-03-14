use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use landscape_scx_bpf::{
    describe_landscape_scheduler_intent, ensure_landscape_scheduler, ensure_scheduler,
    read_sched_ext_ops, read_sched_ext_state, sched_ext_enabled, unload_scheduler,
    validate_custom_bpf_runtime,
};
use landscape_scx_common::{
    affinity_list_matches, apply_ethtool_combined_channels, apply_ethtool_rss_equal,
    build_network_locality_plans, desired_locality_cpus, discover_candidates, get_sched_policy,
    irqbalance_conflicts, load_config, parse_ksoftirqd_cpu, read_online_cpus, rss_equal_matches,
    sched_policy_name, try_set_cpu_affinity, try_set_sched_ext, validate_cpu_config,
    write_irq_affinity, write_rps_cpus, write_xps_cpus, xps_mask_matches, InterfaceLocalityPlan,
    LandscapeQueueIntent, LandscapeSchedulerIntent, LandscapeTaskClass, LandscapeTaskIntent,
    LandscapeTaskKind, SchedulerMode, ScxConfig, ThreadCandidate, ThreadCpuClass,
    LANDSCAPE_DSQ_BASE,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileTrigger {
    Event,
    Interval,
}

const QUEUE_PRESSURE_LEVEL_NONE: u32 = 0;
const QUEUE_PRESSURE_LEVEL_ELEVATED: u32 = 1;
const QUEUE_PRESSURE_LEVEL_HIGH: u32 = 2;

impl ReconcileTrigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Interval => "interval",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReconcileWatchTarget {
    path: PathBuf,
    mask: u32,
}

const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_COMM: u32 = 0x0000_0200;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const PROC_EVENT_ALL: u32 = PROC_EVENT_FORK | PROC_EVENT_EXEC | PROC_EVENT_COMM | PROC_EVENT_EXIT;
const NLMSG_DONE: u16 = 0x3;
const NLMSG_ALIGNTO: usize = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct NetlinkMessageHeader {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectorId {
    idx: u32,
    val: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnectorMessageHeader {
    id: ConnectorId,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcInput {
    mcast_op: u32,
    event_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcConnectorListenMessage {
    nl: NetlinkMessageHeader,
    cn: ConnectorMessageHeader,
    input: ProcInput,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcEventHeader {
    what: u32,
    cpu: u32,
    timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ForkProcEvent {
    parent_pid: i32,
    parent_tgid: i32,
    child_pid: i32,
    child_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecProcEvent {
    process_pid: i32,
    process_tgid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CommProcEvent {
    process_pid: i32,
    process_tgid: i32,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExitProcEvent {
    process_pid: i32,
    process_tgid: i32,
    exit_code: u32,
    exit_signal: u32,
    parent_pid: i32,
    parent_tgid: i32,
}

#[derive(Debug)]
struct InotifyReconcileWatcher {
    fd: RawFd,
    debounce_ms: u64,
}

impl InotifyReconcileWatcher {
    fn new(cfg: &ScxConfig, candidates: &[ThreadCandidate]) -> Result<Option<Self>> {
        let desired_targets = collect_reconcile_watch_targets(cfg, candidates);
        if desired_targets.is_empty() {
            return Ok(None);
        }

        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(anyhow::anyhow!("inotify_init1 failed: {}", io::Error::last_os_error()));
        }

        let mut watch_count = 0usize;
        for target in desired_targets {
            if !target.path.exists() {
                continue;
            }

            let raw_path = target.path.as_os_str().as_bytes();
            let c_path = CString::new(raw_path)
                .with_context(|| format!("watch path contains NUL: {}", target.path.display()))?;
            let wd = unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), target.mask) };
            if wd < 0 {
                warn!(
                    "event-driven reconcile watch failed path={} err={}",
                    target.path.display(),
                    io::Error::last_os_error()
                );
                continue;
            }

            watch_count += 1;
        }

        if watch_count == 0 {
            unsafe {
                libc::close(fd);
            }
            return Ok(None);
        }

        Ok(Some(Self { fd, debounce_ms: cfg.agent.event_debounce_ms }))
    }

    fn wait(&mut self, interval: Duration) -> Result<ReconcileTrigger> {
        let mut pollfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
        loop {
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_timeout_ms(interval)) };
            if rc == 0 {
                return Ok(ReconcileTrigger::Interval);
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("poll on reconcile watcher failed: {}", err));
            }
            if (pollfd.revents & libc::POLLIN) == 0 {
                return Err(anyhow::anyhow!(
                    "reconcile watcher returned unexpected revents={:#x}",
                    pollfd.revents
                ));
            }

            self.drain_events()?;
            self.debounce()?;
            return Ok(ReconcileTrigger::Event);
        }
    }

    fn debounce(&mut self) -> Result<()> {
        if self.debounce_ms == 0 {
            return Ok(());
        }

        let deadline = Instant::now() + Duration::from_millis(self.debounce_ms);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pollfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_timeout_ms(remaining)) };
            if rc == 0 {
                break;
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("poll during debounce failed: {}", err));
            }
            if (pollfd.revents & libc::POLLIN) != 0 {
                self.drain_events()?;
            }
        }

        Ok(())
    }

    fn drain_events(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let rc = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if rc == 0 {
                return Ok(());
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("failed to drain reconcile watcher: {}", err));
            }
        }
    }
}

impl Drop for InotifyReconcileWatcher {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[derive(Debug)]
struct ProcConnectorWatcher {
    fd: RawFd,
    debounce_ms: u64,
    tracked_tgids: BTreeSet<i32>,
    tracked_cgroup_paths: BTreeSet<String>,
}

impl ProcConnectorWatcher {
    fn new(cfg: &ScxConfig, candidates: &[ThreadCandidate]) -> Result<Option<Self>> {
        let tracked_tgids = candidates
            .iter()
            .filter(|candidate| parse_ksoftirqd_cpu(&candidate.comm).is_none())
            .map(|candidate| candidate.pid)
            .collect::<BTreeSet<_>>();
        let mut tracked_cgroup_paths = cfg
            .discovery
            .cgroup_prefixes
            .iter()
            .map(|path| path.to_string())
            .collect::<BTreeSet<_>>();
        for candidate in candidates {
            if parse_ksoftirqd_cpu(&candidate.comm).is_some() {
                continue;
            }
            tracked_cgroup_paths.extend(parse_proc_cgroup_paths(&candidate.cgroup));
        }

        if tracked_tgids.is_empty() && tracked_cgroup_paths.is_empty() {
            return Ok(None);
        }

        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "proc connector socket creation failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut bind_addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        bind_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        bind_addr.nl_pid = std::process::id();
        bind_addr.nl_groups = CN_IDX_PROC;
        let bind_rc = unsafe {
            libc::bind(
                fd,
                (&bind_addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_rc < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!("proc connector bind failed: {}", err));
        }

        let group = CN_IDX_PROC as libc::c_int;
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                (&group as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if let Err(err) = send_proc_connector_mcast(fd, PROC_CN_MCAST_LISTEN, PROC_EVENT_ALL) {
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        Ok(Some(Self {
            fd,
            debounce_ms: cfg.agent.event_debounce_ms,
            tracked_tgids,
            tracked_cgroup_paths,
        }))
    }

    fn wait(&mut self, interval: Duration) -> Result<ReconcileTrigger> {
        let mut pollfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
        loop {
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_timeout_ms(interval)) };
            if rc == 0 {
                return Ok(ReconcileTrigger::Interval);
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("poll on proc connector failed: {}", err));
            }
            if (pollfd.revents & libc::POLLIN) == 0 {
                return Err(anyhow::anyhow!(
                    "proc connector returned unexpected revents={:#x}",
                    pollfd.revents
                ));
            }

            if self.drain_events()? {
                self.debounce()?;
                return Ok(ReconcileTrigger::Event);
            }
        }
    }

    fn debounce(&mut self) -> Result<()> {
        if self.debounce_ms == 0 {
            return Ok(());
        }

        let deadline = Instant::now() + Duration::from_millis(self.debounce_ms);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pollfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_timeout_ms(remaining)) };
            if rc == 0 {
                break;
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("poll during proc connector debounce failed: {}", err));
            }
            if (pollfd.revents & libc::POLLIN) != 0 {
                let _ = self.drain_events()?;
            }
        }

        Ok(())
    }

    fn drain_events(&mut self) -> Result<bool> {
        let mut buf = [0u8; 8192];
        let mut triggered = false;
        loop {
            let rc = unsafe {
                libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT)
            };
            if rc == 0 {
                return Ok(triggered);
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(triggered);
                }
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow::anyhow!("failed to read proc connector event: {}", err));
            }

            let mut offset = 0usize;
            let total = rc as usize;
            while offset + std::mem::size_of::<NetlinkMessageHeader>() <= total {
                let Some(header) = read_unaligned_copy::<NetlinkMessageHeader>(&buf[offset..])
                else {
                    break;
                };
                let message_len = (header.nlmsg_len as usize).min(total.saturating_sub(offset));
                if message_len < std::mem::size_of::<NetlinkMessageHeader>() {
                    break;
                }

                if header.nlmsg_type == NLMSG_DONE {
                    let payload = &buf[offset + std::mem::size_of::<NetlinkMessageHeader>()
                        ..offset + message_len];
                    if self.message_matches_scope(payload) {
                        triggered = true;
                    }
                }

                let aligned = nlmsg_align(header.nlmsg_len as usize);
                if aligned == 0 {
                    break;
                }
                offset = offset.saturating_add(aligned);
            }
        }
    }

    fn message_matches_scope(&self, payload: &[u8]) -> bool {
        let Some(cn) = read_unaligned_copy::<ConnectorMessageHeader>(payload) else {
            return false;
        };
        if cn.id.idx != CN_IDX_PROC || cn.id.val != CN_VAL_PROC {
            return false;
        }
        let event_bytes = &payload[std::mem::size_of::<ConnectorMessageHeader>()..];
        let Some((pid, tgid)) = parse_proc_connector_event_scope(event_bytes) else {
            return false;
        };

        if self.tracked_tgids.contains(&tgid) || self.tracked_tgids.contains(&pid) {
            return true;
        }

        if self.tracked_cgroup_paths.is_empty() {
            return false;
        }

        let cgroup = read_proc_cgroup(tgid).or_else(|| read_proc_cgroup(pid));
        let Some(cgroup) = cgroup else {
            return false;
        };
        self.tracked_cgroup_paths.iter().any(|path| cgroup.contains(path))
    }
}

impl Drop for ProcConnectorWatcher {
    fn drop(&mut self) {
        let _ = send_proc_connector_mcast(self.fd, PROC_CN_MCAST_IGNORE, PROC_EVENT_ALL);
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn send_proc_connector_mcast(fd: RawFd, mcast_op: u32, event_type: u32) -> Result<()> {
    let mut kernel_addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    kernel_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    kernel_addr.nl_pid = 0;
    kernel_addr.nl_groups = CN_IDX_PROC;

    let msg = ProcConnectorListenMessage {
        nl: NetlinkMessageHeader {
            nlmsg_len: std::mem::size_of::<ProcConnectorListenMessage>() as u32,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: std::process::id(),
        },
        cn: ConnectorMessageHeader {
            id: ConnectorId { idx: CN_IDX_PROC, val: CN_VAL_PROC },
            seq: 0,
            ack: 0,
            len: std::mem::size_of::<ProcInput>() as u16,
            flags: 0,
        },
        input: ProcInput { mcast_op, event_type },
    };

    let rc = unsafe {
        libc::sendto(
            fd,
            (&msg as *const ProcConnectorListenMessage).cast(),
            std::mem::size_of::<ProcConnectorListenMessage>(),
            0,
            (&kernel_addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(anyhow::anyhow!(
            "proc connector mcast {} failed: {}",
            mcast_op,
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

fn read_unaligned_copy<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }

    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn parse_proc_connector_event_scope(event_bytes: &[u8]) -> Option<(i32, i32)> {
    let header = read_unaligned_copy::<ProcEventHeader>(event_bytes)?;
    let payload = &event_bytes[std::mem::size_of::<ProcEventHeader>()..];

    match header.what {
        PROC_EVENT_FORK => {
            let event = read_unaligned_copy::<ForkProcEvent>(payload)?;
            Some((event.child_pid, event.child_tgid))
        }
        PROC_EVENT_EXEC => {
            let event = read_unaligned_copy::<ExecProcEvent>(payload)?;
            Some((event.process_pid, event.process_tgid))
        }
        PROC_EVENT_COMM => {
            let event = read_unaligned_copy::<CommProcEvent>(payload)?;
            Some((event.process_pid, event.process_tgid))
        }
        PROC_EVENT_EXIT => {
            let event = read_unaligned_copy::<ExitProcEvent>(payload)?;
            Some((event.process_pid, event.process_tgid))
        }
        _ => None,
    }
}

fn read_proc_cgroup(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
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
    let prepared = if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        Some(prepare_builtin_scheduler_runtime(&cfg)?)
    } else {
        None
    };
    let list = if let Some(prepared) = &prepared {
        prepared.candidates.clone()
    } else {
        discover_agent_candidates(&cfg)?
    };
    info!(
        "sched_ext state={} enabled={} matched_threads={}",
        read_sched_ext_state(),
        sched_ext_enabled(),
        list.len()
    );
    for c in &list {
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
    if let Some(prepared) = &prepared {
        print!("{}", describe_landscape_scheduler_intent(&prepared.intent));
        if let Some(report) = read_builtin_pressure_report(&cfg)? {
            print!("{}", format_builtin_pressure_report(&report));
        }
    }
    Ok(())
}

fn load_scheduler(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        let prepared = prepare_builtin_scheduler_runtime(&cfg)?;
        info!(
            "builtin scheduler load prepared: queues={} tasks={}",
            prepared.intent.queues.len(),
            prepared.intent.tasks.len()
        );
        ensure_landscape_scheduler_with_fallback(&cfg, &prepared.intent)?;
        apply_builtin_switch_to_candidates(&cfg, &prepared.intent, &prepared.selected, false)
    } else {
        ensure_scheduler_with_fallback(&cfg)
    }
}

fn unload_scheduler_cmd(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    unload_scheduler(&cfg.scheduler)
}

fn validate(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;
    validate_custom_bpf_runtime(&cfg.scheduler)?;
    if irqbalance_conflicts(&cfg) {
        warn!("irqbalance is active while network.apply_irq_affinity=true; it may overwrite manual IRQ affinity");
    }
    let online = read_online_cpus()?;
    info!("config validation passed; online_cpus={:?}", online);
    Ok(())
}

fn run(config: PathBuf, dry_run: bool, once: bool) -> Result<()> {
    let cfg = load_or_default(config)?;
    validate_cpu_config(&cfg)?;
    let mut pressure_tracker = matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf)
        .then(BuiltinPressureTracker::default);

    if !dry_run && !matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        ensure_scheduler_with_fallback(&cfg)?;
    }

    loop {
        let candidates = reconcile_once_with_pressure(&cfg, dry_run, pressure_tracker.as_mut())?;
        if once {
            break;
        }

        let trigger = if cfg.agent.event_driven {
            match wait_for_reconcile_trigger(&cfg, &candidates) {
                Ok(trigger) => trigger,
                Err(err) => {
                    warn!(
                        "event-driven reconcile wait failed, fallback to interval sleep: {}",
                        err
                    );
                    thread::sleep(Duration::from_secs(cfg.agent.apply_interval_secs));
                    ReconcileTrigger::Interval
                }
            }
        } else {
            thread::sleep(Duration::from_secs(cfg.agent.apply_interval_secs));
            ReconcileTrigger::Interval
        };
        info!(
            "reconcile trigger={} fallback_interval={}s",
            trigger.as_str(),
            cfg.agent.apply_interval_secs
        );
    }

    Ok(())
}

fn discover_agent_candidates(cfg: &ScxConfig) -> Result<Vec<ThreadCandidate>> {
    let self_pid = std::process::id() as i32;
    Ok(discover_candidates(cfg)?
        .into_iter()
        .filter(|candidate| candidate.pid != self_pid)
        .collect())
}

fn reconcile_once_with_pressure(
    cfg: &ScxConfig,
    dry_run: bool,
    pressure_tracker: Option<&mut BuiltinPressureTracker>,
) -> Result<Vec<ThreadCandidate>> {
    apply_network_locality(cfg, dry_run)?;

    if matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        let prepared = prepare_builtin_scheduler_runtime_with_pressure(cfg, pressure_tracker)?;
        let pressured_queues =
            prepared.intent.queues.iter().filter(|queue| queue.pressure_level > 0).count();
        info!(
            "builtin scheduler intent prepared: ops={} queues={} pressured_queues={} tasks={}",
            read_sched_ext_ops(),
            prepared.intent.queues.len(),
            pressured_queues,
            prepared.intent.tasks.len()
        );
        if let Some(report) = &prepared.pressure_report {
            if let Err(err) = write_builtin_pressure_report(cfg, report) {
                warn!("failed to write builtin pressure report: {}", err);
            }
            for queue in report.queues.iter().filter(|queue| queue.pressure_level > 0) {
                info!(
                    "queue_pressure qid={} iface={} queue={} cpu={} level={} irq_delta={} softnet_drop_delta={} softnet_time_squeeze_delta={} ksoftirqd_runtime_delta={} reasons={}",
                    queue.qid,
                    queue.interface,
                    queue.queue_index,
                    queue.owner_cpu,
                    queue.pressure_level,
                    queue.irq_delta,
                    queue.softnet_dropped_delta,
                    queue.softnet_time_squeeze_delta,
                    queue.ksoftirqd_runtime_delta,
                    queue.reasons.join("|")
                );
            }
        }
        if dry_run {
            print!("{}", describe_landscape_scheduler_intent(&prepared.intent));
            if let Some(report) = &prepared.pressure_report {
                print!("{}", format_builtin_pressure_report(report));
            }
        } else {
            ensure_landscape_scheduler_with_fallback(cfg, &prepared.intent)?;
        }

        apply_builtin_switch_to_candidates(cfg, &prepared.intent, &prepared.selected, dry_run)?;
        Ok(prepared.candidates)
    } else {
        let list = discover_agent_candidates(cfg)?;
        apply_partial_switch_to_candidates(cfg, &list, dry_run)?;
        Ok(list)
    }
}

fn wait_for_reconcile_trigger(
    cfg: &ScxConfig,
    candidates: &[ThreadCandidate],
) -> Result<ReconcileTrigger> {
    let interval = Duration::from_secs(cfg.agent.apply_interval_secs);
    match ProcConnectorWatcher::new(cfg, candidates) {
        Ok(Some(mut watcher)) => return watcher.wait(interval),
        Ok(None) => {}
        Err(err) => {
            warn!("proc connector watcher unavailable, fallback to inotify: {}", err);
        }
    }

    match InotifyReconcileWatcher::new(cfg, candidates) {
        Ok(Some(mut watcher)) => watcher.wait(interval),
        Ok(None) => {
            thread::sleep(interval);
            Ok(ReconcileTrigger::Interval)
        }
        Err(err) => Err(err),
    }
}

fn collect_reconcile_watch_targets(
    cfg: &ScxConfig,
    candidates: &[ThreadCandidate],
) -> Vec<ReconcileWatchTarget> {
    let mut targets = BTreeMap::<PathBuf, u32>::new();

    for prefix in &cfg.discovery.cgroup_prefixes {
        insert_cgroup_watch_targets(&mut targets, prefix);
    }

    let mut userspace_pids = BTreeSet::new();
    let mut discovered_cgroup_paths = BTreeSet::new();
    for candidate in candidates {
        if parse_ksoftirqd_cpu(&candidate.comm).is_some() {
            continue;
        }

        userspace_pids.insert(candidate.pid);
        for cgroup_path in parse_proc_cgroup_paths(&candidate.cgroup) {
            if cgroup_path != "/" {
                discovered_cgroup_paths.insert(cgroup_path);
            }
        }
    }

    for cgroup_path in discovered_cgroup_paths {
        insert_cgroup_watch_targets(&mut targets, &cgroup_path);
    }

    for pid in userspace_pids {
        insert_watch_target(
            &mut targets,
            PathBuf::from(format!("/proc/{pid}/task")),
            libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF,
        );
    }

    if cfg.discovery.cgroup_prefixes.is_empty() {
        insert_watch_target(
            &mut targets,
            PathBuf::from("/proc"),
            libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO,
        );
    }

    targets.into_iter().map(|(path, mask)| ReconcileWatchTarget { path, mask }).collect()
}

fn insert_cgroup_watch_targets(targets: &mut BTreeMap<PathBuf, u32>, cgroup_path: &str) {
    let dir_path = cgroup_fs_path(cgroup_path);
    insert_watch_target(
        targets,
        dir_path.clone(),
        libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF,
    );
    insert_watch_target(
        targets,
        dir_path.join("cgroup.procs"),
        libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE
            | libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF,
    );
    insert_watch_target(
        targets,
        dir_path.join("cgroup.threads"),
        libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE
            | libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF,
    );
}

fn insert_watch_target(targets: &mut BTreeMap<PathBuf, u32>, path: PathBuf, mask: u32) {
    targets.entry(path).and_modify(|existing| *existing |= mask).or_insert(mask);
}

fn cgroup_fs_path(cgroup_path: &str) -> PathBuf {
    let trimmed = cgroup_path.trim();
    let relative = trimmed.trim_start_matches('/');
    if relative.is_empty() {
        PathBuf::from("/sys/fs/cgroup")
    } else {
        Path::new("/sys/fs/cgroup").join(relative)
    }
}

fn parse_proc_cgroup_paths(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .filter_map(|line| line.rsplit(':').next())
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn poll_timeout_ms(duration: Duration) -> i32 {
    let millis = duration.as_millis();
    millis.min(i32::MAX as u128) as i32
}

fn print_network_status(cfg: &ScxConfig) -> Result<()> {
    let plans = build_network_locality_plans(cfg)?;
    if plans.is_empty() {
        return Ok(());
    }

    println!("network_locality:");
    if irqbalance_conflicts(cfg) {
        println!("irqbalance=active status=warning");
    }
    for plan in plans {
        println!(
            "iface={} forwarding_cpus={} queue_mapping_mode={:?} xps_mode={:?} rps_mode={:?} active_queues={}/{} irqs={}/{} rxqs={}/{}",
            plan.interface,
            landscape_scx_common::cpu_list_string(&plan.forwarding_cpus),
            plan.queue_mapping_mode,
            plan.xps_mode,
            plan.rps_mode,
            plan.active_queue_count,
            plan.total_tx_queues,
            plan.irq_actions.len(),
            plan.total_irqs,
            plan.active_queue_count.min(plan.total_rx_queues),
            plan.total_rx_queues,
        );

        if let Some(action) = &plan.channel_action {
            println!(
                "  combined_channels={} expected={} max={} status={}",
                action.current_combined,
                action.expected_combined,
                action.max_combined,
                if action.current_combined == action.expected_combined { "ok" } else { "mismatch" }
            );
        }

        if let Some(action) = &plan.rss_action {
            let expected = (0..action.expected_queue_count).collect::<Vec<_>>();
            println!(
                "  rss_equal ring_count={} queues={} expected={} status={}",
                action.current_ring_count,
                landscape_scx_common::cpu_list_string(&action.current_used_queues),
                landscape_scx_common::cpu_list_string(&expected),
                if rss_equal_matches(&action.current_used_queues, action.expected_queue_count) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        if !plan.inactive_xps_actions.is_empty() {
            let zeroed = plan
                .inactive_xps_actions
                .iter()
                .filter(|action| xps_mask_matches(&action.current_value, &action.indices))
                .count();
            println!(
                "  inactive_xps_zeroed={}/{} status={}",
                zeroed,
                plan.inactive_xps_actions.len(),
                if zeroed == plan.inactive_xps_actions.len() { "ok" } else { "mismatch" }
            );
        }

        for action in &plan.irq_actions {
            println!(
                "  irq={} label={} affinity={} expected={} status={}",
                action.irq,
                action.label,
                action.current_affinity_list,
                action.affinity_list,
                if affinity_list_matches(&action.current_affinity_list, &action.cpus) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        for action in &plan.xps_actions {
            println!(
                "  tx_queue={} {}={} expected={} status={}",
                action.queue_name,
                if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                    "xps_cpus"
                } else {
                    "xps_rxqs"
                },
                action.current_value,
                action.mask,
                if xps_mask_matches(&action.current_value, &action.indices) {
                    "ok"
                } else {
                    "mismatch"
                }
            );
        }

        if !plan.rps_actions.is_empty() {
            let zeroed = plan
                .rps_actions
                .iter()
                .filter(|action| xps_mask_matches(&action.current_value, &action.indices))
                .count();
            println!(
                "  rps_zeroed={}/{} status={}",
                zeroed,
                plan.rps_actions.len(),
                if zeroed == plan.rps_actions.len() { "ok" } else { "mismatch" }
            );
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

    if irqbalance_conflicts(cfg) {
        warn!("irqbalance is active while network.apply_irq_affinity=true; it may overwrite manual IRQ affinity");
    }

    if dry_run {
        for plan in plans {
            if let Some(action) = &plan.channel_action {
                println!(
                    "[DRY][NET] iface={} combined_channels={} -> {}",
                    action.interface, action.current_combined, action.expected_combined
                );
            }
            if let Some(action) = &plan.rss_action {
                println!(
                    "[DRY][NET] iface={} rss_equal={} -> 0-{}",
                    action.interface,
                    landscape_scx_common::cpu_list_string(&action.current_used_queues),
                    action.expected_queue_count.saturating_sub(1)
                );
            }
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
                    "[DRY][NET] iface={} tx_queue={} {}={} -> {}",
                    action.interface,
                    action.queue_name,
                    if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                        "xps_cpus"
                    } else {
                        "xps_rxqs"
                    },
                    action.current_value,
                    action.mask
                );
            }
            for action in &plan.rps_actions {
                println!(
                    "[DRY][NET] iface={} rx_queue={} rps_cpus={} -> {}",
                    action.interface, action.queue_name, action.current_value, action.mask
                );
            }
            for action in &plan.inactive_xps_actions {
                println!(
                    "[DRY][NET] iface={} inactive_tx_queue={} {}={} -> {}",
                    action.interface,
                    action.queue_name,
                    if matches!(action.mode, landscape_scx_common::XpsMode::Cpus) {
                        "xps_cpus"
                    } else {
                        "xps_rxqs"
                    },
                    action.current_value,
                    action.mask
                );
            }
        }
        return Ok(());
    }

    let mut channel_ok = 0usize;
    let mut channel_fail = 0usize;
    let mut channel_skip = 0usize;
    let mut rss_ok = 0usize;
    let mut rss_fail = 0usize;
    let mut rss_skip = 0usize;
    let mut irq_ok = 0usize;
    let mut irq_fail = 0usize;
    let mut irq_skip = 0usize;
    let mut xps_ok = 0usize;
    let mut xps_fail = 0usize;
    let mut xps_skip = 0usize;
    let mut rps_ok = 0usize;
    let mut rps_fail = 0usize;
    let mut rps_skip = 0usize;
    let mut inactive_xps_ok = 0usize;
    let mut inactive_xps_fail = 0usize;
    let mut inactive_xps_skip = 0usize;
    let mut plans = plans;

    // Restore RSS indirection before reducing combined queue count; some drivers
    // reject `ethtool -L combined N` while the indirection table still references
    // queues outside the target range.
    let mut refresh_after_rss = false;
    for plan in &plans {
        if let Some(action) = &plan.rss_action {
            if rss_equal_matches(&action.current_used_queues, action.expected_queue_count) {
                rss_skip += 1;
            } else if let Err(e) = apply_ethtool_rss_equal(action) {
                rss_fail += 1;
                warn!(
                    "rss equal update failed iface={} target={} err={}",
                    action.interface, action.expected_queue_count, e
                );
            } else {
                rss_ok += 1;
                refresh_after_rss = true;
            }
        }
    }

    if refresh_after_rss {
        plans = build_network_locality_plans(cfg)?;
    }

    let mut refresh_after_channels = false;
    for plan in &plans {
        if let Some(action) = &plan.channel_action {
            if action.current_combined == action.expected_combined {
                channel_skip += 1;
            } else if let Err(e) = apply_ethtool_combined_channels(action) {
                channel_fail += 1;
                warn!(
                    "combined queue update failed iface={} current={} target={} err={}",
                    action.interface, action.current_combined, action.expected_combined, e
                );
            } else {
                channel_ok += 1;
                refresh_after_channels = true;
            }
        }
    }

    if refresh_after_channels {
        plans = build_network_locality_plans(cfg)?;
    }

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
            if xps_mask_matches(&action.current_value, &action.indices) {
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

        for action in plan.rps_actions {
            if xps_mask_matches(&action.current_value, &action.indices) {
                rps_skip += 1;
                continue;
            }

            if let Err(e) = write_rps_cpus(&action) {
                rps_fail += 1;
                warn!(
                    "rps update failed iface={} rx_queue={} err={}",
                    action.interface, action.queue_name, e
                );
            } else {
                rps_ok += 1;
            }
        }

        for action in plan.inactive_xps_actions {
            if xps_mask_matches(&action.current_value, &action.indices) {
                inactive_xps_skip += 1;
                continue;
            }

            if let Err(e) = write_xps_cpus(&action) {
                inactive_xps_fail += 1;
                warn!(
                    "inactive xps cleanup failed iface={} tx_queue={} err={}",
                    action.interface, action.queue_name, e
                );
            } else {
                inactive_xps_ok += 1;
            }
        }
    }

    info!(
        "network locality apply finished: channel_success={} channel_failed={} channel_skipped={} rss_success={} rss_failed={} rss_skipped={} irq_success={} irq_failed={} irq_skipped={} xps_success={} xps_failed={} xps_skipped={} rps_success={} rps_failed={} rps_skipped={} inactive_xps_success={} inactive_xps_failed={} inactive_xps_skipped={}",
        channel_ok,
        channel_fail,
        channel_skip,
        rss_ok,
        rss_fail,
        rss_skip,
        irq_ok,
        irq_fail,
        irq_skip,
        xps_ok,
        xps_fail,
        xps_skip,
        rps_ok,
        rps_fail,
        rps_skip,
        inactive_xps_ok,
        inactive_xps_fail,
        inactive_xps_skip
    );
    if channel_fail > 0
        || rss_fail > 0
        || irq_fail > 0
        || xps_fail > 0
        || rps_fail > 0
        || inactive_xps_fail > 0
    {
        warn!("some network locality updates failed, verify root permission, ethtool support, and interface state");
    }

    Ok(())
}

fn health(config: PathBuf) -> Result<()> {
    let cfg = load_or_default(config)?;
    let list = discover_agent_candidates(&cfg)?;

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

#[derive(Debug, Clone)]
struct BuiltinSchedulerPrepared {
    candidates: Vec<ThreadCandidate>,
    intent: LandscapeSchedulerIntent,
    selected: Vec<ThreadCandidate>,
    pressure_report: Option<BuiltinPressureReport>,
}

#[derive(Debug, Default, Clone)]
struct BuiltinPressureTracker {
    previous_irq_totals: BTreeMap<u32, u64>,
    previous_softnet_counters: BTreeMap<usize, SoftnetCpuCounters>,
    previous_ksoftirqd_runtime: BTreeMap<usize, u64>,
    previous_softirq_totals: SoftirqTotals,
    last_report: Option<BuiltinPressureReport>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SoftnetCpuCounters {
    dropped: u64,
    time_squeeze: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SoftirqTotals {
    net_rx: u64,
    net_tx: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BuiltinPressureReport {
    net_rx_softirq_delta: u64,
    net_tx_softirq_delta: u64,
    queues: Vec<BuiltinQueuePressureReport>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BuiltinQueuePressureReport {
    qid: u32,
    interface: String,
    queue_index: usize,
    owner_cpu: usize,
    pressure_level: u32,
    irq_delta: u64,
    task_count: usize,
    softnet_dropped_delta: u64,
    softnet_time_squeeze_delta: u64,
    ksoftirqd_runtime_delta: u64,
    reasons: Vec<String>,
}

fn prepare_builtin_scheduler_runtime(cfg: &ScxConfig) -> Result<BuiltinSchedulerPrepared> {
    prepare_builtin_scheduler_runtime_with_pressure(cfg, None)
}

fn prepare_builtin_scheduler_runtime_with_pressure(
    cfg: &ScxConfig,
    pressure_tracker: Option<&mut BuiltinPressureTracker>,
) -> Result<BuiltinSchedulerPrepared> {
    let candidates = discover_agent_candidates(cfg)?;
    let plans = build_network_locality_plans(cfg)?;
    let mut intent = build_landscape_scheduler_intent(cfg, &plans, &candidates);
    let pressure_report = apply_builtin_queue_pressure(&mut intent, &plans, pressure_tracker);
    let selected = select_builtin_scheduler_candidates(&intent, &candidates);

    Ok(BuiltinSchedulerPrepared { candidates, intent, selected, pressure_report })
}

fn apply_builtin_queue_pressure(
    intent: &mut LandscapeSchedulerIntent,
    plans: &[InterfaceLocalityPlan],
    pressure_tracker: Option<&mut BuiltinPressureTracker>,
) -> Option<BuiltinPressureReport> {
    let Some(tracker) = pressure_tracker else {
        return None;
    };

    let current_irq_totals = collect_irq_totals(plans);
    let current_softnet_counters = read_softnet_cpu_counters();
    let current_ksoftirqd_runtime = collect_ksoftirqd_runtime_by_cpu(intent);
    let current_softirq_totals = read_softirq_totals();
    let pressure_report = derive_queue_pressure_report(
        intent,
        plans,
        &tracker.previous_irq_totals,
        &current_irq_totals,
        &tracker.previous_softnet_counters,
        &current_softnet_counters,
        &tracker.previous_ksoftirqd_runtime,
        &current_ksoftirqd_runtime,
        &tracker.previous_softirq_totals,
        &current_softirq_totals,
    );

    for queue in &mut intent.queues {
        queue.pressure_level = pressure_report
            .queues
            .iter()
            .find(|entry| entry.qid == queue.qid)
            .map(|entry| entry.pressure_level)
            .unwrap_or(QUEUE_PRESSURE_LEVEL_NONE);
    }

    tracker.previous_irq_totals = current_irq_totals;
    tracker.previous_softnet_counters = current_softnet_counters;
    tracker.previous_ksoftirqd_runtime = current_ksoftirqd_runtime;
    tracker.previous_softirq_totals = current_softirq_totals;
    tracker.last_report = Some(pressure_report.clone());
    Some(pressure_report)
}

fn collect_irq_totals(plans: &[InterfaceLocalityPlan]) -> BTreeMap<u32, u64> {
    let mut totals = BTreeMap::new();
    for plan in plans {
        for irq in &plan.status.irqs {
            totals.insert(irq.irq, irq.total_count);
        }
    }
    totals
}

fn read_softnet_cpu_counters() -> BTreeMap<usize, SoftnetCpuCounters> {
    let Ok(raw) = std::fs::read_to_string("/proc/net/softnet_stat") else {
        return BTreeMap::new();
    };

    raw.lines()
        .enumerate()
        .filter_map(|(cpu, line)| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let dropped = fields.get(1).and_then(|value| u64::from_str_radix(value, 16).ok())?;
            let time_squeeze =
                fields.get(2).and_then(|value| u64::from_str_radix(value, 16).ok())?;
            Some((cpu, SoftnetCpuCounters { dropped, time_squeeze }))
        })
        .collect()
}

fn read_softirq_totals() -> SoftirqTotals {
    let Ok(raw) = std::fs::read_to_string("/proc/softirqs") else {
        return SoftirqTotals::default();
    };

    SoftirqTotals {
        net_rx: parse_softirq_total(&raw, "NET_RX"),
        net_tx: parse_softirq_total(&raw, "NET_TX"),
    }
}

fn parse_softirq_total(raw: &str, name: &str) -> u64 {
    raw.lines()
        .find_map(|line| {
            let trimmed = line.trim_start();
            let prefix = format!("{name}:");
            if !trimmed.starts_with(&prefix) {
                return None;
            }
            Some(
                trimmed[prefix.len()..]
                    .split_whitespace()
                    .filter_map(|field| field.parse::<u64>().ok())
                    .sum(),
            )
        })
        .unwrap_or(0)
}

fn collect_ksoftirqd_runtime_by_cpu(intent: &LandscapeSchedulerIntent) -> BTreeMap<usize, u64> {
    let mut runtime_by_cpu = BTreeMap::new();

    for task in &intent.tasks {
        if !matches!(task.kind, LandscapeTaskKind::Ksoftirqd) {
            continue;
        }

        let Ok(runtime_ticks) = read_task_runtime_ticks(task.pid, task.tid) else {
            continue;
        };
        runtime_by_cpu.insert(task.owner_cpu, runtime_ticks);
    }

    runtime_by_cpu
}

fn read_task_runtime_ticks(pid: i32, tid: i32) -> Result<u64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))
        .with_context(|| format!("failed to read /proc/{pid}/task/{tid}/stat"))?;
    let Some(comm_end) = raw.rfind(") ") else {
        anyhow::bail!("missing task stat comm terminator for pid={} tid={}", pid, tid);
    };
    let fields = raw[comm_end + 2..].split_whitespace().collect::<Vec<_>>();
    let utime = fields
        .get(11)
        .context("missing task stat utime field")?
        .parse::<u64>()
        .context("invalid task stat utime field")?;
    let stime = fields
        .get(12)
        .context("missing task stat stime field")?
        .parse::<u64>()
        .context("invalid task stat stime field")?;
    Ok(utime.saturating_add(stime))
}

fn builtin_pressure_report_path(cfg: &ScxConfig) -> Option<PathBuf> {
    if !matches!(cfg.scheduler.mode, SchedulerMode::CustomBpf) {
        return None;
    }
    Some(cfg.scheduler.custom_bpf.build_dir.join("pressure.toml"))
}

fn write_builtin_pressure_report(cfg: &ScxConfig, report: &BuiltinPressureReport) -> Result<()> {
    let Some(path) = builtin_pressure_report_path(cfg) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, toml::to_string(report).context("failed to serialize pressure report")?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_builtin_pressure_report(cfg: &ScxConfig) -> Result<Option<BuiltinPressureReport>> {
    let Some(path) = builtin_pressure_report_path(cfg) else {
        return Ok(None);
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let report = toml::from_str(&raw)
        .with_context(|| format!("failed to parse builtin pressure report {}", path.display()))?;
    Ok(Some(report))
}

fn format_builtin_pressure_report(report: &BuiltinPressureReport) -> String {
    let mut out = String::new();
    out.push_str("builtin_pressure:\n");
    out.push_str(&format!(
        "  net_rx_softirq_delta={} net_tx_softirq_delta={}\n",
        report.net_rx_softirq_delta, report.net_tx_softirq_delta
    ));
    for queue in &report.queues {
        out.push_str(&format!(
            "  qid={} iface={} queue={} cpu={} level={} irq_delta={} softnet_drop_delta={} softnet_time_squeeze_delta={} ksoftirqd_runtime_delta={} task_count={} reasons={}\n",
            queue.qid,
            queue.interface,
            queue.queue_index,
            queue.owner_cpu,
            queue.pressure_level,
            queue.irq_delta,
            queue.softnet_dropped_delta,
            queue.softnet_time_squeeze_delta,
            queue.ksoftirqd_runtime_delta,
            queue.task_count,
            if queue.reasons.is_empty() { "none".to_string() } else { queue.reasons.join("|") }
        ));
    }
    out
}

fn softnet_delta(
    previous: &BTreeMap<usize, SoftnetCpuCounters>,
    current: &BTreeMap<usize, SoftnetCpuCounters>,
    cpu: usize,
) -> SoftnetCpuCounters {
    let Some(current) = current.get(&cpu) else {
        return SoftnetCpuCounters::default();
    };
    let Some(previous) = previous.get(&cpu) else {
        return SoftnetCpuCounters::default();
    };

    SoftnetCpuCounters {
        dropped: current.dropped.saturating_sub(previous.dropped),
        time_squeeze: current.time_squeeze.saturating_sub(previous.time_squeeze),
    }
}

fn counter_delta(
    previous: &BTreeMap<usize, u64>,
    current: &BTreeMap<usize, u64>,
    key: usize,
) -> u64 {
    current
        .get(&key)
        .zip(previous.get(&key))
        .map(|(current, previous)| current.saturating_sub(*previous))
        .unwrap_or(0)
}

#[cfg(test)]
fn derive_queue_pressure_levels(
    intent: &LandscapeSchedulerIntent,
    plans: &[InterfaceLocalityPlan],
    previous_irq_totals: &BTreeMap<u32, u64>,
    current_irq_totals: &BTreeMap<u32, u64>,
    previous_softnet_counters: &BTreeMap<usize, SoftnetCpuCounters>,
    current_softnet_counters: &BTreeMap<usize, SoftnetCpuCounters>,
    previous_ksoftirqd_runtime: &BTreeMap<usize, u64>,
    current_ksoftirqd_runtime: &BTreeMap<usize, u64>,
    previous_softirq_totals: &SoftirqTotals,
    current_softirq_totals: &SoftirqTotals,
) -> BTreeMap<u32, u32> {
    derive_queue_pressure_report(
        intent,
        plans,
        previous_irq_totals,
        current_irq_totals,
        previous_softnet_counters,
        current_softnet_counters,
        previous_ksoftirqd_runtime,
        current_ksoftirqd_runtime,
        previous_softirq_totals,
        current_softirq_totals,
    )
    .queues
    .into_iter()
    .map(|entry| (entry.qid, entry.pressure_level))
    .collect()
}

fn derive_queue_pressure_report(
    intent: &LandscapeSchedulerIntent,
    plans: &[InterfaceLocalityPlan],
    previous_irq_totals: &BTreeMap<u32, u64>,
    current_irq_totals: &BTreeMap<u32, u64>,
    previous_softnet_counters: &BTreeMap<usize, SoftnetCpuCounters>,
    current_softnet_counters: &BTreeMap<usize, SoftnetCpuCounters>,
    previous_ksoftirqd_runtime: &BTreeMap<usize, u64>,
    current_ksoftirqd_runtime: &BTreeMap<usize, u64>,
    previous_softirq_totals: &SoftirqTotals,
    current_softirq_totals: &SoftirqTotals,
) -> BuiltinPressureReport {
    let mut irq_by_queue = BTreeMap::new();
    for plan in plans {
        for irq in &plan.status.irqs {
            let Some(queue_index) = irq.queue_index else {
                continue;
            };
            irq_by_queue.entry((plan.interface.clone(), queue_index)).or_insert(irq.irq);
        }
    }

    let mut tasks_per_qid = BTreeMap::new();
    for task in &intent.tasks {
        *tasks_per_qid.entry(task.qid).or_insert(0usize) += 1;
    }

    let mut samples_by_interface = BTreeMap::<String, Vec<(u32, u64, usize)>>::new();
    for queue in &intent.queues {
        let irq_delta = irq_by_queue
            .get(&(queue.interface.clone(), queue.queue_index))
            .and_then(|irq| {
                current_irq_totals
                    .get(irq)
                    .zip(previous_irq_totals.get(irq))
                    .map(|(current, previous)| current.saturating_sub(*previous))
            })
            .unwrap_or(0);
        let task_count = tasks_per_qid.get(&queue.qid).copied().unwrap_or(0);
        samples_by_interface
            .entry(queue.interface.clone())
            .or_default()
            .push((queue.qid, irq_delta, task_count));
    }

    let net_rx_softirq_delta =
        current_softirq_totals.net_rx.saturating_sub(previous_softirq_totals.net_rx);
    let net_tx_softirq_delta =
        current_softirq_totals.net_tx.saturating_sub(previous_softirq_totals.net_tx);
    let mut queues = Vec::new();
    for samples in samples_by_interface.values() {
        let sample_count = samples.len() as u64;
        let total_irq_delta = samples.iter().map(|(_, irq_delta, _)| *irq_delta).sum::<u64>();
        let avg_irq_delta = if sample_count == 0 { 0 } else { total_irq_delta / sample_count };

        for (qid, irq_delta, task_count) in samples {
            let mut level = QUEUE_PRESSURE_LEVEL_NONE;
            let owner_cpu = intent
                .queues
                .iter()
                .find(|queue| queue.qid == *qid)
                .map(|queue| queue.owner_cpu)
                .unwrap_or(usize::MAX);
            let softnet =
                softnet_delta(previous_softnet_counters, current_softnet_counters, owner_cpu);
            let ksoftirqd_delta =
                counter_delta(previous_ksoftirqd_runtime, current_ksoftirqd_runtime, owner_cpu);
            let mut reasons = Vec::new();

            if *task_count >= 2 && *irq_delta > 0 {
                level = QUEUE_PRESSURE_LEVEL_ELEVATED;
                reasons.push("dataplane_task_density".into());
            }

            if softnet.time_squeeze > 0 {
                level = level.max(QUEUE_PRESSURE_LEVEL_ELEVATED);
                reasons.push("softnet_time_squeeze".into());
            }
            if softnet.time_squeeze >= 8 {
                level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                reasons.push("softnet_time_squeeze_high".into());
            }
            if softnet.dropped > 0 {
                level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                reasons.push("softnet_drop".into());
            }
            if ksoftirqd_delta >= 10 && *irq_delta > 0 {
                level = level.max(QUEUE_PRESSURE_LEVEL_ELEVATED);
                reasons.push("ksoftirqd_runtime".into());
            }
            if ksoftirqd_delta >= 50 {
                level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                reasons.push("ksoftirqd_runtime_high".into());
            }

            if avg_irq_delta > 0 {
                if *irq_delta >= avg_irq_delta.saturating_mul(3) / 2
                    && irq_delta.saturating_sub(avg_irq_delta) >= 256
                {
                    level = level.max(QUEUE_PRESSURE_LEVEL_ELEVATED);
                    reasons.push("irq_imbalance".into());
                }
                if *irq_delta >= avg_irq_delta.saturating_mul(2)
                    && irq_delta.saturating_sub(avg_irq_delta) >= 1024
                {
                    level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                    reasons.push("irq_imbalance_high".into());
                }
            } else if sample_count == 1 {
                if *irq_delta >= 8_192 {
                    level = level.max(QUEUE_PRESSURE_LEVEL_ELEVATED);
                    reasons.push("single_queue_irq_busy".into());
                }
                if *irq_delta >= 65_536 {
                    level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                    reasons.push("single_queue_irq_busy_high".into());
                }
            }

            if sample_count == 1
                && net_rx_softirq_delta.saturating_add(net_tx_softirq_delta) >= 8_192
                && *irq_delta > 0
            {
                level = level.max(QUEUE_PRESSURE_LEVEL_ELEVATED);
                reasons.push("global_softirq_activity".into());
            }
            if sample_count == 1 && net_rx_softirq_delta >= 65_536 && *irq_delta >= 4_096 {
                level = level.max(QUEUE_PRESSURE_LEVEL_HIGH);
                reasons.push("global_net_rx_high".into());
            }

            reasons.sort();
            reasons.dedup();
            let queue = intent.queues.iter().find(|queue| queue.qid == *qid).cloned().unwrap_or(
                LandscapeQueueIntent {
                    qid: *qid,
                    interface: String::new(),
                    queue_index: 0,
                    owner_cpu,
                    dsq_id: 0,
                    pressure_level: 0,
                },
            );

            queues.push(BuiltinQueuePressureReport {
                qid: *qid,
                interface: queue.interface,
                queue_index: queue.queue_index,
                owner_cpu,
                pressure_level: level,
                irq_delta: *irq_delta,
                task_count: *task_count,
                softnet_dropped_delta: softnet.dropped,
                softnet_time_squeeze_delta: softnet.time_squeeze,
                ksoftirqd_runtime_delta: ksoftirqd_delta,
                reasons,
            });
        }
    }

    queues.sort_by(|a, b| a.qid.cmp(&b.qid));
    BuiltinPressureReport { net_rx_softirq_delta, net_tx_softirq_delta, queues }
}

fn apply_partial_switch_to_candidates(
    cfg: &ScxConfig,
    list: &[ThreadCandidate],
    dry_run: bool,
) -> Result<()> {
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

fn apply_builtin_switch_to_candidates(
    cfg: &ScxConfig,
    intent: &LandscapeSchedulerIntent,
    list: &[ThreadCandidate],
    dry_run: bool,
) -> Result<()> {
    let intent_actions = intent
        .tasks
        .iter()
        .map(|task| (task.key(), builtin_task_policy_action(task)))
        .collect::<BTreeMap<_, _>>();

    info!("discovered {} candidate threads", list.len());

    if dry_run {
        info!("dry-run mode, no scheduler syscalls will be issued");
        for c in list {
            let action = intent_actions
                .get(&c.task_key())
                .cloned()
                .unwrap_or_else(|| thread_policy_action(cfg, &c.comm));
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
        let action = intent_actions
            .get(&c.task_key())
            .cloned()
            .unwrap_or_else(|| thread_policy_action(cfg, &c.comm));

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

fn build_landscape_scheduler_intent(
    cfg: &ScxConfig,
    plans: &[InterfaceLocalityPlan],
    candidates: &[ThreadCandidate],
) -> LandscapeSchedulerIntent {
    let housekeeping_cpus = effective_housekeeping_cpus(cfg);
    let mut queues = Vec::new();
    let mut owner_cpu_to_qid = BTreeMap::new();
    let mut interface_first_qid = BTreeMap::new();
    let mut qid = 0u32;

    for plan in plans {
        for queue_index in 0..plan.active_queue_count {
            let Some(owner_cpu) =
                desired_locality_cpus(&plan.forwarding_cpus, &plan.queue_mapping_mode, queue_index)
                    .into_iter()
                    .next()
            else {
                continue;
            };

            owner_cpu_to_qid.insert(owner_cpu, qid);
            interface_first_qid.entry(plan.interface.clone()).or_insert((qid, owner_cpu));
            queues.push(LandscapeQueueIntent {
                qid,
                interface: plan.interface.clone(),
                queue_index,
                owner_cpu,
                dsq_id: LANDSCAPE_DSQ_BASE + qid as u64,
                pressure_level: 0,
            });
            qid += 1;
        }
    }

    let mut seen = BTreeSet::new();
    let mut tasks = Vec::new();
    for candidate in candidates {
        let task = if let Some(cpu) = parse_ksoftirqd_cpu(&candidate.comm) {
            owner_cpu_to_qid.get(&cpu).copied().map(|qid| LandscapeTaskIntent {
                pid: candidate.pid,
                tid: candidate.tid,
                start_time_ns: candidate.start_time_ns,
                comm: candidate.comm.clone(),
                kind: LandscapeTaskKind::Ksoftirqd,
                class: LandscapeTaskClass::DataplaneStrict,
                qid,
                owner_cpu: cpu,
            })
        } else if matches_forwarding_worker(cfg, &candidate.comm) {
            resolve_forwarding_worker_intent(
                cfg,
                candidate,
                &owner_cpu_to_qid,
                &interface_first_qid,
            )
        } else {
            None
        };

        let Some(task) = task else {
            continue;
        };
        if seen.insert(task.key()) {
            tasks.push(task);
        }
    }

    tasks.sort_by(|a, b| a.qid.cmp(&b.qid).then_with(|| a.key().cmp(&b.key())));

    LandscapeSchedulerIntent {
        switch_mode: cfg.scheduler.custom_bpf.switch_mode.clone(),
        housekeeping_cpus,
        queues,
        tasks,
    }
}

fn effective_housekeeping_cpus(cfg: &ScxConfig) -> Vec<usize> {
    if !cfg.scheduler.custom_bpf.housekeeping_cpus.is_empty() {
        return cfg.scheduler.custom_bpf.housekeeping_cpus.clone();
    }
    if !cfg.policy.control_cpus.is_empty() {
        return cfg.policy.control_cpus.clone();
    }
    cfg.policy.forwarding_cpus.clone()
}

fn matches_forwarding_worker(cfg: &ScxConfig, comm: &str) -> bool {
    cfg.scheduler
        .custom_bpf
        .forwarding_thread_prefixes
        .iter()
        .any(|prefix| !prefix.is_empty() && comm.starts_with(prefix))
}

fn forwarding_worker_requires_interface(comm: &str) -> bool {
    matches!(comm, "pppd") || comm.starts_with("landscape_pppoe") || comm.starts_with("pppoe-rx-")
}

fn resolve_forwarding_worker_interface_owner(
    candidate: &ThreadCandidate,
    interface_first_qid: &BTreeMap<String, (u32, usize)>,
) -> Option<(u32, usize)> {
    interface_first_qid.iter().find_map(|(iface, mapping)| {
        if candidate.cmdline.contains(iface) || candidate.comm.contains(iface) {
            Some(*mapping)
        } else {
            None
        }
    })
}

fn resolve_forwarding_worker_intent(
    cfg: &ScxConfig,
    candidate: &ThreadCandidate,
    owner_cpu_to_qid: &BTreeMap<usize, u32>,
    interface_first_qid: &BTreeMap<String, (u32, usize)>,
) -> Option<LandscapeTaskIntent> {
    if let Some((qid, owner_cpu)) =
        resolve_forwarding_worker_interface_owner(candidate, interface_first_qid)
    {
        return Some(LandscapeTaskIntent {
            pid: candidate.pid,
            tid: candidate.tid,
            start_time_ns: candidate.start_time_ns,
            comm: candidate.comm.clone(),
            kind: LandscapeTaskKind::ForwardingWorker,
            class: LandscapeTaskClass::DataplaneStrict,
            qid,
            owner_cpu,
        });
    }

    // PPP/PPPoE workers are interface-scoped. If their cmdline/comm no longer
    // exposes the attach interface, treat them as stale residual processes
    // instead of falling back to an unrelated owner CPU.
    if forwarding_worker_requires_interface(&candidate.comm) {
        return None;
    }

    let action = thread_policy_action(cfg, &candidate.comm);
    if action.cpus.len() != 1 {
        return None;
    }

    let owner_cpu = action.cpus[0];
    owner_cpu_to_qid.get(&owner_cpu).copied().map(|qid| LandscapeTaskIntent {
        pid: candidate.pid,
        tid: candidate.tid,
        start_time_ns: candidate.start_time_ns,
        comm: candidate.comm.clone(),
        kind: LandscapeTaskKind::ForwardingWorker,
        class: LandscapeTaskClass::DataplaneStrict,
        qid,
        owner_cpu,
    })
}

#[derive(Debug, Clone)]
struct ThreadPolicyAction {
    cpus: Vec<usize>,
    apply_sched_ext: bool,
    apply_affinity: bool,
}

fn builtin_task_policy_action(task: &LandscapeTaskIntent) -> ThreadPolicyAction {
    match task.kind {
        LandscapeTaskKind::Ksoftirqd => ThreadPolicyAction {
            cpus: vec![task.owner_cpu],
            apply_sched_ext: true,
            apply_affinity: false,
        },
        LandscapeTaskKind::ForwardingWorker => ThreadPolicyAction {
            cpus: vec![task.owner_cpu],
            apply_sched_ext: true,
            apply_affinity: true,
        },
    }
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

fn select_builtin_scheduler_candidates(
    intent: &LandscapeSchedulerIntent,
    candidates: &[ThreadCandidate],
) -> Vec<ThreadCandidate> {
    let task_keys = intent.tasks.iter().map(|task| task.key()).collect::<BTreeSet<_>>();
    candidates.iter().filter(|c| task_keys.contains(&c.task_key())).cloned().collect()
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

fn ensure_landscape_scheduler_with_fallback(
    cfg: &ScxConfig,
    intent: &LandscapeSchedulerIntent,
) -> Result<()> {
    match ensure_landscape_scheduler(&cfg.scheduler, intent) {
        Ok(()) => {
            info!(
                "builtin scheduler ensure success, sched_ext state={} ops={}",
                read_sched_ext_state(),
                read_sched_ext_ops()
            );
            Ok(())
        }
        Err(e) => {
            if cfg.scheduler.fallback_on_error {
                warn!("builtin scheduler ensure failed but fallback enabled: {}", e);
                Ok(())
            } else {
                error!("builtin scheduler ensure failed: {}", e);
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
    use super::{
        apply_builtin_queue_pressure, build_landscape_scheduler_intent, builtin_task_policy_action,
        collect_irq_totals, collect_reconcile_watch_targets, derive_queue_pressure_levels,
        parse_proc_connector_event_scope, thread_policy_action, BuiltinPressureTracker,
        ExecProcEvent, ForkProcEvent, ProcEventHeader, ScxConfig, SoftirqTotals,
        SoftnetCpuCounters, ThreadCpuClass, PROC_EVENT_EXEC, PROC_EVENT_FORK,
        QUEUE_PRESSURE_LEVEL_ELEVATED, QUEUE_PRESSURE_LEVEL_HIGH,
    };
    use landscape_scx_common::{
        InterfaceLocalityPlan, InterfaceLocalityStatus, IrqLocalityState, LandscapeQueueIntent,
        LandscapeSchedulerIntent, LandscapeTaskClass, LandscapeTaskIntent, LandscapeTaskKind,
        QueueMappingMode, ScxSwitchMode, ThreadCandidate, XpsMode,
    };
    use std::path::PathBuf;

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

    #[test]
    fn builtin_intent_maps_ksoftirqd_cpu_to_queue_owner() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.housekeeping_cpus = vec![6, 7];

        let plan = InterfaceLocalityPlan {
            interface: "eth0".into(),
            forwarding_cpus: vec![2, 3],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "eth0".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        };
        let candidates = vec![
            ThreadCandidate {
                pid: 15,
                tid: 15,
                start_time_ns: 1_500,
                comm: "ksoftirqd/2".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 16,
                tid: 16,
                start_time_ns: 1_600,
                comm: "ksoftirqd/3".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &[plan], &candidates);
        assert_eq!(intent.housekeeping_cpus, vec![6, 7]);
        assert_eq!(intent.queues.len(), 2);
        assert_eq!(intent.queues[0].pressure_level, 0);
        assert_eq!(intent.tasks.len(), 2);
        assert_eq!(intent.tasks[0].kind, LandscapeTaskKind::Ksoftirqd);
        assert_eq!(intent.tasks[0].class, LandscapeTaskClass::DataplaneStrict);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 2);
        assert_eq!(intent.tasks[1].qid, 1);
        assert_eq!(intent.tasks[1].owner_cpu, 3);
    }

    #[test]
    fn builtin_intent_maps_pppd_to_interface_queue_owner() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["pppd".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "pppd".into(),
            cpus: vec![20],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![
            InterfaceLocalityPlan {
                interface: "ens27f0".into(),
                forwarding_cpus: vec![0, 2],
                queue_mapping_mode: QueueMappingMode::RoundRobin,
                xps_mode: XpsMode::Cpus,
                rps_mode: landscape_scx_common::RpsMode::Auto,
                apply_rss_equal: false,
                apply_combined_channels: false,
                clear_inactive_xps: false,
                active_queue_count: 2,
                total_tx_queues: 2,
                total_rx_queues: 2,
                total_irqs: 2,
                status: InterfaceLocalityStatus {
                    interface: "ens27f0".into(),
                    tx_xps_cpus: Vec::new(),
                    tx_xps_rxqs: Vec::new(),
                    rx_queues: Vec::new(),
                    irqs: Vec::new(),
                    channel_status: None,
                    rss_status: None,
                },
                channel_action: None,
                rss_action: None,
                xps_actions: Vec::new(),
                rps_actions: Vec::new(),
                inactive_xps_actions: Vec::new(),
                irq_actions: Vec::new(),
            },
            InterfaceLocalityPlan {
                interface: "ens16f1np1".into(),
                forwarding_cpus: vec![11, 16],
                queue_mapping_mode: QueueMappingMode::RoundRobin,
                xps_mode: XpsMode::Cpus,
                rps_mode: landscape_scx_common::RpsMode::Auto,
                apply_rss_equal: false,
                apply_combined_channels: false,
                clear_inactive_xps: false,
                active_queue_count: 2,
                total_tx_queues: 2,
                total_rx_queues: 2,
                total_irqs: 2,
                status: InterfaceLocalityStatus {
                    interface: "ens16f1np1".into(),
                    tx_xps_cpus: Vec::new(),
                    tx_xps_rxqs: Vec::new(),
                    rx_queues: Vec::new(),
                    irqs: Vec::new(),
                    channel_status: None,
                    rss_status: None,
                },
                channel_action: None,
                rss_action: None,
                xps_actions: Vec::new(),
                rps_actions: Vec::new(),
                inactive_xps_actions: Vec::new(),
                irq_actions: Vec::new(),
            },
        ];
        let candidates = vec![
            ThreadCandidate {
                pid: 200,
                tid: 200,
                start_time_ns: 20_000,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens27f0-h8a".into(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 201,
                tid: 201,
                start_time_ns: 20_100,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens16f1np1-uplink".into(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 2);
        assert_eq!(intent.tasks[0].kind, LandscapeTaskKind::ForwardingWorker);
        assert_eq!(intent.tasks[0].class, LandscapeTaskClass::DataplaneStrict);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 0);
        assert_eq!(intent.tasks[1].qid, 2);
        assert_eq!(intent.tasks[1].owner_cpu, 11);
    }

    #[test]
    fn builtin_forwarding_worker_action_forces_sched_ext_on_owner_cpu() {
        let action = builtin_task_policy_action(&LandscapeTaskIntent {
            pid: 15630,
            tid: 15630,
            start_time_ns: 123_456,
            comm: "pppd".into(),
            kind: LandscapeTaskKind::ForwardingWorker,
            class: LandscapeTaskClass::DataplaneStrict,
            qid: 8,
            owner_cpu: 11,
        });

        assert_eq!(action.cpus, vec![11]);
        assert!(action.apply_sched_ext);
        assert!(action.apply_affinity);
    }

    fn test_pressure_plan(total_q0: u64, total_q1: u64) -> InterfaceLocalityPlan {
        InterfaceLocalityPlan {
            interface: "eth0".into(),
            forwarding_cpus: vec![2, 3],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "eth0".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: vec![
                    IrqLocalityState {
                        irq: 100,
                        label: "eth0-TxRx-0".into(),
                        queue_index: Some(0),
                        total_count: total_q0,
                        affinity_list_path: PathBuf::from("/proc/irq/100/smp_affinity_list"),
                        affinity_mask_path: PathBuf::from("/proc/irq/100/smp_affinity"),
                        affinity_list: "2".into(),
                    },
                    IrqLocalityState {
                        irq: 101,
                        label: "eth0-TxRx-1".into(),
                        queue_index: Some(1),
                        total_count: total_q1,
                        affinity_list_path: PathBuf::from("/proc/irq/101/smp_affinity_list"),
                        affinity_mask_path: PathBuf::from("/proc/irq/101/smp_affinity"),
                        affinity_list: "3".into(),
                    },
                ],
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        }
    }

    fn test_pressure_intent() -> LandscapeSchedulerIntent {
        LandscapeSchedulerIntent {
            switch_mode: ScxSwitchMode::Partial,
            housekeeping_cpus: vec![0, 1],
            queues: vec![
                LandscapeQueueIntent {
                    qid: 0,
                    interface: "eth0".into(),
                    queue_index: 0,
                    owner_cpu: 2000,
                    dsq_id: 0x1000,
                    pressure_level: 0,
                },
                LandscapeQueueIntent {
                    qid: 1,
                    interface: "eth0".into(),
                    queue_index: 1,
                    owner_cpu: 2001,
                    dsq_id: 0x1001,
                    pressure_level: 0,
                },
            ],
            tasks: vec![
                LandscapeTaskIntent {
                    pid: 1000,
                    tid: 1001,
                    start_time_ns: 10,
                    comm: "ksoftirqd/2".into(),
                    kind: LandscapeTaskKind::Ksoftirqd,
                    class: LandscapeTaskClass::DataplaneStrict,
                    qid: 0,
                    owner_cpu: 2000,
                },
                LandscapeTaskIntent {
                    pid: 1002,
                    tid: 1003,
                    start_time_ns: 11,
                    comm: "forwarder-0".into(),
                    kind: LandscapeTaskKind::ForwardingWorker,
                    class: LandscapeTaskClass::DataplaneStrict,
                    qid: 0,
                    owner_cpu: 2000,
                },
                LandscapeTaskIntent {
                    pid: 1004,
                    tid: 1005,
                    start_time_ns: 12,
                    comm: "ksoftirqd/3".into(),
                    kind: LandscapeTaskKind::Ksoftirqd,
                    class: LandscapeTaskClass::DataplaneStrict,
                    qid: 1,
                    owner_cpu: 2001,
                },
            ],
        }
    }

    #[test]
    fn builtin_queue_pressure_uses_second_sample() {
        let mut tracker = BuiltinPressureTracker::default();
        let mut first_intent = test_pressure_intent();
        let first_plans = vec![test_pressure_plan(1_000, 1_000)];

        apply_builtin_queue_pressure(&mut first_intent, &first_plans, Some(&mut tracker));
        assert_eq!(first_intent.queues[0].pressure_level, 0);
        assert_eq!(first_intent.queues[1].pressure_level, 0);

        let mut second_intent = test_pressure_intent();
        let second_plans = vec![test_pressure_plan(21_000, 1_000)];

        apply_builtin_queue_pressure(&mut second_intent, &second_plans, Some(&mut tracker));
        assert_eq!(second_intent.queues[0].pressure_level, QUEUE_PRESSURE_LEVEL_HIGH);
        assert_eq!(second_intent.queues[1].pressure_level, 0);
    }

    #[test]
    fn builtin_queue_pressure_derives_relative_imbalance() {
        let intent = test_pressure_intent();
        let plans = vec![test_pressure_plan(9_000, 1_800)];
        let previous_irq_totals =
            std::collections::BTreeMap::from([(100u32, 1_000u64), (101u32, 1_000u64)]);
        let current_irq_totals = collect_irq_totals(&plans);

        let levels = derive_queue_pressure_levels(
            &intent,
            &plans,
            &previous_irq_totals,
            &current_irq_totals,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &SoftirqTotals::default(),
            &SoftirqTotals::default(),
        );

        assert_eq!(levels.get(&0), Some(&QUEUE_PRESSURE_LEVEL_ELEVATED));
        assert_eq!(levels.get(&1), Some(&0));
    }

    #[test]
    fn builtin_queue_pressure_escalates_on_softnet_and_ksoftirqd_signals() {
        let intent = test_pressure_intent();
        let plans = vec![test_pressure_plan(1_500, 1_500)];
        let previous_irq_totals =
            std::collections::BTreeMap::from([(100u32, 1_000u64), (101u32, 1_000u64)]);
        let current_irq_totals = collect_irq_totals(&plans);
        let previous_softnet = std::collections::BTreeMap::from([
            (2000usize, SoftnetCpuCounters { dropped: 10, time_squeeze: 20 }),
            (2001usize, SoftnetCpuCounters { dropped: 0, time_squeeze: 0 }),
        ]);
        let current_softnet = std::collections::BTreeMap::from([
            (2000usize, SoftnetCpuCounters { dropped: 11, time_squeeze: 28 }),
            (2001usize, SoftnetCpuCounters { dropped: 0, time_squeeze: 0 }),
        ]);
        let previous_ksoftirqd =
            std::collections::BTreeMap::from([(2000usize, 100u64), (2001usize, 0u64)]);
        let current_ksoftirqd =
            std::collections::BTreeMap::from([(2000usize, 180u64), (2001usize, 0u64)]);
        let previous_softirq = SoftirqTotals { net_rx: 1_000, net_tx: 500 };
        let current_softirq = SoftirqTotals { net_rx: 10_000, net_tx: 2_000 };

        let levels = derive_queue_pressure_levels(
            &intent,
            &plans,
            &previous_irq_totals,
            &current_irq_totals,
            &previous_softnet,
            &current_softnet,
            &previous_ksoftirqd,
            &current_ksoftirqd,
            &previous_softirq,
            &current_softirq,
        );

        assert_eq!(levels.get(&0), Some(&QUEUE_PRESSURE_LEVEL_HIGH));
        assert_eq!(levels.get(&1), Some(&0));
    }

    #[test]
    fn reconcile_watch_targets_include_cgroup_and_task_paths() {
        let mut cfg = ScxConfig::default();
        cfg.discovery.cgroup_prefixes = vec!["/system.slice/landscape-router.service".into()];

        let targets = collect_reconcile_watch_targets(
            &cfg,
            &[ThreadCandidate {
                pid: 5910,
                tid: 5915,
                start_time_ns: 123,
                comm: "tokio-runtime-w".into(),
                cmdline: "/root/landscape-webserver".into(),
                cgroup: "0::/system.slice/landscape-router.service/dataplane".into(),
            }],
        );
        let target_paths = targets
            .into_iter()
            .map(|target| target.path)
            .collect::<std::collections::BTreeSet<_>>();

        assert!(target_paths.contains(&std::path::PathBuf::from("/proc/5910/task")));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service"
        )));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service/cgroup.procs"
        )));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service/cgroup.threads"
        )));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service/dataplane"
        )));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service/dataplane/cgroup.procs"
        )));
        assert!(target_paths.contains(&std::path::PathBuf::from(
            "/sys/fs/cgroup/system.slice/landscape-router.service/dataplane/cgroup.threads"
        )));
    }

    #[test]
    fn reconcile_watch_targets_fallback_to_proc_without_cgroup_scope() {
        let cfg = ScxConfig::default();
        let targets = collect_reconcile_watch_targets(&cfg, &[]);
        let target_paths = targets
            .into_iter()
            .map(|target| target.path)
            .collect::<std::collections::BTreeSet<_>>();

        assert!(target_paths.contains(&std::path::PathBuf::from("/proc")));
    }

    #[test]
    fn parse_proc_connector_scope_uses_fork_child_identity() {
        let event = (
            ProcEventHeader { what: PROC_EVENT_FORK, cpu: 3, timestamp_ns: 42 },
            ForkProcEvent {
                parent_pid: 10,
                parent_tgid: 10,
                child_pid: 21,
                child_tgid: 20,
            },
        );
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const (ProcEventHeader, ForkProcEvent)).cast::<u8>(),
                std::mem::size_of::<(ProcEventHeader, ForkProcEvent)>(),
            )
        };

        assert_eq!(parse_proc_connector_event_scope(bytes), Some((21, 20)));
    }

    #[test]
    fn parse_proc_connector_scope_uses_exec_identity() {
        let event = (
            ProcEventHeader { what: PROC_EVENT_EXEC, cpu: 1, timestamp_ns: 7 },
            ExecProcEvent { process_pid: 88, process_tgid: 77 },
        );
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const (ProcEventHeader, ExecProcEvent)).cast::<u8>(),
                std::mem::size_of::<(ProcEventHeader, ExecProcEvent)>(),
            )
        };

        assert_eq!(parse_proc_connector_event_scope(bytes), Some((88, 77)));
    }

    #[test]
    fn builtin_intent_filters_stale_pppd_without_interface_binding() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["pppd".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "pppd".into(),
            cpus: vec![20],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![InterfaceLocalityPlan {
            interface: "ens27f0".into(),
            forwarding_cpus: vec![0, 2],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "ens27f0".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        }];
        let candidates = vec![
            ThreadCandidate {
                pid: 200,
                tid: 200,
                start_time_ns: 20_000,
                comm: "pppd".into(),
                cmdline: String::new(),
                cgroup: String::new(),
            },
            ThreadCandidate {
                pid: 201,
                tid: 201,
                start_time_ns: 20_100,
                comm: "pppd".into(),
                cmdline: "pppd nodetach call ppp-ens27f0-h8a".into(),
                cgroup: String::new(),
            },
        ];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 1);
        assert_eq!(intent.tasks[0].tid, 201);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 0);
    }

    #[test]
    fn builtin_intent_allows_generic_forwarder_single_cpu_fallback() {
        let mut cfg = ScxConfig::default();
        cfg.scheduler.mode = landscape_scx_common::SchedulerMode::CustomBpf;
        cfg.scheduler.custom_bpf.forwarding_thread_prefixes = vec!["landscape-forwarder".into()];
        cfg.policy.thread_cpu_classes = vec![ThreadCpuClass {
            thread_name_prefix: "landscape-forwarder".into(),
            cpus: vec![11],
            apply_sched_ext: Some(false),
            apply_affinity: Some(true),
        }];

        let plans = vec![InterfaceLocalityPlan {
            interface: "ens16f1np1".into(),
            forwarding_cpus: vec![11, 16],
            queue_mapping_mode: QueueMappingMode::RoundRobin,
            xps_mode: XpsMode::Cpus,
            rps_mode: landscape_scx_common::RpsMode::Auto,
            apply_rss_equal: false,
            apply_combined_channels: false,
            clear_inactive_xps: false,
            active_queue_count: 2,
            total_tx_queues: 2,
            total_rx_queues: 2,
            total_irqs: 2,
            status: InterfaceLocalityStatus {
                interface: "ens16f1np1".into(),
                tx_xps_cpus: Vec::new(),
                tx_xps_rxqs: Vec::new(),
                rx_queues: Vec::new(),
                irqs: Vec::new(),
                channel_status: None,
                rss_status: None,
            },
            channel_action: None,
            rss_action: None,
            xps_actions: Vec::new(),
            rps_actions: Vec::new(),
            inactive_xps_actions: Vec::new(),
            irq_actions: Vec::new(),
        }];
        let candidates = vec![ThreadCandidate {
            pid: 300,
            tid: 301,
            start_time_ns: 42_000,
            comm: "landscape-forwarder".into(),
            cmdline: String::new(),
            cgroup: String::new(),
        }];

        let intent = build_landscape_scheduler_intent(&cfg, &plans, &candidates);
        assert_eq!(intent.tasks.len(), 1);
        assert_eq!(intent.tasks[0].tid, 301);
        assert_eq!(intent.tasks[0].qid, 0);
        assert_eq!(intent.tasks[0].owner_cpu, 11);
    }
}
