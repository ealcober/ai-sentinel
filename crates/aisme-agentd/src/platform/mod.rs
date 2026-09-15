// SPDX-License-Identifier: Apache-2.0
//! The composition root (`F1.PA.06`; plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in the workspace permitted to name a concrete adapter
//! or use `cfg(target_os)`.** Everything above it is written against the
//! `aisme-core` traits, which is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK; `cargo xtask verify-layering` fails on a
//! `cfg(target_os)` anywhere else.
//!
//! The adapters arrive with their phases — `aisme-linux`'s `BpfSensor` in
//! `F2.WS.01`, the rest of it in F3, `sentinel-core` in F10, `aisme-sdkhost`
//! in F9 — and each is added here, behind the `cfg` its platform needs,
//! without changing a line above.

use aisme_core::adjudicate::Adjudicator;
use aisme_core::capability::CapabilitySet;
use aisme_core::enforce::Enforcer;
use aisme_core::ladder::AdjudicatorLadder;
use aisme_core::mock::{MockSensor, NullEnforcer, PolicyAdjudicator};
#[cfg(not(target_os = "linux"))]
use aisme_core::resolve::NullResolver;
use aisme_core::resolve::PathResolver;
use aisme_core::sensor::{Sensor, SensorConfig};
use aisme_core::tier::{tier_of, Tier};
use aisme_ebpf_common::Verdict;

/// What the platform probes measured. The probe itself is an adapter's
/// (`F3.LD.*` on Linux); until one exists this reports nothing present,
/// which is the honest answer and yields tier L1.
#[must_use]
pub fn probe() -> CapabilitySet {
    #[cfg(target_os = "linux")]
    {
        // The two seccomp flags are measured, because `F2.WS.05`'s enforcer is
        // gated on `seccomp_addfd` and a set that never reports it would leave
        // that enforcer compiled and never composed — the defect `docs/09`
        // finding 5 names. Feature-tested in a forked child: a seccomp filter
        // is irreversible, so the process that asks must not be the one that
        // wears the answer.
        //
        // The Landlock ABI is measured too, because `F2.WS.11` gates on it:
        // the ruleset is applied when the kernel has one and skipped with the
        // lost function named when it does not, and a set reporting 0
        // unconditionally would report `L2-` on a kernel that enforces. It is
        // asked of the kernel — `landlock_create_ruleset(NULL, 0, VERSION)` —
        // and not read off the LSM list, which says Landlock is compiled in
        // and not which rights it accepts.
        //
        // The rest is still unprobed and still `F3.LD.01`'s: securityfs,
        // /proc/config.gz, an attach test for the connect hook. Nothing else is
        // claimed present, which is why the banner keeps reporting those as
        // degraded rather than absent-and-fine.
        // `CapabilitySet` is `#[non_exhaustive]` (`ADR-08`), so it is built by
        // starting from `NONE` and setting what was measured — which is also
        // the honest shape: everything is absent until something measured it.
        let seccomp = aisme_linux::probe_seccomp();
        let mut caps = CapabilitySet::NONE;
        caps.seccomp_unotify = seccomp.unotify;
        caps.seccomp_addfd = seccomp.addfd;
        caps.landlock_abi = aisme_linux::probe_landlock().abi;
        caps
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows is served by WSL2 (ADR-02) and mobile by AI Sentinel; a
        // native build of `agentd` on another OS has no sensors at all.
        CapabilitySet::NONE
    }
}

/// Load the BPF sensor on this kernel and report what happened, in the words
/// the reader needs: accepted with its capabilities, or refused with the
/// platform's own message. Returns the process exit code — 0 accepted, 1
/// refused — so a guest run can be read by a script as well as by a person.
#[cfg(target_os = "linux")]
pub fn load_sensor_report() -> i32 {
    use aisme_core::sensor::{Sensor as _, SensorConfig};
    let mut sensor = aisme_linux::BpfSensor::new();
    match sensor.start(&SensorConfig::default()) {
        Ok(()) => {
            let caps = sensor.capabilities();
            println!("load-sensor: ACCEPTED");
            println!("  ringbuf: {}", caps.ringbuf);
            println!("  health: {:?}", sensor.health());
            // Detach immediately: this is a question, not a session.
            if let Err(e) = sensor.stop() {
                println!("  stop: {} ({:?})", e.detail, e.kind);
            }
            0
        }
        Err(e) => {
            // The reason is the product of this command. A bare "failed" would
            // make the run useless on the one kernel where it matters most.
            println!("load-sensor: REFUSED ({:?})", e.kind);
            println!("  {}", e.detail);
            1
        }
    }
}

/// Not Linux: there is no sensor to load, and saying so beats a silent zero.
#[cfg(not(target_os = "linux"))]
pub fn load_sensor_report() -> i32 {
    println!("load-sensor: UNSUPPORTED (this build has no Linux adapter)");
    1
}

/// Load the policy maps on this kernel and report what happened (`F2.WS.04`).
///
/// A separate object with no programs, so the answer is about the maps alone.
/// Returns the process exit code — 0 created, 1 refused — so a guest run reads
/// as easily to a script as to a person.
#[cfg(target_os = "linux")]
pub fn load_policy_report() -> i32 {
    match aisme_linux::load_policy_maps() {
        Ok(names) => {
            println!("load-policy: ACCEPTED");
            for name in names {
                println!("  map: {name}");
            }
            0
        }
        Err(e) => {
            // Every link of the cause. A wrapper whose Display is a constant is
            // what turned one failure into a diagnosis nobody had established.
            println!("load-policy: REFUSED ({:?})", e.kind);
            println!("  {}", e.detail);
            1
        }
    }
}

/// Not Linux: there are no BPF maps to create, and saying so beats a silent zero.
#[cfg(not(target_os = "linux"))]
pub fn load_policy_report() -> i32 {
    println!("load-policy: UNSUPPORTED (this build has no Linux adapter)");
    1
}

/// The path resolver for this platform (`F2.WS.02`).
///
/// Canonicalization is I/O, so it lives in an adapter and this is where the
/// adapter is named. On Linux that is `RealpathResolver`, which asks the
/// kernel; everywhere else it is `NullResolver`, which reports every path
/// unresolved — true, and it keeps `FLAG_PATH_UNRESOLVED` on the event so
/// nothing downstream mistakes a requested path for a canonical one.
#[must_use]
pub fn resolver() -> Box<dyn PathResolver> {
    #[cfg(target_os = "linux")]
    {
        Box::new(aisme_linux::RealpathResolver::for_sessions())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(NullResolver)
    }
}

/// The sensors for this platform and this capability set.
#[must_use]
pub fn sensors(caps: &CapabilitySet) -> Vec<Box<dyn Sensor>> {
    let mut sensors: Vec<Box<dyn Sensor>> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // `F2.WS.01`. The gate is `caps.ringbuf`, and it is load-bearing twice
        // over. It is the honest condition — the sensor needs
        // `BPF_MAP_TYPE_RINGBUF` and refuses the perf-buffer fallback, which
        // is `F3.PT.*`'s — and it is what keeps `I-12` intact: `probe()`
        // reports nothing present until `F3.LD.01`, so no BPF load is
        // attempted on a host running the test suite. The in-VM composition
        // (`F2.WS.10`) passes a capability set that was actually measured.
        if caps.ringbuf {
            let mut bpf = aisme_linux::BpfSensor::new();
            match bpf.start(&SensorConfig::default()) {
                Ok(()) => sensors.push(Box::new(bpf)),
                Err(e) => {
                    // The daemon still starts (`I-19`) — the mock below covers
                    // — but the reason is never swallowed: a sensor that
                    // silently did not attach is a machine reported quiet.
                    eprintln!("aisme: BpfSensor did not attach: {}", e.detail);
                }
            }
        }
        // F3.PT.*: UprobeSensor for TLS, CooperativeSensor for JSONL tailing.
    }
    if sensors.is_empty() {
        // Never zero sensors: an engine with no producer would report a quiet
        // machine, which is an absence read as "nothing happened" (I-16).
        // The mock produces nothing and says so through its health.
        sensors.push(Box::new(MockSensor::new(Vec::new())));
    }
    sensors
}

/// Serve one registered session for its whole life: answer its notifications
/// if it is filtered, and release its cgroup when it empties.
///
/// **Both halves, because a session is not only a filter.** A session without
/// `--trap-openat` has no listener and still has a cgroup that nothing else
/// will remove: `exec` has no after, so the process that created the directory
/// is the supervised command by the time it could clean up (`docs/10` point 2).
///
/// The composition root names the adapter; the caller passes an `Option<OwnedFd>`
/// and gets back nothing platform-specific, which is what keeps `A-05` true
/// with a second engine in the tree.
#[cfg(target_os = "linux")]
pub fn serve_session_notifications(
    listener: Option<std::os::fd::OwnedFd>,
    session_id: u64,
    tty: Option<&str>,
    escalate: &[String],
    unattended: Option<&str>,
    policy: Option<&aisme_core::policy::CompiledPolicy>,
    cgroup: Option<&str>,
) {
    if let Some(listener) = listener {
        answer_notifications(listener, session_id, tty, escalate, unattended, policy);
    } else {
        // Not an error and not a silence: an unfiltered session is one the
        // daemon watches rather than supervises, and saying so is what stops a
        // reader concluding the filter failed.
        println!("session {session_id:016x} watched; no filter, nothing to answer");
    }
    release_session_cgroup(session_id, cgroup);
}

/// Wait for a session's cgroup to empty, then remove it.
///
/// **No sweeper and no interval.** cgroup v2 publishes `cgroup.events` with a
/// `populated` line and that file is pollable: `poll(2)` returns `POLLPRI` when
/// it changes, so the daemon waits for the kernel to say the session is empty
/// instead of guessing how often to look. A sweeper would either run too often
/// or leave a window, and could not tell a new empty session from a finished
/// one.
///
/// The state is **read before it is waited on**, because the session may have
/// ended already and an edge that has passed never arrives again.
///
/// Nothing here is recursive. `rmdir` on a cgroup with processes in it fails
/// with `EBUSY`, which the kernel enforces and this code therefore does not
/// have to; and a session subtree with children of its own is not F2's, so
/// removing one would be removing something nobody asked about.
#[cfg(target_os = "linux")]
fn release_session_cgroup(session_id: u64, cgroup: Option<&str>) {
    use std::os::fd::AsRawFd as _;

    let Some(path) = cgroup else {
        return;
    };
    let events = std::path::Path::new(path).join("cgroup.events");
    let Ok(watch) = std::fs::File::open(&events) else {
        eprintln!(
            "session {session_id:016x}: {} cannot be read; its cgroup stays",
            events.display()
        );
        return;
    };

    loop {
        // Re-opened each turn rather than seeking: `cgroup.events` is a few
        // bytes, and a seek that was forgotten would read an empty string and
        // be taken for "not populated" — an absence read as a value.
        match std::fs::read_to_string(&events) {
            Ok(text) => {
                if text.lines().any(|line| line.trim() == "populated 0") {
                    break;
                }
            }
            Err(e) => {
                // The directory went away under us: somebody else removed it,
                // which is the outcome this function wanted anyway.
                eprintln!("session {session_id:016x}: {} : {e}", events.display());
                return;
            }
        }
        let mut fds = [libc::pollfd {
            fd: watch.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        }];
        // `-1`: a session may run for days, and the event this waits for is the
        // only thing that ends it. The thread is this session's own and the
        // daemon does not join it, so a session that never ends costs one
        // parked thread and nothing else.
        // SAFETY: one live descriptor in an array we own, for the length given.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, -1) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("session {session_id:016x}: waiting on cgroup.events: {e}; its cgroup stays");
            return;
        }
    }

    match std::fs::remove_dir(path) {
        Ok(()) => println!("session {session_id:016x} cgroup released: {path}"),
        Err(e) => eprintln!("session {session_id:016x}: {path} could not be removed: {e}"),
    }
}

#[cfg(target_os = "linux")]
fn answer_notifications(
    listener: std::os::fd::OwnedFd,
    session_id: u64,
    tty: Option<&str>,
    escalate: &[String],
    unattended: Option<&str>,
    policy: Option<&aisme_core::policy::CompiledPolicy>,
) {
    use std::os::fd::AsFd as _;

    use aisme_core::adjudicate::{Adjudicator as _, Escalation};
    use aisme_core::enforce::EscalationId;
    use aisme_core::ontology::{PermissionGroup, SessionId, Severity};
    use aisme_ebpf_common::Verdict;

    // Named on the way in, because a session with no terminal cannot be
    // prompted and `F2.WS.06` will answer it with a timeout verdict instead —
    // which an operator should learn when the session starts, not when a
    // decision is silently defaulted.
    println!(
        "session {session_id:016x} supervised; terminal {}",
        tty.unwrap_or("none — escalations will take the timeout verdict")
    );
    // The answer comes from the session's registration, never from this
    // process's environment: a daemon-side read could be steered by anything
    // able to set a variable in the daemon, which includes the agent being
    // adjudicated.
    let unattended = unattended.and_then(|v| match v {
        "d" => Some(crate::terminal::Unattended(Verdict::Deny)),
        "1" | "s" | "a" => Some(crate::terminal::Unattended(Verdict::Allow)),
        _ => None,
    });
    let mut adjudicator =
        crate::terminal::TerminalAdjudicator::new(tty.map(ToOwned::to_owned), unattended);
    // An unattended session waits for nobody: the answer is already known, and
    // a ten-second budget it will never spend would only slow a gate down.
    if unattended.is_some() {
        adjudicator = adjudicator.with_budget(std::time::Duration::ZERO);
    }
    let mut asked = 0u64;
    let mut escalation_id = 0u64;

    // What this session is judged against, in order of authority:
    //
    // 1. The **daemon's compiled policy**, when it has one. This is the real
    //    answer: `Verdict::Deny` refuses and **asks nobody**, which is what
    //    makes it stronger than an escalation that denies on a timeout — no
    //    answer exists to get wrong and no budget has to expire for it to
    //    hold. `evaluate` is `aisme-core`'s and already handles globs, which
    //    the trie lowering does not.
    // 2. Failing that, the prefixes the session declared with `--escalate`:
    //    a shorthand for tests and for a daemon started without a policy. It
    //    can only ever *ask*, never refuse outright.
    let decide = |path: &str| -> Verdict {
        if let Some(policy) = policy {
            let facts = aisme_core::policy::EventFacts {
                // No group: at F2 the supervisor matches paths and does not
                // classify, and `evaluate` reads an absent group as "every
                // rule applies" rather than as "none does".
                path: Some(path),
                ..aisme_core::policy::EventFacts::default()
            };
            return aisme_core::policy::evaluate(policy, &facts).verdict;
        }
        if escalate
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
        {
            Verdict::Escalate
        } else {
            Verdict::Allow
        }
    };

    let mut delivered = 0u64;
    let mut denied = 0u64;
    let result = aisme_linux::serve_notifications_with(
        listener.as_fd(),
        |path| {
            match decide(path) {
                // Refused by the policy, and nobody is asked. A deny that could
                // become a prompt is a deny that can be argued with.
                Verdict::Deny => return false,
                Verdict::Allow | Verdict::Warn => return true,
                Verdict::Escalate => {}
            }
            asked += 1;
            escalation_id += 1;
            let question = Escalation::new(
                EscalationId(escalation_id),
                SessionId(session_id),
                PermissionGroup::Credentials,
                "escalate-declared",
                Severity::High,
                format!("read {path}"),
            );
            // Blocking, on this session's own thread and never the hot loop: a
            // human takes seconds and the hot loop's budget is microseconds.
            crate::runtime::block_on(adjudicator.ask(&question)) == Verdict::Allow
        },
        |pid, ok, why| {
            if ok {
                delivered += 1;
            } else {
                denied += 1;
                // One line per denial, with its reason: "unsupported" tells an
                // operator nothing they can act on. The WAL record is F2.WS.09's.
                eprintln!(
                    "session {session_id:016x}: denied an openat from pid {pid}: {}",
                    why.unwrap_or("no reason recorded")
                );
            }
        },
    );
    if let Err(e) = result {
        eprintln!(
            "session {session_id:016x}: the notification loop stopped: {}",
            e.detail
        );
    }
    // Closing the listener is what ends the session's enforcement: any syscall
    // still held then gets ENOSYS from the kernel, which is fail-closed.
    drop(listener);
    println!(
        "session {session_id:016x} ended: {delivered} delivered, {denied} denied, {asked} asked ({} unattended)",
        adjudicator.answered_unattended
    );
}

/// Off Linux there are no notifications to answer and no cgroup to release.
#[cfg(not(target_os = "linux"))]
pub fn serve_session_notifications(
    _listener: Option<std::os::fd::OwnedFd>,
    _session_id: u64,
    _tty: Option<&str>,
    _escalate: &[String],
    _unattended: Option<&str>,
    _policy: Option<&aisme_core::policy::CompiledPolicy>,
    _cgroup: Option<&str>,
) {
}

/// The enforcers for this platform and this capability set.
#[must_use]
pub fn enforcers(caps: &CapabilitySet) -> Vec<Box<dyn Enforcer>> {
    let mut enforcers: Vec<Box<dyn Enforcer>> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // F3.EN.*: LsmEnforcer at L3, LandlockEnforcer and
        // CgroupConnectEnforcer at L2, SeccompEnforcer for T1, FreezerEnforcer
        // for T2 — each gated on the capability it needs.
        let _ = caps;
    }
    if enforcers.is_empty() {
        // Observe-only is a real tier (L1), not a failure to start (I-19).
        enforcers.push(Box::new(NullEnforcer::new()));
    }
    enforcers
}

/// The adjudicator ladder for this platform.
///
/// `PolicyAdjudicator` is always last and always present, so a question
/// always has an answer (§7 tier 5). Its default is `deny`: the escalate
/// class's timeout default (§2.20.5).
#[must_use]
pub fn adjudicators(caps: &CapabilitySet) -> AdjudicatorLadder {
    let mut adjudicators: Vec<Box<dyn Adjudicator>> = Vec::new();
    // F8's uiagent supplies Modal and Notification; `aisme run` supplies
    // Terminal (F8.CLI.*); a paired device supplies Remote (F11), and only
    // when one is reachable.
    let _ = caps.local_ui_attached;
    let _ = caps.remote_devices;
    adjudicators.push(Box::new(PolicyAdjudicator::new(Verdict::Deny)));
    AdjudicatorLadder::from(adjudicators)
}

/// The tier this composition serves, derived from the probe (`F1.PA.04`).
#[must_use]
pub fn tier(caps: &CapabilitySet) -> Tier {
    tier_of(caps)
}

#[cfg(test)]
// A panic *is* the failure report in a test, so the two lints the daemon
// denies are allowed here — and only here, which is the point: the denial
// covers the code that runs in production (§3.5, F1.RT.08).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aisme_core::adjudicate::AdjudicationChannel;
    use aisme_core::enforce::EnforcementTier;

    /// This process's own cgroup, when the kernel has delegated it to us.
    ///
    /// The release tests need a **real** cgroup: `cgroup.events` exists nowhere
    /// else, and a plain file would make `poll` return immediately and turn the
    /// wait into a spin. Where the subtree is not delegated the tests say so
    /// and stop, rather than passing without having tested anything.
    #[cfg(target_os = "linux")]
    fn delegated_cgroup() -> Option<std::path::PathBuf> {
        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = text.lines().find_map(|l| l.strip_prefix("0::"))?;
        let dir =
            std::path::Path::new("/sys/fs/cgroup").join(relative.trim().trim_start_matches('/'));
        let probe = dir.join(format!("aisme-probe-{}", std::process::id()));
        std::fs::create_dir(&probe).ok()?;
        let _ = std::fs::remove_dir(&probe);
        Some(dir)
    }

    /// A session cgroup that is already empty is removed.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_empty_session_cgroup_is_released() {
        let Some(parent) = delegated_cgroup() else {
            eprintln!("skipped: this process's cgroup subtree is not delegated");
            return;
        };
        let id = 0x0123_4567_89ab_cdef_u64 ^ u64::from(std::process::id());
        let dir = parent.join(format!("aisme-{id:016x}"));
        let _ = std::fs::remove_dir(&dir);
        std::fs::create_dir(&dir).expect("a session cgroup");

        release_session_cgroup(id, dir.to_str());

        assert!(
            !dir.exists(),
            "an empty session cgroup was left behind: {}",
            dir.display()
        );
    }

    /// A session cgroup with a process in it is **not** removed until that
    /// process leaves.
    ///
    /// This is the test that makes the one above mean something: a release that
    /// simply removed the directory at once would pass that one and destroy a
    /// running session's accounting here. `rmdir` would also fail with `EBUSY`
    /// — which is the kernel refusing, not this code deciding — so the
    /// assertion is on the directory still being there *while* the process
    /// runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_populated_session_cgroup_is_released_only_once_it_empties() {
        let Some(parent) = delegated_cgroup() else {
            eprintln!("skipped: this process's cgroup subtree is not delegated");
            return;
        };
        let id = 0xfedc_ba98_7654_3210_u64 ^ u64::from(std::process::id());
        let dir = parent.join(format!("aisme-{id:016x}"));
        let _ = std::fs::remove_dir(&dir);
        std::fs::create_dir(&dir).expect("a session cgroup");

        // A real process, moved in by writing its pid to `cgroup.procs` — which
        // is what `aisme run` does to itself.
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("a process to occupy the cgroup");
        std::fs::write(dir.join("cgroup.procs"), child.id().to_string())
            .expect("moving the child into the session cgroup");

        let watcher = {
            let path = dir.clone();
            std::thread::spawn(move || release_session_cgroup(id, path.to_str()))
        };

        // While it runs the directory stands. Read from the filesystem and not
        // from anything the daemon says, because the daemon reports what it
        // believes.
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(
            dir.exists(),
            "the cgroup of a running session was removed: {}",
            dir.display()
        );

        let _ = child.wait();
        watcher.join().expect("the release thread");
        assert!(
            !dir.exists(),
            "the cgroup was not released after its last process left: {}",
            dir.display()
        );
    }

    #[test]
    fn the_composition_always_yields_a_sensor_an_enforcer_and_an_answer() {
        let caps = probe();
        assert_eq!(sensors(&caps).len(), 1);
        let enforcers = enforcers(&caps);
        assert_eq!(enforcers.len(), 1);
        assert_eq!(enforcers[0].tier(), EnforcementTier::Observe);
        let ladder = adjudicators(&caps);
        assert_eq!(ladder.channels(), [AdjudicationChannel::Policy]);
        assert!(!ladder.is_empty(), "there is always an answer");
    }

    /// `I-12` in the test suite, not only in the invariant list: this runs on
    /// a developer's host, so nothing here may touch the kernel. `probe()`
    /// reports nothing present until `F3.LD.01`, and `sensors()` only reaches
    /// `BpfSensor` when `ringbuf` was measured — so the composition under test
    /// loads no BPF program. If someone later makes the sensor unconditional,
    /// this test is where it shows: the composition would try a real load and
    /// the count below would move on a machine with `CAP_BPF`.
    #[test]
    fn nothing_measured_means_no_bpf_load_is_attempted_on_the_host() {
        let caps = probe();
        assert!(
            !caps.ringbuf,
            "probe() must not claim what it did not measure"
        );
        let sensors = sensors(&caps);
        assert_eq!(sensors.len(), 1, "the mock alone");
        assert!(
            matches!(
                sensors[0].health(),
                aisme_core::sensor::SensorHealth::Detached { .. }
                    | aisme_core::sensor::SensorHealth::Healthy
            ),
            "the mock reports its own state; what matters is that it is the mock"
        );
        assert!(!sensors[0].capabilities().ringbuf);
    }

    /// The composition always yields a resolver, and it never claims a path is
    /// canonical without having resolved one. Asked about a path that cannot
    /// exist, every implementation must answer `None` rather than echo the
    /// input — an echo would clear `FLAG_PATH_UNRESOLVED` downstream and turn a
    /// requested path into a decision about the wrong file.
    #[test]
    fn the_composed_resolver_refuses_a_path_that_cannot_resolve() {
        let mut resolver = resolver();
        let raw = b"/aisme-does-not-exist/nor-does-this";
        let mut buf = [0u8; 200];
        buf[..raw.len()].copy_from_slice(raw);
        assert_eq!(resolver.resolve(&mut buf, raw.len()), None);
        assert_eq!(&buf[..raw.len()], raw, "and it leaves the buffer alone");
    }

    #[test]
    fn a_platform_with_nothing_measured_is_l1_not_a_failure_to_start() {
        assert_eq!(tier(&probe()), Tier::L1);
        assert_eq!(tier(&CapabilitySet::NONE), Tier::L1);
    }
}
