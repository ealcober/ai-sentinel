// SPDX-License-Identifier: Apache-2.0
//! `aisme run -- <cmd>` — the supervised session (`F2.WS.08`).
//!
//! The preferred session-discovery path (`H-18`): the supervisor owns the
//! process from before its first syscall, so identity is a fact rather than a
//! heuristic. Every alternative in the plan — binary catalogues, lineage
//! guessing, `/proc` scanning — exists for the case where we did *not* start the
//! process, and each of them can be wrong.
//!
//! `docs/design/02_aisme-run.md` §3 lists nine steps across seven tasks in five
//! phases. **F2 implements four**: resolve one scope, create and join the
//! session cgroup, `exec`, and the line printed before it. Step 3 (register with
//! `agentd`) is `F8.CLI.01`, step 4 (the seccomp filter) is `F2.WS.05`, step 5
//! (Landlock) is `F2.WS.11`, step 6 (environment) is `F4.CO.04` and step 8
//! (terminal adjudication) is `F2.WS.06`. The seams those occupy are defined
//! here, because a seam invented later is a rewrite.

use std::path::{Path, PathBuf};

use aisme_proto::rpc::Method;

use crate::platform;

/// What the command line asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The session's declared scope. F2 takes it from `--scope` or the working
    /// directory; the full ladder — `.aisme/scope.toml` narrowing only, VCS-root
    /// detection, per-agent baselines — is `F7.PS.07` and is **deferred, not
    /// half-built**: a partial detector is the kind of thing that later looks
    /// implemented.
    pub scopes: Vec<PathBuf>,
    /// The supervised command and its arguments.
    pub command: Vec<String>,
    /// Whether to trap this session's `openat` calls and have `agentd` answer
    /// them (`F2.WS.05`).
    ///
    /// **Opt-in, and it stays opt-in until `F3.PT.02`.** A classic BPF filter
    /// sees syscall numbers and register values, never paths, so the filter
    /// traps *every* `openat` and the supervisor answers each one. The only
    /// "permit unchanged" the kernel offers is
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which `I-28` forbids for a
    /// path-bearing syscall — so an open the supervisor cannot reproduce cannot
    /// be permitted either. F2 reproduces `O_RDONLY` only (limit one of
    /// `Q-13`), which means a session under this filter **cannot write**.
    /// Making it the default would break every session; `F3.PT.02`'s
    /// kernel-side trie is what will let the filter trap the escalate class
    /// alone.
    pub trap_openat: bool,
    /// Path prefixes whose opens are escalated to a human instead of being
    /// permitted silently — F2's one rule, declared by the session.
    pub escalate: Vec<String>,
}

/// Parse `run [--scope <path>…] -- <cmd> [args…]`.
///
/// # Errors
///
/// The usage line, when the command is missing or a flag is unknown. An empty
/// command is refused rather than defaulted to a shell: `aisme run` with nothing
/// to run is a typo, and exec'ing a shell for it would supervise the wrong
/// process and report success.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    const USAGE: &str = "usage: aisme run [--scope <path>…] [--trap-openat] [--escalate <prefix>…] -- <command> [args…]";
    let mut scopes = Vec::new();
    let mut trap_openat = false;
    let mut escalate = Vec::new();
    let mut rest = args.iter();
    let mut command = Vec::new();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--" => {
                command.extend(rest.cloned());
                break;
            }
            "--scope" => {
                let path = rest
                    .next()
                    .ok_or_else(|| format!("--scope needs a path\n{USAGE}"))?;
                let path = PathBuf::from(path);
                if !path.exists() {
                    // Refused before anything is created: a scope that does not
                    // exist cannot be narrowed to, and discovering that after a
                    // cgroup exists leaves one behind.
                    return Err(format!("--scope {}: no such path", path.display()));
                }
                scopes.push(path);
            }
            "--trap-openat" => trap_openat = true,
            "--escalate" => {
                let prefix = rest
                    .next()
                    .ok_or_else(|| format!("--escalate needs a path prefix\n{USAGE}"))?;
                escalate.push(prefix.clone());
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if command.is_empty() {
        return Err(format!("nothing to run\n{USAGE}"));
    }
    if scopes.is_empty() {
        scopes.push(std::env::current_dir().map_err(|e| format!("no working directory: {e}"))?);
    }
    Ok(Invocation {
        scopes,
        command,
        trap_openat,
        escalate,
    })
}

/// This process's own cgroup v2 path, from `/proc/self/cgroup`.
///
/// Read rather than assumed: under `aisme-agentd.service` the session subtree is
/// the one systemd delegated (`Delegate=yes`, `DelegateSubgroup=sessions`), and
/// on a developer's machine it is the user's own `user@UID.service` subtree.
/// Reading where we already are works in both and assumes neither layout.
fn v2_path_of(proc_self_cgroup: &str) -> Option<&str> {
    // A unified-hierarchy line is `0::<path>`. A v1 host has no such line, which
    // is the honest answer and not a path to guess at.
    proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
}

/// Create the session cgroup under our own and move this process into it.
///
/// **Before `exec`, and this process places itself.** Any other order leaves a
/// window in which the supervised child is outside the tree, and the whole point
/// of this path is that there is no window.
///
/// # Errors
///
/// A v1 host, an undelegated subtree, or a write that reported success while
/// `cgroup.procs` does not contain us — each named, never worked around. A
/// session that cannot be attributed by construction is not attributed by
/// heuristic instead; that is what this command exists to avoid.
pub fn enter_session_cgroup(id: u64) -> Result<PathBuf, String> {
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("cannot read /proc/self/cgroup: {e}"))?;
    let relative = v2_path_of(&own).ok_or_else(|| {
        "no cgroup v2 hierarchy: this host cannot attribute a session tree".to_owned()
    })?;
    let base = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let dir = base.join(format!("aisme-{id:016x}"));
    std::fs::create_dir(&dir).map_err(|e| {
        format!(
            "cannot create {}: {e} — the subtree must be delegated (systemd Delegate=yes)",
            dir.display()
        )
    })?;
    let pid = std::process::id();
    std::fs::write(dir.join("cgroup.procs"), pid.to_string())
        .map_err(|e| format!("cannot join {}: {e}", dir.display()))?;
    // Read back. A write that returns Ok and a cgroup.procs without us in it is
    // the failure this check exists for — reporting the effect, not the call.
    let members = std::fs::read_to_string(dir.join("cgroup.procs"))
        .map_err(|e| format!("cannot read back {}: {e}", dir.display()))?;
    if !members.lines().any(|l| l.trim() == pid.to_string()) {
        return Err(format!(
            "{} does not contain pid {pid} after joining it",
            dir.display()
        ));
    }
    Ok(dir)
}

/// A session identifier.
///
/// Eight bytes of `/dev/urandom`. F2 needs it unique on one machine and nothing
/// more; `F8.CLI.01` will say if it has to become a UUID.
fn session_id() -> u64 {
    use std::io::Read as _;

    // Exactly eight bytes. `std::fs::read` on this path reads until EOF, and
    // `/dev/urandom` has none: the first version of this function hung `aisme
    // run` before it printed a line and was OOM-killed under `cargo test`.
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .ok()
        .map_or_else(
            || {
                // No urandom is not a reason to refuse a session, and it is not a
                // reason to pretend either: the pid and the clock are weaker and the
                // fallback says so by being obviously derived.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
                now ^ (u64::from(std::process::id()) << 32)
            },
            |()| u64::from_ne_bytes(bytes),
        )
}

/// Where `aisme-agentd` serves its control plane, per its unit.
///
/// `AISME_AGENTD_SOCKET` overrides it. That is configuration and not test
/// scaffolding: the unit's `RuntimeDirectory=aisme` puts the default under
/// `/run`, which a developer running both halves by hand cannot write to.
/// `F8.CLI.01` gives it a proper configuration file.
fn agentd_socket() -> String {
    std::env::var("AISME_AGENTD_SOCKET").unwrap_or_else(|_| "/run/aisme/agentd.sock".to_owned())
}

/// Deny writes outside the session's declared scope, in kernel (`F2.WS.11`).
///
/// **A denial here produces no notification traffic at all**, which is the
/// second half of the task's done-condition and the whole performance argument
/// for L2 (§2.2.1): the kernel refuses the syscall and no supervisor is woken.
/// The denial is recorded from the syscall's return value instead, by the
/// exit tracepoint, so that a denial nobody was notified about is still a
/// denial somebody can audit.
///
/// **A kernel without Landlock is a named degradation, not a failure** (`I-19`,
/// and `docs/design/02_aisme-run.md` §5): the step is skipped, the lost
/// function is stated once on stderr, and the session runs. The alternative —
/// refusing to start — would make the product unusable on exactly the kernels
/// the degradation ladder exists for.
///
/// # Errors
///
/// Anything that stopped an available Landlock from being applied: a scope
/// that cannot be opened, a ruleset the kernel refused. A write scope that
/// silently failed to apply is worse than none, because the session believes
/// it is confined.
fn apply_write_scope(scopes: &[PathBuf]) -> Result<(), String> {
    match platform::restrict_writes_to(scopes) {
        Ok(Some(abi)) => {
            // One line, at the moment it takes effect, naming what is in force.
            // A confinement nobody can see is one nobody can debug.
            println!(
                "landlock: ABI {abi} — writes are denied outside {}",
                scopes
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            );
            Ok(())
        }
        Ok(None) => {
            eprintln!(
                "landlock: unavailable on this kernel — writes outside the scope are not denied \
                 in kernel (tier L2-); they arrive one syscall late through seccomp, if at all"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Everything that must happen between the cgroup and `exec`.
///
/// `F2.WS.05` installs the seccomp filter here; `F2.WS.11`'s Landlock ruleset
/// joins it. Both must run after the cgroup exists and before `exec`, because a
/// filter installed later has a window and a ruleset installed later is not
/// inherited.
///
/// **The order inside is the safety.** The daemon is reached *first*: a filter
/// is irreversible and inherited across `exec`, so installing one and then
/// finding nobody to answer its notifications would leave the supervised
/// command with every `openat` failing `ENOSYS` — a session that cannot run,
/// created by the guard meant to protect it.
///
/// # Errors
///
/// Anything that stopped the session being supervised, with its reason. The
/// caller refuses to `exec` rather than running unsupervised: a command the
/// caller asked to have watched must not run unwatched without being told.
fn pre_exec(invocation: &Invocation, session_id: u64) -> Result<(), String> {
    use std::fmt::Write as _;
    use std::os::fd::AsFd as _;

    // 0. The write scope, in kernel (`F2.WS.11`). It runs **before** the early
    //    return below, because Landlock is not part of the trap: a session
    //    without `--trap-openat` is still a session, and step 5 of
    //    `docs/design/02_aisme-run.md` applies to every one of them.
    //
    //    It also runs **before** the seccomp filter, and that ordering is a
    //    correction to the design note rather than a reading of it. The note
    //    lists the filter as step 4 and this as step 5, which looks like an
    //    order and is not one: `landlock_add_rule` needs an `O_PATH`
    //    descriptor for each allowed directory, so applying the ruleset under
    //    a filter that traps every `openat` would send the session's own setup
    //    to the supervisor to be answered — and `I-28` forbids permitting an
    //    `O_PATH` open, so the supervisor would have to refuse it. The filter
    //    is also irreversible, and everything that can still fail belongs
    //    above it.
    apply_write_scope(&invocation.scopes)?;

    if !invocation.trap_openat {
        return Ok(());
    }
    // 1. The daemon, before anything irreversible.
    let socket_path = agentd_socket();
    let socket = std::os::unix::net::UnixStream::connect(&socket_path)
        .map_err(|e| format!("{socket_path}: {e} — --trap-openat needs aisme-agentd running"))?;

    // 2. The grant, before the filter, because it can still fail. The
    //    supervisor reads the path argument of each trapped `openat` with
    //    `process_vm_readv`, which needs ptrace permission that Yama's default
    //    scope gives only to an ancestor — and the daemon is this session's
    //    sibling. Measured: without it every open was denied and `cat` reported
    //    "libc.so.6: Permission denied", fourteen times.
    let supervisor = platform::allow_supervision_by(socket.as_fd())?;

    // 3. The filter. From here the session is trapped whatever happens next,
    //    which is why nothing above may fail after it.
    let listener = platform::install_filter()?;

    // 4. The listener, to the daemon that will answer it. The method name comes
    //    from `aisme-proto` rather than a literal so the two cannot drift.
    let tty = std::fs::read_link("/proc/self/fd/0")
        .ok()
        .and_then(|p| p.to_str().map(ToOwned::to_owned))
        .filter(|p| p.starts_with("/dev/"));
    // `AISME_TERMINAL_ANSWER` is read **here**, once, before `exec`, and carried
    // to the daemon — never read by the adjudicator from its own environment,
    // which anything able to set a variable in the daemon could steer,
    // including the agent being adjudicated.
    let unattended = std::env::var("AISME_TERMINAL_ANSWER")
        .ok()
        .filter(|v| matches!(v.as_str(), "d" | "1" | "s" | "a"));

    let mut params = format!(
        r#""session_id":{}"#,
        // The codec has no unsigned integer, and a session id is an opaque
        // token: the daemon reads the same bits back.
        i64::from_ne_bytes(session_id.to_ne_bytes())
    );
    if let Some(tty) = &tty {
        let _ = write!(params, r#","tty":"{tty}""#);
    }
    if let Some(answer) = &unattended {
        let _ = write!(params, r#","unattended":"{answer}""#);
    }
    if !invocation.escalate.is_empty() {
        let list = invocation
            .escalate
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<String>>()
            .join(",");
        let _ = write!(params, r#","escalate":[{list}]"#);
    }
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{{params}}}}}"#,
        Method::RegisterSession.as_str()
    );
    // One message: the request and the descriptor it carries. Two would put a
    // filler byte in the daemon's stream ahead of the line.
    let mut request = line.into_bytes();
    request.push(b'\n');
    platform::send_listener(socket.as_fd(), listener.as_fd(), &request)?;

    // Read the answer. A registration the daemon refused must not be mistaken
    // for one it accepted: the filter is already installed, so proceeding would
    // exec a command whose every `openat` fails with ENOSYS — measured, before
    // this check existed, as `cat: libc.so.6: Error 38`.
    let mut reply = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(&socket), &mut reply)
        .map_err(|e| format!("registering the session: {e}"))?;
    if !reply.contains("\"accepted\"") {
        return Err(format!("the daemon refused the session: {}", reply.trim()));
    }
    eprintln!("aisme run: supervised by pid {supervisor}");
    // The daemon holds its own copy now; ours would keep the notification alive
    // after this process is replaced by the supervised command.
    drop(listener);
    Ok(())
}

/// Run the supervised command, replacing this process.
///
/// Returns only on failure: on success `exec` never comes back, which is the
/// point. The supervised command **is** this process from that moment, so its
/// pid, its terminal and its exit status are the ones the caller sees, and
/// nothing in the chain can be skipped by killing an intermediary.
pub fn run(args: &[String]) -> u8 {
    use std::os::unix::process::CommandExt as _;

    let invocation = match parse(args) {
        Ok(i) => i,
        Err(problem) => {
            eprintln!("{problem}");
            return 1;
        }
    };
    let id = session_id();
    let cgroup = match enter_session_cgroup(id) {
        Ok(dir) => dir,
        Err(problem) => {
            eprintln!("aisme run: {problem}");
            return 1;
        }
    };
    // Printed before `exec`, because `exec` has no after. What the session did
    // is `forensicd`'s to report.
    println!(
        "session {id:016x} · scope {} · cgroup {}",
        invocation.scopes[0].display(),
        cgroup.display()
    );
    if let Err(e) = pre_exec(&invocation, id) {
        eprintln!("aisme run: {e}");
        return 1;
    }
    let (program, rest) = invocation
        .command
        .split_first()
        .unwrap_or((&invocation.command[0], &[]));
    let error = std::process::Command::new(program).args(rest).exec();
    eprintln!("aisme run: cannot exec {program}: {error}");
    // 127 is the shell's convention for "command not found", and a caller that
    // scripts around us reads it the same way.
    127
}

#[cfg(test)]
// A panic is the failure report in a test; the command's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{parse, session_id, v2_path_of};
    use std::path::PathBuf;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn nothing_to_run_is_refused_rather_than_exec_ing_a_shell() {
        let problem = parse(&argv(&[])).unwrap_err();
        assert!(problem.contains("nothing to run"), "{problem}");
        let problem = parse(&argv(&["--"])).unwrap_err();
        assert!(problem.contains("nothing to run"), "{problem}");
    }

    #[test]
    fn a_scope_that_does_not_exist_is_refused_before_anything_is_created() {
        let problem = parse(&argv(&["--scope", "/nonexistent/aisme", "--", "true"])).unwrap_err();
        assert!(problem.contains("no such path"), "{problem}");
    }

    /// `--trap-openat` is opt-in, and its absence is the default state rather
    /// than a value nobody set.
    #[test]
    fn trapping_is_opt_in() {
        assert!(!parse(&argv(&["--", "true"])).unwrap().trap_openat);
        assert!(
            parse(&argv(&["--trap-openat", "--", "true"]))
                .unwrap()
                .trap_openat
        );
        // After the separator it belongs to the command, like every other flag.
        let i = parse(&argv(&["--", "sh", "--trap-openat"])).unwrap();
        assert!(!i.trap_openat);
        assert_eq!(i.command, argv(&["sh", "--trap-openat"]));
    }

    /// With no daemon reachable, the session is refused **before** the filter
    /// is installed.
    ///
    /// The order is the safety: a seccomp filter is irreversible and inherited
    /// across `exec`, so installing one and then finding nobody to answer its
    /// notifications would leave the supervised command with every `openat`
    /// failing `ENOSYS` — a session that cannot run, created by the guard meant
    /// to protect it. This test asserts the refusal names the socket, which is
    /// only true if the connect came first.
    #[test]
    fn trapping_without_a_daemon_refuses_before_installing_the_filter() {
        let invocation = parse(&argv(&["--trap-openat", "--", "true"])).unwrap();
        let problem = super::pre_exec(&invocation, 1).unwrap_err();
        assert!(problem.contains("aisme-agentd"), "{problem}");
        // And this process is still unfiltered: if the filter had gone in
        // first, the test binary would wear it for the rest of the run.
        assert!(
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .any(|l| l.starts_with("Seccomp:") && l.contains('0')),
            "the probing process was left filtered"
        );
    }

    #[test]
    fn the_command_is_everything_after_the_separator() {
        let i = parse(&argv(&["--scope", "/tmp", "--", "sh", "-c", "exit 3"])).unwrap();
        assert_eq!(i.scopes, vec![PathBuf::from("/tmp")]);
        assert_eq!(i.command, argv(&["sh", "-c", "exit 3"]));
        // A flag after `--` belongs to the command, not to us.
        let i = parse(&argv(&["--", "ls", "--scope"])).unwrap();
        assert_eq!(i.command, argv(&["ls", "--scope"]));
    }

    #[test]
    fn an_unknown_flag_is_named() {
        let problem = parse(&argv(&["--wat", "--", "true"])).unwrap_err();
        assert!(problem.contains("--wat"), "{problem}");
    }

    #[test]
    fn the_unified_hierarchy_line_is_the_one_read() {
        // A hybrid host lists v1 controllers too; only `0::` is v2.
        let hybrid =
            "12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice/user-1000.slice\n";
        assert_eq!(v2_path_of(hybrid), Some("/user.slice/user-1000.slice"));
        // A pure v1 host has no such line, and that is the honest answer.
        assert_eq!(v2_path_of("1:name=systemd:/user.slice\n"), None);
    }

    #[test]
    fn session_ids_differ() {
        assert_ne!(session_id(), session_id());
    }

    // The done-condition — this process's tree inside the session cgroup — is
    // NOT tested here, and the reason is worth writing down: `enter_session_cgroup`
    // moves *the calling process*, so a unit test would move the test harness
    // itself into a cgroup it then has to leave. The first version of this test
    // did exactly that and the run died with SIGKILL. It lives in
    // `tests/session.rs`, where the production binary is the process that moves.
}
