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
pub(crate) fn agentd_socket() -> String {
    std::env::var("AISME_AGENTD_SOCKET").unwrap_or_else(|_| "/run/aisme/agentd.sock".to_owned())
}

/// Register the session with `agentd`, and keep the connection.
///
/// **Every session registers, filtered or not**, and no descriptor travels on
/// the message. An unregistered session is one whose cgroup nothing will ever
/// release, and the seccomp listener now stays here: the process that answers a
/// held open must be able to read its path argument, and Yama grants that to an
/// **ancestor** — which is this process and never the daemon.
///
/// The connection is kept for the life of the session, because `decideOpen`
/// travels on it once per held open.
///
/// # Errors
///
/// Only for a session that asked to be trapped. One that did not is warned and
/// runs: refusing it would invent a new reason for `aisme run` to fail that it
/// never had, and the cost of no daemon there is a directory left behind.
/// One JSON string body, escaped.
///
/// A path is not a safe thing to interpolate: `--scope` is the operator's own
/// string, and a directory may legally contain a quote, a backslash or a
/// **newline** — and this protocol is one JSON object per line, so a newline
/// would not corrupt a field, it would split the frame and the daemon would
/// read the remainder as a second request.
fn json_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn register(
    invocation: &Invocation,
    session_id: u64,
    cgroup: &Path,
) -> Result<Option<std::os::unix::net::UnixStream>, String> {
    use std::fmt::Write as _;
    use std::io::Write as _;

    let socket_path = agentd_socket();
    let socket = match std::os::unix::net::UnixStream::connect(&socket_path) {
        Ok(socket) => socket,
        Err(e) if invocation.trap_openat => {
            return Err(format!(
                "{socket_path}: {e} — --trap-openat needs aisme-agentd running"
            ));
        }
        Err(e) => {
            eprintln!(
                "aisme run: {socket_path}: {e} — this session is unregistered; \
                 its cgroup will be left behind"
            );
            return Ok(None);
        }
    };

    let mut params = format!(
        r#""session_id":{}"#,
        // The codec has no unsigned integer, and a session id is an opaque
        // token: the daemon reads the same bits back.
        i64::from_ne_bytes(session_id.to_ne_bytes())
    );
    // `AISME_TERMINAL_ANSWER` is read **here**, once, before the command runs,
    // and carried to the daemon — never read by the adjudicator from its own
    // environment, which anything able to set a variable in the daemon could
    // steer, including the agent being adjudicated.
    if let Ok(answer) = std::env::var("AISME_TERMINAL_ANSWER") {
        if matches!(answer.as_str(), "d" | "1" | "s" | "a") {
            let _ = write!(params, r#","unattended":"{answer}""#);
        }
    }
    // What `${workspace}` resolves to in the operator's policy, which the
    // daemon compiles **per session**: two sessions under one daemon have
    // different workspaces, so a policy compiled once before either existed
    // would be a policy about neither. The value is the scope this session
    // declared, which the person launching the agent chose — never the agent.
    let _ = write!(
        params,
        r#","scope":"{}""#,
        json_string(&invocation.scopes[0].display().to_string())
    );
    if let Some(tty) = std::fs::read_link("/proc/self/fd/0")
        .ok()
        .and_then(|p| p.to_str().map(ToOwned::to_owned))
        .filter(|p| p.starts_with("/dev/"))
    {
        let _ = write!(params, r#","tty":"{}""#, json_string(&tty));
    }
    // The daemon releases this when the kernel says it is empty, and refuses
    // any path that is not a session cgroup under the unified hierarchy.
    let _ = write!(
        params,
        r#","cgroup":"{}""#,
        json_string(&cgroup.display().to_string())
    );
    let _ = write!(params, r#","trapping":{}"#, invocation.trap_openat);
    if !invocation.escalate.is_empty() {
        let list = invocation
            .escalate
            .iter()
            .map(|p| format!("\"{}\"", json_string(p)))
            .collect::<Vec<String>>()
            .join(",");
        let _ = write!(params, r#","escalate":[{list}]"#);
    }
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{{params}}}}}"#,
        Method::RegisterSession.as_str()
    );
    writeln!(&socket, "{line}").map_err(|e| format!("registering the session: {e}"))?;

    let mut reply = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(&socket), &mut reply)
        .map_err(|e| format!("registering the session: {e}"))?;
    if !reply.contains("\"accepted\"") {
        if invocation.trap_openat {
            return Err(format!("the daemon refused the session: {}", reply.trim()));
        }
        eprintln!(
            "aisme run: the daemon refused the registration: {} — \
             this session's cgroup will be left behind",
            reply.trim()
        );
        return Ok(None);
    }
    Ok(Some(socket))
}

/// Ask the daemon what the policy says about one held open.
///
/// **The daemon decides and this process enforces**, which is the split the
/// kernel forces: only an ancestor may read a held open's path without a
/// capability, and only the daemon holds the compiled policy, the adjudicator
/// and the WAL. A session that decided what governs it would be deciding
/// whether to be enforced.
///
/// A daemon that cannot be asked **denies**. That is the one place in this file
/// where failure is closed, and it is the right one: the session is filtered, so
/// there is a guard to honour, and an unanswerable question is not permission.
fn ask_daemon(
    socket: &std::os::unix::net::UnixStream,
    session_id: u64,
    path: &str,
    asked: &mut u64,
) -> bool {
    use std::io::Write as _;

    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{"session_id":{},"path":"{}"}}}}"#,
        Method::DecideOpen.as_str(),
        i64::from_ne_bytes(session_id.to_ne_bytes()),
        path.replace('\\', "\\\\").replace('"', "\\\"")
    );
    if writeln!(&*socket, "{line}").is_err() {
        return false;
    }
    let mut reply = String::new();
    if std::io::BufRead::read_line(&mut std::io::BufReader::new(socket), &mut reply).is_err() {
        return false;
    }
    // Deny is 3 on the wire (`aisme-ebpf-common`); anything else the daemon
    // answers is a permit. A reply this cannot parse is a denial, because a
    // verdict nobody could read is not a verdict that said yes.
    let Ok(value) = aisme_proto::json::parse(reply.trim()) else {
        return false;
    };
    let Some(result) = value.get("result") else {
        return false;
    };
    // Counted here because the verdict alone cannot say it: an escalation
    // answered *deny* and a compiled deny both arrive as `Deny`, and the
    // difference is the whole security argument.
    if matches!(
        result.get("asked"),
        Some(aisme_proto::json::Value::Bool(true))
    ) {
        *asked += 1;
    }
    result
        .get("verdict")
        .and_then(aisme_proto::json::Value::as_int)
        .is_some_and(|verdict| verdict != 3)
}

/// Run the supervised command as this process's **child**, and supervise it.
///
/// Returns the command's exit code, or never returns when the command died by
/// a signal — see `exit_like`.
///
/// **`aisme run` is the session's ancestor, and that is what makes supervision
/// possible at all.** There are two ways to observe a process tree on Linux:
/// own the tree, or hold a capability. Yama grants an ancestor the memory of
/// every descendant and grants a sibling only the process that named it, so a
/// daemon-side supervisor sees the first process of a session and nothing it
/// forks — and every real agent forks (`docs/11` point 1, `docs/12`).
pub fn run(args: &[String]) -> u8 {
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
    // Printed before the command starts. What the session did is `forensicd`'s
    // to report.
    println!(
        "session {id:016x} · scope {} · cgroup {}",
        invocation.scopes[0].display(),
        cgroup.display()
    );

    // The daemon first, before anything irreversible: a session that is
    // confined and filtered and then finds nobody to answer it is a session
    // that cannot run, created by the guard meant to protect it.
    let socket = match register(&invocation, id, &cgroup) {
        Ok(socket) => socket,
        Err(problem) => {
            eprintln!("aisme run: {problem}");
            return 1;
        }
    };

    let (program, rest) = invocation
        .command
        .split_first()
        .unwrap_or((&invocation.command[0], &[]));
    let supervised =
        match platform::spawn_supervised(program, rest, &invocation.scopes, invocation.trap_openat)
        {
            Ok(supervised) => supervised,
            Err((code, problem)) => {
                eprintln!("aisme run: {problem}");
                return code;
            }
        };
    match supervised.landlock_abi {
        Some(abi) => println!(
            "landlock: ABI {abi} — writes are denied outside {}",
            invocation
                .scopes
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<String>>()
                .join(", ")
        ),
        None => eprintln!(
            "landlock: unavailable on this kernel — writes outside the scope are not denied \
             in kernel (tier L2-)"
        ),
    }

    let mut child = supervised.child;
    if let (Some(listener), Some(socket)) = (supervised.listener, socket.as_ref()) {
        supervise(&listener, socket, id);
    }
    // The loop above returns when the last process under the filter is gone, so
    // this does not block for long. An unfiltered session waits here instead.
    match child.wait() {
        Ok(status) => platform::exit_like(status),
        Err(e) => {
            eprintln!("aisme run: waiting for the command: {e}");
            1
        }
    }
}

/// Answer this session's held opens until its last process is gone.
fn supervise(listener: &std::os::fd::OwnedFd, socket: &std::os::unix::net::UnixStream, id: u64) {
    use std::os::fd::AsFd as _;

    let (mut delivered, mut denied, mut asked) = (0u64, 0u64, 0u64);
    let result = platform::serve_notifications(
        listener.as_fd(),
        |path| ask_daemon(socket, id, path, &mut asked),
        |pid, ok, why| {
            if ok {
                delivered += 1;
            } else {
                denied += 1;
                // One line per denial with its reason: "unsupported" tells an
                // operator nothing they can act on.
                eprintln!(
                    "session {id:016x}: denied an openat from pid {pid}: {}",
                    why.unwrap_or("no reason recorded")
                );
            }
        },
    );
    if let Err(problem) = result {
        eprintln!("session {id:016x}: the notification loop stopped: {problem}");
    }
    println!("session {id:016x} ended: {delivered} delivered, {denied} denied, {asked} asked");
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

    /// With no daemon reachable, a trapping session is refused **before**
    /// anything irreversible happens.
    ///
    /// The order is the safety: the seccomp filter and the Landlock ruleset are
    /// both irreversible, so confining a child and then finding nobody to
    /// answer its notifications would leave the supervised command with every
    /// `openat` failing `ENOSYS` — a session that cannot run, created by the
    /// guard meant to protect it. This test asserts the refusal names the
    /// socket, which is only true if the registration came first.
    ///
    /// It also asserts that **this process** is untouched, and that half is not
    /// decoration: the confinement now happens in a forked child, and a version
    /// that applied it here would confine the **test harness** for the rest of
    /// the run, failing later tests in whatever order the runner chose.
    #[test]
    fn trapping_without_a_daemon_refuses_before_confining_anything() {
        let invocation = parse(&argv(&["--trap-openat", "--", "true"])).unwrap();
        let problem = super::register(
            &invocation,
            1,
            std::path::Path::new("/sys/fs/cgroup/aisme-0123456789abcdef"),
        )
        .unwrap_err();
        assert!(problem.contains("aisme-agentd"), "{problem}");
        assert!(
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .any(|l| l.starts_with("Seccomp:") && l.contains('0')),
            "the probing process was left filtered"
        );
    }

    /// A session that asked for no trap is **warned** and runs, rather than
    /// refused, when no daemon answers.
    ///
    /// Refusing it would invent a new reason for `aisme run` to fail that it
    /// never had: that session asked for no supervision, and the cost of no
    /// daemon there is a directory left behind rather than a guard bypassed.
    #[test]
    fn an_untrapped_session_without_a_daemon_is_warned_and_not_refused() {
        let invocation = parse(&argv(&["--", "true"])).unwrap();
        let answer = super::register(
            &invocation,
            1,
            std::path::Path::new("/sys/fs/cgroup/aisme-0123456789abcdef"),
        );
        assert!(
            matches!(answer, Ok(None)),
            "an unsupervised session must still run"
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
