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
    const USAGE: &str = "usage: aisme run [--scope <path>…] -- <command> [args…]";
    let mut scopes = Vec::new();
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
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if command.is_empty() {
        return Err(format!("nothing to run\n{USAGE}"));
    }
    if scopes.is_empty() {
        scopes.push(std::env::current_dir().map_err(|e| format!("no working directory: {e}"))?);
    }
    Ok(Invocation { scopes, command })
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

/// Everything that must happen between the cgroup and `exec`.
///
/// **Empty in F2, and deliberately named.** `F2.WS.05` installs the seccomp
/// filter here and `F2.WS.11` the Landlock ruleset; both must run after the
/// cgroup exists and before `exec`, because a filter installed later has a
/// window and a ruleset installed later is not inherited. The hook exists now so
/// neither task has to invent it.
//
// `expect`, not `allow`: the day an occupant makes this fallible for real, the
// lint stops firing and clippy demands this attribute be removed — so the
// annotation cannot outlive its reason.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the seam is fallible for its occupants, F2.WS.05 and F2.WS.11, not for F2"
)]
fn pre_exec() -> std::io::Result<()> {
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
    if let Err(e) = pre_exec() {
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
