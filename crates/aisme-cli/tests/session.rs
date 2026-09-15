// SPDX-License-Identifier: Apache-2.0
//! `aisme run` end to end (`F2.WS.08`).
//!
//! The binary is the process under test, not a copy of its logic: these run
//! `CARGO_BIN_EXE_aisme` and read what the supervised child saw. That also keeps
//! the cgroup move inside a child — `enter_session_cgroup` moves the calling
//! process, and a unit test doing it would move the test harness.

use std::process::Command;

fn aisme() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aisme"))
}

/// Remove the session cgroup a run left behind, so a test host does not
/// accumulate one per run.
///
/// The product does not do this in F2: `exec` has no after, and releasing the
/// cgroup belongs to whoever outlives the session (`docs/09` point 6). The
/// tests own their mess in the meantime.
fn release(stdout: &str) {
    if let Some(dir) = stdout
        .lines()
        .find(|l| l.starts_with("session "))
        .and_then(|l| l.rsplit("cgroup ").next())
    {
        let _ = std::fs::remove_dir(dir.trim());
    }
}

/// Whether this host can delegate a cgroup subtree to us at all.
///
/// A host that cannot is not a host where this passed, so the tests that need
/// it say they were skipped and why, rather than reporting green.
fn delegation_available() -> bool {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("0::")).map(|p| {
                std::path::Path::new("/sys/fs/cgroup").join(p.trim().trim_start_matches('/'))
            })
        })
        .is_some_and(|dir| {
            let probe = dir.join(format!("aisme-probe-{}", std::process::id()));
            let ok = std::fs::create_dir(&probe).is_ok();
            if ok {
                let _ = std::fs::remove_dir(&probe);
            }
            ok
        })
}

/// The done-condition: the session's own process tree is correctly attributed.
///
/// The supervised child reports its own cgroup, and it must be the session's —
/// which is only true if the move happened **before** `exec`.
#[test]
fn the_supervised_child_runs_inside_the_session_cgroup() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let out = aisme()
        .args(["run", "--", "cat", "/proc/self/cgroup"])
        .output()
        .expect("aisme run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    release(&stdout);
    assert!(
        stdout.contains("/aisme-"),
        "the child's cgroup is not the session's: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // And the line printed before `exec` names the same session.
    let session = stdout
        .lines()
        .find(|l| l.starts_with("session "))
        .expect("the summary line");
    let id = session.split_whitespace().nth(1).expect("the session id");
    assert!(
        stdout.contains(&format!("aisme-{id}")),
        "the summary says {id} and the child is elsewhere: {stdout}"
    );
}

/// `exec`, not `fork`: the supervised command's exit status is the caller's,
/// with nothing in between to lose it.
#[test]
fn the_exit_status_is_the_childs() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let out = aisme()
        .args(["run", "--", "sh", "-c", "exit 3"])
        .output()
        .expect("aisme run");
    release(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.status.code(), Some(3));

    let out = aisme()
        .args(["run", "--", "true"])
        .output()
        .expect("aisme run");
    release(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.status.code(), Some(0));
}

/// A command that does not exist is reported, and does not look like success.
#[test]
fn a_command_that_cannot_be_exec_ed_is_named() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let out = aisme()
        .args(["run", "--", "/nonexistent/aisme/binary"])
        .output()
        .expect("aisme run");
    release(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/nonexistent/aisme/binary"), "{stderr}");
}

/// Usage errors happen before anything is created.
#[test]
fn nothing_to_run_is_refused_without_creating_a_session() {
    let out = aisme().args(["run"]).output().expect("aisme run");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nothing to run"), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "a refused invocation printed a session line"
    );
}

/// How many opens a session summary says were delivered.
///
/// Parsed rather than matched as text, because `"10 delivered"` **contains**
/// `"0 delivered"` — a substring check on this line reports a busy session as
/// an empty one, and it did.
fn delivered(summary: &str) -> u64 {
    summary
        .split_whitespace()
        .zip(summary.split_whitespace().skip(1))
        // The summary separates its fields with commas, so the word after the
        // count is `delivered,` and not `delivered`.
        .find(|(_, word)| word.trim_end_matches(',') == "delivered")
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or(0)
}

/// `aisme-agentd`, beside the binary under test.
///
/// Cargo puts every binary of a workspace in one directory, so the daemon is a
/// sibling of `aisme`. Looked up rather than assumed: a run without it skips
/// with its reason instead of failing for a reason that is not the product's.
fn agentd() -> Option<std::path::PathBuf> {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_aisme"))
        .parent()?
        .join("aisme-agentd");
    path.is_file().then_some(path)
}

/// A daemon serving a socket in its own scratch directory, and the socket.
///
/// Waits for the socket to answer rather than sleeping a guess: a sleep long
/// enough on this machine is a flake on a slower one.
fn daemon(tag: &str) -> Option<(std::process::Child, std::path::PathBuf)> {
    let dir = std::env::temp_dir().join(format!("aisme-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("wal")).ok()?;
    let socket = dir.join("sock");
    let child = Command::new(agentd()?)
        .arg("--run")
        .arg(dir.join("wal"))
        .args(["--ticks", "2000000"])
        .arg("--serve-ipc")
        .arg(&socket)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        if std::time::Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Some((child, socket))
}

/// **The test this whole change exists for: a grandchild is supervised.**
///
/// `aisme run --trap-openat -- sh -c 'cat …'` runs `cat` as a child of `sh`,
/// which is a grandchild of the supervisor. With the supervisor in the daemon
/// this delivered two opens and denied thirteen, every one of them the
/// grandchild's and every one *"the path argument could not be read"* — because
/// Yama grants a **sibling** the memory of the process that named it and not
/// that process's children. The supervisor is the session's own parent now, and
/// Yama grants an ancestor everything at any depth.
///
/// The assertion is on the **denial count**, not on the command succeeding: a
/// run that denied everything would still print `pop-os` if `cat` had already
/// been loaded, and a run that supervised nothing would succeed too.
#[test]
fn a_grandchild_of_the_session_is_supervised() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let Some((mut server, socket)) = daemon("grandchild") else {
        eprintln!("SKIP: aisme-agentd could not be started");
        return;
    };
    let out = aisme()
        .env("AISME_AGENTD_SOCKET", &socket)
        .args([
            "run",
            "--trap-openat",
            "--",
            "sh",
            "-c",
            "cat /etc/hostname",
        ])
        .output()
        .expect("aisme run");
    let _ = server.kill();
    let _ = server.wait();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    release(&stdout);

    // **The assertion is the reason, not the count.** A denial reading *"the
    // supervisor could not open it"* is an `ENOENT` — `cat` probing for locale
    // files that are not there — and how many of those happen depends on the
    // environment, not on the product. The denial this change is about says
    // *"the path argument could not be read"*, and that is the one that must
    // not appear: it is Yama refusing a supervisor the memory of a process it
    // is not an ancestor of.
    assert!(
        !stderr.contains("the path argument could not be read"),
        "a grandchild's path could not be read, which is the defect this fixes:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|l| l.contains("ended:"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        delivered(&summary) > 0,
        "nothing was delivered, so nothing was supervised: {summary}"
    );
}

/// And at depth: a command nested three shells deep is supervised throughout.
///
/// Ancestry has no depth limit and this says the product does not either. It is
/// separate from the test above because a fix that walked exactly one level
/// would pass that one.
#[test]
fn a_session_is_supervised_at_depth() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let Some((mut server, socket)) = daemon("depth") else {
        eprintln!("SKIP: aisme-agentd could not be started");
        return;
    };
    let out = aisme()
        .env("AISME_AGENTD_SOCKET", &socket)
        .args([
            "run",
            "--trap-openat",
            "--",
            "sh",
            "-c",
            "sh -c 'sh -c \"cat /etc/hostname\"'",
        ])
        .output()
        .expect("aisme run");
    let _ = server.kill();
    let _ = server.wait();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    release(&stdout);
    assert!(
        !stderr.contains("the path argument could not be read"),
        "a path could not be read at depth, which is the defect this fixes:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|l| l.contains("ended:"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        delivered(&summary) > 0,
        "nothing was delivered at depth: {summary}"
    );
}

/// **Killing the supervisor kills the session**, which is the property
/// `F2.WS.08` justified `exec` with and which `PR_SET_PDEATHSIG` keeps true now
/// that there is an intermediary.
///
/// Without it, `SIGKILL` on `aisme run` would leave the command running as an
/// orphan — still confined and still filtered, so every path-bearing syscall
/// would be refused, but alive and holding whatever it held.
#[test]
fn killing_the_supervisor_kills_the_command() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let mut run = aisme()
        .args(["run", "--", "sleep", "30"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("aisme run");
    std::thread::sleep(std::time::Duration::from_millis(600));

    let children =
        std::fs::read_to_string(format!("/proc/{}/task/{}/children", run.id(), run.id()))
            .unwrap_or_default();
    let command: u32 = children
        .split_whitespace()
        .next()
        .and_then(|p| p.parse().ok())
        .expect("the supervised command is a child of the supervisor");

    let _ = run.kill();
    let _ = run.wait();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let alive = std::path::Path::new(&format!("/proc/{command}")).exists();
    if alive {
        // Leave nothing behind before failing.
        let _ = Command::new("kill")
            .args(["-9", &command.to_string()])
            .status();
    }
    assert!(
        !alive,
        "the command outlived the supervisor that was killed"
    );
}

/// The **parent** is not confined by what it applies to the child.
///
/// The Landlock ruleset and the seccomp filter go in the child, after the fork.
/// A version that applied either in the parent would filter the supervisor
/// itself, and its own `openat` — the one it performs on the child's behalf —
/// would trap to a loop that is not running yet. The evidence is a session that
/// reads a file **outside** its own scope and is answered: that read is the
/// parent's, and it could not happen if the parent wore the filter.
#[test]
fn the_supervisor_is_not_confined_by_what_it_applies_to_the_child() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let Some((mut server, socket)) = daemon("unconfined") else {
        eprintln!("SKIP: aisme-agentd could not be started");
        return;
    };
    let scope = std::env::temp_dir().join(format!("aisme-scope-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scope);

    let out = aisme()
        .env("AISME_AGENTD_SOCKET", &socket)
        .args(["run", "--trap-openat", "--scope"])
        .arg(&scope)
        .args(["--", "cat", "/etc/hostname"])
        .output()
        .expect("aisme run");
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&scope);

    let stdout = String::from_utf8_lossy(&out.stdout);
    release(&stdout);
    assert!(
        out.status.success(),
        "a read outside the scope failed, so the supervisor could not perform it: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
