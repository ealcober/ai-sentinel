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
