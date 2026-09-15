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
            // **A name per call, not per process.** Every test in this binary
            // runs in the *same* process, so a probe named after the pid is one
            // name shared by every thread: measured, two tests probing at once
            // had the second fail with `EEXIST` and report that the host does
            // not delegate — and it skipped, in green, saying so. A check that
            // reads contention as absence is worse than no check, because the
            // suite keeps passing with four of its tests no longer running.
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let probe = dir.join(format!("aisme-probe-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir(&probe);
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
    daemon_with_policy(tag, None)
}

/// [`daemon`], holding a policy file.
///
/// The daemon **parses** it at startup and compiles it once per session
/// registration, because `${workspace}` and `${home}` are facts about a session
/// and there is none yet when the daemon starts (`F2.WS.11`).
fn daemon_with_policy(
    tag: &str,
    policy: Option<&std::path::Path>,
) -> Option<(std::process::Child, std::path::PathBuf)> {
    let dir = std::env::temp_dir().join(format!("aisme-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("wal")).ok()?;
    let socket = dir.join("sock");
    let mut command = Command::new(agentd()?);
    command
        .arg("--run")
        .arg(dir.join("wal"))
        .args(["--ticks", "2000000"])
        .arg("--serve-ipc")
        .arg(&socket);
    if let Some(policy) = policy {
        command.arg("--policy").arg(policy);
    }
    let child = command
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

/// The summary's three counts, as numbers.
///
/// Parsed for the same reason [`delivered`] is: the fields are counted words in
/// one line, and a substring check on them reports a busy session as an empty
/// one.
fn counts(summary: &str) -> (u64, u64, u64) {
    let of = |name: &str| {
        summary
            .split_whitespace()
            .zip(summary.split_whitespace().skip(1))
            .find(|(_, word)| word.trim_end_matches(',') == name)
            .and_then(|(n, _)| n.parse().ok())
            .unwrap_or(u64::MAX)
    };
    (of("delivered"), of("denied"), of("asked"))
}

/// **A known gap, with a test on it**: a supervised session can write the agent
/// configuration files its own host executes.
///
/// This test asserts the gap, not the fix. Measured on 2026-09-15: under
/// `aisme run --scope <ws>`, a session created `<ws>/.claude/settings.json`,
/// `<ws>/.vscode/tasks.json`, `<ws>/.mcp.json` and `<ws>/.git/config`. The
/// write scope is a **grant** — Landlock rules only grant, there is no deny
/// rule and no way to subtract a subtree from an allowed one — so a scope that
/// covers the workspace covers these.
///
/// It matters because the host executes them: hooks in a repository's settings
/// run on clone-and-run with no confirmation (CVE-2025-59536), an agent writing
/// one gets it executed unsandboxed (CVE-2026-48124, CVSS 8.5, task-file
/// variant unfixed), and CHAINDROP — a worm, in the wild, August 2026 — commits
/// one into victim repositories so that reopening the folder re-runs its
/// payload. `DT-14` detects this class; nothing denies it, and `F3.EN.11` is
/// the task that would.
///
/// A known gap with a test on it is a gap somebody closes; a known gap with
/// nothing on it survives three phases. The day this starts failing, whoever is
/// holding it should delete it and read `docs/14` point 4 for the three routes
/// and what each costs.
#[test]
fn a_session_can_still_write_the_agent_configuration_its_host_executes() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let dir = std::env::temp_dir().join(format!("aisme-agentcfg-{}", std::process::id()));
    let scope = dir.join("workspace");
    std::fs::create_dir_all(&scope).expect("the scope");

    let mut writable = Vec::new();
    for relative in [
        ".claude/settings.json",
        ".vscode/tasks.json",
        ".mcp.json",
        ".git/config",
    ] {
        let target = scope.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("the directory");
        }
        // Written by the supervised process itself, not by the test: what is
        // being measured is what the session's own confinement permits.
        let out = aisme()
            .env("LC_ALL", "C")
            .args(["run", "--scope"])
            .arg(&scope)
            .args(["--", "/bin/cp"])
            .arg("/etc/hostname")
            .arg(&target)
            .output()
            .expect("aisme run");
        release(&String::from_utf8_lossy(&out.stdout));
        if target.exists() {
            writable.push(relative);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        writable,
        [
            ".claude/settings.json",
            ".vscode/tasks.json",
            ".mcp.json",
            ".git/config"
        ],
        "one of these stopped being writable. That is the right direction — read \
         `docs/14` point 4, record which route was taken, and replace this test with \
         one that asserts the denial for a file that is **absent** as well as one that \
         is present (CVE-2026-25725 was a protection applied only to a file that \
         already existed)"
    );
}

/// **Enforcement does not move when the agent disables its own approvals.**
///
/// In the one supply-chain incident where AI agents were the attack
/// *instrument* rather than the target, the malware did not defeat the
/// permission system: it invoked the agents with their own permission-skipping
/// flags. The human gate was not bypassed, it was not present — 2,349
/// credentials from 1,079 systems.
///
/// AISME's verdicts never consult the agent, so this holds by construction.
/// **By construction is not the same as under test**: a later change that made
/// any verdict depend on something the session supplies would break it in
/// silence, and every other test here would still pass. `I-20`'s determinism
/// and `H-11`'s "no LLM in the decision path" are the same claim; this is the
/// executable form of it.
///
/// The variables set below are the *agent's*, never AISME's. AISME's own
/// unattended answer is set identically in both runs, because it is the
/// operator's control and varying it would make this a test of something else.
///
/// The `asked` count is asserted alongside the verdict, and that is the half
/// that matters: a session that skipped the prompt and was *allowed* looks
/// exactly like one that was never asked, and only this column tells them
/// apart.
#[test]
fn enforcement_does_not_move_when_the_agent_disables_its_own_approvals() {
    // The switches a compromised caller reaches for. They belong to the agents,
    // not to AISME, which is the point: none of them is an input to a verdict.
    const AGENT_FLAGS: [(&str, &str); 4] = [
        ("CLAUDE_CODE_DANGEROUSLY_SKIP_PERMISSIONS", "1"),
        ("DANGEROUSLY_SKIP_PERMISSIONS", "1"),
        ("AIDER_YES_ALWAYS", "1"),
        ("CI", "true"),
    ];

    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    // Not `aisme-flags-…`: `daemon_with_policy` builds its scratch directory
    // from the tag the same way and wipes it, which would delete the policy
    // file written here a moment before it is read.
    let dir = std::env::temp_dir().join(format!("aisme-flags-input-{}", std::process::id()));
    let scope = dir.join("workspace");
    std::fs::create_dir_all(&scope).expect("the scope");
    // Two rules bound to this session's own workspace, so the test needs
    // nothing of the machine it runs on — not a home directory, not /etc.
    let policy = dir.join("policy.aisme");
    std::fs::write(
        &policy,
        concat!(
            "[[rule]]\nid = \"deny-secret\"\ngroup = \"CREDENTIALS\"\n",
            "match = { path_under = \"${workspace}/secret\" }\nverdict = \"deny\"\n\n",
            "[[rule]]\nid = \"escalate-asked\"\ngroup = \"CREDENTIALS\"\n",
            "match = { path_under = \"${workspace}/asked\" }\nverdict = \"escalate\"\n",
        ),
    )
    .expect("the policy");
    for name in ["secret", "asked", "ordinary"] {
        std::fs::write(scope.join(name), b"x").expect("the file");
    }

    let Some((mut server, socket)) = daemon_with_policy("flags", Some(&policy)) else {
        eprintln!("SKIP: aisme-agentd could not be started");
        return;
    };

    let run = |name: &str, permissive: bool| {
        let mut command = aisme();
        command
            .env("AISME_AGENTD_SOCKET", &socket)
            .env("LC_ALL", "C")
            // The operator's own answer, identical in both runs.
            .env("AISME_TERMINAL_ANSWER", "d");
        if permissive {
            for (k, v) in AGENT_FLAGS {
                command.env(k, v);
            }
        }
        let out = command
            .args(["run", "--scope"])
            .arg(&scope)
            .args(["--trap-openat", "--", "/bin/cat"])
            .arg(scope.join(name))
            .output()
            .expect("aisme run");
        let stdout = String::from_utf8_lossy(&out.stdout);
        release(&stdout);
        let summary = stdout
            .lines()
            .find(|l| l.contains("ended:"))
            .unwrap_or_default()
            .to_owned();
        (counts(&summary), out.status.success(), summary)
    };

    for name in ["secret", "asked", "ordinary"] {
        let (plain, plain_ok, plain_summary) = run(name, false);
        let (loose, loose_ok, loose_summary) = run(name, true);
        assert_eq!(
            (plain, plain_ok),
            (loose, loose_ok),
            "the agent's own permission flags changed what AISME enforced for {name}:\n  \
             without: {plain_summary}\n  with:    {loose_summary}"
        );
    }

    // And the policy really did decide, or the comparison above compared two
    // runs of nothing.
    //
    // **The assertion is `asked` and the exit status, never the denial count.**
    // How many denials a run produces belongs to the environment: `cat` failing
    // walks its locale search path, and now that a missing file is answered
    // `ENOENT` rather than `EACCES` it walks all of it, exactly as it would
    // unsupervised. That is the point of answering truthfully, and it makes the
    // count a measurement of this machine.
    let ((_, _, asked), ok, summary) = run("secret", false);
    assert!(
        !ok && asked == 0,
        "the compiled deny did not fire, or it asked somebody: {summary}"
    );
    let ((_, _, asked), ok, summary) = run("asked", false);
    assert!(
        !ok && asked == 1,
        "the escalation did not reach an adjudicator, or its `deny` answer was not obeyed: \
         {summary}"
    );
    let ((_, _, asked), ok, summary) = run("ordinary", false);
    assert!(
        ok && asked == 0,
        "a file no rule names was not simply allowed: {summary}"
    );

    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A denial the filter does not trap wakes nobody**, which is §2.2.1's whole
/// argument for putting the write scope in the kernel (`F2.WS.11`).
///
/// The done-condition as originally written — *"a write outside the workspace
/// produces zero notification traffic"* — is **not measurable on a write-mode
/// `openat`**, and it took a measurement to see why: `seccomp_unotify` fires
/// **before** the LSM hook, so under `--trap-openat` such an open is trapped
/// by the filter and refused by `reproducible` long before Landlock is
/// consulted. Counting notifications there would count seccomp wearing
/// Landlock's name.
///
/// The property is real and it belongs to the operations the filter does not
/// trap: `unlink` is one. So the measurement is a **comparison**: the same
/// binary deleting a file inside the scope and outside it. One deletion happens
/// and the other does not, and the notification traffic is identical — the
/// enforcement that made the difference woke nobody.
///
/// `LC_ALL=C` is not decoration. Without it, `rm` failing loads locale
/// catalogues and probes for twenty-odd files that are not there, and each
/// `ENOENT` is a notification; measured, that noise was 22 denials and it is
/// the environment's, not the product's.
#[test]
fn a_denial_the_filter_does_not_trap_wakes_nobody() {
    if !delegation_available() {
        eprintln!("SKIP: this host does not delegate a cgroup subtree to us");
        return;
    }
    let Some((mut server, socket)) = daemon("unlink") else {
        eprintln!("SKIP: aisme-agentd could not be started");
        return;
    };

    let dir = std::env::temp_dir().join(format!("aisme-unlink-{}", std::process::id()));
    let scope = dir.join("workspace");
    std::fs::create_dir_all(&scope).expect("the scope");
    let outside = dir.join("outside.txt");
    let inside = scope.join("inside.txt");

    // Each run deletes its own file, so the two differ in one thing only:
    // whether the target lies within the session's declared scope.
    let mut traffic = Vec::new();
    for target in [&outside, &inside] {
        std::fs::write(target, b"x").expect("the victim");
        let out = aisme()
            .env("AISME_AGENTD_SOCKET", &socket)
            .env("LC_ALL", "C")
            .args(["run", "--scope"])
            .arg(&scope)
            .args(["--trap-openat", "--", "/bin/rm", "-f"])
            .arg(target)
            .output()
            .expect("aisme run");
        let stdout = String::from_utf8_lossy(&out.stdout);
        release(&stdout);
        let summary = stdout
            .lines()
            .find(|l| l.contains("ended:"))
            .unwrap_or_default()
            .to_owned();
        traffic.push((summary, target.exists()));
    }
    let _ = server.kill();
    let _ = server.wait();

    let (outside_summary, outside_survived) = &traffic[0];
    let (inside_summary, inside_survived) = &traffic[1];
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        *outside_survived,
        "a file outside the declared scope was deleted: {outside_summary}"
    );
    assert!(
        !*inside_survived,
        "a file inside the scope could not be deleted, so the scope is not a scope: {inside_summary}"
    );
    // The point of the test. If the write scope were enforced by waking the
    // supervisor, the refused run would carry a denial the permitted one does
    // not — and it carries nothing.
    assert_eq!(
        counts(outside_summary),
        counts(inside_summary),
        "the denied deletion raised notification traffic the permitted one did not, \
         so it was not denied in kernel:\n  outside: {outside_summary}\n  inside:  {inside_summary}"
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
