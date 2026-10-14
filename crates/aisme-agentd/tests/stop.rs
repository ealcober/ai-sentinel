// SPDX-License-Identifier: Apache-2.0
//! `aisme-agentd --run` as a service: no `--ticks`, alive until a signal, and a
//! clean exit when one comes.
//!
//! The binary is the process under test. A unit test could set the stop flag
//! itself, but what a unit depends on is the **signal**: `systemctl stop` sends
//! `SIGTERM`, a terminal sends `SIGINT`, and only a real process receives
//! either.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A daemon this test started. It runs until a signal, so a test that fails
/// before sending one must not leave it running: drop kills and reaps it.
struct Service(Child);

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the daemon exactly as `deploy/systemd/aisme-agentd.service` does —
/// a WAL and nothing bounding it — and return once it says it is running.
fn service(tag: &str) -> (Service, BufReader<std::process::ChildStdout>) {
    let dir = std::env::temp_dir().join(format!("aisme-stop-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut child = Service(
        Command::new(env!("CARGO_BIN_EXE_aisme-agentd"))
            .arg("--run")
            .arg(&dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "the daemon exited before running"
        );
        if line.starts_with("run: wal") {
            assert!(line.contains("until SIGTERM or SIGINT"), "{line}");
            return (child, out);
        }
    }
}

/// Send `signal` and wait, bounded, for the exit. The rest of stdout is returned.
fn stop(mut child: Service, mut out: BufReader<std::process::ChildStdout>, signal: i32) -> String {
    let pid = libc::pid_t::try_from(child.0.id()).unwrap();
    // SAFETY: `kill(2)` on a pid this test spawned and has not yet reaped, so
    // the pid cannot have been reused.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() <= deadline,
            "the daemon did not stop within 5 s of the signal"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(status.success(), "exit {status:?}: {rest}");
    rest
}

/// 1 000 ticks is about 1.1 s, so a daemon still alive at 2 s is not on a
/// hidden bound — and `SIGTERM` then ends it cleanly,
/// with its accounting printed rather than cut off.
#[test]
fn without_ticks_the_daemon_runs_until_sigterm_and_exits_cleanly() {
    let (mut child, out) = service("term");
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the daemon exited on its own"
    );
    let rest = stop(child, out, libc::SIGTERM);
    assert!(rest.contains("run: stopped by signal after"), "{rest}");
    assert!(rest.contains("event(s) drained"), "{rest}");
}

/// Ctrl-C in the terminal the daemon was started from is the same clean stop.
#[test]
fn sigint_is_the_same_clean_stop() {
    let (child, out) = service("int");
    let rest = stop(child, out, libc::SIGINT);
    assert!(rest.contains("run: stopped by signal after"), "{rest}");
}
