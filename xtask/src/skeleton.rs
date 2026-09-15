// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask test-skeleton` — `F2.WS.10`: the whole slice on `MockSensor`,
//! with no kernel at all.
//!
//! **It orchestrates the shipped binaries; it does not rebuild the slice.** A
//! gate that wired its own engine, its own policy and its own adjudicator would
//! prove that the gate works. So the daemon composes itself as it always does —
//! `platform::sensors` returns the mock on a machine with nothing measured
//! (`I-12`) — and the only substitution is the end that would have touched the
//! kernel: a recorded trace replayed through the composition root's own
//! `MockSensor`, by `aisme-agentd --trace`.
//!
//! **What it deliberately does not assert**, because the plan gives each to
//! somebody else and a gate that claims another phase's property is a gate that
//! reports what it did not test:
//!
//! * *correlation precision and recall* — plan `:1866`, `F5`'s
//!   `test-correlation --harness ground-truth`. `F2.WS.03` exists so that
//!   scoring is **possible** from day one, not so that F2 scores it.
//! * *zero allocations in the hot loop* — `F1.RT.03`, measured by
//!   `bench-hotloop` with a counting allocator, and already asserted by
//!   `aisme-core`'s `hot_loop_allocations` test. Re-asserting it here with a
//!   different mechanism would be a second answer to the same question.
//! * *the tailer resuming with zero loss across a restart* — `aisme-forensicd`'s
//!   own `tail` test owns it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use aisme_core::policy::{compile, parse, Bindings};
use aisme_ebpf_common::{EventKind, FilePayload, RawEvent, Verdict};

use crate::SKIP;

/// The three paths the skeleton policy has an opinion about, and what it says.
///
/// Spelled here so the gate states its expectation **before** it measures, and
/// so a policy edit that silently changed a verdict fails a named assertion
/// rather than passing a vaguer one.
const EXPECTED: [(&str, Verdict); 3] = [
    ("/etc/shadow", Verdict::Deny),
    // **A resolved path, with no `~` in it.** The first version of this gate
    // asserted `~/.aws/credentials`, which the policy matched because the gate
    // handed it that exact string — and which no kernel ever produces, because
    // the tilde is expanded by the shell long before the syscall. The assertion
    // passed while the rule it tested could not fire on a real machine.
    ("/home/agent/.aws/credentials", Verdict::Escalate),
    ("/etc/hostname", Verdict::Allow),
];

/// `cargo xtask test-skeleton`.
pub(crate) fn run(args: &[&str]) -> u8 {
    for arg in args {
        if !arg.starts_with("--") {
            eprintln!("usage: cargo xtask test-skeleton");
            return 1;
        }
    }
    let mut bad = 0;

    let root = workspace_root();
    let (agentd, forensicd) = (
        binary(&root, "aisme-agentd"),
        binary(&root, "aisme-forensicd"),
    );
    for path in [&agentd, &forensicd] {
        if !path.exists() {
            println!(
                "SKIP test-skeleton — {} is not built; run `cargo build --workspace` first",
                path.display()
            );
            return SKIP;
        }
    }

    // Touch each binary once before the clock starts. **This is not a way of
    // getting a better number**: the first execution of a freshly linked binary
    // pays for the dynamic loader and for faulting its pages in, which is the
    // build's cost and not the slice's. Measured, once, and it is why this
    // exists: immediately after `cargo build` the same run took **5304 ms**
    // and 79 ms on every attempt after. A gate that fails the first time it is
    // run after a build and passes the second is a gate people learn to re-run.
    for path in [&agentd, &forensicd] {
        let _ = Command::new(path).output();
    }
    let started = Instant::now();

    // 1. The shipped policy, through the real compiler — the same two calls the
    //    loader and the daemon make. A gate that hand-built a `CompiledPolicy`
    //    would prove nothing about the pipeline it exists to prove.
    let policy_file = root.join("deploy/policy/skeleton.aisme");
    let Ok(source) = std::fs::read_to_string(&policy_file) else {
        eprintln!("FAIL: {} cannot be read", policy_file.display());
        return 1;
    };
    // `compile`, not `compile_with`: the skeleton declares no grants, and this
    // is the call `aisme-agentd --policy` makes — so what the gate compiles is
    // what the daemon compiles, not a near-miss of it.
    let compiled = match parse(&source)
        .map_err(|e| format!("{e:?}"))
        .and_then(|p| compile(&p, &Bindings::new()).map_err(|e| format!("{e:?}")))
    {
        Ok(compiled) => compiled,
        Err(why) => {
            eprintln!("FAIL: the shipped policy does not compile: {why}");
            return 1;
        }
    };
    println!("policy: {} rule(s) compiled", compiled.rules.len());

    // 2. Each of the three verdicts, from the same `evaluate` the supervisor
    //    calls.
    bad += wrong_verdicts(&compiled);

    // 3. The slice: a recorded trace of those three opens, through the daemon's
    //    own composition and into the real WAL.
    let Some((dir, trace_file)) = scratch_with_trace() else {
        return 1;
    };

    let run = Command::new(&agentd)
        .arg("--run")
        .arg(dir.join("wal"))
        .args(["--ticks", "50"])
        .arg("--policy")
        .arg(&policy_file)
        .arg("--trace")
        .arg(&trace_file)
        .output();
    let Ok(run) = run else {
        eprintln!("FAIL: {} could not be run", agentd.display());
        return 1;
    };
    let said = String::from_utf8_lossy(&run.stdout);
    if !run.status.success() {
        eprintln!(
            "FAIL: the daemon exited {:?}: {}",
            run.status.code(),
            String::from_utf8_lossy(&run.stderr).trim()
        );
        bad += 1;
    }
    // The daemon's own accounting, not the gate's: it says how many events it
    // drained, and three is the trace.
    if said.contains(&format!("trace: {} event(s)", EXPECTED.len())) {
        println!("  trace: {} event(s) replayed", EXPECTED.len());
    } else {
        eprintln!("FAIL: the daemon did not report replaying the trace: {said:?}");
        bad += 1;
    }

    // 4. The WAL, read back by `forensicd` — a second process, because
    //    "the record survives the writer" is a two-process property.
    match tailed(&forensicd, &dir.join("wal")) {
        Some(wrong) => bad += wrong,
        None => return 1,
    }

    let _ = std::fs::remove_dir_all(&dir);

    // 5. "In milliseconds", measured rather than claimed.
    let took = started.elapsed();
    println!("test-skeleton: {} ms", took.as_millis());
    if took > Duration::from_secs(1) {
        eprintln!(
            "FAIL: the slice took {} ms; the done-condition is milliseconds",
            took.as_millis()
        );
        bad += 1;
    }

    if bad == 0 {
        println!("PASS test-skeleton — the whole slice ran with no kernel");
        0
    } else {
        eprintln!("FAIL test-skeleton — {bad} assertion(s) failed");
        1
    }
}

/// A scratch directory holding a WAL and the recorded trace, or `None` when
/// neither could be created — which is the gate unable to ask, not an assertion
/// failing.
fn scratch_with_trace() -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("aisme-skeleton-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(dir.join("wal")) {
        eprintln!("FAIL: {}: {e}", dir.display());
        return None;
    }
    let trace_file = dir.join("trace.bin");
    if let Err(e) = write_trace(&trace_file) {
        eprintln!("FAIL: writing the trace: {e}");
        return None;
    }
    Some((dir, trace_file))
}

/// Every verdict the shipped policy gets wrong, counted and named.
///
/// The escalate case is the load-bearing one: it is a `path_glob`, and lowering
/// a policy to a prefix trie keeps only prefixes — so a route that carried the
/// lowered table instead of the compiled policy would pass the other two and
/// drop this rule silently.
fn wrong_verdicts(compiled: &aisme_core::policy::CompiledPolicy) -> usize {
    let mut wrong = 0;
    for (path, want) in EXPECTED {
        let got = aisme_core::policy::evaluate(
            compiled,
            &aisme_core::policy::EventFacts {
                path: Some(path),
                ..aisme_core::policy::EventFacts::default()
            },
        )
        .verdict;
        if got == want {
            println!("  verdict {path} = {got:?}");
        } else {
            eprintln!("FAIL: {path} evaluated to {got:?}, expected {want:?}");
            wrong += 1;
        }
    }
    wrong
}

/// Read the WAL back with `forensicd` and count what is missing or out of
/// order. `None` when the tailer could not be run at all, which is not an
/// assertion failing but the gate being unable to ask.
fn tailed(forensicd: &Path, wal: &Path) -> Option<usize> {
    let tail = Command::new(forensicd)
        .arg("--tail")
        .arg(wal)
        .arg("--once")
        .output()
        .ok()?;
    let lines = String::from_utf8_lossy(&tail.stdout);
    let mut wrong = 0;
    for (path, _) in EXPECTED {
        if lines.contains(path) {
            println!("  wal: {path}");
        } else {
            eprintln!("FAIL: {path} is not in the WAL the tailer read back");
            wrong += 1;
        }
    }
    if let Some(why) = out_of_order(&lines, EXPECTED.len()) {
        eprintln!("FAIL: {why}");
        wrong += 1;
    }
    Some(wrong)
}

/// The three opens, in the wire layout the kernel would have produced.
fn write_trace(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    for (seq, (asked, _)) in EXPECTED.iter().enumerate() {
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::FileOpen.into();
        event.seq = seq as u64;
        let mut payload = FilePayload {
            inode: seq as u64,
            dev: 1,
            size: 0,
            flags: 0,
            mode: 0,
            path_class: 0,
            pad0: 0,
            path_len: 0,
            path: [0; 200],
            reserved: [0; 20],
        };
        payload.path_len = u16::try_from(asked.len()).unwrap_or(0);
        payload.path[..asked.len()].copy_from_slice(asked.as_bytes());
        event.payload.file = payload;
        file.write_all(&event.to_bytes())?;
    }
    file.flush()
}

/// Whether the sequence numbers the tailer printed ascend without a gap.
///
/// A WAL that dropped an event and a WAL that reordered two are different
/// failures with the same symptom if only membership is checked, which is why
/// the three paths above are not the whole assertion.
///
/// **It counts what it found**, and that is not decoration: `seq=` is a format
/// this gate does not own, and a renderer that stopped printing it would leave
/// a loop with nothing to iterate and an assertion that passes by finding
/// nothing — an absence read as a value, in the check written to catch one.
fn out_of_order(lines: &str, expected: usize) -> Option<String> {
    let mut last: Option<u64> = None;
    let mut seen = 0;
    for seq in lines.lines().filter_map(sequence_of) {
        seen += 1;
        if let Some(previous) = last {
            if seq != previous + 1 {
                return Some(format!("seq jumped from {previous} to {seq}"));
            }
        }
        last = Some(seq);
    }
    if seen < expected {
        return Some(format!(
            "the tailer printed {seen} sequence number(s), expected {expected} — \
             nothing was checked for order"
        ));
    }
    None
}

/// The `seq=` field of one tailer line, when it has one.
fn sequence_of(line: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix("seq="))
        .and_then(|n| n.parse().ok())
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Where `cargo build` put a binary.
///
/// `CARGO_TARGET_DIR` is honoured because a developer who moved their target
/// directory has not moved the binaries somewhere this gate may not look.
fn binary(root: &Path, name: &str) -> PathBuf {
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let debug = target.join("debug").join(name);
    if debug.exists() {
        return debug;
    }
    target.join("release").join(name)
}
