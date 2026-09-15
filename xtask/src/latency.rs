// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask bench-t0` — `F2.WS.09`: what the tiers that exist at this shape
//! actually cost.
//!
//! **The name is Annex H's and the command refuses to let it mislead.** At F2
//! there is no in-kernel decision: the sensor is a tracepoint and enforcement is
//! seccomp plus Landlock, so **no T0 is measured here** and the output says so
//! in its own words before it prints a single figure. A gate whose output can be
//! pasted into a report must not let a reader infer a number that does not
//! exist.
//!
//! Every figure carries its sample count, because a p999 over a hundred samples
//! is not a p999 — it is the maximum wearing a percentile's name. Percentiles
//! and never means: §2.22 states p99 and p95, and a mean hides exactly the tail
//! these budgets exist to bound.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use crate::SKIP;

/// What is and is not measured, before any figure.
///
/// **`docs/05` point 9 wrote this sentence as "no decision is taken in kernel",
/// and that is wrong by `budgets.toml`'s own words**: *"T0 exists at both
/// enforcement tiers but through different primitives … L3 is BPF-LSM; **L2 is
/// Landlock (files)** + cgroup connect hooks"*. A Landlock deny **is** an
/// in-kernel decision, so F2 measures T0 at L2 and only L3's T0 is absent.
/// Printing the original sentence would have hidden a figure the project has a
/// budget for behind a disclaimer.
const NO_T0: &str = "T0 at L3 is not measured at this shape: the L3 layer is BPF-LSM and F2 has \
                     none, so F3 measures it. T0 at **L2** is measured below — budgets.toml \
                     defines it as the in-kernel deny, which at this tier is Landlock.";

/// And the second absence, which is different and must not be merged with it.
const NO_T_TEL: &str = "T-tel is not measured on a host: it times a tracepoint's event reaching \
                        the hot loop, and that needs a loaded BPF program, which `I-12` keeps \
                        off a developer's machine. It is measured by `vm run --with-dist`.";

/// One leg of the measurement: what it is, and what it cost.
struct Leg {
    /// The budget key this leg answers to, when it has one.
    key: Option<&'static str>,
    /// What the figure means, in the words a report needs.
    label: String,
    /// The percentile line the probe printed.
    line: String,
    /// The p99, in microseconds.
    p99_us: f64,
}

/// `cargo xtask bench-t0 [--syscalls N]`.
pub(crate) fn run(args: &[&str]) -> u8 {
    let mut syscalls: u32 = 10_000;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--syscalls" => {
                let Some(raw) = it.next() else {
                    eprintln!("--syscalls needs a value");
                    return 1;
                };
                match raw.parse() {
                    Ok(n) if n > 0 => syscalls = n,
                    _ => {
                        eprintln!("--syscalls {raw} is not a positive number");
                        return 1;
                    }
                }
            }
            other => {
                eprintln!("usage: cargo xtask bench-t0 [--syscalls N]  (unknown: {other})");
                return 1;
            }
        }
    }

    println!("{NO_T0}");
    println!("{NO_T_TEL}");
    println!();

    let root = workspace_root();
    let sim = binary(&root, "aisme-agentsim");
    let aisme = binary(&root, "aisme");
    let agentd = binary(&root, "aisme-agentd");
    for path in [&sim, &aisme, &agentd] {
        if !path.exists() {
            println!(
                "SKIP bench-t0 — {} is not built; run `cargo build --workspace` first",
                path.display()
            );
            return SKIP;
        }
    }

    let dir = std::env::temp_dir().join(format!("aisme-bench-t0-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(dir.join("wal")).is_err()
        || std::fs::create_dir(dir.join("ws")).is_err()
    {
        eprintln!("FAIL: {} cannot be created", dir.display());
        return 1;
    }

    let mut legs = Vec::new();

    // 1. The baseline: the same probe with nothing supervising it. Without this
    //    every figure below is a duration with nothing to compare it to.
    let Some(baseline) = probe(&sim, &[], "/etc/hostname", syscalls, false, &[]) else {
        eprintln!("FAIL: the unsupervised baseline did not run");
        return 1;
    };
    legs.push(Leg {
        key: Some("latency.skeleton_baseline_open_p99_us"),
        label: "one openat, unsupervised — the floor every figure below stands on".to_owned(),
        p99_us: baseline.1,
        line: baseline.0,
    });

    // The daemon, for the two supervised legs.
    let socket = dir.join("sock");
    let Some(mut daemon) = start_daemon(&agentd, &dir, &socket) else {
        eprintln!("FAIL: aisme-agentd did not start");
        return 1;
    };
    supervised_legs(&sim, &aisme, &socket, syscalls, &mut legs);
    let _ = daemon.kill();
    let _ = daemon.wait();
    landlock_leg(&sim, &aisme, &dir, syscalls, &mut legs);

    for leg in &legs {
        println!("  {}", leg.label);
        println!("    {}", leg.line);
    }

    let artefact = write_artefact(&legs);
    match artefact {
        Ok(path) => println!("\nwrote {}", path.display()),
        Err(e) => {
            eprintln!("FAIL: the artefact could not be written: {e}");
            return 1;
        }
    }
    if legs.len() < 3 {
        eprintln!("FAIL bench-t0 — {} of 4 legs measured", legs.len());
        return 1;
    }
    println!(
        "PASS bench-t0 — {} leg(s) measured; T0 at L3 and T-tel named as absent, not as zero",
        legs.len()
    );
    0
}

/// The two legs that need a daemon: T1, and the T2 path with a scripted answer.
fn supervised_legs(sim: &Path, aisme: &Path, socket: &Path, syscalls: u32, legs: &mut Vec<Leg>) {
    // T1 — the escalate-class notification answered by the supervisor, with
    //    no human in it. The path is allowed by the skeleton policy, so the
    //    answer is a descriptor the supervisor opened: the full held-syscall
    //    round trip, which is what T1 names.
    let supervised = probe(
        sim,
        &[
            aisme.to_string_lossy().as_ref(),
            "run",
            "--trap-openat",
            "--",
        ],
        "/etc/hostname",
        syscalls,
        false,
        &[("AISME_AGENTD_SOCKET", socket.to_string_lossy().as_ref())],
    );
    match supervised {
        Some((line, p99_us)) => legs.push(Leg {
            key: Some("latency.t1_p99_us"),
            label: "T1 — openat held, supervisor answered with a validated descriptor, no human"
                .to_owned(),
            line,
            p99_us,
        }),
        None => eprintln!("FAIL: the supervised leg did not run"),
    }

    // T2 with a **scripted** answer. The human's own thinking time is not in
    //    this figure and must never be read as if it were: what it measures is
    //    everything around the answer — the notification reaching the
    //    adjudicator, the verdict returning, the syscall resuming. The budget
    //    `latency.t2_p95_ms` is about a person, so this leg deliberately does
    //    not claim that key.
    let asked = syscalls.min(2_000);
    let escalated = probe(
        sim,
        &[
            aisme.to_string_lossy().as_ref(),
            "run",
            "--trap-openat",
            "--escalate",
            "/etc/hostname",
            "--",
        ],
        "/etc/hostname",
        asked,
        false,
        &[
            ("AISME_AGENTD_SOCKET", socket.to_string_lossy().as_ref()),
            ("AISME_TERMINAL_ANSWER", "1"),
        ],
    );
    match escalated {
        Some((line, p99_us)) => legs.push(Leg {
            key: Some("latency.skeleton_t2_scripted_p99_us"),
            label: format!(
                "T2 path with a scripted answer over {asked} opens — the adjudicator round trip, \
                 and **not** a human's time"
            ),
            line,
            p99_us,
        }),
        None => eprintln!("FAIL: the escalated leg did not run"),
    }
}

/// The Landlock leg, which needs no daemon at all — which is the point of it.
fn landlock_leg(sim: &Path, aisme: &Path, dir: &Path, syscalls: u32, legs: &mut Vec<Leg>) {
    // 4. The Landlock deny cost, as two figures rather than one difference. A
    //    denied write and a successful write are different operations, so
    //    subtracting them would report a number that is partly the cost of
    //    denial and partly the cost of not having written anything.
    let outside = std::env::temp_dir().join(format!("aisme-bench-outside-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&outside);
    let target = outside.join("probe");
    let denied = probe(
        sim,
        &[
            aisme.to_string_lossy().as_ref(),
            "run",
            "--scope",
            dir.join("ws").to_string_lossy().as_ref(),
            "--",
        ],
        target.to_string_lossy().as_ref(),
        syscalls.min(20_000),
        true,
        &[],
    );
    match denied {
        Some((line, p99_us)) if line.contains("ok=0") => legs.push(Leg {
            // `t0_l2_p99_us`, the key budgets.toml describes as the in-kernel
            // deny at L2 — which is this, and not something F3 will measure.
            key: Some("latency.t0_l2_p99_us"),
            label: "T0 at L2 — a write outside the scope, denied in kernel by Landlock, \
                    with no supervisor woken"
                .to_owned(),
            line,
            p99_us,
        }),
        Some((line, _)) => {
            // Not a slow figure: a wrong one. If the writes succeeded, the
            // ruleset did not apply and the number below would be the cost of
            // writing rather than of being denied.
            eprintln!("FAIL: the Landlock leg was not denied — the ruleset did not apply: {line}");
        }
        None => println!(
            "  landlock: absent on this kernel (tier L2-) — the deny cost is **not measured**, \
             which is not the same as zero"
        ),
    }
    let _ = std::fs::remove_dir_all(&outside);
    let _ = std::fs::remove_dir_all(dir);
}

/// Run the probe, optionally under a wrapper, and return its line and p99.
fn probe(
    sim: &Path,
    wrapper: &[&str],
    path: &str,
    count: u32,
    create: bool,
    env: &[(&str, &str)],
) -> Option<(String, f64)> {
    let mut cmd = if let Some((program, rest)) = wrapper.split_first() {
        let mut cmd = Command::new(program);
        cmd.args(rest);
        cmd.arg(sim);
        cmd
    } else {
        Command::new(sim)
    };
    cmd.arg("--open-bench")
        .arg(path)
        .args(["--count", &count.to_string()]);
    if create {
        cmd.arg("--create");
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.starts_with("open-bench "))?
        .to_owned();
    let p99 = field(&line, "p99_us=")?;
    Some((line, p99))
}

/// One `key=value` field of the probe's line, as a number.
fn field(line: &str, key: &str) -> Option<f64> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(key))
        .and_then(|v| v.parse().ok())
}

/// Start the daemon with the shipped policy, and wait until its socket answers.
///
/// It waits for the **socket**, not for a duration: a sleep long enough on this
/// machine is a flake on a slower one, and a run that started measuring before
/// the daemon was listening would time a connection refusal.
fn start_daemon(agentd: &Path, dir: &Path, socket: &Path) -> Option<Child> {
    let child = Command::new(agentd)
        .arg("--run")
        .arg(dir.join("wal"))
        .args(["--ticks", "2000000"])
        .arg("--serve-ipc")
        .arg(socket)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return Some(child);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
}

/// Write what was measured where `verify-budgets` reads it.
///
/// A measurement is a **file a run produced**, never a number in a source file,
/// which is what keeps "measured" from drifting into "assumed" — the shape
/// `F1.RT.06` established with `idle.toml`.
fn write_artefact(legs: &[Leg]) -> std::io::Result<PathBuf> {
    let dir = Path::new("target/budget");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("skeleton-latency.toml");
    let mut text = String::from(
        "# Written by `cargo xtask bench-t0` (F2.WS.09). Read by `cargo xtask verify-budgets`.\n\
         #\n\
         # T0 is absent on purpose: at F2 no decision is taken in kernel. So is T-tel,\n\
         # which needs a loaded BPF program and therefore a VM (I-12). An absent key is\n\
         # not a zero, and verify-budgets reports a missing artefact as skipped.\n",
    );
    for leg in legs {
        if let Some(key) = leg.key {
            let _ = writeln!(text, "\"{key}\" = {:.3}", leg.p99_us);
        }
    }
    std::fs::write(&path, text)?;
    Ok(path)
}

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Where `cargo build` put a binary.
fn binary(root: &Path, name: &str) -> PathBuf {
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let debug = target.join("debug").join(name);
    if debug.exists() {
        return debug;
    }
    target.join("release").join(name)
}
