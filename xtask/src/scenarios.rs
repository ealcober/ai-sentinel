// SPDX-License-Identifier: Apache-2.0
//! Scenario runners: `test-taint` (`F1.ON.05`), `test-policy-compiler`
//! (`F1.PL.05`).
//!
//! A scenario is a named integration test in the crate that owns the logic;
//! the command selects it and reports in the gate's vocabulary. `--mock`
//! drives the scenario through the algebra with no sensor and no kernel — the
//! only mode F1 has. Without `--mock` the kernel-backed run is asked for, and
//! that is F3's (`F3.PT.*` sensors inside a VM, `I-12`): exit 2, named.

use std::process::Command;

use crate::SKIP;

/// `cargo xtask test-taint [--scenario <name>] [--mock]`.
pub(crate) fn test_taint(args: &[&str]) -> u8 {
    let mut scenario: Option<&str> = None;
    let mut mock = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--scenario" => scenario = it.next().copied(),
            "--mock" => mock = true,
            other => {
                eprintln!(
                    "usage: cargo xtask test-taint [--scenario <name>] --mock  (unknown: {other})"
                );
                return 1;
            }
        }
    }
    if !mock {
        println!("SKIP test-taint — only --mock exists in F1; the kernel-backed run is F3's, inside a VM (I-12)");
        return SKIP;
    }
    // Scenario names are spelled as in the plan (`rf-09`); test names cannot
    // carry a hyphen, so the filter is the same name with underscores.
    let filter = scenario.map(|s| s.replace('-', "_"));
    let mut cmd = Command::new("cargo");
    cmd.args([
        "test",
        "-q",
        "-p",
        "aisme-core",
        "--test",
        "taint_scenarios",
        "--",
    ]);
    if let Some(filter) = &filter {
        cmd.arg(filter);
    }
    let Ok(output) = cmd.output() else {
        eprintln!("skip: could not run cargo");
        return SKIP;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let ran = text
        .lines()
        .find_map(|l| l.strip_prefix("test result: "))
        .unwrap_or("no test result line");
    let label = scenario.unwrap_or("all scenarios");
    if output.status.success() && !ran.contains("0 passed") {
        println!("PASS test-taint {label} --mock: {ran}");
        0
    } else {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        println!("FAIL test-taint {label} --mock: {ran}");
        1
    }
}

/// `cargo xtask test-policy-compiler` — determinism, static validation,
/// `I-05` and `I-26`: the parser, compiler and determinism suites of
/// `aisme-core`, reported in the gate's vocabulary.
pub(crate) fn test_policy_compiler(args: &[&str]) -> u8 {
    if let Some(other) = args.first() {
        eprintln!("usage: cargo xtask test-policy-compiler  (unexpected: {other})");
        return 1;
    }
    let mut cmd = Command::new("cargo");
    cmd.args(["test", "-q", "-p", "aisme-core"]);
    for suite in [
        "policy_parse",
        "policy_compile",
        "policy_determinism",
        "policy_backend",
        "policy_diagnostics",
        "policy_evaluate",
    ] {
        cmd.args(["--test", suite]);
    }
    let Ok(output) = cmd.output() else {
        eprintln!("skip: could not run cargo");
        return SKIP;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let results: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("test result: "))
        .collect();
    if output.status.success()
        && results.len() == 6
        && results.iter().all(|r| !r.contains("0 passed"))
    {
        println!("PASS test-policy-compiler: {}", results.join(" · "));
        0
    } else {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        println!("FAIL test-policy-compiler: {}", results.join(" · "));
        1
    }
}
