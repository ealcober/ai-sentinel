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

/// `cargo xtask test-detect [--determinism]` (`F1.DT.01`).
///
/// Annex G.0's claim is that detectors are pure functions with no platform
/// variants, "which is why they can be tested once, on CI, for every
/// target". This runs that test; `--determinism` is the only mode there is,
/// and passing nothing runs the same suite, because a detector that was
/// non-deterministic would be broken in every mode.
pub(crate) fn test_detect(args: &[&str]) -> u8 {
    for arg in args {
        if *arg != "--determinism" {
            eprintln!("usage: cargo xtask test-detect [--determinism]  (unknown: {arg})");
            return 1;
        }
    }
    let Ok(output) = Command::new("cargo")
        .args([
            "test",
            "-q",
            "-p",
            "aisme-core",
            "--test",
            "detect_determinism",
        ])
        .output()
    else {
        eprintln!("skip: could not run cargo");
        return SKIP;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let result = text
        .lines()
        .find_map(|l| l.strip_prefix("test result: "))
        .unwrap_or("no test result line");
    if output.status.success() && !result.contains("0 passed") {
        println!("PASS test-detect --determinism: {result}");
        0
    } else {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        println!("FAIL test-detect --determinism: {result}");
        1
    }
}

/// `cargo xtask test-policy-publish` — `F2.WS.04`'s two done-conditions, in one
/// guest boot (`docs/06` point 6).
///
/// Three properties, and each is a **negative** as much as a positive:
///
/// * the generation increments and the index alternates;
/// * a reader never sees a policy the publisher never had in force, while a
///   publisher republishes underneath it;
/// * a process without `CAP_BPF` cannot write the pinned maps, and fails with
///   `EPERM` — not `ENOENT`, which would pass because the map was missing and
///   prove nothing about capabilities.
///
/// The third runs under `capsh --drop=cap_bpf` rather than inside `aisme-agentd`.
/// `docs/06` point 6 named the daemon; adding a write-the-policy-map path to it
/// so a test can watch that path fail would give the daemon the very authority
/// the privilege split removes. Dropping the capability tests the same kernel
/// rule against the same pins, and leaves the product without the code.
pub(crate) fn test_policy_publish(args: &[&str]) -> u8 {
    let image = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .copied()
        .unwrap_or("ubuntu-24.04");
    let samples = args
        .iter()
        .find_map(|a| a.strip_prefix("--samples="))
        .unwrap_or("200000");
    let script = guest_script(samples);
    crate::vm::run("vm run", &[image, "--with-dist", "--", &script])
}

/// The guest side, as one script so the three tests share one boot.
///
/// **Nothing here exits early.** A non-zero exit truncates the marked block the
/// host reads, so a legitimate failure costs a fifteen-minute timeout instead
/// of an answer — measured once, which is why failures accumulate in `BAD` and
/// the script always runs to its end.
///
/// A plain string with one placeholder rather than `format!`: the script is
/// mostly shell braces, and escaping every one of them for a formatter is how a
/// working script becomes a compile error nobody can read.
fn guest_script(samples: &str) -> String {
    GUEST.replace("@SAMPLES@", samples)
}

const GUEST: &str = r#"set -u
L=/usr/lib/aisme/aisme-loaderd
BAD=0
fail() { echo "FAIL: $*"; BAD=1; }

# Two policies that disagree about one path, so a sample can be checked against
# what the publisher actually wrote rather than against "not empty".
cat > /tmp/deny.aisme <<'EOF'
[session.defaults]
learning_mode_days = 7
grant_ttl_days = 30
profile = "default"
[[rule]]
id = "shadow"
group = "CREDENTIALS"
match = { path_under = "/etc/shadow" }
verdict = "deny"
EOF
sed 's/verdict = "deny"/verdict = "allow"/' /tmp/deny.aisme > /tmp/allow.aisme

echo "--- 1. the generation increments and the index alternates"
first=$($L --publish /tmp/deny.aisme 2>/dev/null)
second=$($L --publish /tmp/allow.aisme 2>/dev/null)
echo "generations: $first then $second"
[ "$first" = "1" ] && [ "$second" = "2" ] || fail "generations $first,$second"

echo "--- 2. the pins outlive the loader"
ls /sys/fs/bpf/aisme/ | tr '\n' ' '; echo
[ -e /sys/fs/bpf/aisme/AISME_POLICY_META ] || fail "no pin survived the loader"

echo "--- 3. the torn-read run, with a publisher underneath it"
( while :; do $L --publish /tmp/deny.aisme >/dev/null 2>&1
              $L --publish /tmp/allow.aisme >/dev/null 2>&1; done ) &
PUB=$!
# 3 = Deny, 0 = Allow (Annex B B.10). Anything else, or an absent key, is torn.
$L --sample @SAMPLES@ /etc/shadow 3 0 || fail "torn-read run"
kill $PUB 2>/dev/null; wait $PUB 2>/dev/null

echo "--- 4. the privilege negative: the daemon's user cannot reach the maps"
# Read the map FIRST, as root. Without this the refusal below could be a
# missing map wearing a permission error's clothes, which is how this test
# passes for the wrong reason (docs/06 point 6).
if bpftool map dump pinned /sys/fs/bpf/aisme/AISME_POLICY_META >/dev/null 2>&1; then
  echo "the map exists and root can read it"
  # `docs/06` point 6 asked for EPERM from an *update* attempted by agentd.
  # That is unobservable here, and the reason is that point 3 made it
  # unnecessary: the pin directory is 0700 root, so a process running as the
  # daemon's unprivileged user (CapabilityBoundingSet= and User=aisme in the
  # unit) never opens the map at all. The refusal arrives one step earlier,
  # at open, and that is a stronger protection than a refused write — there is
  # no write to refuse. What is asserted is the refusal and its kind.
  # Asserted through `cat`, not `bpftool`. bpftool reports this refusal as
  # "directory not in bpf file system (bpffs)", which is not the reason: the
  # directory IS bpffs and the process cannot traverse it. Accepting that
  # message would be accepting a refusal whose cause was never established,
  # which is the failure this test exists to refuse. `cat` reports its errno.
  BPFTOOL=$(setpriv --reuid=65534 --regid=65534 --clear-groups -- bpftool map dump pinned /sys/fs/bpf/aisme/AISME_POLICY_META 2>&1)
  echo "unprivileged bpftool says: ${BPFTOOL:-<no output>}"
  OUT=$(setpriv --reuid=65534 --regid=65534 --clear-groups -- cat /sys/fs/bpf/aisme/AISME_POLICY_META 2>&1)
  RC=$?
  echo "unprivileged open: rc=$RC ${OUT:-<no output>}"
  if [ $RC -ne 0 ] && echo "$OUT" | grep -qiE "permission denied|eacces|eperm"; then
    echo "PASS: the daemon's user cannot reach the published policy"
  else
    fail "an unprivileged process reached the maps: rc=$RC ${OUT:-<no output>}"
  fi
else
  fail "cannot read the map before testing that an unprivileged read is refused"
fi

[ $BAD -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"
# No `exit` here. This script runs inside the wrapper that prints the closing
# marker the host waits for, so exiting kills the wrapper first and a finished
# run is reported as a timeout — measured twice before it was believed.
"#;
