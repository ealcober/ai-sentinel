// SPDX-License-Identifier: Apache-2.0
//! The privilege split, checked against the units that implement it
//! (`F1.RT.07`).
//!
//! The split is a property of `deploy/systemd/*.service`, not of this crate's
//! code, so this is where it is verified: the loader has exactly the
//! capabilities it needs and no more, the daemon has none and cannot gain
//! any, and the daemon's unit delegates its cgroup subtree — which is what
//! makes T2's freeze an ordinary write by the subtree's owner instead of a
//! reason to keep `CAP_SYS_ADMIN` in a long-running process.

use std::path::{Path, PathBuf};

/// Where the units live in the repository.
#[must_use]
pub fn unit_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/systemd")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("deploy/systemd"))
}

/// Read a unit's directives as `(key, value)`, ignoring comments and
/// sections — a unit file is not TOML and does not need a parser for this.
fn directives(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

fn value<'a>(directives: &'a [(String, String)], key: &str) -> Option<&'a str> {
    directives
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The binary a unit must start, and the flags it may pass it.
///
/// This file cannot ask the other binary what it parses: `aisme-agentd` is a
/// sibling at L3 and depending on it would invert the layering. What can be
/// checked exactly is that the unit starts the expected binary and passes only
/// flags named here — which catches a unit drifting away from the design, and
/// is stated as the weaker claim it is: it does not catch a binary that drops a
/// flag its unit still passes.
///
/// The list is short on purpose. `--handoff` was on both units for two phases
/// and no binary ever parsed it, because the directive that says what the
/// process *is* was the one directive nothing read.
fn check_exec_start(
    unit: &str,
    binary: &str,
    allowed: &[&str],
    directives: &[(String, String)],
) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(exec) = value(directives, "ExecStart") else {
        problems.push(format!("{unit}: ExecStart= is missing"));
        return problems;
    };
    let mut words = exec.split_whitespace();
    match words.next() {
        Some(started) if started == binary => {}
        other => problems.push(format!(
            "{unit}: ExecStart starts {} and not {binary}",
            other.unwrap_or("nothing")
        )),
    }
    for word in words {
        if word.starts_with("--") && !allowed.contains(&word) {
            problems.push(format!(
                "{unit}: ExecStart passes {word}, which the binary does not parse — it takes {allowed:?}"
            ));
        }
    }
    problems
}

/// Check both units.
///
/// # Errors
///
/// Every problem found, in the words an operator would need.
pub fn check_all() -> Result<(), Vec<String>> {
    let dir = unit_dir();
    let mut problems = Vec::new();
    match std::fs::read_to_string(dir.join("aisme-agentd.service")) {
        Ok(text) => problems.extend(check_agentd(&directives(&text))),
        Err(e) => problems.push(format!("aisme-agentd.service: {e}")),
    }
    match std::fs::read_to_string(dir.join("aisme-loaderd.service")) {
        Ok(text) => problems.extend(check_loaderd(&directives(&text))),
        Err(e) => problems.push(format!("aisme-loaderd.service: {e}")),
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// The daemon holds nothing and is handed its own subtree.
fn check_agentd(directives: &[(String, String)]) -> Vec<String> {
    let mut problems = Vec::new();
    if value(directives, "CapabilityBoundingSet") != Some("") {
        problems.push(
            "aisme-agentd: CapabilityBoundingSet must be empty — the hot loop holds no capability (F1.RT.07)".to_owned(),
        );
    }
    if value(directives, "AmbientCapabilities") != Some("") {
        problems.push("aisme-agentd: AmbientCapabilities must be empty".to_owned());
    }
    if value(directives, "NoNewPrivileges") != Some("yes") {
        problems.push(
            "aisme-agentd: NoNewPrivileges=yes, or the empty bounding set can be re-earned"
                .to_owned(),
        );
    }
    if value(directives, "Delegate") != Some("yes") {
        problems.push(
            "aisme-agentd: Delegate=yes — without the delegated subtree, freezing a scope for T2 needs privilege the daemon must not have".to_owned(),
        );
    }
    if value(directives, "User").is_none() {
        problems.push("aisme-agentd: User= must name the unprivileged account".to_owned());
    }
    if value(directives, "Type") != Some("exec") {
        problems.push(
            "aisme-agentd: Type=exec — the daemon sends no READY=1, and a notify unit whose process never does is held in activating until the timeout and then failed".to_owned(),
        );
    }
    problems.extend(check_exec_start(
        "aisme-agentd",
        "/usr/lib/aisme/aisme-agentd",
        &["--run", "--serve-ipc"],
        directives,
    ));
    problems
}

/// The loader holds what it needs, and not `CAP_SYS_ADMIN`.
fn check_loaderd(directives: &[(String, String)]) -> Vec<String> {
    let mut problems = Vec::new();
    let bounding = value(directives, "CapabilityBoundingSet").unwrap_or_default();
    for needed in ["CAP_BPF", "CAP_NET_ADMIN"] {
        if !bounding.split_whitespace().any(|c| c == needed) {
            problems.push(format!(
                "aisme-loaderd: {needed} is required to load and attach"
            ));
        }
    }
    if bounding.split_whitespace().any(|c| c == "CAP_SYS_ADMIN") {
        problems.push(
            "aisme-loaderd: CAP_SYS_ADMIN makes the split decorative — a loader that can do anything is not a smaller surface".to_owned(),
        );
    }
    if value(directives, "Type") != Some("oneshot") {
        problems.push(
            "aisme-loaderd: Type=oneshot — the privileged half does not stay resident".to_owned(),
        );
    }
    if value(directives, "NoNewPrivileges") != Some("yes") {
        problems.push("aisme-loaderd: NoNewPrivileges=yes".to_owned());
    }
    if value(directives, "RemainAfterExit") != Some("yes") {
        problems.push(
            "aisme-loaderd: RemainAfterExit=yes — what it loads outlives it through its bpffs pin, so systemd must not read the exit as the unit going away".to_owned(),
        );
    }
    problems.extend(check_exec_start(
        "aisme-loaderd",
        "/usr/lib/aisme/aisme-loaderd",
        &["--publish"],
        directives,
    ));
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_units_implement_the_split() {
        check_all().unwrap_or_else(|problems| panic!("{problems:#?}"));
    }

    #[test]
    fn a_unit_that_kept_a_capability_or_lost_delegation_is_refused() {
        // The checks are shown failing, not only passing: a check nobody has
        // seen fail is a check nobody should trust (F1.PA.07's lesson).
        // A well-formed agentd unit, so each case below differs from a passing
        // one in exactly the way it is named for. Asserting on the problem
        // rather than on how many there are keeps the cases independent: a new
        // check does not invalidate an old case.
        const AGENTD: &str = "[Service]\nUser=aisme\nType=exec\nExecStart=/usr/lib/aisme/aisme-agentd --run /var/lib/aisme/wal\nCapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\nDelegate=yes\n";
        const LOADERD: &str = "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/lib/aisme/aisme-loaderd --publish /etc/aisme/policy.aisme\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN\n";
        assert!(check_agentd(&directives(AGENTD)).is_empty());

        let with_caps = directives(&AGENTD.replace(
            "CapabilityBoundingSet=\n",
            "CapabilityBoundingSet=CAP_BPF\n",
        ));
        let problems = check_agentd(&with_caps);
        assert!(
            problems.iter().any(|p| p.contains("holds no capability")),
            "{problems:?}"
        );

        let no_delegate = directives(&AGENTD.replace("Delegate=yes\n", ""));
        let problems = check_agentd(&no_delegate);
        assert!(
            problems.iter().any(|p| p.contains("Delegate=yes")),
            "{problems:?}"
        );

        // The unit declares a startup protocol the binary does not speak.
        let notify = directives(&AGENTD.replace("Type=exec", "Type=notify"));
        let problems = check_agentd(&notify);
        assert!(
            problems.iter().any(|p| p.contains("READY=1")),
            "{problems:?}"
        );

        // The unit passes a flag no binary parses — two phases of `--handoff`.
        let ghost_flag = directives(&AGENTD.replace(
            "--run /var/lib/aisme/wal",
            "--handoff /run/aisme/loader.sock",
        ));
        let problems = check_agentd(&ghost_flag);
        assert!(
            problems.iter().any(|p| p.contains("--handoff")),
            "{problems:?}"
        );

        assert!(check_loaderd(&directives(LOADERD)).is_empty());

        let sys_admin = directives(&LOADERD.replace(
            "CAP_BPF CAP_NET_ADMIN",
            "CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN",
        ));
        let problems = check_loaderd(&sys_admin);
        assert!(
            problems.iter().any(|p| p.contains("decorative")),
            "{problems:?}"
        );

        let resident = directives(&LOADERD.replace("Type=oneshot", "Type=simple"));
        assert!(check_loaderd(&resident)
            .iter()
            .any(|p| p.contains("does not stay resident")));

        // Without it systemd reads the loader's exit as the unit going away,
        // while its pinned maps are still there.
        let forgets_pin = directives(&LOADERD.replace("RemainAfterExit=yes\n", ""));
        let problems = check_loaderd(&forgets_pin);
        assert!(
            problems.iter().any(|p| p.contains("RemainAfterExit=yes")),
            "{problems:?}"
        );

        let wrong_binary =
            directives(&LOADERD.replace("/usr/lib/aisme/aisme-loaderd", "/usr/bin/aisme-loaderd"));
        let problems = check_loaderd(&wrong_binary);
        assert!(
            problems.iter().any(|p| p.contains("and not")),
            "{problems:?}"
        );
    }

    #[test]
    fn directives_ignore_comments_and_sections() {
        let parsed = directives("# a comment\n[Service]\n\nExecStart=/x --flag=1\nDelegate=yes\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            value(&parsed, "ExecStart"),
            Some("/x --flag=1"),
            "only the first `=` splits"
        );
        assert_eq!(value(&parsed, "Nothing"), None);
    }
}
