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
        let with_caps = directives(
            "[Service]\nUser=aisme\nCapabilityBoundingSet=CAP_BPF\nAmbientCapabilities=\nNoNewPrivileges=yes\nDelegate=yes\n",
        );
        let problems = check_agentd(&with_caps);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("holds no capability"), "{problems:?}");

        let no_delegate =
            directives("[Service]\nUser=aisme\nCapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\n");
        let problems = check_agentd(&no_delegate);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("Delegate=yes"), "{problems:?}");

        let sys_admin = directives(
            "[Service]\nType=oneshot\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN\n",
        );
        let problems = check_loaderd(&sys_admin);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("decorative"), "{problems:?}");

        let resident = directives("[Service]\nType=simple\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN\n");
        assert!(check_loaderd(&resident)[0].contains("does not stay resident"));
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
