// SPDX-License-Identifier: Apache-2.0
//! Architecture rules `A-01`…`A-06` (`F0.GATE.06`) and the forbidden-dependency
//! gate (`F0.GATE.05`). Both run inside `cargo xtask verify-layering`.
//!
//! `A-02` — direction and L2 siblings — is checked in `verify::layering` from
//! `layers.toml`, because that is where the layer of each crate is declared. The
//! rules here are the ones that need source or the resolved dependency graph.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every `.rs` file under a directory, with its contents.
fn rust_sources(root: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    walk(Path::new(root), &mut out);
    out
}

/// Drop comments so a doc comment that *names* a forbidden construct is not read
/// as a use of it. Line comments only; a block comment holding one of these
/// strings would still be flagged, which errs toward reporting rather than silence.
fn code_only(body: &str) -> String {
    body.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Build output is not our source: scanning it would judge vendored
            // core and generated bindings by rules written for this repository.
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(body) = std::fs::read_to_string(&path) {
                out.push((path, body));
            }
        }
    }
}

/// Crates that make a crate platform-aware or introduce an async runtime.
const RUNTIME_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "smol",
    "libc",
    "nix",
    "windows",
    "aya",
];

/// `A-01` — `aisme-core` has no `cfg(target_os)`, no platform crate, no async runtime.
///
/// The moment it learns what OS it is on, one engine stops serving Linux, WSL2,
/// Android, iOS and the SDK. This is the rule the whole layering exists for.
pub(crate) fn a01_core_is_platform_free(direct_deps: &[(String, String)]) -> Result<(), String> {
    let mut bad = Vec::new();
    for (path, body) in rust_sources("crates/aisme-core/src") {
        if code_only(&body).contains("cfg(target_os") {
            bad.push(format!("{} uses cfg(target_os)", path.display()));
        }
    }
    for (from, to) in direct_deps {
        if from == "aisme-core" && RUNTIME_CRATES.contains(&to.as_str()) {
            bad.push(format!("aisme-core depends on {to}"));
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

/// `A-03` — `aisme-ebpf-common` is `no_std` with zero dependencies.
///
/// It is compiled into kernel-verified code, so a dependency here is a dependency
/// inside the kernel.
pub(crate) fn a03_wire_is_no_std_zero_deps(direct_deps: &[(String, String)]) -> Result<(), String> {
    let mut bad = Vec::new();
    let sources = rust_sources("crates/aisme-ebpf-common/src");
    if sources.is_empty() {
        bad.push("crates/aisme-ebpf-common/src has no Rust source".to_owned());
    } else if !sources.iter().any(|(_, b)| b.contains("#![no_std]")) {
        bad.push("no #![no_std] in crates/aisme-ebpf-common".to_owned());
    }
    let deps: Vec<&String> = direct_deps
        .iter()
        .filter(|(f, _)| f == "aisme-ebpf-common")
        .map(|(_, t)| t)
        .collect();
    if !deps.is_empty() {
        bad.push(format!("aisme-ebpf-common depends on {deps:?}"));
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

/// `A-05` — only `aisme-agentd::platform` names a concrete adapter or uses `cfg(target_os)`.
///
/// A rule with no legal home is not a rule; this is the home, and it is
/// recognised by path.
pub(crate) fn a05_composition_root_is_the_only_platform_module(
    adapters: &BTreeSet<String>,
) -> Result<(), String> {
    let root = Path::new("crates/aisme-agentd/src/platform");
    let mut bad = Vec::new();
    for (path, body) in rust_sources("crates/aisme-agentd/src") {
        if path.starts_with(root) {
            continue;
        }
        let body = code_only(&body);
        if body.contains("cfg(target_os") {
            bad.push(format!(
                "{} uses cfg(target_os) outside the composition root",
                path.display()
            ));
        }
        for adapter in adapters {
            // `use aisme_linux::…` is the concrete-adapter form the rule forbids.
            let ident = adapter.replace('-', "_");
            if body.contains(&format!("use {ident}::")) || body.contains(&format!("{ident}::")) {
                bad.push(format!("{} names the adapter {adapter}", path.display()));
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

/// `F0.GATE.05` — the forbidden-dependency gate.
///
/// `serde_json` is checked over the **resolved** graph, not the direct list: a
/// transitive pull into the hot path breaks `I-21` exactly as a direct one does.
pub(crate) fn forbidden_dependencies() -> Result<(), String> {
    let mut bad = Vec::new();

    match resolved_deps_of("aisme-agentd") {
        None => bad.push("could not resolve aisme-agentd's dependency graph".to_owned()),
        Some(deps) => {
            if deps.contains("serde_json") {
                bad.push(
                    "serde_json reaches aisme-agentd (I-21: no JSON on the hot path)".to_owned(),
                );
            }
        }
    }

    if let Some(all) = all_resolved_packages() {
        let frida: Vec<&String> = all.iter().filter(|n| n.starts_with("frida")).collect();
        if !frida.is_empty() {
            bad.push(format!(
                "{frida:?} present (I-01: AISME never modifies an observed process)"
            ));
        }
    }

    // `bpf_probe_write_user` makes the product a rootkit (I-02, H-05). It is
    // permitted only behind the research feature, so a mention outside a
    // cfg(feature = "research") file is a violation.
    for (path, body) in rust_sources("crates") {
        if code_only(&body).contains("bpf_probe_write_user")
            && !body.contains("feature = \"research\"")
        {
            bad.push(format!(
                "{} uses bpf_probe_write_user outside the research feature",
                path.display()
            ));
        }
    }

    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

fn full_metadata() -> Option<serde_json::Value> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .output()
        .ok()?;
    out.status.success().then_some(())?;
    serde_json::from_slice(&out.stdout).ok()
}

/// Every package name reachable from `root` in the resolved graph.
fn resolved_deps_of(root: &str) -> Option<BTreeSet<String>> {
    let meta = full_metadata()?;
    let nodes = meta["resolve"]["nodes"].as_array()?;
    let id_of = |name: &str| -> Option<String> {
        nodes.iter().find_map(|n| {
            let id = n["id"].as_str()?;
            package_name(id).eq(name).then(|| id.to_owned())
        })
    };
    let start = id_of(root)?;
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        let Some(node) = nodes.iter().find(|n| n["id"].as_str() == Some(id.as_str())) else {
            continue;
        };
        for dep in node["dependencies"].as_array().into_iter().flatten() {
            let Some(dep_id) = dep.as_str() else { continue };
            if seen.insert(package_name(dep_id).to_owned()) {
                stack.push(dep_id.to_owned());
            }
        }
    }
    Some(seen)
}

fn all_resolved_packages() -> Option<BTreeSet<String>> {
    let meta = full_metadata()?;
    Some(
        meta["packages"]
            .as_array()?
            .iter()
            .filter_map(|p| p["name"].as_str().map(str::to_owned))
            .collect(),
    )
}

/// The package name out of a cargo id. Cargo writes three forms, and the third is
/// the one that bites: a path package is `path+file:///…/<name>#<version>`, whose
/// fragment is the **version**, so splitting on `#` yields `0.1.0` and every
/// workspace lookup silently misses.
fn package_name(id: &str) -> &str {
    let Some(hash) = id.rfind('#') else {
        return id.split_whitespace().next().unwrap_or(id); // `name version (source)`
    };
    let (url, tail) = id.split_at(hash);
    let tail = &tail[1..];
    if let Some((name, _version)) = tail.split_once('@') {
        return name; // `…#name@version`
    }
    if tail.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return url.rsplit('/').next().unwrap_or(tail); // `…/<name>#<version>`
    }
    tail
}

#[cfg(test)]
mod tests {
    use super::{package_name, rust_sources};

    fn at_root() {
        std::env::set_current_dir(crate::workspace_root()).unwrap();
    }

    #[test]
    fn package_name_handles_both_cargo_id_forms() {
        assert_eq!(
            package_name("serde_json 1.0.1 (registry+https://x)"),
            "serde_json"
        );
        assert_eq!(
            package_name("path+file:///w/crates/aisme-core#aisme-core@0.1.0"),
            "aisme-core"
        );
        assert_eq!(
            package_name("registry+https://x#serde_json@1.0.1"),
            "serde_json"
        );
        // The form cargo 1.97 writes for a workspace member: the fragment is the
        // version, so the name has to come from the last path segment.
        assert_eq!(
            package_name("path+file:///w/crates/aisme-agentd#0.1.0"),
            "aisme-agentd"
        );
    }

    #[test]
    fn rust_sources_reads_the_tree_it_is_pointed_at() {
        at_root();
        let core = rust_sources("crates/aisme-core/src");
        assert!(!core.is_empty(), "aisme-core has no Rust source");
        assert!(core
            .iter()
            .all(|(p, _)| p.extension().is_some_and(|e| e == "rs")));
    }
}
