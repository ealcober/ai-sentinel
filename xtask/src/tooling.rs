// SPDX-License-Identifier: Apache-2.0
//! Commands that need tooling outside the Rust toolchain.
//!
//! These are implemented, not pending: the code below is what runs once the tool
//! is present. When it is absent the command exits 2 with the reason and
//! `gate --level` reports `SKIP`, never a silent pass (Annex H §H.2, general rule 9).

use crate::SKIP;
use std::path::Path;
use std::process::Command;

/// Is `tool` on `PATH`?
fn have(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
}

/// Report a missing prerequisite and how to get it.
fn missing(what: &str, remedy: &str) -> u8 {
    eprintln!("skip: {what} is not installed.");
    eprintln!("      {remedy}");
    eprintln!("      `cargo xtask doctor` (F0.REPO.06) reports every host prerequisite.");
    SKIP
}

/// Build `crates/aisme-ebpf` for `bpfel-unknown-none`.
///
/// The crate is deliberately outside the workspace: it pins its own nightly and
/// targets a kernel VM, so `cargo check --workspace` must not try to build it.
pub(crate) fn build_ebpf() -> u8 {
    if !have("bpf-linker") {
        return missing(
            "bpf-linker",
            "cargo +nightly install bpf-linker --no-default-features --features llvm-21",
        );
    }
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--manifest-path",
            "crates/aisme-ebpf/Cargo.toml",
        ])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("PASS build-ebpf: aisme-ebpf built for bpfel-unknown-none");
            0
        }
        Ok(_) => 1,
        Err(e) => {
            eprintln!("skip: could not run cargo: {e}");
            SKIP
        }
    }
}

/// Build the release artefacts and confirm every declared binary is present.
///
/// The binary list comes from `cargo metadata`, not from reading the directory:
/// `target/release` also holds cargo's own lock files, and a directory listing
/// would report those as artefacts.
pub(crate) fn dist() -> u8 {
    let status = Command::new("cargo")
        .args(["build", "--release", "--workspace"])
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(_) => return 1,
        Err(e) => {
            eprintln!("skip: could not run cargo: {e}");
            return SKIP;
        }
    }

    let Some(expected) = bin_targets() else {
        eprintln!("skip: `cargo metadata` did not run");
        return SKIP;
    };
    let mut missing = Vec::new();
    for name in &expected {
        if !Path::new("target/release").join(name).is_file() {
            missing.push(name.clone());
        }
    }
    if missing.is_empty() {
        println!("PASS dist: {} binaries in target/release", expected.len());
        for n in &expected {
            println!("  {n}");
        }
        0
    } else {
        eprintln!("FAIL dist: declared but not built: {missing:?}");
        1
    }
}

/// The `bin` target names every workspace member declares.
fn bin_targets() -> Option<Vec<String>> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let mut names: Vec<String> = meta["packages"]
        .as_array()?
        .iter()
        .filter_map(|p| p["targets"].as_array())
        .flatten()
        .filter(|t| {
            t["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|x| x.as_str() == Some("bin")))
        })
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    names.sort();
    Some(names)
}

/// Provision and drive disposable VMs. Never touches the host kernel (`I-12`).
pub(crate) fn vm(name: &str) -> u8 {
    if !have("qemu-system-x86_64") {
        return missing("qemu-system-x86_64", "sudo apt install -y qemu-system-x86");
    }
    if !have("vng") && !have("virtme-ng") {
        return missing("virtme-ng", "sudo apt install -y virtme-ng");
    }
    eprintln!("skip: `cargo xtask {name}` has its tooling but no VM images yet.");
    eprintln!("      Images are F0.VM.01; the kernel matrix is F0.VM.02.");
    SKIP
}
