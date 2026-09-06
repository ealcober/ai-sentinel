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
    // Run from the crate directory and do NOT pass `+nightly`. The crate pins its
    // own toolchain in crates/aisme-ebpf/rust-toolchain.toml, rustup resolves that
    // from the working directory, and an explicit `+nightly` would override the
    // pin with whatever "nightly" happens to be today — which is how a validated
    // LLVM pairing silently stops being the one that was validated.
    let status = Command::new("cargo")
        .current_dir("crates/aisme-ebpf")
        // `cargo run` exports RUSTUP_TOOLCHAIN (and RUSTC) for the toolchain it
        // launched xtask with, and the rustup shim honours the environment ahead
        // of any rust-toolchain.toml. Inherited, they pin the child to the
        // workspace's stable and the crate's own pin is ignored — which fails as
        // "-Z is only accepted on the nightly channel", nowhere near the cause.
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("CARGO")
        .args([
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
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
///
/// `I-12` is why these exist: no kernel-touching test ever runs on a host OS. It
/// is also what makes them the *only* place `F0.VER.16` and `F0.VER.19` can be
/// measured — both load a BPF program, this host reports
/// `unprivileged_bpf_disabled = 2` and grants the shell no capabilities, and
/// loading one on the host would violate the invariant even if it were possible.
pub(crate) fn vm(name: &str) -> u8 {
    if !have("qemu-system-x86_64") {
        return missing("qemu-system-x86_64", "sudo apt install -y qemu-system-x86");
    }
    if !have("vng") && !have("virtme-ng") {
        return missing("virtme-ng", "sudo apt install -y virtme-ng");
    }
    if !Path::new("/dev/kvm").exists() {
        eprintln!("note: /dev/kvm is absent; qemu falls back to TCG — correct, an order slower.");
    } else if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_err()
    {
        eprintln!("note: /dev/kvm is not writable in this session, so qemu falls back to TCG.");
        eprintln!("      `usermod -aG kvm` has been run; a session keeps the groups it started");
        eprintln!("      with, so this clears on the next login (F0.VER.21).");
    }

    eprintln!("skip: `cargo xtask {name}` has its tooling and no bootable kernel.");
    eprintln!();
    eprintln!("      Measured while implementing F0.VM.01, and none of it was in the plan:");
    eprintln!("      * WSL2 has no /boot/vmlinuz — its kernel comes from the Windows side —");
    eprintln!("        so virtme-ng cannot reuse the running kernel the way it does elsewhere.");
    eprintln!("      * An Ubuntu distro kernel, fetched with `apt-get download` and unpacked");
    eprintln!("        with `dpkg-deb -x` (both work without sudo), panics under virtme-ng at");
    eprintln!("        mount_root_generic: 9p and virtiofs are modules there, and virtme-ng");
    eprintln!("        needs them built in to mount the host rootfs.");
    eprintln!("      * So the matrix wants kernels built for it — `vng --build` per version,");
    eprintln!("        which is F0.VM.02's real shape and its real cost.");
    eprintln!();
    eprintln!("      F0.VM.01 owns the images; F0.VM.02 owns the kernel matrix.");
    SKIP
}
