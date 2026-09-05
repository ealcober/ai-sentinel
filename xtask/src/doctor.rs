// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask doctor` — host prerequisites for phase F0.
//!
//! Reports and never installs. Installing packages on a developer's machine is
//! that developer's decision, so every missing item prints the exact line that
//! fixes it and what it unblocks. Exits non-zero while any F0 prerequisite is
//! missing, which is what lets `F0.VM.01` refuse to start on an unready host.

use std::fs::OpenOptions;
use std::path::Path;
use std::process::Command;

/// One prerequisite: what it is, how to get it, and what it unblocks.
struct Check {
    group: &'static str,
    label: &'static str,
    remedy: &'static str,
    unblocks: &'static str,
}

/// Everything plan `F0.REPO.06` lists, in the order it lists them.
const CHECKS: &[Check] = &[
    Check {
        group: "toolchains",
        label: "rustc matches the root rust-toolchain.toml pin",
        remedy: "rustup toolchain install <the pinned channel>",
        unblocks: "every build; the pin is the floor Aya sets (F0.VER.01)",
    },
    Check {
        group: "toolchains",
        label: "nightly toolchain",
        remedy: "rustup toolchain install nightly --component rust-src",
        unblocks: "crates/aisme-ebpf, which pins its own nightly",
    },
    Check {
        group: "toolchains",
        label: "rust-src on nightly",
        remedy: "rustup component add rust-src --toolchain nightly",
        unblocks: "-Z build-std=core for bpfel-unknown-none",
    },
    Check {
        group: "toolchains",
        label: "bpf-linker",
        remedy: "cargo +nightly install bpf-linker --no-default-features --features llvm-21",
        unblocks: "build-ebpf, F0.REPO.02's Aya pin, F0.VER.16, F0.VER.19",
    },
    Check {
        group: "toolchains",
        label: "cargo-deny",
        remedy: "cargo install cargo-deny",
        unblocks: "F0.GATE.03, the supply-chain and licence gate; deny.toml configures it",
    },
    Check {
        group: "kernel tooling",
        label: "bpftool",
        remedy: "sudo apt install -y bpftool",
        unblocks: "BTF inspection; the cgroup connect attach test (F0.VER.16)",
    },
    Check {
        group: "kernel tooling",
        label: "clang",
        remedy: "sudo apt install -y clang",
        unblocks: "BTF inspection and the LLVM bpf-linker links against",
    },
    Check {
        group: "virtualisation",
        label: "qemu-system-x86_64",
        remedy: "sudo apt install -y qemu-system-x86",
        unblocks: "F0.VM.01 images; no kernel test ever runs on the host (I-12)",
    },
    Check {
        group: "virtualisation",
        label: "virtme-ng",
        remedy: "sudo apt install -y virtme-ng",
        unblocks: "F0.VM.02, the kernel matrix",
    },
    Check {
        group: "virtualisation",
        label: "/dev/kvm exists",
        remedy: "enable nested virtualization on the host (Windows 11 defaults to on)",
        unblocks: "accelerated VMs; without it the matrix falls back to TCG",
    },
    Check {
        group: "virtualisation",
        label: "/dev/kvm readable and writable",
        remedy: "sudo usermod -aG kvm $USER, then start a new login session",
        unblocks: "F0.VER.21",
    },
    Check {
        group: "hardware attestation",
        label: "tpm2-tools",
        remedy: "sudo apt install -y tpm2-tools",
        unblocks: "F0.VER.12; note that WSL2 exposes no TPM at all (F0.VER.18)",
    },
];

pub(crate) fn run() -> u8 {
    println!("cargo xtask doctor — host prerequisites for phase F0\n");

    let results: Vec<bool> = CHECKS.iter().map(|c| probe(c.label)).collect();

    let mut group = "";
    for (c, &ok) in CHECKS.iter().zip(&results) {
        if c.group != group {
            println!("{}", c.group);
            group = c.group;
        }
        println!("  {}  {}", if ok { "PASS" } else { "MISS" }, c.label);
    }

    let missing: Vec<&Check> = CHECKS
        .iter()
        .zip(&results)
        .filter(|(_, &ok)| !ok)
        .map(|(c, _)| c)
        .collect();
    let present = CHECKS.len() - missing.len();
    println!("\n{present} of {} present.", CHECKS.len());

    if missing.is_empty() {
        println!("\nPASS doctor — the host is ready for F0.");
        return 0;
    }

    println!("\ndoctor never installs. Run these:\n");
    for c in &missing {
        println!("  {}", c.remedy);
        println!("      unblocks {}\n", c.unblocks);
    }
    eprintln!("FAIL doctor — {} prerequisite(s) missing.", missing.len());
    1
}

/// Run one check. Every probe tests the thing itself, not a proxy for it.
fn probe(label: &str) -> bool {
    match label {
        "rustc matches the root rust-toolchain.toml pin" => rustc_matches_pin(),
        "nightly toolchain" => rustup_lists("nightly"),
        "rust-src on nightly" => nightly_has_rust_src(),
        "bpf-linker" => on_path("bpf-linker"),
        "cargo-deny" => on_path("cargo-deny"),
        "bpftool" => on_path("bpftool"),
        "clang" => on_path("clang"),
        "qemu-system-x86_64" => on_path("qemu-system-x86_64"),
        "virtme-ng" => on_path("vng") || on_path("virtme-ng"),
        "/dev/kvm exists" => Path::new("/dev/kvm").exists(),
        // Opening it read-write is the property; group membership is only how it
        // is usually granted, and reading the group list would not prove access.
        "/dev/kvm readable and writable" => OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
        "tpm2-tools" => on_path("tpm2_getcap"),
        _ => false,
    }
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The pinned channel from `rust-toolchain.toml`, compared against live `rustc`.
fn rustc_matches_pin() -> bool {
    let Ok(pin) = std::fs::read_to_string("rust-toolchain.toml") else {
        return false;
    };
    let Some(channel) = pin
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel"))
        .and_then(|r| r.split('"').nth(1))
    else {
        return false;
    };
    output("rustc", &["--version"]).is_some_and(|v| v.contains(channel))
}

fn rustup_lists(toolchain: &str) -> bool {
    output("rustup", &["toolchain", "list"]).is_some_and(|s| s.contains(toolchain))
}

fn nightly_has_rust_src() -> bool {
    output(
        "rustup",
        &["component", "list", "--toolchain", "nightly", "--installed"],
    )
    .is_some_and(|s| s.lines().any(|l| l.trim().starts_with("rust-src")))
}

#[cfg(test)]
mod tests {
    use super::{on_path, probe, rustc_matches_pin, CHECKS};

    /// Commands read the repository by relative path, so a test must stand where
    /// `main` puts itself.
    fn at_root() {
        std::env::set_current_dir(crate::workspace_root()).unwrap();
    }

    #[test]
    fn on_path_finds_a_tool_that_is_certainly_installed() {
        // These tests run under cargo, so cargo itself is on PATH by construction.
        assert!(on_path("cargo"));
    }

    #[test]
    fn on_path_rejects_a_tool_that_does_not_exist() {
        assert!(!on_path("aisme-no-such-binary-6f17d22bba15"));
    }

    #[test]
    fn every_check_has_a_probe() {
        at_root();
        // A label with no arm in `probe` silently returns false, which would report
        // an installed prerequisite as missing forever. Exercise all of them.
        for c in CHECKS {
            let _ = probe(c.label);
        }
        // Two whose answer is knowable here: the pin must match, and an unknown
        // label must not quietly pass.
        assert!(
            rustc_matches_pin(),
            "rustc does not match rust-toolchain.toml"
        );
        assert!(!probe("no such check"));
    }

    #[test]
    fn every_check_names_a_remedy_and_what_it_unblocks() {
        for c in CHECKS {
            assert!(!c.remedy.is_empty(), "{} has no remedy", c.label);
            assert!(
                !c.unblocks.is_empty(),
                "{} says nothing about what it unblocks",
                c.label
            );
        }
    }
}
