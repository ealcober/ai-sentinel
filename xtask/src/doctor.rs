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
        label: "the nightly crates/aisme-ebpf pins",
        remedy: "rustup toolchain install <the channel in crates/aisme-ebpf/rust-toolchain.toml> --component rust-src",
        unblocks: "crates/aisme-ebpf; any other nightly is the wrong one",
    },
    Check {
        group: "toolchains",
        label: "rust-src on the pinned nightly",
        remedy: "rustup component add rust-src --toolchain <the pinned channel>",
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
        label: "the pinned nightly's LLVM matches bpf-linker's",
        remedy: "rebuild bpf-linker for that LLVM, or move the pin to a nightly on the LLVM you have",
        unblocks: "build-ebpf; a mismatch fails at link with \"Unknown attribute kind\" and nothing earlier catches it",
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
        label: "qemu-img",
        remedy: "sudo apt install -y qemu-utils",
        unblocks: "the fresh qcow2 overlay `vm up` boots — the restore-from-snapshot I-12 asks for",
    },
    Check {
        group: "virtualisation",
        label: "genisoimage",
        remedy: "sudo apt install -y genisoimage",
        unblocks: "the NoCloud seed ISO that carries commands into the guest",
    },
    Check {
        group: "virtualisation",
        label: "virtme-ng",
        remedy: "sudo apt install -y virtme-ng",
        unblocks: "F0.VM.02 for a kernel no distribution ships; cloud images cover the rest",
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
        remedy: "sudo usermod -aG kvm $USER and a new login session — or, when the node came up in another group (see observed), sudo chgrp kvm /dev/kvm",
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
        if c.label == "/dev/kvm readable and writable" {
            if let Some(observed) = kvm_observed() {
                println!("      observed: {observed}");
            }
        }
        println!("      unblocks {}\n", c.unblocks);
    }
    eprintln!("FAIL doctor — {} prerequisite(s) missing.", missing.len());
    1
}

/// Run one check. Every probe tests the thing itself, not a proxy for it.
fn probe(label: &str) -> bool {
    match label {
        "rustc matches the root rust-toolchain.toml pin" => rustc_matches_pin(),
        "the nightly crates/aisme-ebpf pins" => pinned_channel().is_some_and(|c| rustup_lists(&c)),
        "rust-src on the pinned nightly" => pinned_channel().is_some_and(|c| has_rust_src(&c)),
        "bpf-linker" => on_path("bpf-linker"),
        "cargo-deny" => on_path("cargo-deny"),
        "the pinned nightly's LLVM matches bpf-linker's" => llvm_majors_match(),
        "bpftool" => on_path("bpftool"),
        "clang" => on_path("clang"),
        "qemu-system-x86_64" => on_path("qemu-system-x86_64"),
        "virtme-ng" => on_path("vng") || on_path("virtme-ng"),
        "qemu-img" => on_path("qemu-img"),
        "genisoimage" => on_path("genisoimage"),
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

/// What stands between the user and `/dev/kvm`, read from the node itself.
///
/// Group membership is the usual cause, but not the only one: after a WSL
/// restart the node came up owned by group `sgx` while the user sat in `kvm`
/// (2026-09-07), although udev's `50-udev-default.rules` says `GROUP="kvm"`.
/// A remedy that assumes the group is `kvm` sends the owner to `usermod` for
/// nothing, so the observed group, mode and membership are printed instead.
fn kvm_observed() -> Option<String> {
    let node = output("stat", &["-c", "%G %a", "/dev/kvm"])?;
    let (group, mode) = node.trim().split_once(' ')?;
    let mine = output("id", &["-Gn"])?;
    let member = mine.split_whitespace().any(|g| g == group);
    Some(match (member, group) {
        (true, _) => format!("/dev/kvm is group {group}, mode {mode}, and you are in {group}: the mode itself denies"),
        (false, "kvm") => format!("/dev/kvm is group kvm, mode {mode}; your groups: {}", mine.trim()),
        (false, other) => format!(
            "/dev/kvm is group {other}, mode {mode} — not kvm, as udev's 50-udev-default.rules sets; your groups: {}",
            mine.trim()
        ),
    })
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

/// Does the eBPF crate's pinned nightly emit bitcode `bpf-linker` can read?
///
/// `bpf-linker` links the bitcode rustc produces, so their LLVM **major**
/// versions must be equal. They are pinned in two different places by two
/// different people, and the only symptom of a mismatch is a link-time
/// "Unknown attribute kind (NNN)" that names neither.
fn llvm_majors_match() -> bool {
    let (Some(pin), Some(linker)) = (pinned_nightly_llvm(), bpf_linker_llvm()) else {
        return false;
    };
    pin == linker
}

/// The LLVM major of the channel pinned in `crates/aisme-ebpf/rust-toolchain.toml`.
fn pinned_nightly_llvm() -> Option<u32> {
    let channel = pinned_channel()?;
    let out = output("rustc", &[&format!("+{channel}"), "--version", "--verbose"])?;
    llvm_major(&out)
}

/// The LLVM major `bpf-linker` was built against.
///
/// It does not print this: `bpf-linker --version` reports only its own crate
/// version. The linked library is the fact, so read it from `ldd` — a build
/// against `libLLVM.so.21.1` cannot read LLVM 23 bitcode whatever it calls
/// itself.
fn bpf_linker_llvm() -> Option<u32> {
    let path = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("bpf-linker"))
            .find(|p| p.is_file())
    })?;
    let out = output("ldd", &[&path.to_string_lossy()])?;
    let lib = out.lines().find(|l| l.contains("libLLVM"))?;
    let after = lib.split("libLLVM.so.").nth(1)?;
    after.split('.').next()?.trim().parse().ok()
}

fn llvm_major(text: &str) -> Option<u32> {
    let after = text.split("LLVM version: ").nth(1)?;
    after.split('.').next()?.trim().parse().ok()
}

fn rustup_lists(toolchain: &str) -> bool {
    output("rustup", &["toolchain", "list"]).is_some_and(|s| s.contains(toolchain))
}

fn has_rust_src(toolchain: &str) -> bool {
    output(
        "rustup",
        &["component", "list", "--toolchain", toolchain, "--installed"],
    )
    .is_some_and(|s| s.lines().any(|l| l.trim().starts_with("rust-src")))
}

/// The channel `crates/aisme-ebpf/rust-toolchain.toml` pins.
///
/// Checking for "a nightly" would pass while the pinned one is absent or lacks
/// `rust-src`, which is the failure this exists to catch.
fn pinned_channel() -> Option<String> {
    let pin = std::fs::read_to_string("crates/aisme-ebpf/rust-toolchain.toml").ok()?;
    pin.lines()
        .find_map(|l| l.trim().strip_prefix("channel"))
        .and_then(|r| r.split('"').nth(1))
        .map(str::to_owned)
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
