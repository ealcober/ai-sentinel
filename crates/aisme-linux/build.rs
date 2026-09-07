// SPDX-License-Identifier: Apache-2.0
//! Locate the BPF objects `cargo xtask build-ebpf` produces, if they exist.
//!
//! Both are built by a *different* toolchain — the nightly pinned in each
//! crate's `rust-toolchain.toml`, for `bpfel-unknown-none` — so neither can be
//! a Cargo dependency and `cargo check --workspace` must not require them. This
//! script reports whether each is there rather than insisting: a fresh clone
//! builds, and the code that needs one returns `Unsupported` naming the command
//! that produces it, which is the documented degradation (`I-19`).

use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(bpf_object_present)");
    println!("cargo:rustc-check-cfg=cfg(policy_object_present)");

    locate(
        &manifest,
        "../aisme-ebpf/target/bpfel-unknown-none/release/aisme-ebpf",
        "AISME_BPF_OBJECT",
        "bpf_object_present",
        "no BPF sensor object",
    );
    locate(
        &manifest,
        "../aisme-ebpf-policy/target/bpfel-unknown-none/release/aisme-ebpf-policy",
        "AISME_POLICY_OBJECT",
        "policy_object_present",
        "no BPF policy object",
    );
}

/// Emit the env var and cfg for one object, or a warning naming what is absent.
fn locate(manifest: &Path, relative: &str, var: &str, cfg: &str, what: &str) {
    match manifest.join(relative).canonicalize() {
        Ok(path) if path.is_file() => {
            println!("cargo:rerun-if-changed={}", path.display());
            println!("cargo:rustc-env={var}={}", path.display());
            println!("cargo:rustc-cfg={cfg}");
        }
        _ => {
            // Not an error, and not silent either: the reason surfaces where a
            // caller can act on it.
            println!("cargo:warning=aisme-linux: {what}; run `cargo xtask build-ebpf`");
        }
    }
}
