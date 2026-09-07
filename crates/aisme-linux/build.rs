// SPDX-License-Identifier: Apache-2.0
//! Locate the BPF object `cargo xtask build-ebpf` produces, if it exists.
//!
//! The object is built by a *different* toolchain — the nightly pinned in
//! `crates/aisme-ebpf/rust-toolchain.toml`, for `bpfel-unknown-none` — so it
//! cannot be a Cargo dependency and `cargo check --workspace` must not require
//! it. This script therefore reports whether it is there rather than insisting
//! on it: a fresh clone builds and its `BpfSensor::start` returns
//! `Unsupported` naming the command that produces the object, which is the
//! documented degradation (`I-19`) rather than a build failure nobody expected.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let obj = manifest
        .join("../aisme-ebpf/target/bpfel-unknown-none/release/aisme-ebpf")
        .canonicalize();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(bpf_object_present)");
    match obj {
        Ok(path) if path.is_file() => {
            println!("cargo:rerun-if-changed={}", path.display());
            println!("cargo:rustc-env=AISME_BPF_OBJECT={}", path.display());
            println!("cargo:rustc-cfg=bpf_object_present");
        }
        _ => {
            // Not an error, and not silent either: the reason surfaces at
            // `start()`, where a caller can act on it.
            println!("cargo:warning=aisme-linux: no BPF object; run `cargo xtask build-ebpf` to embed one");
        }
    }
}
