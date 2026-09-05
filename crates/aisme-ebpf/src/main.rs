//! The BPF programs.
//!
//! Built for `bpfel-unknown-none` by `cargo xtask build-ebpf`, never by
//! `cargo check --workspace`. The object it produces is embedded into
//! `aisme-agentd` with `include_bytes!`.

#![no_std]
#![no_main]

// Phase F0: the crate exists and pins its toolchain. The programs arrive in F2
// (one tracepoint) and F3 (the full probe set).
