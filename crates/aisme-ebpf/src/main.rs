// SPDX-License-Identifier: GPL-2.0-only
//! The BPF programs.
//!
//! Built for `bpfel-unknown-none` by `cargo xtask build-ebpf`, never by
//! `cargo check --workspace`. The object it produces is embedded into
//! `aisme-agentd` with `include_bytes!`.
//!
//! GPL-2.0-only is not a preference: the verifier inspects which helpers a
//! program calls, and a `gpl_only` helper requires the program to declare a
//! GPL-compatible licence at load time. `LICENSE` below is that declaration, and
//! it is read by the kernel, not by a human.

#![no_std]
#![no_main]

// Phase F0 pins the toolchain and proves it builds against Aya. The programs
// arrive in F2 (one tracepoint) and F3 (the full probe set).

/// Compile-time proof that `aya-ebpf` itself compiles for `bpfel-unknown-none`
/// under the pinned toolchain, which is what `F0.REPO.02` validates.
///
/// Resolving the dependency is not the same as building it: naming a type from
/// it is what puts Aya through the BPF codegen path. `F2.WS.02` replaces this
/// with the first real program.
const _: () = {
    let _helper_return: Option<aya_ebpf::cty::c_long> = None;
};

/// The licence string the verifier reads when the object is loaded.
#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// `no_std` with `no_main` has no runtime to unwind into. A BPF program cannot
/// panic in the Rust sense anyway — the verifier rejects unbounded loops, so this
/// is unreachable by construction and exists to satisfy the target.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
