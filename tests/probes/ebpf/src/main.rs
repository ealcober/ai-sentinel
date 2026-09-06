// SPDX-License-Identifier: Apache-2.0
//! Verification probes for plan §F0.4, loaded inside a disposable VM (`I-12`).
//!
//! Two programs, one row each:
//!
//! * `kind_range` — `F0.VER.19`. §F1.1.1 claims "is this an execution hazard?"
//!   compiles to **one** comparison: `(kind - 0x4000) < 0x1000` in unsigned
//!   arithmetic, no map lookup. Loading this object is a full verifier pass over
//!   that pattern with a runtime input, which is what "verifier-accepted" means.
//! * `connect4` — `F0.VER.16`. A `BPF_CGROUP_INET4_CONNECT` hook that denies one
//!   destination port. Attached to a session cgroup it must deny from inside that
//!   cgroup and nothing else, with `bpf` absent from the active LSM list.
//!
//! Neither calls a BPF helper, so no `gpl_only` requirement applies and the
//! licence section below is the honest Apache-2.0 (see Cargo.toml).

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, socket_filter},
    programs::{SkBuffContext, SockAddrContext},
};

/// The port the connect probe denies. 9998, so the host-side probe of
/// `F0.VER.20` and this one read alike in the register.
const DENIED_PORT_BE: u32 = 9998u16.to_be() as u32;

/// The §F1.1.1 EXEC range: `0x4000..0x5000`.
const EXEC_BASE: u16 = 0x4000;
const EXEC_SPAN: u16 = 0x1000;

/// `F0.VER.19` — one unsigned comparison decides range membership.
///
/// The "kind" is the low 16 bits of the packet length, so the verifier sees a
/// runtime value rather than a constant it can fold away. Returns 1 when the
/// kind is an execution hazard, else 0.
#[socket_filter]
pub fn kind_range(ctx: SkBuffContext) -> i64 {
    let kind = (ctx.len() & 0xFFFF) as u16;
    // Wrapping subtraction turns `base <= kind < base + span` into a single
    // unsigned compare; anything below `base` wraps high and fails it.
    i64::from(kind.wrapping_sub(EXEC_BASE) < EXEC_SPAN)
}

/// `F0.VER.16` — deny `connect()` to one port for whatever cgroup this is
/// attached to; allow everything else. 1 allows, 0 denies with `EPERM`.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    // SAFETY: `sock_addr` is the kernel-provided context for this program type
    // and is valid for the duration of the call; reading a field is the only use.
    let port = unsafe { (*ctx.sock_addr).user_port };
    i32::from(port != DENIED_PORT_BE)
}

/// Read by the verifier at load time.
#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 11] = *b"Apache-2.0\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
