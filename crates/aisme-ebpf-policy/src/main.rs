// SPDX-License-Identifier: GPL-2.0-only
//! The policy maps, and nothing else (`F2.WS.04`).
//!
//! A second object, deliberately. `BPF_MAP_TYPE_ARRAY_OF_MAPS` exists at the
//! pinned `aya-ebpf 0.2.1` only as a **BTF** map, while the sensor's four maps
//! are `#[map]` and land in the legacy `maps` section. Adding these two to that
//! object left it carrying both sections and unable to load at all — measured
//! on 6.8 and 5.4, where 6.8 had been loading — so they live here, where a
//! failure cannot regress a program that works.
//!
//! **No programs.** The question this object answers is whether the maps load;
//! a program would add a second way to fail and make the answer ambiguous. The
//! programs that read these maps arrive with `F3.PT.02`.

#![no_std]
#![no_main]

use aya_ebpf::btf_maps::{Array, ArrayOfMaps, LpmTrie};
use aya_ebpf::macros::btf_map;

/// The policy double buffer: two inner LPM tries behind one outer array.
///
/// Publication fills the **idle** inner map — which nothing is looking up — and
/// then swaps it in with a single `bpf_map_update_elem` on the outer array. One
/// element write is the only mutation a reader can observe, which is what makes
/// `PL-04`'s "never a torn policy" a property rather than a hope: filling a trie
/// entry by entry would let a reader see half a policy.
///
/// The key is the path bytes, bounded by the wire's own 200 (`FilePayload::path`
/// is that long, so a path that cannot be a key could not have been an event).
/// The value is the verdict's wire byte (§B.10).
#[btf_map]
static AISME_POLICY: ArrayOfMaps<LpmTrie<[u8; 200], u8, 1024>, 2> = ArrayOfMaps::new();

/// `[generation, active_index]`.
///
/// Written before the swap and read after it, so a reader that sees generation
/// N sees policy N. The generation travels **in** the publication rather than
/// beside it, which is what `PL-04` asks for.
#[btf_map]
static AISME_POLICY_META: Array<u64, 2> = Array::new();

/// The licence the verifier reads at load time.
#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// `no_std` with `no_main` has no runtime to unwind into.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
