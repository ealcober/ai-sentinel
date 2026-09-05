// SPDX-License-Identifier: Apache-2.0
//! Minimal privileged loader.
//!
//! Holds `CAP_BPF` and `CAP_NET_ADMIN` just long enough to load and attach, so the
//! long-running daemons do not have to.

fn main() {
    // Phase F0: the crate exists and compiles. Behaviour arrives with its
    // own task; see docs/ai/STATE.md for the current one.
}
