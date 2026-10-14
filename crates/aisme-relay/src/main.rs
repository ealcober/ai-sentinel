// SPDX-License-Identifier: Apache-2.0
//! Blind store-and-forward relay.
//!
//! It sees ciphertext and routing metadata, never plaintext telemetry, verdicts or
//! notification content (`I-07`). Self-hostable.
//!
//! **A stub until phase `F11`**, which owns pairing, the blind relay and the
//! mobile app.

fn main() {
    // Phase F0: the crate exists and compiles. Behaviour arrives with its
    // own task; see docs/ai/STATE.md for the current one.
}
