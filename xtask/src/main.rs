//! Build, test, budget certification and gate orchestration.
//!
//! Every gate in this project runs locally through this binary; there is no hosted
//! CI and no workflow triggers on push (`I-27`). Command surface: plan Annex H.

fn main() {
    // Phase F0: the crate exists and compiles. Behaviour arrives with its
    // own task; see docs/ai/STATE.md for the current one.
}
