// SPDX-License-Identifier: Apache-2.0
//! The hot-path daemon. Budget: 50 MB RSS, under 3% CPU, T0 p99 under 15 µs.
//!
//! Depends on adapters only through the `aisme-core` traits. `src/platform` is the
//! composition root — the only module permitted to name concrete adapters or use
//! `cfg(target_os)` (plan §3.1).

mod platform;

fn main() {
    // F1: the composition root exists and composes. The hot loop that drives
    // it is F1.RT.03; until then, report what this machine would serve.
    let caps = platform::probe();
    println!(
        "aisme-agentd: tier {}, {} sensor(s), {} enforcer(s), {} adjudicator rung(s)",
        platform::tier(&caps).as_str(),
        platform::sensors(&caps).len(),
        platform::enforcers(&caps).len(),
        platform::adjudicators(&caps).len()
    );
    for lost in aisme_core::tier::degradations(&caps) {
        println!("  degraded: {lost}");
    }
}
