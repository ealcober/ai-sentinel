// SPDX-License-Identifier: Apache-2.0
//! The hot-path daemon. Budget: 50 MB RSS, under 3% CPU, T0 p99 under 15 µs.
//!
//! Depends on adapters only through the `aisme-core` traits. `src/platform` is the
//! composition root — the only module permitted to name concrete adapters or use
//! `cfg(target_os)` (plan §3.1).

mod platform;
mod runtime;
mod selfobs;

/// `H-03`: RSS is a budget, not an outcome. mimalloc's purge returns freed
/// pages to the OS instead of holding an arena that only ever grows; the
/// delay is set in `main` before anything allocates, because the variable is
/// read when the allocator initialises.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // 10 ms: purge soon after a burst, not on every free. The plan's value
    // (§F1.6, MIMALLOC_PURGE_DELAY=10); `verify-budgets --profile idle`
    // measures what it buys.
    if std::env::var_os("MIMALLOC_PURGE_DELAY").is_none() {
        // SAFETY: single-threaded here — this runs before the runtime starts
        // and before any thread is spawned, so no other thread can be
        // reading the environment.
        unsafe { std::env::set_var("MIMALLOC_PURGE_DELAY", "10") };
    }
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
    // F1.RT.03 moves the hot loop onto this; for now, building it is what
    // proves the cap holds on this machine.
    let mut metrics = aisme_core::metrics::Metrics::default();
    metrics.observe_tier(
        &aisme_core::tier::Degradation::starting_at(&caps)
            .state()
            .clone(),
    );
    if let Some(usage) = selfobs::SelfObserver::new().sample() {
        metrics.observe_process(usage.rss_bytes, usage.cpu_milli);
        println!(
            "self: rss {} MiB, capability level {:?}, attention {}",
            usage.rss_bytes / (1024 * 1024),
            metrics.capability_level,
            metrics.needs_attention()
        );
    } else {
        println!("self: /proc/self unavailable — rss and cpu stay absent, not zero");
    }
    match runtime::build() {
        Ok(rt) => {
            let set = runtime::hot_loop_set();
            let ready = set.block_on(&rt, async { rt.metrics().num_workers() });
            println!(
                "runtime: {ready} worker thread(s), {} KiB stack each, hot-loop set ready",
                runtime::WORKER_STACK_BYTES / 1024
            );
        }
        Err(e) => eprintln!("runtime: could not start: {e}"),
    }
}
