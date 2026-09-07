// SPDX-License-Identifier: Apache-2.0
//! The hot-path daemon. Budget: 50 MB RSS, under 3% CPU, T0 p99 under 15 µs.
//!
//! Depends on adapters only through the `aisme-core` traits. `src/platform` is the
//! composition root — the only module permitted to name concrete adapters or use
//! `cfg(target_os)` (plan §3.1).

// §3.5, `F1.RT.08`: a panic in a security daemon is a silent protection
// outage — the process dies and nothing is watched until someone notices. So
// the two ways to write one by accident are denied here rather than left to
// review. `expect_used` is denied too: a message does not make a panic safe,
// it makes it legible after the fact.
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod ipc;
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
    // F1.RT.06 + the GATE F1 budget line: compose the engine on MockSensor,
    // let it settle, and write what this daemon actually costs. A budget
    // nobody measured is a budget nobody keeps.
    if std::env::args().nth(1).as_deref() == Some("--measure-idle") {
        match measure_idle() {
            Ok(path) => println!("idle profile written to {path}"),
            Err(e) => {
                eprintln!("measure-idle: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    // F1.IPC.01: the control socket. `--serve-ipc <path>` runs it; without
    // the flag the daemon reports that it can, because F1 has no hot loop to
    // serve alongside it yet (that is F2's walking skeleton).
    let mut args = std::env::args().skip(1);
    if let Some(flag) = args.next() {
        if flag == "--serve-ipc" {
            let Some(path) = args.next() else {
                eprintln!("--serve-ipc needs a socket path");
                return;
            };
            let owner = ipc::Peer::from_current_uid();
            println!("ipc: serving {path} for uid {}", owner.uid);
            if let Err(e) = ipc::serve(std::path::Path::new(&path), owner.uid, || false) {
                eprintln!("ipc: {e}");
            }
            return;
        }
        eprintln!("unknown argument `{flag}`");
        return;
    }
    println!(
        "ipc: ready — `--serve-ipc <path>` serves the control plane (protocol {})",
        aisme_proto::rpc::PROTOCOL_VERSION
    );
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

/// Run the engine on `MockSensor` and write the idle profile's artefact
/// (`profiles.idle.agentd_rss_mb`, GATE F1).
///
/// "Idle" is the plan's sense: `agentd` composed and running, with the mock
/// sensor and no platform sensors attached (`budgets.toml`'s comment says
/// exactly that). The number is this process's RSS after the loop has run,
/// so it includes the allocator, the runtime and the engine's arenas — the
/// things a smaller measurement would leave out.
fn measure_idle() -> std::io::Result<String> {
    use std::io::Write as _;
    use std::time::Duration;

    use aisme_core::detect::DetectorSet;
    use aisme_core::engine::Engine;
    use aisme_core::mock::{CountingSink, MockSensor};
    use aisme_core::sensor::SensorConfig;

    let mut engine = Engine::new(
        vec![Box::new(MockSensor::with_every_kind())],
        Box::new(CountingSink::new()),
        DetectorSet::new(),
        128,
    );
    engine
        .start(&SensorConfig::default())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    for tick in 0..1_000u64 {
        if engine.tick(Duration::ZERO, 1_000 + tick).is_err() {
            break;
        }
        if tick % 100 == 0 {
            // The trace is short; starting again rewinds it, so the loop
            // keeps working rather than idling on an exhausted sensor.
            let _ = engine.start(&SensorConfig::default());
        }
    }
    let usage = selfobs::SelfObserver::new().sample().ok_or_else(|| {
        std::io::Error::other("/proc/self is unavailable; RSS cannot be measured here")
    })?;
    #[allow(clippy::cast_precision_loss)] // an RSS is far below 2^53 bytes
    let rss_mb = usage.rss_bytes as f64 / (1024.0 * 1024.0);
    let dir = std::path::Path::new("target/budget");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("idle.toml");
    let mut file = std::fs::File::create(&path)?;
    writeln!(
        file,
        "# Written by `aisme-agentd --measure-idle` ({} events through the engine on\n\
         # MockSensor, no platform sensors). Read by `cargo xtask verify-budgets`.\n\
         \"profiles.idle.agentd_rss_mb\" = {rss_mb:.2}\n\
         \"process.agentd.rss_mb\" = {rss_mb:.2}",
        engine.totals().drained
    )?;
    println!(
        "idle: rss {rss_mb:.2} MB after {} events",
        engine.totals().drained
    );
    Ok(path.display().to_string())
}
