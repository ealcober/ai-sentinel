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

mod declare;
mod ipc;
mod platform;
mod runtime;
mod selfobs;
mod wal;

/// `H-03`: RSS is a budget, not an outcome. mimalloc's purge returns freed
/// pages to the OS instead of holding an arena that only ever grows; the
/// delay is set in `main` before anything allocates, because the variable is
/// read when the allocator initialises.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// `--ticks N` and `--serve-ipc <path>`, as `--run` takes them.
///
/// Its own function so `run_slice` stays about the slice: an argument parser
/// inline in a composition root makes the composition harder to read than the
/// thing it composes.
fn parse_run_args(rest: &[String]) -> std::io::Result<(u64, Option<String>)> {
    let mut ticks: u64 = 1_000;
    let mut socket: Option<String> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ticks" => {
                let Some(raw) = it.next() else {
                    return Err(std::io::Error::other("--ticks needs a value"));
                };
                ticks = raw
                    .parse()
                    .map_err(|_| std::io::Error::other(format!("--ticks {raw} is not a number")))?;
            }
            "--serve-ipc" => socket = it.next().cloned(),
            other => return Err(std::io::Error::other(format!("unknown argument `{other}`"))),
        }
    }
    Ok((ticks, socket))
}

/// Compose the whole slice and drive it (`F2.WS.02`).
///
/// Everything is the real thing except what the platform cannot supply: the
/// sensors are whatever `platform::sensors` composed, the resolver is the
/// platform's, and the sink is the file-backed WAL. Declarations arrive as a
/// `Sensor` like any other producer, so the engine sees one stream.
fn run_slice(dir: &std::path::Path, rest: &[String]) -> std::io::Result<()> {
    use aisme_core::detect::DetectorSet;
    use aisme_core::engine::Engine;
    use aisme_core::sensor::{Sensor, SensorConfig};
    use std::time::Duration;

    let (ticks, socket) = parse_run_args(rest)?;

    let caps = platform::probe();
    let mut sensors: Vec<Box<dyn Sensor>> = platform::sensors(&caps);
    let (declarations, declared) = declare::DeclarationSensor::new();
    sensors.push(Box::new(declarations));

    // `None`, not zero: nothing has published a policy to this daemon yet, and
    // a segment claiming generation 0 answers a forensic reader wrongly rather
    // than not at all. `aisme-loaderd --publish` tells it the real one.
    let sink = wal::WalSink::create(dir, None).map_err(|e| std::io::Error::other(e.detail))?;
    let segment = sink.current_segment();
    // Taken before the sink moves into the engine: the control plane writes
    // this cell when `aisme-loaderd --publish` reports a generation, and the
    // sink reads it at each segment roll.
    let generation = sink.generation_cell();
    let mut engine = Engine::new(sensors, Box::new(sink), DetectorSet::new(), 512);
    engine
        .start(&SensorConfig::default())
        .map_err(|e| std::io::Error::other(e.detail))?;
    let mut resolver = platform::resolver();

    // The socket runs on its own thread; the loop never blocks on it, and a
    // declaration crosses by channel rather than by sharing the engine.
    if let Some(path) = socket {
        let owner = ipc::Peer::from_current_uid();
        println!("ipc: serving {path} for uid {}", owner.uid);
        std::thread::spawn(move || {
            if let Err(e) = ipc::serve_feeding_sharing(
                std::path::Path::new(&path),
                owner.uid,
                declared,
                &generation,
                || false,
            ) {
                eprintln!("ipc: {e}");
            }
        });
    }

    println!("run: wal {}, {ticks} tick(s)", segment.display());
    // The tick budget, and the pace. Nothing in the loop blocks — a sensor with
    // no events returns immediately — so without this the loop spins a core
    // flat out, burns the §2.22 CPU budget on nothing, and drains no more
    // events for having tried. An idle tick sleeps what it did not spend; a
    // busy one does not sleep at all, so throughput under load is unaffected.
    let budget = Duration::from_millis(1);
    let mut totals = aisme_core::engine::TickReport::default();
    for tick in 0..ticks {
        let started = std::time::Instant::now();
        match engine.tick(resolver.as_mut(), budget, tick) {
            Ok(report) => {
                if report.drained == 0 {
                    if let Some(left) = budget.checked_sub(started.elapsed()) {
                        std::thread::sleep(left);
                    }
                }
                totals.drained += report.drained;
                totals.resolved += report.resolved;
                totals.unresolved += report.unresolved;
                totals.findings += report.findings;
            }
            // A sink that cannot write is the one failure the loop must not
            // continue through: events would be observed and lost, which is
            // worse than stopping and saying so.
            Err(e) => return Err(std::io::Error::other(e.detail)),
        }
    }
    println!(
        "run: {} event(s) drained, {} path(s) resolved, {} unresolved, {} finding(s)",
        totals.drained, totals.resolved, totals.unresolved, totals.findings
    );
    Ok(())
}

/// Say what this machine would serve, and what it costs where it falls short.
///
/// Its own function because it is the daemon's answer to "what am I", which is
/// a different question from "what do I do next" — and because `main` is a
/// dispatcher, not a place to grow prose.
fn report_composition() -> aisme_core::capability::CapabilitySet {
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
    caps
}

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
    let caps = report_composition();
    // Whether this platform can turn a requested path into a canonical one
    // (`F2.WS.02`), asked rather than assumed: `/` resolves to itself wherever
    // canonicalization works at all, and to nothing where it does not. A
    // daemon that cannot canonicalize still runs — every path simply keeps
    // `FLAG_PATH_UNRESOLVED` and no stage may decide on it (`I-28`) — so this
    // is a line to read, not a reason to refuse to start (`I-19`).
    {
        let mut resolver = platform::resolver();
        let mut probe = [0u8; 200];
        probe[0] = b'/';
        println!(
            "canonicalization: {}",
            match resolver.resolve(&mut probe, 1) {
                Some(_) => "available",
                None => "unavailable — every path stays FLAG_PATH_UNRESOLVED",
            }
        );
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
    // `--load-sensor`: ask this kernel whether it accepts the F2.WS.01 program,
    // and say what it answered. It exists because nothing else can ask: the
    // program is loaded by `aya`, and `bpftool` — which links libbpf — refuses
    // an aya object over the container before examining an instruction (bare
    // `tracepoint` section name, legacy `maps` section). So the verifier's
    // verdict is only obtainable from the product's own loader, run on the
    // kernel in question, which `cargo xtask vm run --with-dist` now stages.
    //
    // It attaches and detaches immediately. `I-12` keeps this out of the host
    // suite; it is a diagnostic for a disposable guest.
    if std::env::args().nth(1).as_deref() == Some("--load-sensor") {
        std::process::exit(platform::load_sensor_report());
    }
    // `--load-policy-probe`: the same question for the policy maps' own object
    // (`F2.WS.04`). Separate from `--load-sensor` so one answer cannot be read
    // as the other, and both are run in the same guest boot so a regression in
    // either is visible at once.
    if std::env::args().nth(1).as_deref() == Some("--load-policy-probe") {
        std::process::exit(platform::load_policy_report());
    }
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
    // `--run <wal-dir> [--serve-ipc <socket>] [--ticks N]` is F2's walking
    // skeleton, composed: the platform's sensors and resolver at one end, the
    // real WAL at the other, and — when a socket is given — declarations
    // arriving on the same stream as everything the kernel reports.
    let mut args = std::env::args().skip(1);
    if let Some(flag) = args.next() {
        if flag == "--run" {
            let Some(dir) = args.next() else {
                eprintln!("--run needs a directory for the WAL");
                return;
            };
            let rest: Vec<String> = args.collect();
            if let Err(e) = run_slice(std::path::Path::new(&dir), &rest) {
                eprintln!("run: {e}");
            }
            return;
        }
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
    use aisme_core::resolve::NullResolver;
    use aisme_core::sensor::SensorConfig;

    let mut resolver = NullResolver;

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
        if engine
            .tick(&mut resolver, Duration::ZERO, 1_000 + tick)
            .is_err()
        {
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

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod slice_tests {
    use aisme_core::detect::DetectorSet;
    use aisme_core::engine::Engine;
    use aisme_core::policy::PolicyGeneration;
    use aisme_core::sensor::{Sensor, SensorConfig};
    use aisme_core::wal;
    use aisme_ebpf_common::{EventKind, Payload};
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// The whole slice, over a real socket and onto a real file: a declaration
    /// crosses the control plane, becomes an event on the sensor stream, goes
    /// through the engine with the platform's resolver, and lands in the WAL
    /// where the core's own replayer reads it back.
    ///
    /// It is one test rather than four because the seams are what it exists to
    /// check. Each piece already has its own unit tests; this is the one that
    /// fails when they stop being connected to each other.
    #[test]
    fn a_declaration_crosses_the_socket_and_lands_in_the_wal() {
        let dir = std::env::temp_dir().join(format!("aisme-slice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("sock");

        let (declarations, declared) = crate::declare::DeclarationSensor::new();
        let sensors: Vec<Box<dyn Sensor>> = vec![Box::new(declarations)];

        let sink = crate::wal::WalSink::create(&dir, Some(PolicyGeneration(4))).unwrap();
        let segment = sink.current_segment();
        let mut engine = Engine::new(sensors, Box::new(sink), DetectorSet::new(), 16);
        engine.start(&SensorConfig::default()).unwrap();
        let mut resolver = crate::platform::resolver();

        // The server runs where it runs in production: its own thread, with the
        // hot loop never blocking on it.
        let uid = crate::ipc::Peer::from_current_uid().uid;
        let path = socket_path.clone();
        let server = std::thread::spawn(move || {
            let mut served = 0;
            let _ = crate::ipc::serve_feeding_sharing(
                &path,
                uid,
                declared,
                &crate::ipc::generation_cell(),
                move || {
                    served += 1;
                    served >= 1
                },
            );
        });

        // Connect, declare, read the answer.
        let mut stream = None;
        for _ in 0..100 {
            match UnixStream::connect(&socket_path) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let mut stream = stream.expect("the server binds its socket");
        writeln!(
            stream,
            r#"{{"jsonrpc":"2.0","id":1,"method":"declareToolCall","params":{{"toolcall_id":77,"tool_name":"Bash"}}}}"#
        )
        .unwrap();
        let mut answer = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut answer)
            .unwrap();
        assert!(answer.contains(r#""outcome":"accepted""#), "{answer}");
        drop(stream);

        // Drive the loop until the declaration has been through it.
        let mut drained = 0;
        for tick in 0..200u64 {
            let report = engine
                .tick(resolver.as_mut(), Duration::from_millis(1), tick)
                .unwrap();
            drained += report.drained;
            if drained > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(drained, 1, "the declaration reached the engine");

        // And it is on disk, readable by the core's own replayer.
        let bytes = std::fs::read(&segment).unwrap();
        let header = wal::SegmentHeader::decode(&bytes).unwrap();
        header
            .readable()
            .expect("this binary can read what it wrote");
        let mut events = Vec::new();
        wal::replay(&bytes, wal::SEGMENT_HEADER_SIZE, &mut events).unwrap();
        assert_eq!(events.len(), 1, "one declaration, one record");
        assert_eq!(events[0].kind.decode(), Ok(EventKind::ToolCall));
        match events[0].payload() {
            Some(Payload::Semantic(s)) => {
                assert_eq!(s.toolcall_id, 77);
                assert_eq!(&s.tool_name[..usize::from(s.name_len)], b"Bash");
            }
            other => panic!("wrong view: {other:?}"),
        }

        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
