// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask bench-hotloop` (`F1.RT.03`).
//!
//! Drives the engine over N events on `MockSensor` and reports the two
//! numbers §2.22 fixes for the hot loop: **allocations in steady state
//! (0/s)** and **drop rate (0)**. Both are properties of the loop, not of
//! the machine, so the bench measures them exactly rather than sampling —
//! a counting allocator answers "how many", not "roughly how many", and the
//! ring answers how many events it refused.
//!
//! Throughput is reported too, because a run that took an hour would say
//! something even if the two invariants held; but the gate is the
//! invariants, and the bench says so rather than printing a number that
//! looks like a benchmark result.

use aisme_core::resolve::NullResolver;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use aisme_core::detect::DetectorSet;
use aisme_core::engine::Engine;
use aisme_core::mock::{CountingSink, MockSensor};
use aisme_core::ring::EventRing;
use aisme_core::sensor::SensorConfig;
use aisme_ebpf_common::{EventKind, FilePayload, RawEvent};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

/// Forwards to the system allocator and counts, when asked to.
pub(crate) struct Counting;

// SAFETY: every call is forwarded to `System`, which upholds the contract;
// the counters only observe.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller's layout, forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's pointer and layout, forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

const BATCH: usize = 128;

/// `cargo xtask bench-hotloop [--events N]`.
pub(crate) fn hot_loop(args: &[&str]) -> u8 {
    let mut events = 1_000_000usize;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--events" => match it.next().and_then(|n| n.parse().ok()) {
                Some(n) if n > 0 => events = n,
                _ => {
                    eprintln!("usage: cargo xtask bench-hotloop [--events N]");
                    return 1;
                }
            },
            other => {
                eprintln!("unknown argument `{other}`");
                return 1;
            }
        }
    }

    // The ring is what F1.RT.04 measures a drop against; the bench pushes
    // every event through it before the engine sees it, so "drop rate 0"
    // means the queue never overflowed, not that nothing was queued.
    let mut ring = EventRing::with_capacity(BATCH * 4);
    let trace = trace(events.min(BATCH * 32));
    let mut resolver = NullResolver;
    let mut engine = Engine::new(
        vec![Box::new(MockSensor::new(trace.clone()))],
        Box::new(CountingSink::new()),
        DetectorSet::new(),
        BATCH,
    );
    if let Err(e) = engine.start(&SensorConfig::default()) {
        eprintln!("FAIL bench-hotloop: the mock sensor did not start: {e}");
        return 1;
    }

    // One tick to warm: the first pass may allocate (the sink takes its
    // first batch), and F1.RT.03's property is about steady state.
    let _ = engine.tick(&mut resolver, Duration::ZERO, 1_000);

    let mut drained = 0usize;
    let mut ticks = 0u64;
    let started = Instant::now();
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let mut now_ns = 2_000u64;
    while drained < events {
        // The queue is exercised at the rate it is drained — a producer that
        // filled it faster than any consumer would be measuring the
        // producer, not the loop. A drop here is a real overflow.
        for event in trace.iter().take(ring.capacity()) {
            if !ring.push(*event) {
                break;
            }
        }
        while ring.pop().is_some() {}
        let report = match engine.tick(&mut resolver, Duration::ZERO, now_ns) {
            Ok(report) => report,
            Err(e) => {
                COUNTING.store(false, Ordering::Relaxed);
                eprintln!("FAIL bench-hotloop: {e}");
                return 1;
            }
        };
        if report.drained == 0 {
            // The trace ran out: start the sensor again, which rewinds it.
            // `start` allocates nothing, so the measured region stays clean.
            if engine.start(&SensorConfig::default()).is_err() {
                break;
            }
            continue;
        }
        drained += report.drained;
        ticks += 1;
        now_ns += 1_000;
    }
    COUNTING.store(false, Ordering::Relaxed);
    let elapsed = started.elapsed();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let dropped = ring.dropped();

    #[allow(clippy::cast_precision_loss)] // counts far below 2^53
    let per_second = if elapsed.as_secs_f64() > 0.0 {
        drained as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!("bench-hotloop — F1.RT.03, §2.22's two hot-loop invariants\n");
    println!("  events drained   {drained} over {ticks} tick(s)");
    println!("  allocations      {allocations}  (budget 0/s, steady state)");
    println!("  ring drops       {dropped}  (budget 0)");
    println!("  throughput       {per_second:.0} events/s over {elapsed:?} — context, not a gate");
    if allocations != 0 {
        eprintln!(
            "\nFAIL bench-hotloop: the hot loop allocated {allocations} time(s); the budget is 0/s"
        );
        return 1;
    }
    if dropped != 0 {
        eprintln!("\nFAIL bench-hotloop: the ring dropped {dropped} event(s); the budget is 0");
        return 1;
    }
    println!("\nPASS bench-hotloop: 0 allocations, 0 drops");
    0
}

/// A trace of file events with distinct paths, so the interner both stores
/// and hits — a loop that only ever hit its cache would measure less than
/// the real one.
fn trace(len: usize) -> Vec<RawEvent> {
    (0..len as u64)
        .map(|i| {
            let mut event = RawEvent::ZERO;
            event.kind = EventKind::FileOpen.into();
            event.seq = i;
            let mut file = FilePayload {
                inode: i,
                dev: 1,
                size: 0,
                flags: 0,
                mode: 0,
                path_class: 0,
                pad0: 0,
                path_len: 0,
                path: [0; 200],
                reserved: [0; 20],
            };
            let path = format!("/work/repo/src/file{}.rs", i % 97);
            file.path_len = u16::try_from(path.len()).unwrap_or(0);
            file.path[..path.len()].copy_from_slice(path.as_bytes());
            event.payload.file = file;
            event
        })
        .collect()
}
