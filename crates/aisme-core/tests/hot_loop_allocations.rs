// SPDX-License-Identifier: Apache-2.0
//! `F1.RT.03`: the hot loop allocates nothing in steady state.
//!
//! Measured with a counting global allocator rather than `dhat`: the
//! property is "how many allocations did this call make", which a counter
//! answers exactly, and a counter needs no dependency, no profiler output
//! to parse and no second global allocator fighting the one `agentd` sets
//! (`F1.RT.01`). The first tick is allowed to allocate — sensors start, the
//! trace is handed over — and every tick after it must not.

use aisme_core::resolve::NullResolver;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use aisme_core::detect::DetectorSet;
use aisme_core::engine::Engine;
use aisme_core::mock::{CountingSink, MockSensor};
use aisme_core::sensor::SensorConfig;
use aisme_ebpf_common::RawEvent;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

struct Counting;

// SAFETY: every call is forwarded to `System`, which upholds the contract;
// the counter only observes.
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

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f` with the counter on, and return how many allocations it made.
fn allocations(f: impl FnOnce()) -> usize {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    f();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCATIONS.load(Ordering::Relaxed)
}

#[test]
fn a_steady_state_tick_allocates_nothing() {
    // A trace long enough to keep the loop fed for many ticks, so what is
    // measured is the steady state and not an empty pass.
    let trace: Vec<RawEvent> = (0..4_096)
        .map(|i| {
            let mut event = RawEvent::ZERO;
            event.kind = aisme_ebpf_common::EventKind::FileOpen.into();
            event.seq = i;
            let mut file = aisme_ebpf_common::FilePayload {
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
            // A handful of distinct paths, so the interner both stores and
            // hits — a loop that only ever hit its cache would not measure
            // the storing path.
            let path = format!("/work/repo/src/file{}.rs", i % 97);
            file.path_len = u16::try_from(path.len()).unwrap();
            file.path[..path.len()].copy_from_slice(path.as_bytes());
            event.payload.file = file;
            event
        })
        .collect();

    let mut resolver = NullResolver;

    let mut engine = Engine::new(
        vec![Box::new(MockSensor::new(trace))],
        // A sink that keeps every event would grow its own Vec, and that
        // growth is not the loop's: the WAL writes into mapped segments
        // (F1.RT.05). CountingSink has the shape the measurement needs.
        Box::new(CountingSink::new()),
        DetectorSet::new(),
        128,
    );
    engine.start(&SensorConfig::default()).unwrap();

    // The first tick may allocate: the sink is taking its first batch.
    let first = engine.tick(&mut resolver, Duration::ZERO, 1_000).unwrap();
    assert_eq!(first.drained, 128);

    // Every tick after it must not. Ten of them, measured together, so a
    // single stray allocation anywhere in the loop shows up.
    let mut drained = 0;
    let allocated = allocations(|| {
        for i in 0..10u64 {
            drained += engine
                .tick(&mut resolver, Duration::ZERO, 2_000 + i * 1_000)
                .unwrap()
                .drained;
        }
    });
    assert_eq!(drained, 1_280, "ten full batches");
    assert_eq!(
        allocated, 0,
        "the hot loop allocated {allocated} time(s) over ten ticks; F1.RT.03 requires zero"
    );
    assert_eq!(engine.totals().interned, 1_408);
}

#[test]
fn the_measurement_itself_would_notice_an_allocation() {
    // A counter that never fires proves nothing; this is the control.
    let allocated = allocations(|| {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..1_000 {
            v.push(i);
        }
        assert_eq!(v.len(), 1_000);
    });
    assert!(allocated > 0, "the counting allocator saw nothing at all");
}
