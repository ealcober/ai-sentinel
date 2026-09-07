// SPDX-License-Identifier: Apache-2.0
//! The daemon's runtime (`F1.RT.02`).
//!
//! Tokio, **explicitly capped at two worker threads**, with a `LocalSet` for
//! the hot loop. The cap is not a tuning knob: an unbounded worker pool sizes
//! itself to the machine's cores, and every worker carries its own stacks,
//! its own allocator arenas and its own queues — on a 32-core workstation the
//! default pool costs more than the entire 50 MB budget (`H-03`, `I-13`).
//!
//! The hot loop runs on a `LocalSet` because it owns `!Send` state — the
//! interner's arena, the graph, the batch — and moving that between workers
//! would mean either locks on the T0 path or a copy per batch. One thread
//! owning it is both cheaper and easier to reason about (§3.4).

use std::io;

use tokio::runtime::{Builder, Runtime};
use tokio::task::LocalSet;

/// Worker threads the daemon may use, whatever the machine has.
pub const WORKER_THREADS: usize = 2;

/// Stack size per worker. The default 2 MiB is reserved address space rather
/// than resident memory, but the hot loop's frames are small and a smaller
/// stack keeps a runaway recursion from being a long fall.
pub const WORKER_STACK_BYTES: usize = 512 * 1024;

/// Build the daemon's runtime.
///
/// # Errors
///
/// Whatever tokio says when it cannot spawn its workers.
pub fn build() -> io::Result<Runtime> {
    Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        // A named thread is what shows up in `top`, in a core dump and in the
        // budget report; "tokio-runtime-worker" tells the reader nothing.
        .thread_name("aisme-agentd")
        .thread_stack_size(WORKER_STACK_BYTES)
        .enable_time()
        .build()
}

/// The set the hot loop's `!Send` tasks live on.
///
/// `F1.RT.03` is what drives it; until then it is exercised by this module's
/// own test, which is why it is not dead code but is not yet called from
/// `main` either.
#[must_use]
pub fn hot_loop_set() -> LocalSet {
    LocalSet::new()
}

#[cfg(test)]
// A panic *is* the failure report in a test, so the two lints the daemon
// denies are allowed here — and only here, which is the point: the denial
// covers the code that runs in production (§3.5, F1.RT.08).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_is_capped_at_two_workers() {
        let runtime = build().expect("runtime");
        assert_eq!(runtime.metrics().num_workers(), WORKER_THREADS);
        // And the cap does not depend on the machine: a 32-core host gets
        // the same two.
        assert!(
            std::thread::available_parallelism().map_or(true, |n| n.get() >= WORKER_THREADS),
            "the test machine has fewer cores than the cap, which would make this vacuous"
        );
    }

    #[test]
    fn the_hot_loop_set_runs_a_non_send_task() {
        let runtime = build().expect("runtime");
        let set = hot_loop_set();
        // `Rc` is the marker: this task could not be spawned on the runtime.
        let counted = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let handle = counted.clone();
        let out = set.block_on(&runtime, async move {
            handle.set(handle.get() + 1);
            handle.get()
        });
        assert_eq!(out, 1);
        assert_eq!(counted.get(), 1);
    }
}
