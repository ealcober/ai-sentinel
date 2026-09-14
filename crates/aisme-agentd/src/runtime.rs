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
use std::os::unix::ffi::OsStringExt as _;

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

/// Tell the service manager this daemon is up (`sd_notify(3)`, `Type=notify`).
///
/// The unit is `Type=notify` because that is what the state means: systemd
/// holds it in `activating` until the sensors are attached, the engine is
/// running and the control socket is listening — so `aisme-loaderd`'s
/// `Requires=` and anything ordered `After=` this unit start against a daemon
/// that is *ready*, not merely one that has been forked. `Type=exec` would
/// report ready at `exec`, before a single sensor existed.
///
/// **No dependency for eleven lines of protocol.** `NOTIFY_SOCKET` names an
/// `AF_UNIX` datagram socket; a leading `@` means the abstract namespace, where
/// the first byte is `NUL`. Writing `READY=1` to it is the whole contract.
///
/// Outside systemd `NOTIFY_SOCKET` is unset and this does nothing, which is why
/// it returns whether it notified rather than a `Result`: not being under a
/// service manager is not a failure, and a daemon started by hand must not
/// print an error about it.
pub(crate) fn notify_ready() -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some_and(|socket| notify_to(&socket, "READY=1"))
}

/// The send itself, with the socket passed in so a test can stand a real
/// listener behind it.
fn notify_to(socket: &std::ffi::OsStr, message: &str) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = socket.as_bytes();
    let path = if bytes.first() == Some(&b'@') {
        // Abstract namespace: systemd writes a leading `@`, the kernel wants a
        // leading NUL. A daemon that sent the `@` would create a *file* called
        // `@…` in the current directory and report success.
        let mut p = vec![0u8];
        p.extend_from_slice(&bytes[1..]);
        std::ffi::OsString::from_vec(p)
    } else {
        socket.to_owned()
    };
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return false;
    };
    sock.send_to(message.as_bytes(), std::path::Path::new(&path))
        .is_ok()
}

/// Drive a future to completion on this thread.
///
/// The adjudicators this daemon composes do their waiting **before** the future
/// is built — a terminal prompt blocks on `poll(2)` inside `ask`, and hands
/// back a future that is ready the moment it is polled. So a poll-once executor
/// is the whole of what is needed on the control thread, and pulling the Tokio
/// runtime into a path that never yields would buy nothing.
///
/// # Panics
///
/// If a future is not ready when polled. That is a contract break in the
/// adjudicator, not a state to recover from: an adjudicator that yields has to
/// say so, and the ladder would then need a real executor.
pub(crate) fn block_on<T>(future: aisme_core::adjudicate::BoxFuture<'_, T>) -> T {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: the vtable's four functions are no-ops over a null pointer they
    // never dereference, which is sound for a waker nothing ever wakes.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = future;
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an adjudicator returned a future that was not ready"),
    }
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

    /// A real listener, a real datagram: the production function is what runs.
    #[test]
    fn ready_reaches_a_listening_socket() {
        use std::os::unix::net::UnixDatagram;
        let dir = std::env::temp_dir().join(format!("aisme-notify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();

        assert!(notify_to(path.as_os_str(), "READY=1"));

        let mut buf = [0u8; 32];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Nothing listening is `false`, not a panic and not a silent `true`: the
    /// caller decides whether that matters, and outside systemd it does not.
    #[test]
    fn a_socket_nobody_is_listening_to_is_reported_and_not_survived_silently() {
        assert!(!notify_to(
            std::ffi::OsStr::new("/nonexistent/aisme/notify"),
            "READY=1"
        ));
    }
}
