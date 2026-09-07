// SPDX-License-Identifier: Apache-2.0
//! `PathResolver`: the ingest hook that turns a requested path into a
//! canonical one (`F2.WS.02`).
//!
//! **This is not one of the three §3.2 traits and is not part of the GATE F1
//! freeze.** `Sensor`, `Enforcer` and `Adjudicator` are the platform contracts;
//! this is an internal ingest hook, and it exists because canonicalizing a path
//! is I/O — `readlink`, `openat2`, `/proc/self/fd` — and `aisme-core` has no
//! I/O by rule `A-01`. The loop does not need to know *how* a path is resolved,
//! only that something resolves it, so the syscall stays in L2 where platform
//! code belongs and both consumers resolve the same way.
//!
//! `F5.CO.04` widens this into full canonical path matching; this is that
//! component arriving early, not a second one.

/// Turns the path a caller asked for into the path the kernel would open.
///
/// Bytes in, bytes out, no allocation: the buffer is the event's own, so a
/// resolution is a rewrite in place and the hot loop's zero-allocation
/// invariant (`I-22`) is unaffected.
pub trait PathResolver {
    /// Resolve the first `len` bytes of `buf` in place, returning the new
    /// length, or `None` when the path cannot be resolved.
    ///
    /// `None` is a real answer, not a failure: a file unlinked between the
    /// syscall and the drain has no canonical path, and the event keeps
    /// `FLAG_PATH_UNRESOLVED` to say the path is what the caller asked for.
    /// Guessing would be worse than not knowing, because a decision made on a
    /// guessed path is a decision made on the wrong file.
    fn resolve(&mut self, buf: &mut [u8], len: usize) -> Option<usize>;
}

/// Resolves nothing and says so.
///
/// The resolver for every path with no kernel behind it: `MockSensor` runs,
/// the benches run, and `F2.WS.10`'s no-kernel gate measures **the same code**
/// as the real composition rather than a shorter one. It returns `None`, so an
/// event keeps `FLAG_PATH_UNRESOLVED` — which is exactly true, and is why this
/// is not `Some(len)`: returning the input unchanged would claim the path was
/// canonicalized and it was not.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullResolver;

impl PathResolver for NullResolver {
    fn resolve(&mut self, _buf: &mut [u8], _len: usize) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_null_resolver_reports_unresolved_rather_than_echoing_the_input() {
        let mut buf = *b"/tmp/x\0\0";
        let mut r = NullResolver;
        // Echoing `Some(6)` would tell the loop the path is canonical. It is
        // not, and the flag that says so must survive.
        assert_eq!(r.resolve(&mut buf, 6), None);
        assert_eq!(&buf[..6], b"/tmp/x", "it must not touch the buffer either");
    }
}
