//! Linux and WSL2 adapter: Aya loader, Landlock, cgroup hooks, seccomp, freezer.
//!
//! Implements the `aisme-core` traits for Linux. All Linux `cfg` and FFI live
//! here, never in the core (plan §3.1).
