// SPDX-License-Identifier: Apache-2.0
//! Linux and WSL2 adapter: Aya loader, Landlock, cgroup hooks, seccomp, freezer.
//!
//! Implements the `aisme-core` traits for Linux. All Linux `cfg` and FFI live
//! here, never in the core (plan §3.1).

#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
mod resolve;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod sensor;
#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
pub use landlock::{
    probe as probe_landlock, restrict_writes_to, write_access_for, LandlockSupport,
};
#[cfg(target_os = "linux")]
pub use policy::{
    load_policy_maps, publish, BpfTrieBackend, PolicyReader, Sample, TrieEntry, TrieImage,
    MAP_POLICY_A, MAP_POLICY_B, MAP_POLICY_META, META_ACTIVE_INDEX, META_GENERATION, PIN_DIR,
    POLICY_TRIE_ENTRIES, TRIE_PATH_BYTES,
};
#[cfg(target_os = "linux")]
pub use resolve::{RealpathResolver, ResolverCounts};
#[cfg(target_os = "linux")]
pub use seccomp::{
    allow_ptrace_by, canonical_path, id_valid, install_openat_filter, locate_as_target,
    open_located, peer_pid, probe as probe_seccomp, read_target_path, recv, recv_fd, reproducible,
    respond_deny, respond_with_fd, send_fd, serve_notifications, serve_notifications_with,
    Notification, OpenRequest, SeccompSupport, Unreproducible,
};
#[cfg(target_os = "linux")]
pub use sensor::BpfSensor;
#[cfg(target_os = "linux")]
pub use session::{exit_like, spawn_supervised, Supervised};
