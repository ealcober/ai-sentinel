// SPDX-License-Identifier: Apache-2.0
//! Linux and WSL2 adapter: Aya loader, Landlock, cgroup hooks, seccomp, freezer.
//!
//! Implements the `aisme-core` traits for Linux. All Linux `cfg` and FFI live
//! here, never in the core (plan §3.1).

#[cfg(target_os = "linux")]
mod policy;
#[cfg(target_os = "linux")]
mod resolve;
#[cfg(target_os = "linux")]
mod sensor;

#[cfg(target_os = "linux")]
pub use policy::{
    load_policy_maps, publish, BpfTrieBackend, PolicyReader, Sample, TrieEntry, TrieImage,
    MAP_POLICY_A, MAP_POLICY_B, MAP_POLICY_META, META_ACTIVE_INDEX, META_GENERATION, PIN_DIR,
    POLICY_TRIE_ENTRIES, TRIE_PATH_BYTES,
};
#[cfg(target_os = "linux")]
pub use resolve::{RealpathResolver, ResolverCounts};
#[cfg(target_os = "linux")]
pub use sensor::BpfSensor;
