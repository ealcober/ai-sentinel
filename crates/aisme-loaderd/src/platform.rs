// SPDX-License-Identifier: Apache-2.0
//! The loader's composition root (plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in this crate permitted to name a concrete adapter or use
//! `cfg(target_os)`.** `A-05` is checked on every L3 engine, not only
//! `aisme-agentd`: a binary that holds `CAP_BPF` is exactly the one whose
//! platform choices must sit in one auditable place.
//!
//! Everything above it works on `aisme-core` types — a `TrieImage` and a
//! `PolicyGeneration` — and does not know which kernel interface put them
//! there.

use aisme_core::error::Result;
use aisme_core::policy::PolicyGeneration;

/// Publish a lowered policy and return the generation it became.
///
/// # Errors
///
/// Whatever the platform's publication refused, with its cause.
#[cfg(target_os = "linux")]
pub fn publish(image: &aisme_linux::TrieImage) -> Result<PolicyGeneration> {
    aisme_linux::publish(image)
}

/// No platform here can hold a BPF map, and saying so beats pretending.
#[cfg(not(target_os = "linux"))]
pub fn publish(_image: &Unsupported) -> Result<PolicyGeneration> {
    Err(aisme_core::error::Error::unsupported(
        "publishing a policy needs a Linux kernel with bpffs",
    ))
}

/// The image type, named once so the code above is written against a type and
/// not against a `cfg`.
#[cfg(target_os = "linux")]
pub type Image = aisme_linux::TrieImage;
/// Off Linux there is no lowered form to carry.
#[cfg(not(target_os = "linux"))]
pub type Image = Unsupported;

/// A stand-in so the signature above exists on every target.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Default)]
pub struct Unsupported;

/// The backend that lowers a compiled policy for this platform.
///
/// # Errors
///
/// Whatever the backend refused, with the rule that caused it.
#[cfg(target_os = "linux")]
pub fn lower(policy: &aisme_core::policy::CompiledPolicy) -> Result<Image> {
    use aisme_core::policy::PolicyBackend as _;
    aisme_linux::BpfTrieBackend
        .lower(policy)
        .map_err(|e| aisme_core::error::Error::unsupported(format!("{e:?}")))
}

/// Off Linux nothing lowers.
#[cfg(not(target_os = "linux"))]
pub fn lower(_policy: &aisme_core::policy::CompiledPolicy) -> Result<Image> {
    Err(aisme_core::error::Error::unsupported(
        "no policy backend on this platform",
    ))
}
