// SPDX-License-Identifier: Apache-2.0
//! The engine: ontology, the three traits, policy IR, taint algebra, detectors.
//!
//! This crate has no I/O, no async runtime, no `cfg(target_os)` and no platform
//! dependency. That single rule is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK (plan §3.1, rule `A-01`).

pub mod intern;
pub mod ontology;
pub mod taint;

pub use intern::{Interner, InternerStats, StrId, TooLong};
pub use ontology::{
    BootNs, Digest, Edge, EdgeKind, Node, NodeId, NodeKind, PathClass, PermissionGroup, SessionId,
};
pub use taint::Taint;
