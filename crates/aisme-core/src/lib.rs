// SPDX-License-Identifier: Apache-2.0
//! The engine: ontology, the three traits, policy IR, taint algebra, detectors.
//!
//! This crate has no I/O, no async runtime, no `cfg(target_os)` and no platform
//! dependency. That single rule is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK (plan §3.1, rule `A-01`).
