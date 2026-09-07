// SPDX-License-Identifier: Apache-2.0
//! Causal graph construction and Lamport ordering.
//!
//! Pure logic, no I/O — it runs inside the hot loop. The taint algebra lives in
//! `aisme-core`.

pub mod clock;
pub mod graph;

pub use clock::{order, Causality, ClockDomain, ProducerId, Stamp, VectorClock, MAX_PRODUCERS};
pub use graph::{Attribution, Graph, GraphError, GraphStats};
