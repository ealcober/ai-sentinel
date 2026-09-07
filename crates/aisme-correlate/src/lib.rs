// SPDX-License-Identifier: Apache-2.0
//! Causal graph construction and Lamport ordering.
//!
//! Pure logic, no I/O — it runs inside the hot loop. The taint algebra lives in
//! `aisme-core`.

pub mod graph;

pub use graph::{Attribution, Graph, GraphError, GraphStats};
