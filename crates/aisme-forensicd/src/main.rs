// SPDX-License-Identifier: Apache-2.0
//! The cold-path daemon: `DuckDB`, `Parquet`, the Merkle chain, `OTLP` export.
//!
//! Everything expensive lives here so the hot path stays inside its budget.

fn main() {
    // Phase F0: the crate exists and compiles. Behaviour arrives with its
    // own task; see docs/ai/STATE.md for the current one.
}
