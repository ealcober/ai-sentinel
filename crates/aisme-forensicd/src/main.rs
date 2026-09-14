// SPDX-License-Identifier: Apache-2.0
//! The cold-path daemon: `DuckDB`, `Parquet`, the Merkle chain, `OTLP` export.
//!
//! Everything expensive lives here so the hot path stays inside its budget.

mod tail;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((verb, rest)) if verb == "--tail" => std::process::exit(i32::from(tail::run(rest))),
        _ => {
            println!("aisme-forensicd --tail <wal-dir> [--once]");
            println!("DuckDB, Parquet, the Merkle chain and OTLP export arrive with F5");
        }
    }
}
