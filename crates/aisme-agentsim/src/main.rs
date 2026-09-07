// SPDX-License-Identifier: Apache-2.0
//! The simulator's command line.

use aisme_agentsim::trace;

fn main() {
    println!(
        "aisme-agentsim: trace format v{} (F1.SIM.02)",
        trace::FORMAT_VERSION
    );
    println!("replay arrives in the same phase (F1.SIM.01)");
}
