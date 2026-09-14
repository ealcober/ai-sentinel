// SPDX-License-Identifier: Apache-2.0
//! The `aisme` command line: run, status, policy, verify, pair.
//!
//! `aisme run -- <cmd>` is the documented default onboarding path and the primary
//! prompt channel on headless and WSL2 hosts.

mod run;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((verb, rest)) if verb == "run" => std::process::exit(i32::from(run::run(rest))),
        _ => {
            println!("aisme run [--scope <path>…] -- <command> [args…]");
            println!("status, policy, verify and pair arrive with F8.CLI.01");
        }
    }
}
