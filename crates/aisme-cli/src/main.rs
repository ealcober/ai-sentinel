// SPDX-License-Identifier: Apache-2.0
//! The `aisme` command line: run, status, policy, verify, pair.
//!
//! `aisme run -- <cmd>` is the documented default onboarding path and the primary
//! prompt channel on headless and WSL2 hosts.

mod declare;
mod platform;
mod run;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((verb, rest)) if verb == "run" => std::process::exit(i32::from(run::run(rest))),
        // The agent's harness saying what it is about to do (`F2.WS.03`). It
        // reads a pre-tool hook's JSON on stdin and always exits 0: a
        // declaration authorizes nothing, so a failure here has nothing to
        // protect, and enforcement is in the kernel where failure is closed.
        Some((verb, rest)) if verb == "declare" => {
            std::process::exit(i32::from(declare::declare(rest)));
        }
        _ => {
            println!(
                "aisme run [--scope <path>…] [--trap-openat] [--escalate <prefix>…] -- <command> [args…]"
            );
            println!(
                "aisme declare [--tool <name>] [--session <id>] [--phase start|end]   # from a tool hook, on stdin"
            );
            println!("status, policy, verify and pair arrive with F8.CLI.01");
        }
    }
}
