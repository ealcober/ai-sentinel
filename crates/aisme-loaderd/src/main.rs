// SPDX-License-Identifier: Apache-2.0
//! Minimal privileged loader (`F1.RT.07`).
//!
//! Holds `CAP_BPF` and `CAP_NET_ADMIN` just long enough to load and attach,
//! so the long-running daemons do not have to. What it loads arrives in F3
//! (`F3.LD.*`); what F1 owns is the **shape** of the split, and the shape is
//! only real if the units say so — `deploy/systemd/` carries them and
//! `units.rs` checks them, because a hardening directive that is silently
//! ignored is the failure mode this whole task exists to avoid.

mod platform;
mod policy;
mod units;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(rest) = args.split_first().filter(|(f, _)| *f == "--publish") {
        let (_, tail) = rest;
        let Some((file, binding_args)) = tail.split_first() else {
            eprintln!("--publish takes a policy file, then optional k=v bindings");
            std::process::exit(1);
        };
        let bindings = match policy::bindings_from(binding_args) {
            Ok(b) => b,
            Err(problem) => {
                eprintln!("{problem}");
                std::process::exit(1);
            }
        };
        std::process::exit(i32::from(policy::publish(file, &bindings)));
    }

    println!("aisme-loaderd: the privileged half of the split (F1.RT.07)");
    match units::check_all() {
        Ok(()) => println!("units: the privilege split holds"),
        Err(problems) => {
            for problem in &problems {
                eprintln!("units: {problem}");
            }
            std::process::exit(1);
        }
    }
    println!(
        "`--publish <policy-file> [k=v …]` compiles, pins and publishes; attaching is F3.LD.01"
    );
}
