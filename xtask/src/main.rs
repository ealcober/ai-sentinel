// SPDX-License-Identifier: Apache-2.0
//! Build, test, budget certification and gate orchestration.
//!
//! Every gate in this project runs locally through this binary; there is no hosted
//! CI and no workflow triggers on push (`I-27`). Command surface: plan Annex H.
//!
//! Exit codes are the contract (Annex H §H.2), and `gate --level` reads them:
//!
//! | Exit | Meaning | Reported as |
//! |---|---|---|
//! | 0 | the property holds | `PASS` |
//! | 1 | the property does not hold | `FAIL` |
//! | 2 | could not run: missing VM, fixture, corpus, hardware or tooling | `SKIP` |
//! | 3 | not implemented in any phase yet | `PENDING <phase>` |
//!
//! A command that has no implementation yet still parses its arguments normally
//! and then exits 3 naming the task that owes it. That is what makes this surface
//! the plan's own progress report rather than a pile of missing subcommands.

mod annex_h;
mod assets;
mod bench;
mod budgets;
mod docgate;
mod doctor;
mod gate;
mod rules;
mod scenarios;
mod skeleton;
mod tooling;
mod verify;
mod vm;

use annex_h::COMMANDS;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Exit 2: a command that exists but cannot run here, with the reason.
pub(crate) const SKIP: u8 = 2;
/// Exit 3: a command no phase has implemented yet.
pub(crate) const PENDING: u8 = 3;

/// The workspace root, resolved at compile time from this crate's location.
///
/// Every command reads `layers.toml`, `budgets.toml` and the plan by relative
/// path, so they must run from the root. `cargo run` inherits the caller's
/// directory, which means `cargo xtask verify-docs` from inside `crates/` would
/// otherwise read nothing and report a clean pass over an empty file set — an
/// absence read as a value (general rule 9).
pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The counting allocator `bench-hotloop` needs (`F1.RT.03`). It is installed
/// for the whole tool because a global allocator can only be chosen once; it
/// forwards everything to the system allocator and counts only while the
/// bench asks it to, so every other command runs exactly as before.
#[global_allocator]
static ALLOCATOR: bench::Counting = bench::Counting;

fn main() -> ExitCode {
    if let Err(e) = std::env::set_current_dir(workspace_root()) {
        eprintln!("error: cannot enter the workspace root: {e}");
        return ExitCode::FAILURE;
    }
    let owned: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = owned.iter().map(String::as_str).collect();

    match words.split_first() {
        Some((&head, rest)) if !matches!(head, "-h" | "--help" | "help") => dispatch(head, rest),
        _ => {
            usage();
            ExitCode::SUCCESS
        }
    }
}

/// Sub-namespaces owned by F9, F10, Annex F, and the VM family (Annex H §H.3).
const NAMESPACES: [&str; 4] = ["sdk", "sentinel", "win", "vm"];

fn dispatch(head: &str, rest: &[&str]) -> ExitCode {
    // A namespaced command is two words: `vm up`, `sdk test-forgery`.
    let (name, args) = if NAMESPACES.contains(&head) {
        let Some((&sub, tail)) = rest.split_first() else {
            eprintln!("error: `{head}` is a namespace, not a command. Try `cargo xtask --help`.");
            return ExitCode::FAILURE;
        };
        (format!("{head} {sub}"), tail)
    } else {
        (head.to_owned(), rest)
    };

    let Some(cmd) = COMMANDS.iter().find(|c| c.name == name) else {
        eprintln!("error: `cargo xtask {name}` is not in Annex H.");
        eprintln!("       Add its Annex H row first, then the task that implements it.");
        return ExitCode::FAILURE;
    };

    let Some(code) = run(&name, args) else {
        eprintln!("error: `cargo xtask {name}` is not implemented yet.");
        eprintln!(
            "       Implemented by {} (phase {} — {}).",
            cmd.owner,
            cmd.phase,
            annex_h::phase_name(cmd.phase)
        );
        eprintln!("       Annex H lists every command and the task that implements it.");
        return ExitCode::from(PENDING);
    };
    ExitCode::from(code)
}

/// Dispatch to the commands `F0.REPO.03` implements.
///
/// `None` means no phase has implemented the command yet: the caller prints the
/// Annex H message naming the task that owes it and exits 3. A command that ran
/// returns its own exit code, including when it declines with 2.
fn run(name: &str, args: &[&str]) -> Option<u8> {
    Some(match name {
        "verify-layering" => verify::layering(),
        "verify-budgets" => verify::budgets(args),
        "verify-docs" => verify::docs(),
        "verify-backlog" => verify::backlog(),
        "doctor" => doctor::run(),
        "gate" => gate::run(args),
        "build-ebpf" => tooling::build_ebpf(),
        "bench-hotloop" => bench::hot_loop(args),
        "dist" => tooling::dist(),
        "test-taint" => scenarios::test_taint(args),
        "test-detect" => scenarios::test_detect(args),
        "test-policy-compiler" => scenarios::test_policy_compiler(args),
        "test-policy-publish" => scenarios::test_policy_publish(args),
        "test-skeleton" => skeleton::run(args),
        "vm up" | "vm run" | "vm probe" => vm::run(name, args),
        _ => return None,
    })
}

fn usage() {
    println!("cargo xtask <command> [args]\n");
    println!("Every gate in this project runs locally (I-27). Command surface: plan Annex H.\n");
    println!("Exit codes: 0 PASS · 1 FAIL · 2 SKIP (missing prerequisite) · 3 PENDING (not yet implemented)\n");

    let mut last_family = "";
    for c in COMMANDS {
        let family = family_of(c.name);
        if family != last_family {
            println!("\n{family}:");
            last_family = family;
        }
        let level = c.level.map_or("—", |l| match l {
            annex_h::Level::Commit => "commit",
            annex_h::Level::Pr => "pr",
            annex_h::Level::Nightly => "nightly",
            annex_h::Level::Weekly => "weekly",
        });
        println!("  {:<34} {:<12} {:>7}  {}", c.name, c.owner, level, c.phase);
    }
    println!("\n{} commands.", COMMANDS.len());
}

fn family_of(name: &str) -> &'static str {
    for ns in NAMESPACES {
        if name.starts_with(ns) && name.contains(' ') {
            return match ns {
                "sdk" => "sdk",
                "sentinel" => "sentinel",
                "win" => "win",
                _ => "vm",
            };
        }
    }
    match name.split('-').next() {
        Some("bench") => "bench",
        Some("build") => "build",
        Some("test") => "test",
        Some("verify") => "verify",
        _ => "other",
    }
}
