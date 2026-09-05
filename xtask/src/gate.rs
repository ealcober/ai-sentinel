//! `gate --level` — the composite.
//!
//! Runs one level's members and reports **each member's result**, never a summary
//! (`AGENTS.md` §3). Levels are cumulative: `pr` runs everything `commit` runs.
//! A `PENDING` member does not fail the gate; that is what makes the gate a
//! progress report from the first week (Annex H §H.2).

use crate::annex_h::{phase_name, Command as HCommand, Level, COMMANDS};
use std::process::Command;

pub(crate) fn run(args: &[&str]) -> u8 {
    let level = match parse_level(args) {
        Ok(l) => l,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    let members: Vec<&HCommand> = COMMANDS
        .iter()
        .filter(|c| c.level.is_some_and(|l| l <= level))
        .collect();

    println!(
        "gate --level {} — {} members, cumulative\n",
        label(level),
        members.len()
    );

    let exe = std::env::current_exe().ok();
    let (mut pass, mut fail, mut skip, mut pending) = (0, 0, 0, 0);

    for c in &members {
        let code = exe.as_ref().map_or(3, |p| {
            let mut cmd = Command::new(p);
            for word in c.name.split_whitespace() {
                cmd.arg(word);
            }
            cmd.output().map_or(3, |o| {
                u8::try_from(o.status.code().unwrap_or(1)).unwrap_or(1)
            })
        });
        match code {
            0 => {
                pass += 1;
                println!("  PASS            {}", c.name);
            }
            2 => {
                skip += 1;
                println!("  SKIP            {}  (missing prerequisite)", c.name);
            }
            3 => {
                pending += 1;
                println!("  PENDING {:<7} {}  ({})", c.phase, c.name, c.owner);
            }
            _ => {
                fail += 1;
                println!("  FAIL            {}", c.name);
            }
        }
    }

    println!("\n{pass} PASS · {fail} FAIL · {skip} SKIP · {pending} PENDING");
    if pending > 0 {
        let mut phases: Vec<&str> = members
            .iter()
            .map(|c| c.phase)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        phases.retain(|p| *p != "F0");
        if !phases.is_empty() {
            println!(
                "Owed by: {}",
                phases
                    .iter()
                    .map(|p| format!("{p} ({})", phase_name(p)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if fail > 0 {
        eprintln!(
            "\nGATE FAILS: {fail} member(s) reported FAIL. PENDING and SKIP do not fail a gate."
        );
        return 1;
    }
    println!("\nGATE PASSES at level {}.", label(level));
    0
}

fn parse_level(args: &[&str]) -> Result<Level, String> {
    let mut it = args.iter();
    while let Some(&a) = it.next() {
        if a == "--level" {
            let Some(&value) = it.next() else {
                return Err("error: --level needs a value: commit, pr, nightly or weekly".into());
            };
            return Level::parse(value).ok_or_else(|| {
                format!("error: unknown level `{value}`. Use commit, pr, nightly or weekly.")
            });
        }
        if let Some(value) = a.strip_prefix("--level=") {
            return Level::parse(value).ok_or_else(|| {
                format!("error: unknown level `{value}`. Use commit, pr, nightly or weekly.")
            });
        }
    }
    Err("error: `cargo xtask gate --level <commit|pr|nightly|weekly>`".into())
}

fn label(l: Level) -> &'static str {
    match l {
        Level::Commit => "commit",
        Level::Pr => "pr",
        Level::Nightly => "nightly",
        Level::Weekly => "weekly",
    }
}
