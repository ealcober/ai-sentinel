// SPDX-License-Identifier: Apache-2.0
//! The simulator's command line.
//!
//! The trace comes in on stdin, the action stream goes out on **stdout** and
//! the ground truth on **stderr**. Two streams, because §4.6's whole design
//! is that the correlation engine reads one and the scorer reads the other;
//! a single stream carrying both would make the measurement meaningless.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use aisme_agentsim::{replay, trace};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `--open-bench` is its own mode and returns before the replay: it measures
    // what one `openat` costs the agent, from inside the session, which is the
    // only place T1 can be timed (`F2.WS.09`).
    match aisme_agentsim::openbench::Request::parse(&args) {
        Ok(Some(request)) => {
            let report = aisme_agentsim::openbench::run(&request);
            println!("{}", aisme_agentsim::openbench::render(&request, &report));
            return ExitCode::SUCCESS;
        }
        Ok(None) => {}
        Err(problem) => {
            eprintln!("aisme-agentsim: {problem}");
            eprintln!("usage: aisme-agentsim --open-bench <path> [--count N] [--create]");
            return ExitCode::FAILURE;
        }
    }
    // The two file-producing verbs return before the replay: they write the
    // file the replay consumes, rather than consuming one (`F0.ASSET.02`).
    if let Some(code) = trace_verbs(&args) {
        return code;
    }
    let options = match replay::Options::parse(&args) {
        Ok(options) => options,
        Err(problem) => {
            eprintln!("aisme-agentsim: {problem}");
            eprintln!("usage: aisme-agentsim [--speed 1.0] [--seed 0] [--jitter-us 0] < trace");
            return ExitCode::FAILURE;
        }
    };
    let mut text = String::new();
    if io::stdin().read_to_string(&mut text).is_err() {
        eprintln!("aisme-agentsim: cannot read the trace from stdin");
        return ExitCode::FAILURE;
    }
    if text.trim().is_empty() {
        // F0.ASSET.02 records the trace the gates use, after F2.WS.08; until
        // then the binary says what it is and replays nothing.
        println!(
            "aisme-agentsim: trace format v{} (F1.SIM.02), replay ready (F1.SIM.01); \
             speed {}‰, seed {}, jitter {} µs — no trace on stdin",
            trace::FORMAT_VERSION,
            options.speed_milli,
            options.seed,
            options.jitter_us
        );
        return ExitCode::SUCCESS;
    }
    let trace = match trace::parse(&text) {
        Ok(trace) => trace,
        Err(problem) => {
            eprintln!("aisme-agentsim: {problem}");
            return ExitCode::FAILURE;
        }
    };
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut actions = stdout.lock();
    let mut truth = stderr.lock();
    // `--declare` opens the control socket; without it declarations go to a
    // sink that discards them, so the replay behaves the same and the report
    // still says how many there were.
    let mut declare: Box<dyn io::Write> = match options.declare_to.as_deref() {
        Some(path) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(socket) => Box::new(socket),
            Err(e) => {
                eprintln!("aisme-agentsim: --declare {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => Box::new(io::sink()),
    };
    match replay::replay(
        &trace,
        &options,
        &mut actions,
        &mut truth,
        &mut declare,
        std::thread::sleep,
    ) {
        Ok(report) => {
            let _ = actions.flush();
            eprintln!(
                "# replayed {} entries ({} tool calls) in {} µs against a schedule of {} µs; worst lateness {} µs; faithful: {}",
                report.entries,
                report.tool_calls,
                report.elapsed_us,
                report.scheduled_us,
                report.worst_lateness_us,
                report.faithful()
            );
            // A replay that drifted measured something else, and a CPU figure
            // taken from it is not comparable (§2.22).
            if report.faithful() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("aisme-agentsim: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--to-trace` and `--emit-trace`, or `None` when neither was asked for.
///
/// One function because they are one concern — producing the file the replay
/// reads — and because `main` is a dispatcher and not a place for argument
/// shapes.
fn trace_verbs(args: &[String]) -> Option<ExitCode> {
    if let Some(at) = args.iter().position(|a| a == "--to-trace") {
        let (Some(wal), Some(out)) = (args.get(at + 1), args.get(at + 2)) else {
            eprintln!("usage: aisme-agentsim --to-trace <wal-dir> <trace-file>");
            return Some(ExitCode::FAILURE);
        };
        return Some(to_trace(wal, out));
    }
    if let Some(at) = args.iter().position(|a| a == "--emit-trace") {
        let Some(out) = args.get(at + 1) else {
            eprintln!("usage: aisme-agentsim --emit-trace <trace-file> [--minutes N]");
            return Some(ExitCode::FAILURE);
        };
        let minutes = args
            .iter()
            .position(|a| a == "--minutes")
            .and_then(|i| args.get(i + 1))
            .map_or(Ok(30), |v| v.parse::<u32>());
        return Some(match minutes {
            Ok(minutes) if minutes > 0 => emit_trace(out, minutes),
            _ => {
                eprintln!("aisme-agentsim: --minutes needs a positive number");
                ExitCode::FAILURE
            }
        });
    }
    None
}

/// Recover a trace from a recording and say what it recovered.
///
/// The counts go to stderr rather than into the file, because a summary a
/// person reads and a summary a gate parses are different things and the file
/// already carries the second.
fn to_trace(wal: &str, out: &str) -> ExitCode {
    use aisme_agentsim::record;

    let events = match record::read_wal(std::path::Path::new(wal)) {
        Ok(events) => events,
        Err(e) => {
            eprintln!("aisme-agentsim: {wal}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let recorded = record::from_events(&events);
    // A fixture with no actions would pass a gate by having nothing to check.
    if recorded.trace.entries.is_empty() {
        eprintln!(
            "aisme-agentsim: {wal} holds {} event(s) and no action this format has — \
             nothing written",
            events.len()
        );
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::write(out, aisme_agentsim::trace::write(&recorded.trace)) {
        eprintln!("aisme-agentsim: {out}: {e}");
        return ExitCode::FAILURE;
    }
    let summary = recorded.trace.summary;
    println!(
        "recovered {} action(s) over {} µs: {} tool call(s), {} read(s), {} write(s), \
         {} exec(s), {} https",
        recorded.trace.entries.len(),
        summary.duration_us,
        summary.tool_calls,
        summary.file_reads,
        summary.file_writes,
        summary.execs,
        summary.https_requests
    );
    // Both numbers are printed even when zero: a reader must be able to tell
    // "nothing was skipped" from "nobody looked".
    println!("unattributed: {}", recorded.unattributed);
    println!(
        "skipped by kind: {}",
        if recorded.skipped.is_empty() {
            "none".to_owned()
        } else {
            recorded
                .skipped
                .iter()
                .map(|(kind, n)| format!("{kind}={n}"))
                .collect::<Vec<String>>()
                .join(", ")
        }
    );
    ExitCode::SUCCESS
}

/// Write a synthetic session shaped like §2.22's reference workload.
fn emit_trace(out: &str, minutes: u32) -> ExitCode {
    let trace = aisme_agentsim::record::synthesise(minutes);
    if let Err(e) = std::fs::write(out, aisme_agentsim::trace::write(&trace)) {
        eprintln!("aisme-agentsim: {out}: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "wrote {} action(s) over {minutes} minute(s) — the reference workload's shape, \
         and not a recording",
        trace.entries.len()
    );
    ExitCode::SUCCESS
}
