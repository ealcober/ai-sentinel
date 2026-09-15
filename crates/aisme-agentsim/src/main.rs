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
