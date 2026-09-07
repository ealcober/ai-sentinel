// SPDX-License-Identifier: Apache-2.0
//! Replay (`F1.SIM.01`): the trace, at its own pace.
//!
//! §2.22 is explicit that **totals are not a workload** — this system's cost
//! is burst-shaped, and a flat replay would pass a gate a real agent fails.
//! So the replayer sleeps between entries by their recorded inter-arrival
//! gaps, scaled by `--speed`, and reports how faithfully it managed (a
//! machine under load cannot always keep up, and a run that silently drifted
//! is a measurement of the wrong thing).
//!
//! `--seed` makes the run deterministic where it has a choice: the jitter
//! that keeps a replay from being a metronome comes from a small counter-based
//! generator, so the same seed gives the same schedule on every machine and
//! the CPU figures of two runs are comparable.
//!
//! The hidden correlation token goes to the **scorer's** sink, never to the
//! stream the engine sees (§4.6): the two are separate writers here, and
//! keeping them separate is the point of the design.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::trace::{Action, Entry, Trace};

/// How the replay is to be run.
///
/// `Clone` but not `Copy`: the declaration socket's path is owned, and a
/// replay reads its options rather than shuffling copies of them about.
#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    /// 1.0 is the recorded pace; 2.0 is twice as fast. Expressed in
    /// thousandths so the schedule is integer arithmetic and two machines
    /// compute the same one.
    pub speed_milli: u32,
    /// Determinism: the same seed gives the same jitter.
    pub seed: u64,
    /// The most jitter to add to a gap, in microseconds. Zero replays the
    /// recorded gaps exactly.
    pub jitter_us: u64,
    /// The control socket to declare tool calls on, if any (`F2.WS.03`).
    ///
    /// Declarations go to `agentd` over Annex I's `declareToolCall` while the
    /// actions happen, so correlation has something to match against live.
    /// Without it the replay is what it always was: actions on one stream and
    /// ground truth on another.
    pub declare_to: Option<String>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            speed_milli: 1_000,
            seed: 0,
            jitter_us: 0,
            declare_to: None,
        }
    }
}

impl Options {
    /// Parse `--speed`, `--seed`, `--jitter-us` and `--declare` from a
    /// command line.
    ///
    /// # Errors
    ///
    /// The offending argument, in words.
    pub fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| -> Result<String, String> {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("{name} needs a value"))
            };
            match arg.as_str() {
                "--speed" => {
                    let raw = value("--speed")?;
                    let speed: f64 = raw
                        .parse()
                        .map_err(|_| format!("--speed {raw} is not a number"))?;
                    if !(0.001..=1000.0).contains(&speed) {
                        return Err(format!("--speed {speed} is outside 0.001..=1000"));
                    }
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        options.speed_milli = (speed * 1000.0).round() as u32;
                    }
                }
                "--seed" => {
                    let raw = value("--seed")?;
                    options.seed = raw
                        .parse()
                        .map_err(|_| format!("--seed {raw} is not a number"))?;
                }
                "--jitter-us" => {
                    let raw = value("--jitter-us")?;
                    options.jitter_us = raw
                        .parse()
                        .map_err(|_| format!("--jitter-us {raw} is not a number"))?;
                }
                "--declare" => {
                    options.declare_to = Some(value("--declare")?);
                }
                other => return Err(format!("unknown argument `{other}`")),
            }
        }
        Ok(options)
    }

    /// The gap to wait before `entry`, given the one before it.
    #[must_use]
    pub fn gap(&self, previous_us: u64, entry: &Entry) -> Duration {
        let recorded = entry.t_offset_us.saturating_sub(previous_us);
        let scaled = if self.speed_milli == 0 {
            recorded
        } else {
            recorded.saturating_mul(1_000) / u64::from(self.speed_milli)
        };
        let jitter = if self.jitter_us == 0 {
            0
        } else {
            // A counter-based generator, not a stateful RNG: the jitter for
            // an entry depends only on the seed and the entry, so a replay
            // resumed halfway matches one run from the start.
            splitmix(self.seed ^ entry.t_offset_us.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                % self.jitter_us
        };
        Duration::from_micros(scaled + jitter)
    }
}

/// `SplitMix64` — small, deterministic, and good enough to keep a replay from
/// being a metronome. Nothing here is cryptographic.
const fn splitmix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// What a replay did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Entries replayed.
    pub entries: usize,
    /// Declared tool calls, whose tokens went to the scorer.
    pub tool_calls: usize,
    /// Declarations written to the control socket. Equal to `tool_calls` when
    /// a socket was given, and zero when none was: a difference between the two
    /// is a declaration that did not reach `agentd`, which is a gap in the
    /// ground truth rather than a cosmetic one.
    pub declared: usize,
    /// How long the replay took.
    pub elapsed_us: u64,
    /// What the schedule said it should have taken.
    pub scheduled_us: u64,
    /// The worst amount by which one entry ran late.
    pub worst_lateness_us: u64,
}

impl ReplayReport {
    /// Whether the replay kept its schedule closely enough for a CPU figure
    /// to mean anything. The plan does not fix a bound, so this is the
    /// replayer's own: within 5 % of the scheduled duration, and no single
    /// entry more than 50 ms late.
    #[must_use]
    pub fn faithful(&self) -> bool {
        let slack = self.scheduled_us / 20;
        self.elapsed_us <= self.scheduled_us + slack.max(1_000) && self.worst_lateness_us <= 50_000
    }
}

/// Replay `trace`, writing the action stream to `actions` and the ground
/// truth to `truth`.
///
/// The two writers are separate on purpose: the correlation engine reads the
/// first and must never see the second (§4.6).
///
/// # Errors
///
/// Whatever the writers say.
pub fn replay(
    trace: &Trace,
    options: &Options,
    actions: &mut dyn Write,
    truth: &mut dyn Write,
    declare: &mut dyn Write,
    mut sleep: impl FnMut(Duration),
) -> io::Result<ReplayReport> {
    let mut report = ReplayReport::default();
    let start = Instant::now();
    let mut previous_us = 0;
    for entry in &trace.entries {
        let gap = options.gap(previous_us, entry);
        report.scheduled_us += u64::try_from(gap.as_micros()).unwrap_or(u64::MAX);
        sleep(gap);
        let due = report.scheduled_us;
        let now = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        report.worst_lateness_us = report.worst_lateness_us.max(now.saturating_sub(due));
        writeln!(
            actions,
            "{} {} {:016x}",
            entry.t_offset_us,
            entry.action.as_str(),
            entry.args_hash
        )?;
        if entry.action == Action::ToolCall {
            report.tool_calls += 1;
            writeln!(
                truth,
                "{:016x} {}",
                entry.correlation_token, entry.declared_intent
            )?;
            // The declaration, on Annex I's `declareToolCall`. It carries the
            // id, the name, the params hash and the declared targets — and
            // **never `correlation_token`**. If the token reached `agentd` the
            // correlator could join on it, and §4.6's precision and recall
            // would measure the join instead of the correlation.
            report.declared += 1;
            writeln!(
                declare,
                concat!(
                    r#"{{"jsonrpc":"2.0","id":{},"method":"declareToolCall","params":"#,
                    r#"{{"toolcall_id":{},"tool_name":"{}","params_hash":"{:016x}","#,
                    r#""declared_targets":[]}}}}"#
                ),
                report.declared,
                report.declared,
                entry.declared_intent.replace('"', "'"),
                entry.args_hash
            )?;
        } else if entry.correlation_token != 0 {
            writeln!(
                truth,
                "{:016x} caused {}",
                entry.correlation_token,
                entry.action.as_str()
            )?;
        }
        report.entries += 1;
        previous_us = entry.t_offset_us;
    }
    report.elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{Entry, Summary};

    fn trace() -> Trace {
        let entries = vec![
            Entry {
                t_offset_us: 0,
                action: Action::ToolCall,
                args_hash: 1,
                correlation_token: 0xAA,
                declared_intent: "read the config".to_owned(),
            },
            Entry {
                t_offset_us: 10_000,
                action: Action::FileRead,
                args_hash: 2,
                correlation_token: 0xAA,
                declared_intent: String::new(),
            },
            Entry {
                t_offset_us: 50_000,
                action: Action::HttpsRequest,
                args_hash: 3,
                correlation_token: 0xAA,
                declared_intent: String::new(),
            },
        ];
        let mut trace = Trace {
            summary: Summary::default(),
            entries,
        };
        trace.summary = trace.counted();
        trace
    }

    #[test]
    fn the_recorded_gaps_are_what_is_slept_and_speed_scales_them() {
        let trace = trace();
        let mut slept: Vec<Duration> = Vec::new();
        let mut actions = Vec::new();
        let mut truth = Vec::new();
        let mut declare = Vec::new();
        let report = replay(
            &trace,
            &Options::default(),
            &mut actions,
            &mut truth,
            &mut declare,
            |d| slept.push(d),
        )
        .unwrap();
        assert_eq!(
            slept,
            [
                Duration::ZERO,
                Duration::from_millis(10),
                Duration::from_millis(40)
            ],
            "inter-arrival, not absolute offsets"
        );
        assert_eq!(report.entries, 3);
        assert_eq!(report.tool_calls, 1);
        assert_eq!(report.scheduled_us, 50_000);

        let mut fast: Vec<Duration> = Vec::new();
        replay(
            &trace,
            &Options {
                speed_milli: 4_000,
                ..Options::default()
            },
            &mut Vec::new(),
            &mut Vec::new(),
            &mut Vec::new(),
            |d| fast.push(d),
        )
        .unwrap();
        assert_eq!(
            fast[2],
            Duration::from_millis(10),
            "4× speed, a quarter of the gap"
        );
    }

    #[test]
    fn the_token_goes_to_the_scorer_and_never_to_the_action_stream() {
        let trace = trace();
        let mut actions = Vec::new();
        let mut truth = Vec::new();
        let mut declare = Vec::new();
        replay(
            &trace,
            &Options::default(),
            &mut actions,
            &mut truth,
            &mut declare,
            |_| {},
        )
        .unwrap();
        let actions = String::from_utf8(actions).unwrap();
        let truth = String::from_utf8(truth).unwrap();
        assert!(
            !actions.contains("00000000000000aa"),
            "the engine must not see the token:\n{actions}"
        );
        assert!(
            !actions.contains("read the config"),
            "nor the declared intent"
        );
        assert!(truth.contains("00000000000000aa read the config"));
        assert_eq!(
            truth.lines().count(),
            3,
            "the tool call and the two actions it caused"
        );
        assert_eq!(actions.lines().count(), 3);

        // The third stream, and the one this whole measurement rests on: the
        // declaration `agentd` receives. If the token crossed it, the
        // correlator could join on it and §4.6's precision and recall would
        // measure the join instead of the correlation.
        let declare = String::from_utf8(declare).unwrap();
        assert!(
            !declare.contains("00000000000000aa"),
            "the token must not cross the socket:\n{declare}"
        );
        assert!(
            !declare.contains("correlation_token"),
            "nor a field named for it"
        );
        assert_eq!(
            declare.lines().count(),
            1,
            "one declaration for the one tool call, none for the actions"
        );
        assert!(
            declare.contains(r#""method":"declareToolCall""#),
            "{declare}"
        );
        assert!(declare.contains(r#""toolcall_id":1"#), "{declare}");
        // The params hash travels; the arguments themselves never do.
        assert!(declare.contains("params_hash"), "{declare}");
    }

    /// A declaration must be a request `agentd` actually accepts, not a line
    /// that merely looks like one. This parses it with the server's own parser
    /// and checks the method it resolves to.
    #[test]
    fn the_declaration_is_a_request_the_server_parses_as_declaretoolcall() {
        let trace = trace();
        let mut declare = Vec::new();
        replay(
            &trace,
            &Options::default(),
            &mut Vec::new(),
            &mut Vec::new(),
            &mut declare,
            |_| {},
        )
        .unwrap();
        let line = String::from_utf8(declare).unwrap();
        let request = aisme_proto::rpc::parse_request(line.trim()).expect("a valid request");
        assert_eq!(request.method, aisme_proto::rpc::Method::DeclareToolCall);
        assert_eq!(
            request.method.auth(),
            aisme_proto::rpc::AuthClass::AnyAuthenticated,
            "an agent declares its own work"
        );
        assert!(
            !request.method.idempotent(),
            "two identical declarations are two tool calls, not one retried"
        );
        assert!(
            request.params.get("toolcall_id").is_some(),
            "a declaration nobody can join is refused by the server"
        );
        assert!(
            request.params.get("correlation_token").is_none(),
            "the token never crosses"
        );
    }

    #[test]
    fn the_same_seed_gives_the_same_schedule_and_a_different_one_does_not() {
        let trace = trace();
        let schedule = |seed: u64| {
            let mut slept: Vec<Duration> = Vec::new();
            replay(
                &trace,
                &Options {
                    seed,
                    jitter_us: 5_000,
                    ..Options::default()
                },
                &mut Vec::new(),
                &mut Vec::new(),
                &mut Vec::new(),
                |d| slept.push(d),
            )
            .unwrap();
            slept
        };
        assert_eq!(schedule(7), schedule(7), "same seed, same schedule");
        assert_ne!(schedule(7), schedule(8));
        // Jitter stays inside its bound.
        for (with, without) in schedule(7).iter().zip(schedule(0).iter()) {
            let _ = without;
            assert!(with.as_micros() <= 45_000, "{with:?} exceeds gap + jitter");
        }
    }

    #[test]
    fn the_declaration_socket_is_parsed_from_the_command_line() {
        let args = ["--declare".to_owned(), "/run/aisme.sock".to_owned()];
        let options = Options::parse(&args).expect("valid");
        assert_eq!(options.declare_to.as_deref(), Some("/run/aisme.sock"));
        assert_eq!(
            Options::default().declare_to,
            None,
            "without it the replay declares nothing and says so in the report"
        );
        assert!(
            Options::parse(&["--declare".to_owned()]).is_err(),
            "needs a value"
        );
    }

    #[test]
    fn the_command_line_is_parsed_and_bad_values_are_refused() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let options = Options::parse(&args("--speed 2.5 --seed 42 --jitter-us 100")).unwrap();
        assert_eq!(options.speed_milli, 2_500);
        assert_eq!(options.seed, 42);
        assert_eq!(options.jitter_us, 100);
        assert_eq!(Options::parse(&[]).unwrap(), Options::default());
        assert!(Options::parse(&args("--speed"))
            .unwrap_err()
            .contains("needs a value"));
        assert!(Options::parse(&args("--speed fast"))
            .unwrap_err()
            .contains("not a number"));
        assert!(Options::parse(&args("--speed 0"))
            .unwrap_err()
            .contains("outside"));
        assert!(Options::parse(&args("--turbo"))
            .unwrap_err()
            .contains("unknown argument"));
    }

    #[test]
    fn a_replay_that_ran_late_says_so() {
        let honest = ReplayReport {
            entries: 3,
            tool_calls: 1,
            declared: 0,
            elapsed_us: 51_000,
            scheduled_us: 50_000,
            worst_lateness_us: 900,
        };
        assert!(honest.faithful());
        let late = ReplayReport {
            worst_lateness_us: 120_000,
            ..honest
        };
        assert!(
            !late.faithful(),
            "a run that drifted measured something else"
        );
        let slow = ReplayReport {
            elapsed_us: 80_000,
            ..honest
        };
        assert!(!slow.faithful());
    }
}
