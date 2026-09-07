// SPDX-License-Identifier: Apache-2.0
//! The trace format (`F1.SIM.02`).
//!
//! An append-only log, one line per agent action, plus a summary block with
//! the §2.22 counts. Text, because the three properties the plan asks for —
//! diffable, hashable, human-readable — are properties of text, and because
//! a trace that a reviewer cannot read is a gate input nobody audits.
//!
//! ```text
//! # aisme-trace 1
//! [summary]
//! tool_calls = 2
//! file_reads = 1
//! …
//! [actions]
//! 0        toolcall   a1b2c3d4e5f60718  0f1e2d3c4b5a6978  read the config
//! 1500     file_read  3c4b5a6978a1b2c3  0f1e2d3c4b5a6978  -
//! ```
//!
//! `t_offset_us` is microseconds from the trace's start, so replay can
//! preserve inter-arrival timing (`F1.SIM.01`); the plan is explicit that
//! totals are not a workload, because this system's cost is burst-shaped.
//!
//! The `correlation_token` is the ground truth of §4.6: `agentsim` emits it
//! with the declared tool call and with every action that tool call caused.
//! **The correlation engine never sees it; the scorer does.** A format that
//! carried it into the engine's input would measure nothing.

use std::fmt::Write as _;

/// The format's version, the first line.
pub const FORMAT_VERSION: u32 = 1;

/// What an agent did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// A declared tool call: the intent, carrying the token.
    ToolCall,
    /// A file read.
    FileRead,
    /// A file write.
    FileWrite,
    /// A subprocess execution.
    Exec,
    /// An HTTPS request, SSE-streamed.
    HttpsRequest,
}

impl Action {
    /// Every action, in the order the summary counts them.
    pub const ALL: [Action; 5] = [
        Action::ToolCall,
        Action::FileRead,
        Action::FileWrite,
        Action::Exec,
        Action::HttpsRequest,
    ];

    /// The word used in the file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::ToolCall => "toolcall",
            Action::FileRead => "file_read",
            Action::FileWrite => "file_write",
            Action::Exec => "exec",
            Action::HttpsRequest => "https_request",
        }
    }

    /// From the word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == word)
    }

    /// The summary key that counts it.
    #[must_use]
    pub const fn summary_key(self) -> &'static str {
        match self {
            Action::ToolCall => "tool_calls",
            Action::FileRead => "file_reads",
            Action::FileWrite => "file_writes",
            Action::Exec => "execs",
            Action::HttpsRequest => "https_requests",
        }
    }
}

/// One line of the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Microseconds from the start of the trace.
    pub t_offset_us: u64,
    /// What was done.
    pub action: Action,
    /// A hash of the arguments; the arguments themselves are not in the
    /// trace, because a fixture is committed and a path is data.
    pub args_hash: u64,
    /// The hidden ground truth: which tool call this belongs to.
    pub correlation_token: u64,
    /// What the agent said it was doing. `-` when it said nothing.
    pub declared_intent: String,
}

/// The counts §2.22 uses to say what a workload is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Declared tool calls.
    pub tool_calls: u32,
    /// File reads.
    pub file_reads: u32,
    /// File writes.
    pub file_writes: u32,
    /// Subprocess executions.
    pub execs: u32,
    /// HTTPS requests with SSE streaming.
    pub https_requests: u32,
    /// The trace's own length, in microseconds.
    pub duration_us: u64,
}

impl Summary {
    /// §2.22's reference workload, per hour.
    pub const REFERENCE_PER_HOUR: Summary = Summary {
        tool_calls: 200,
        file_reads: 4_000,
        file_writes: 600,
        execs: 40,
        https_requests: 120,
        duration_us: 3_600 * 1_000_000,
    };

    /// The count for one action.
    #[must_use]
    pub const fn count(&self, action: Action) -> u32 {
        match action {
            Action::ToolCall => self.tool_calls,
            Action::FileRead => self.file_reads,
            Action::FileWrite => self.file_writes,
            Action::Exec => self.execs,
            Action::HttpsRequest => self.https_requests,
        }
    }

    fn bump(&mut self, action: Action) {
        match action {
            Action::ToolCall => self.tool_calls += 1,
            Action::FileRead => self.file_reads += 1,
            Action::FileWrite => self.file_writes += 1,
            Action::Exec => self.execs += 1,
            Action::HttpsRequest => self.https_requests += 1,
        }
    }
}

/// A whole trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// The counts, as written.
    pub summary: Summary,
    /// The actions, in time order.
    pub entries: Vec<Entry>,
}

/// Why a trace was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    /// The first line is not this format at this version.
    BadHeader,
    /// A line could not be read.
    BadLine {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        message: String,
    },
    /// Entries are not in time order: replay would have to sort them, and a
    /// trace that needs sorting is a trace whose ordering nobody checked.
    OutOfOrder {
        /// 1-based line number.
        line: usize,
        /// The offset that went backwards.
        t_offset_us: u64,
        /// The one before it.
        previous_us: u64,
    },
    /// The summary disagrees with the actions — the check that makes a trace
    /// verifiable against the spec (`F1.SIM.02`).
    SummaryMismatch {
        /// Which count.
        key: &'static str,
        /// What the summary says.
        declared: u32,
        /// What the actions say.
        counted: u32,
    },
    /// An action carries a token no tool call declared: the ground truth
    /// would be unattributable.
    OrphanToken {
        /// 1-based line number.
        line: usize,
        /// The token.
        token: u64,
    },
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceError::BadHeader => write!(f, "not an aisme-trace v{FORMAT_VERSION}"),
            TraceError::BadLine { line, message } => write!(f, "line {line}: {message}"),
            TraceError::OutOfOrder {
                line,
                t_offset_us,
                previous_us,
            } => write!(
                f,
                "line {line}: t_offset {t_offset_us} is before {previous_us}"
            ),
            TraceError::SummaryMismatch {
                key,
                declared,
                counted,
            } => write!(
                f,
                "summary says {key} = {declared}, the actions count {counted}"
            ),
            TraceError::OrphanToken { line, token } => {
                write!(
                    f,
                    "line {line}: token {token:016x} belongs to no declared tool call"
                )
            }
        }
    }
}

impl std::error::Error for TraceError {}

/// Write a trace.
#[must_use]
pub fn write(trace: &Trace) -> String {
    let mut out = String::with_capacity(64 + trace.entries.len() * 64);
    let _ = writeln!(out, "# aisme-trace {FORMAT_VERSION}");
    out.push_str("[summary]\n");
    for action in Action::ALL {
        let _ = writeln!(
            out,
            "{} = {}",
            action.summary_key(),
            trace.summary.count(action)
        );
    }
    let _ = writeln!(out, "duration_us = {}", trace.summary.duration_us);
    out.push_str("[actions]\n");
    for entry in &trace.entries {
        let intent = if entry.declared_intent.is_empty() {
            "-"
        } else {
            &entry.declared_intent
        };
        let _ = writeln!(
            out,
            "{:<10} {:<14} {:016x} {:016x} {}",
            entry.t_offset_us,
            entry.action.as_str(),
            entry.args_hash,
            entry.correlation_token,
            intent
        );
    }
    out
}

/// Read a trace, checking everything the format promises.
///
/// # Errors
///
/// The first problem found, with its line.
pub fn parse(text: &str) -> Result<Trace, TraceError> {
    let mut lines = text.lines().enumerate();
    let (_, header) = lines.next().ok_or(TraceError::BadHeader)?;
    if header.trim() != format!("# aisme-trace {FORMAT_VERSION}") {
        return Err(TraceError::BadHeader);
    }
    let mut summary = Summary::default();
    let mut entries: Vec<Entry> = Vec::new();
    let mut in_actions = false;
    let mut previous_us = 0u64;
    let mut tokens: Vec<u64> = Vec::new();
    for (i, raw) in lines {
        let line = raw.trim();
        let number = i + 1;
        if line.is_empty() || line.starts_with('#') || line == "[summary]" {
            continue;
        }
        if line == "[actions]" {
            in_actions = true;
            continue;
        }
        if !in_actions {
            parse_summary_line(line, number, &mut summary)?;
            continue;
        }
        let entry = parse_action_line(line, number)?;
        if entry.t_offset_us < previous_us {
            return Err(TraceError::OutOfOrder {
                line: number,
                t_offset_us: entry.t_offset_us,
                previous_us,
            });
        }
        previous_us = entry.t_offset_us;
        if entry.action == Action::ToolCall {
            tokens.push(entry.correlation_token);
        } else if entry.correlation_token != 0 && !tokens.contains(&entry.correlation_token) {
            return Err(TraceError::OrphanToken {
                line: number,
                token: entry.correlation_token,
            });
        }
        entries.push(entry);
    }
    let trace = Trace { summary, entries };
    trace.check_summary()?;
    Ok(trace)
}

/// One `key = value` of the `[summary]` block.
fn parse_summary_line(line: &str, number: usize, summary: &mut Summary) -> Result<(), TraceError> {
    let (key, value) = line.split_once('=').ok_or_else(|| TraceError::BadLine {
        line: number,
        message: "expected `key = value` in [summary]".to_owned(),
    })?;
    let (key, value) = (key.trim(), value.trim());
    let parsed: u64 = value.parse().map_err(|_| TraceError::BadLine {
        line: number,
        message: format!("`{value}` is not a count"),
    })?;
    let small = u32::try_from(parsed).unwrap_or(u32::MAX);
    match key {
        "tool_calls" => summary.tool_calls = small,
        "file_reads" => summary.file_reads = small,
        "file_writes" => summary.file_writes = small,
        "execs" => summary.execs = small,
        "https_requests" => summary.https_requests = small,
        "duration_us" => summary.duration_us = parsed,
        other => {
            return Err(TraceError::BadLine {
                line: number,
                message: format!("unknown summary key `{other}`"),
            })
        }
    }
    Ok(())
}

/// One line of the `[actions]` block.
///
/// Columns are padded for readability, so fields are separated by *runs* of
/// whitespace: `splitn` on a single whitespace character hands the padding to
/// the next field, which is how the first version of this parser rejected its
/// own output.
fn parse_action_line(line: &str, number: usize) -> Result<Entry, TraceError> {
    let mut fields = line.split_whitespace();
    let mut next = |what: &str| -> Result<String, TraceError> {
        fields
            .next()
            .map(str::to_owned)
            .ok_or_else(|| TraceError::BadLine {
                line: number,
                message: format!("missing {what}"),
            })
    };
    let t_offset_us: u64 = next("t_offset_us")?
        .parse()
        .map_err(|_| TraceError::BadLine {
            line: number,
            message: "t_offset_us is not a number".to_owned(),
        })?;
    let action_word = next("action")?;
    let action = Action::parse(&action_word).ok_or_else(|| TraceError::BadLine {
        line: number,
        message: format!("unknown action `{action_word}`"),
    })?;
    let args_hash =
        u64::from_str_radix(&next("args_hash")?, 16).map_err(|_| TraceError::BadLine {
            line: number,
            message: "args_hash is not 16 hex digits".to_owned(),
        })?;
    let correlation_token =
        u64::from_str_radix(&next("correlation_token")?, 16).map_err(|_| TraceError::BadLine {
            line: number,
            message: "correlation_token is not 16 hex digits".to_owned(),
        })?;
    // The intent is the rest of the line, spaces and all: it is prose.
    let declared_intent = fields.collect::<Vec<_>>().join(" ");
    Ok(Entry {
        t_offset_us,
        action,
        args_hash,
        correlation_token,
        declared_intent: if declared_intent == "-" {
            String::new()
        } else {
            declared_intent
        },
    })
}

impl Trace {
    /// The summary the actions actually add up to.
    #[must_use]
    pub fn counted(&self) -> Summary {
        let mut summary = Summary {
            duration_us: self.entries.last().map_or(0, |e| e.t_offset_us),
            ..Summary::default()
        };
        for entry in &self.entries {
            summary.bump(entry.action);
        }
        summary
    }

    /// Whether the declared summary is the one the actions add up to.
    ///
    /// # Errors
    ///
    /// The first count that disagrees. A trace whose summary lies is a
    /// workload nobody can check against §2.22.
    pub fn check_summary(&self) -> Result<(), TraceError> {
        let counted = self.counted();
        for action in Action::ALL {
            let (declared, actual) = (self.summary.count(action), counted.count(action));
            if declared != actual {
                return Err(TraceError::SummaryMismatch {
                    key: action.summary_key(),
                    declared,
                    counted: actual,
                });
            }
        }
        Ok(())
    }

    /// The actions one tool call caused — the ground truth a scorer joins
    /// against.
    #[must_use]
    pub fn caused_by(&self, token: u64) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.correlation_token == token && e.action != Action::ToolCall)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(t: u64, action: Action, token: u64) -> Entry {
        Entry {
            t_offset_us: t,
            action,
            args_hash: t * 31,
            correlation_token: token,
            declared_intent: if action == Action::ToolCall {
                "read the config".to_owned()
            } else {
                String::new()
            },
        }
    }

    fn trace() -> Trace {
        let entries = vec![
            entry(0, Action::ToolCall, 0x0f1e_2d3c_4b5a_6978),
            entry(1_500, Action::FileRead, 0x0f1e_2d3c_4b5a_6978),
            entry(2_000, Action::FileWrite, 0x0f1e_2d3c_4b5a_6978),
            entry(9_000, Action::ToolCall, 0xdead_beef_dead_beef),
            entry(9_100, Action::Exec, 0xdead_beef_dead_beef),
            entry(9_200, Action::HttpsRequest, 0xdead_beef_dead_beef),
        ];
        let mut trace = Trace {
            summary: Summary::default(),
            entries,
        };
        trace.summary = trace.counted();
        trace
    }

    #[test]
    fn a_trace_round_trips_and_stays_readable() {
        let original = trace();
        let text = write(&original);
        assert!(text.starts_with("# aisme-trace 1\n[summary]\ntool_calls = 2\n"));
        assert!(text.contains("1500       file_read      "), "{text}");
        assert!(
            text.lines().count() == 1 + 1 + 6 + 1 + 6,
            "one line per action plus header"
        );
        let back = parse(&text).unwrap();
        assert_eq!(back, original);
        // Diffable: one changed action is one changed line.
        let mut edited = original.clone();
        edited.entries[1].t_offset_us = 1_600;
        let edited_text = write(&edited);
        let changed: Vec<_> = edited_text
            .lines()
            .zip(text.lines())
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn the_summary_must_be_the_one_the_actions_add_up_to() {
        let mut trace = trace();
        trace.summary.file_reads = 99;
        let text = write(&trace);
        assert_eq!(
            parse(&text),
            Err(TraceError::SummaryMismatch {
                key: "file_reads",
                declared: 99,
                counted: 1
            })
        );
        assert!(trace.check_summary().is_err());
    }

    #[test]
    fn the_ground_truth_joins_actions_to_the_tool_call_that_caused_them() {
        let trace = trace();
        let caused = trace.caused_by(0x0f1e_2d3c_4b5a_6978);
        assert_eq!(caused.len(), 2);
        assert_eq!(caused[0].action, Action::FileRead);
        assert_eq!(
            trace.caused_by(0xdead_beef_dead_beef).len(),
            2,
            "the tool call itself is not one of its own effects"
        );
        assert!(trace.caused_by(1).is_empty());
    }

    #[test]
    fn a_malformed_trace_is_refused_with_its_line() {
        assert_eq!(parse(""), Err(TraceError::BadHeader));
        assert_eq!(parse("# aisme-trace 2\n"), Err(TraceError::BadHeader));
        let base = "# aisme-trace 1\n[summary]\ntool_calls = 1\nfile_reads = 0\nfile_writes = 0\nexecs = 0\nhttps_requests = 0\nduration_us = 0\n[actions]\n";
        let backwards = format!("{base}100 toolcall 0000000000000001 0000000000000002 x\n50 file_read 0000000000000003 0000000000000002 -\n");
        assert!(matches!(
            parse(&backwards),
            Err(TraceError::OutOfOrder { line: 11, .. })
        ));
        let orphan = format!("{base}0 toolcall 0000000000000001 0000000000000002 x\n5 file_read 0000000000000003 00000000000000ff -\n");
        assert!(matches!(
            parse(&orphan),
            Err(TraceError::OrphanToken { line: 11, .. })
        ));
        let unknown = format!("{base}0 teleport 0000000000000001 0000000000000002 x\n");
        assert!(matches!(
            parse(&unknown),
            Err(TraceError::BadLine { line: 10, .. })
        ));
        let bad_key = "# aisme-trace 1\n[summary]\ntool_kalls = 1\n";
        assert!(matches!(
            parse(bad_key),
            Err(TraceError::BadLine { line: 3, .. })
        ));
    }

    #[test]
    fn the_reference_workload_is_the_plans_numbers() {
        let plan = include_str!("../../../docs/01_phase5_implementation_plan.md");
        assert!(plan.contains("200 tool calls/hour, 4,000 file reads, 600 writes, 40 subprocess executions, 120 HTTPS requests"));
        let reference = Summary::REFERENCE_PER_HOUR;
        assert_eq!(
            (
                reference.tool_calls,
                reference.file_reads,
                reference.file_writes,
                reference.execs,
                reference.https_requests
            ),
            (200, 4_000, 600, 40, 120)
        );
    }
}
