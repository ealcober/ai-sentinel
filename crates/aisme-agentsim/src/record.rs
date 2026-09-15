// SPDX-License-Identifier: Apache-2.0
//! Recovering a trace from what a session actually did (`F0.ASSET.02`).
//!
//! The format is agent **actions** joined to the **intents** that caused them,
//! and neither source has both: a kernel sensor sees an `openat` and not the
//! decision behind it, while an agent's own record holds the decision and no
//! actions at all. This module performs the join the project already designed
//! for it — `declareToolCall` carries the intent while the sensor records the
//! actions, and an action belongs to the declaration made by a process in its
//! own **ancestry**.
//!
//! **Why ancestry and not time.** The obvious rule — "the most recent
//! declaration" — is right only while one tool call runs at a time. Two
//! concurrent tool calls interleave their actions in the WAL, and arrival order
//! then attributes half of each to the other. Ancestry is exact rather than
//! heuristic for a subprocess tool call: the command's descendants are that
//! tool call and nothing else.
//!
//! **It lives here and not in `aisme-forensicd`, and the reason is a layer.**
//! `forensicd` is `L3` and this crate is `L4`, so `forensicd` cannot name the
//! trace format; and the reason first given for putting it there — that
//! `forensicd` owns reading the WAL — is not true. The replayer is
//! `aisme_core::wal`, which is `L1` and available to both. Writing and
//! recovering the format in one crate also puts the round trip inside one
//! crate's tests, which is where it belongs.

use std::collections::BTreeMap;
use std::path::Path;

use aisme_ebpf_common::{EventKind, Payload, RawEvent};

use crate::trace::{Action, Entry, Summary, Trace};

/// How deep the ancestry walk will go before it gives up.
///
/// A bound rather than a cycle set: a malformed parent map is a corrupted
/// recording, not an adversary, and a depth no real process tree reaches costs
/// nothing to check. Beyond it the action is attributed to nothing, which is
/// the conservative direction — an unattributed action is visible, while a
/// wrongly attributed one is not.
const MAX_ANCESTRY: usize = 64;

/// What a recording recovered, and what it could not use.
pub struct Recorded {
    /// The trace, in time order.
    pub trace: Trace,
    /// Events whose kind has no action in this format, counted by kind name.
    ///
    /// **Counted and never dropped in silence.** A recording that quietly
    /// discarded half the WAL would look complete, and the summary counts are
    /// what §2.22 compares a workload against.
    pub skipped: BTreeMap<String, u32>,
    /// Actions no declaration in their ancestry explains.
    ///
    /// They are **in** the trace with token `0`, which the format defines as
    /// "no tool call caused this". They are counted here as well because a
    /// recording where this number is large is a recording whose ground truth
    /// is thin, and that is worth seeing before the fixture is sealed.
    pub unattributed: u32,
}

/// The action this event kind becomes, or `None` when the format has none.
///
/// `FileOpen` is a **read** because F2's supervisor reproduces `O_RDONLY` only
/// (limit one of `Q-13`); a write arrives as `FileWrite` from the sensor that
/// sees it. Network kinds are absent rather than guessed: `SockConnect` is an
/// HTTPS request only if its port says so, and F2 has no network sensor to ask.
#[must_use]
pub fn action_of(kind: EventKind) -> Option<Action> {
    match kind {
        EventKind::ToolCall => Some(Action::ToolCall),
        EventKind::FileOpen => Some(Action::FileRead),
        EventKind::FileWrite => Some(Action::FileWrite),
        EventKind::ProcExec => Some(Action::Exec),
        _ => None,
    }
}

/// FNV-1a, 64-bit.
///
/// Stable **by construction**, which a committed fixture needs: the hash of an
/// argument is part of the file, and `DefaultHasher` is explicitly allowed to
/// change between releases. Five lines beat a dependency for this.
#[must_use]
pub fn hash64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One declaration, as the WAL recorded it.
struct Declaration {
    /// The process that made it, from `SO_PEERCRED`.
    tgid: u32,
    /// When.
    ts_ns: u64,
    /// The ground truth this declaration's actions will carry.
    token: u64,
    /// What the agent said it was doing.
    name: String,
}

/// The correlation token for a declaration.
///
/// **Deliberately not the `toolcall_id`.** That id travels on the control
/// socket, so an engine reading the replayed stream would see it — and the
/// plan is explicit that a token the engine can see makes §4.6 measure a join
/// rather than a correlator. A hash of *who declared, when, and which call* is
/// stable, unique in practice, and appears nowhere the engine reads.
fn token_for(tgid: u32, ts_ns: u64, toolcall_id: u64) -> u64 {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&tgid.to_le_bytes());
    bytes[4..12].copy_from_slice(&ts_ns.to_le_bytes());
    bytes[12..20].copy_from_slice(&toolcall_id.to_le_bytes());
    hash64(&bytes)
}

/// Recover a trace from the events a session produced.
///
/// Events are taken in the order given; the WAL is append-only and per-segment
/// ordered, so that order is the recording's own.
#[must_use]
pub fn from_events(events: &[RawEvent]) -> Recorded {
    // Every process the recording saw, and its parent. Built from all events
    // first, because an action may name an ancestor that only appears later.
    let mut parents: BTreeMap<u32, u32> = BTreeMap::new();
    for event in events {
        if event.tgid != 0 {
            parents.insert(event.tgid, event.ppid);
        }
    }

    let mut declarations: Vec<Declaration> = Vec::new();
    for event in events {
        if event.kind.decode() != Ok(EventKind::ToolCall) {
            continue;
        }
        let Some(Payload::Semantic(semantic)) = event.payload() else {
            continue;
        };
        let len = usize::from(semantic.name_len).min(semantic.tool_name.len());
        declarations.push(Declaration {
            tgid: event.tgid,
            ts_ns: event.ts_ns,
            token: token_for(event.tgid, event.ts_ns, semantic.toolcall_id),
            name: String::from_utf8_lossy(&semantic.tool_name[..len]).into_owned(),
        });
    }

    let origin = events.iter().map(|e| e.ts_ns).min().unwrap_or(0);
    let mut trace = Trace {
        summary: Summary::default(),
        entries: Vec::with_capacity(events.len()),
    };
    let mut skipped: BTreeMap<String, u32> = BTreeMap::new();
    let mut unattributed = 0;

    for event in events {
        let Ok(kind) = event.kind.decode() else {
            *skipped.entry("unknown".to_owned()).or_default() += 1;
            continue;
        };
        let Some(action) = action_of(kind) else {
            *skipped.entry(format!("{kind:?}")).or_default() += 1;
            continue;
        };
        let (token, intent) = if action == Action::ToolCall {
            // A declaration carries its own token and its own words.
            let found = declarations
                .iter()
                .find(|d| d.tgid == event.tgid && d.ts_ns == event.ts_ns);
            (
                found.map_or(0, |d| d.token),
                found.map_or(String::new(), |d| d.name.clone()),
            )
        } else {
            let token = attribute(event, &parents, &declarations);
            if token == 0 {
                unattributed += 1;
            }
            (token, String::new())
        };
        trace.entries.push(Entry {
            t_offset_us: (event.ts_ns.saturating_sub(origin)) / 1_000,
            action,
            args_hash: args_hash_of(event),
            correlation_token: token,
            declared_intent: intent,
        });
        trace.summary.bump(action);
    }

    trace.summary.duration_us = trace.entries.last().map_or(0, |entry| entry.t_offset_us);
    Recorded {
        trace,
        skipped,
        unattributed,
    }
}

/// The token of the declaration this action belongs to, or `0`.
fn attribute(event: &RawEvent, parents: &BTreeMap<u32, u32>, declarations: &[Declaration]) -> u64 {
    let mut current = event.tgid;
    for _ in 0..MAX_ANCESTRY {
        if current == 0 {
            break;
        }
        // The latest declaration from this process that was already made when
        // the action happened. Later declarations cannot explain it.
        let best = declarations
            .iter()
            .filter(|d| d.tgid == current && d.ts_ns <= event.ts_ns)
            .max_by_key(|d| d.ts_ns);
        if let Some(found) = best {
            return found.token;
        }
        match parents.get(&current) {
            Some(next) if *next != current => current = *next,
            // The chain broke: the parent never appeared in this recording, so
            // there is nothing further to walk. `0` says "unexplained", which
            // is a fact about the recording and not a default.
            _ => break,
        }
    }
    0
}

/// A hash of the arguments, never the arguments.
///
/// *"The arguments themselves are not in the trace, because a fixture is
/// committed and a path is data"* — so a recording of a real session publishes
/// timings and shapes, and no path anybody can read.
fn args_hash_of(event: &RawEvent) -> u64 {
    match event.payload() {
        Some(Payload::File(file)) => {
            let len = usize::from(file.path_len).min(file.path.len());
            hash64(&file.path[..len])
        }
        Some(Payload::Semantic(semantic)) => {
            let len = usize::from(semantic.name_len).min(semantic.tool_name.len());
            hash64(&semantic.tool_name[..len])
        }
        _ => 0,
    }
}

/// Read every WAL segment in `dir`, in name order, into one event stream.
///
/// # Errors
///
/// The directory, a segment that cannot be read, or a header this build does
/// not understand. A truncated tail is **not** an error: a recording whose last
/// record was being written when the daemon stopped is a normal recording, and
/// the replayer already stops at the last whole record.
pub fn read_wal(dir: &Path) -> std::io::Result<Vec<RawEvent>> {
    use aisme_core::wal::{self, SEGMENT_HEADER_SIZE};

    let mut segments: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|e| e == "wal")
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("segment-"))
        })
        .collect();
    segments.sort();

    let mut events = Vec::new();
    for segment in segments {
        let bytes = std::fs::read(&segment)?;
        if bytes.len() < SEGMENT_HEADER_SIZE {
            continue;
        }
        wal::SegmentHeader::decode(&bytes[..SEGMENT_HEADER_SIZE])
            .map_err(|e| std::io::Error::other(format!("{}: {e:?}", segment.display())))?;
        let mut out = Vec::new();
        wal::replay(&bytes, SEGMENT_HEADER_SIZE, &mut out)
            .map_err(|e| std::io::Error::other(format!("{}: {e:?}", segment.display())))?;
        events.append(&mut out);
    }
    Ok(events)
}

/// A synthetic session in the same format, with tokens known by construction.
///
/// It exists so the recorder and the replayer can be exercised **without any
/// agent at all**, which is what `F0.ASSET.02`'s recording is blocked on. Its
/// shape is §2.22's reference workload scaled to `minutes`, because a synthetic
/// trace of some other shape would exercise the code and calibrate nothing.
///
/// Deterministic: the same `minutes` gives byte-identical output, so a test can
/// compare files and a gate can hash one.
#[must_use]
pub fn synthesise(minutes: u32) -> Trace {
    let scale = f64::from(minutes) / 60.0;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the product is floored deliberately; the counts are far below 2^53"
    )]
    let scaled = |per_hour: u32| -> u32 { (f64::from(per_hour) * scale) as u32 };

    let reference = Summary::REFERENCE_PER_HOUR;
    let tool_calls = scaled(reference.tool_calls).max(1);
    // Everything a tool call causes, divided among them. The remainder lands on
    // the last tool call rather than being dropped, so the totals are the
    // totals and not the totals minus a rounding error.
    let per_call = [
        (Action::FileRead, scaled(reference.file_reads)),
        (Action::FileWrite, scaled(reference.file_writes)),
        (Action::Exec, scaled(reference.execs)),
        (Action::HttpsRequest, scaled(reference.https_requests)),
    ];

    let total_us = u64::from(minutes) * 60 * 1_000_000;
    let gap_us = total_us / u64::from(tool_calls).max(1);
    let mut trace = Trace {
        summary: Summary::default(),
        entries: Vec::new(),
    };

    for call in 0..tool_calls {
        let at = u64::from(call) * gap_us;
        let token = hash64(&call.to_le_bytes());
        trace.entries.push(Entry {
            t_offset_us: at,
            action: Action::ToolCall,
            args_hash: hash64(b"Bash"),
            correlation_token: token,
            declared_intent: "Bash".to_owned(),
        });
        trace.summary.bump(Action::ToolCall);

        for (action, total) in per_call {
            let mut share = total / tool_calls;
            if call == tool_calls - 1 {
                share += total % tool_calls;
            }
            for n in 0..share {
                // Spread inside the tool call's own window, so replay preserves
                // the burst shape §2.22 says the totals do not capture.
                let offset = at + (gap_us * u64::from(n + 1)) / u64::from(share + 1);
                trace.entries.push(Entry {
                    t_offset_us: offset,
                    action,
                    args_hash: hash64(&[&call.to_le_bytes()[..], &n.to_le_bytes()[..]].concat()),
                    correlation_token: token,
                    declared_intent: String::new(),
                });
                trace.summary.bump(action);
            }
        }
    }

    trace.entries.sort_by_key(|entry| entry.t_offset_us);
    trace.summary.duration_us = trace.entries.last().map_or(0, |e| e.t_offset_us);
    trace
}

#[cfg(test)]
// A panic is the failure report in a test; the crate's own code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{from_events, synthesise, token_for};
    use crate::trace::{self, Action};
    use aisme_ebpf_common::{EventKind, FilePayload, RawEvent};

    /// A declaration, as `agentd` records one.
    fn declaration(tgid: u32, ppid: u32, ts_ns: u64, toolcall_id: u64) -> RawEvent {
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::ToolCall.into();
        event.ts_ns = ts_ns;
        event.tgid = tgid;
        event.ppid = ppid;
        if let Some(semantic) = event.semantic_mut() {
            semantic.toolcall_id = toolcall_id;
            semantic.tool_name[..4].copy_from_slice(b"Bash");
            semantic.name_len = 4;
        }
        event
    }

    /// An open, as the sensor records one.
    fn open(tgid: u32, ppid: u32, ts_ns: u64, path: &str) -> RawEvent {
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::FileOpen.into();
        event.ts_ns = ts_ns;
        event.tgid = tgid;
        event.ppid = ppid;
        let mut file = FilePayload {
            inode: 0,
            dev: 1,
            size: 0,
            flags: 0,
            mode: 0,
            path_class: 0,
            pad0: 0,
            path_len: 0,
            path: [0; 200],
            reserved: [0; 20],
        };
        file.path_len = u16::try_from(path.len()).unwrap_or(0);
        file.path[..path.len()].copy_from_slice(path.as_bytes());
        event.payload.file = file;
        event
    }

    /// **The test this module exists for.** Two tool calls run at once and
    /// their actions interleave; each action must be attributed by **ancestry**
    /// and not by which declaration was most recent.
    ///
    /// It is built so the obvious implementation fails it. At the moment the
    /// first tool call's action happens, the *most recent* declaration is the
    /// second one — so "attribute to the latest declaration" hands half of each
    /// tool call's work to the other, and every summary count still comes out
    /// right. A test that only checked the counts would pass with that defect
    /// in place.
    #[test]
    fn actions_are_attributed_by_ancestry_and_not_by_arrival_order() {
        let events = vec![
            declaration(100, 1, 10_000, 7),
            declaration(200, 1, 20_000, 9),
            // A child of the first tool call, acting after the second declared.
            open(101, 100, 30_000, "/a"),
            // A child of the second.
            open(201, 200, 31_000, "/b"),
            // A grandchild of the first: 102 -> 101 -> 100.
            open(102, 101, 32_000, "/c"),
        ];
        let recorded = from_events(&events);

        let first = token_for(100, 10_000, 7);
        let second = token_for(200, 20_000, 9);
        assert_ne!(first, second);

        let tokens: Vec<u64> = recorded
            .trace
            .entries
            .iter()
            .filter(|e| e.action != Action::ToolCall)
            .map(|e| e.correlation_token)
            .collect();
        assert_eq!(
            tokens,
            vec![first, second, first],
            "the third action is a grandchild of the first tool call, and the second \
             declaration is the more recent one — arrival order gets this backwards"
        );
        assert_eq!(recorded.unattributed, 0);
    }

    /// The token is **not** the `toolcall_id`.
    ///
    /// That id travels on the control socket, so an engine reading the replayed
    /// stream would see it — and a token the engine can see makes §4.6 measure
    /// a join rather than a correlator.
    #[test]
    fn the_ground_truth_token_is_not_a_value_the_engine_can_see() {
        let events = vec![declaration(100, 1, 10_000, 7), open(101, 100, 20_000, "/a")];
        let recorded = from_events(&events);
        for entry in &recorded.trace.entries {
            assert_ne!(
                entry.correlation_token, 7,
                "the declared toolcall_id reached the ground truth, so the engine could join on it"
            );
            assert_ne!(entry.correlation_token, 0);
        }
    }

    /// An action no declaration explains is kept, marked `0`, and **counted**.
    ///
    /// Dropping it would make a partial recording look complete, and a summary
    /// that §2.22 compares against would be short by exactly the actions nobody
    /// could explain.
    #[test]
    fn an_unexplained_action_is_zero_and_counted_rather_than_dropped() {
        let events = vec![
            declaration(100, 1, 10_000, 7),
            open(999, 0, 20_000, "/orphan"),
        ];
        let recorded = from_events(&events);
        assert_eq!(recorded.unattributed, 1);
        assert_eq!(
            recorded.trace.summary.file_reads, 1,
            "it is still an action"
        );
        let orphan = recorded
            .trace
            .entries
            .iter()
            .find(|e| e.action == Action::FileRead)
            .unwrap();
        assert_eq!(orphan.correlation_token, 0);
    }

    /// An event kind this format has no action for is counted, never dropped in
    /// silence.
    #[test]
    fn a_kind_with_no_action_is_counted_by_name() {
        let mut other = RawEvent::ZERO;
        other.kind = EventKind::ProcExit.into();
        other.tgid = 100;
        let events = vec![declaration(100, 1, 10_000, 7), other];
        let recorded = from_events(&events);
        assert_eq!(recorded.skipped.get("ProcExit"), Some(&1));
        assert_eq!(recorded.trace.entries.len(), 1, "only the declaration");
    }

    /// The round trip: what is written is what is read back.
    ///
    /// A recorder that lost the attribution would still produce a file that
    /// parses, so the assertion is on the tokens and the summary rather than on
    /// the parse succeeding.
    #[test]
    fn a_synthetic_trace_survives_being_written_and_read_back() {
        let made = synthesise(30);
        let text = trace::write(&made);
        let read = trace::parse(&text).expect("what we wrote must parse");
        assert_eq!(read.summary, made.summary);
        assert_eq!(read.entries.len(), made.entries.len());
        for (a, b) in read.entries.iter().zip(made.entries.iter()) {
            assert_eq!(a.correlation_token, b.correlation_token);
            assert_eq!(a.action, b.action);
            assert_eq!(a.t_offset_us, b.t_offset_us);
            assert_eq!(a.args_hash, b.args_hash);
        }
        // Deterministic: the same input gives the same bytes, which a committed
        // fixture and a hash both need.
        assert_eq!(text, trace::write(&synthesise(30)));
    }

    /// The synthetic session has §2.22's shape, because a synthetic trace of
    /// some other shape would exercise the code and calibrate nothing.
    #[test]
    fn the_synthetic_session_is_the_reference_workload_scaled() {
        let half_hour = synthesise(30);
        let reference = crate::trace::Summary::REFERENCE_PER_HOUR;
        assert_eq!(half_hour.summary.file_reads, reference.file_reads / 2);
        assert_eq!(half_hour.summary.file_writes, reference.file_writes / 2);
        assert_eq!(half_hour.summary.execs, reference.execs / 2);
        assert_eq!(
            half_hour.summary.https_requests,
            reference.https_requests / 2
        );
        assert_eq!(half_hour.summary.tool_calls, reference.tool_calls / 2);
    }
}
