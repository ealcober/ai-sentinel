// SPDX-License-Identifier: Apache-2.0
//! `aisme declare` — the agent's own harness says what it is about to do.
//!
//! **This is the bridge between the two planes, and neither plane has both
//! halves.** A kernel sensor sees an `openat` and not the decision behind it; an
//! agent's transcript holds the decision and no actions at all. Measured across
//! 17 real sessions and 13 686 tool calls: **91.1 % of what an agent does is
//! "run a subprocess"**, and one such call — `cargo test -p aisme-agentsim` —
//! expands into **1 713 `openat` across 58 programs**. One intent, seventeen
//! hundred actions. Nothing downstream can join them unless the intent is
//! stated as it happens, by the only party that knows it.
//!
//! It is written to be run from a pre-tool hook, which receives the tool name
//! and the session on stdin as JSON. The hook is the harness's, not the
//! agent's: the agent cannot choose not to fire it. What the agent *can* do is
//! rewrite the configuration that installs it, which is why the session's
//! Landlock write scope must exclude that configuration — measured, and it
//! already does.
//!
//! **It authorizes nothing and it must never block.** `declareToolCall` creates
//! no grant and changes no verdict (`DT-04`: a declaration may be a lie), so a
//! failure here has nothing to protect. It exits **0 on every path**, including
//! when no daemon is listening: a declaration hook that failed closed would
//! turn the guard's observability into an outage for the user's whole workflow,
//! and enforcement lives in the kernel where a failure is fail-closed already.

use std::io::{BufRead as _, Read as _, Write as _};

/// Read the hook's JSON from stdin, declare, and get out of the way.
///
/// Returns the process exit code, which is **always 0**. See the module note.
#[must_use]
pub fn declare(args: &[String]) -> u8 {
    let mut stdin = String::new();
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        eprintln!("aisme declare: stdin could not be read; nothing declared");
        return 0;
    }

    // The hook's payload, or the flags, whichever is present. Flags exist so the
    // same binary can be driven by a harness that is not Claude Code.
    let (tool, session, event, call) = match aisme_proto::json::parse(stdin.trim()) {
        Ok(value) => {
            let field = |name: &str| {
                value
                    .get(name)
                    .and_then(aisme_proto::json::Value::as_str)
                    .map(ToOwned::to_owned)
            };
            (
                field("tool_name"),
                field("session_id"),
                field("hook_event_name"),
                field("tool_use_id"),
            )
        }
        Err(_) => (None, None, None, None),
    };
    let tool = flag(args, "--tool").or(tool).unwrap_or_default();
    let session = flag(args, "--session").or(session).unwrap_or_default();
    if tool.is_empty() {
        eprintln!("aisme declare: no tool_name on stdin or in --tool; nothing declared");
        return 0;
    }
    let phase = flag(args, "--phase")
        .or(event)
        .map_or(Phase::Start, |name| phase_of(&name));

    // **The harness's own id where there is one.** `tool_use_id` is documented
    // as existing to *"correlate `PreToolUse` and `PostToolUse` events for the
    // same tool call"*, so hashing it gives a start and its end the same
    // `toolcall_id` with no protocol field added — and six vendors carry one.
    // Where there is none, the clock-based id is unique per call and an end
    // cannot be paired to its start: the recording then knows only how many
    // calls were in flight, which is what ambiguity needs and all those
    // vendors can give.
    let id = call.map_or_else(|| call_id(&session, &tool), |id| stable_id(&session, &id));
    let socket = crate::run::agentd_socket();
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&socket) else {
        // Not an error the user should see on every tool call when they simply
        // are not running the daemon.
        return 0;
    };
    // **A declaration may be lost; it may never be a hang.** This runs as a
    // pre-tool hook, in front of every tool call the agent makes, and it
    // authorizes nothing (`DT-04`) — so a daemon that does not answer must cost
    // a dropped declaration and not the agent's turn. Measured 2026-09-15 with
    // no budget here: a declaration made from inside a supervised session waits
    // **forever**, because the daemon accepts connections serially and the
    // session's own supervisor holds one open for the whole session. The
    // process tree read `aisme run` in `recv_wait_event`, the shell in
    // `do_wait`, and this process in `unix_stream_data_wait`.
    //
    // The budget is 100× the measured cost of a declaration (1 ms).
    let budget = std::time::Duration::from_millis(100);
    let _ = stream.set_write_timeout(Some(budget));
    let _ = stream.set_read_timeout(Some(budget));
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{"toolcall_id":{id},"tool_name":"{}","phase":"{}"}}}}"#,
        aisme_proto::rpc::Method::DeclareToolCall.as_str(),
        escape(&tool),
        if phase == Phase::End { "end" } else { "start" }
    );
    if writeln!(stream, "{line}").is_err() {
        return 0;
    }
    // The answer is read but not obeyed: `rate_limited` is a result and not a
    // failure, and there is nothing this process should do differently either
    // way. Reading it keeps the daemon from writing into a closed socket.
    let mut reply = String::new();
    let _ = std::io::BufReader::new(&stream).read_line(&mut reply);
    0
}

/// Which half of a tool call's life this declaration reports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// A tool call is about to run.
    Start,
    /// A tool call that was in flight has stopped running.
    End,
}

/// The phase a hook event name reports.
///
/// **Anything unknown is a start.** A payload this version does not understand
/// must not close a call it never opened: the error then marks more ambiguity
/// in the recording rather than less, which is the safe direction. Four events
/// end a call, and `PostToolUse` alone is not enough — it fires **only on
/// success**, so subscribing to it alone would silently omit every failure and
/// every denial.
fn phase_of(event: &str) -> Phase {
    match event {
        "end" | "PostToolUse" | "PostToolUseFailure" | "PermissionDenied" | "PostToolBatch" => {
            Phase::End
        }
        _ => Phase::Start,
    }
}

/// FNV-1a over the session and the harness's own call id.
///
/// Stable across the two phases of one call, which is the whole point: the
/// clock-based [`call_id`] deliberately is not.
fn stable_id(session: &str, call: &str) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in session.as_bytes().iter().chain(call.as_bytes()) {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    i64::from_ne_bytes(h.to_ne_bytes())
}

/// A value after `--name`, when it is there.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

/// FNV-1a over the session, the tool and the clock.
fn call_id(session: &str, tool: &str) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // Truncation is the intent: the low 64 bits of a nanosecond clock are
        // what makes two calls in one session differ, and the high bits do not
        // move within a session.
        .map_or(0, |d| {
            u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0)
        });
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in session
        .as_bytes()
        .iter()
        .chain(tool.as_bytes())
        .chain(now.to_le_bytes().iter())
    {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // The codec has no unsigned integer; the daemon reads the same bits back.
    i64::from_ne_bytes(h.to_ne_bytes())
}

/// The two characters that would break the line this builds by hand.
///
/// A tool name comes from the harness rather than from the agent, but it
/// reaches this process as text and a quote in it would produce a request the
/// daemon rejects — silently losing the declaration, which is the failure this
/// whole path exists to avoid.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{call_id, escape, flag, phase_of, stable_id, Phase};

    /// **Anything this version does not understand is a start.**
    ///
    /// A payload that cannot say which half of a call it reports must not close
    /// one it never opened: the recording then marks more ambiguity rather than
    /// less, which is the safe direction. The four end events are the four,
    /// because `PostToolUse` fires **only on success** — subscribing to it alone
    /// would silently omit every failure, every denial and every interrupt.
    #[test]
    fn only_the_four_end_events_end_a_call_and_everything_else_starts_one() {
        for ending in [
            "PostToolUse",
            "PostToolUseFailure",
            "PermissionDenied",
            "PostToolBatch",
            "end",
        ] {
            assert!(
                phase_of(ending) == Phase::End,
                "{ending} did not end a call"
            );
        }
        for starting in [
            "PreToolUse",
            "start",
            "",
            "SessionStart",
            // A vendor event this version has never heard of. It must not
            // decrement a counter it never incremented.
            "SomeFutureToolEvent",
        ] {
            assert!(
                phase_of(starting) == Phase::Start,
                "{starting:?} closed a call"
            );
        }
    }

    /// The harness's own id makes a start and its end **the same call**.
    ///
    /// `tool_use_id` is documented as existing to correlate the two hook
    /// events, so hashing it needs no protocol field. The clock-based id
    /// deliberately does the opposite, which is what puts a session without a
    /// per-call id into counted mode.
    #[test]
    fn the_harness_id_is_stable_across_the_two_phases_and_the_clock_id_is_not() {
        assert_eq!(
            stable_id("s", "toolu_01ABC"),
            stable_id("s", "toolu_01ABC"),
            "a start and its end did not land on the same call"
        );
        assert_ne!(
            stable_id("s", "toolu_01ABC"),
            stable_id("s", "toolu_01XYZ"),
            "two different calls collided"
        );
        assert_ne!(
            stable_id("s", "toolu_01ABC"),
            stable_id("other", "toolu_01ABC"),
            "two sessions share a call id"
        );

        let a = call_id("s", "Bash");
        std::thread::sleep(std::time::Duration::from_nanos(1));
        assert_ne!(
            a,
            call_id("s", "Bash"),
            "the fallback id is stable, so an end would pair with the wrong start"
        );
    }

    /// Two calls in the same session are two tool calls.
    #[test]
    fn each_call_gets_its_own_id() {
        let a = call_id("s", "Bash");
        std::thread::sleep(std::time::Duration::from_nanos(1));
        assert_ne!(a, call_id("s", "Bash"));
    }

    /// A flag beats the payload, and a missing value is not read as the next
    /// flag's name.
    #[test]
    fn a_flag_without_its_value_is_absent_rather_than_the_next_flag() {
        let args = ["--tool".to_owned(), "--session".to_owned(), "s".to_owned()];
        assert_eq!(flag(&args, "--tool"), None);
        assert_eq!(flag(&args, "--session"), Some("s".to_owned()));
    }

    /// A quote in a tool name does not produce a request the daemon rejects.
    #[test]
    fn a_quote_in_a_tool_name_does_not_break_the_line() {
        let line = format!(r#"{{"tool_name":"{}"}}"#, escape(r#"Ba"sh\x"#));
        assert!(aisme_proto::json::parse(&line).is_ok(), "{line}");
    }
}
