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
    let (tool, session) = match aisme_proto::json::parse(stdin.trim()) {
        Ok(value) => (
            value
                .get("tool_name")
                .and_then(aisme_proto::json::Value::as_str)
                .map(ToOwned::to_owned),
            value
                .get("session_id")
                .and_then(aisme_proto::json::Value::as_str)
                .map(ToOwned::to_owned),
        ),
        Err(_) => (None, None),
    };
    let tool = flag(args, "--tool").or(tool).unwrap_or_default();
    let session = flag(args, "--session").or(session).unwrap_or_default();
    if tool.is_empty() {
        eprintln!("aisme declare: no tool_name on stdin or in --tool; nothing declared");
        return 0;
    }

    // Unique per call without holding any state: the same tool declared twice in
    // one nanosecond would collide, and nothing in a session does that.
    let id = call_id(&session, &tool);
    let socket = crate::run::agentd_socket();
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&socket) else {
        // Not an error the user should see on every tool call when they simply
        // are not running the daemon.
        return 0;
    };
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{"toolcall_id":{id},"tool_name":"{}"}}}}"#,
        aisme_proto::rpc::Method::DeclareToolCall.as_str(),
        escape(&tool)
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
    use super::{call_id, escape, flag};

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
