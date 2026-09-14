// SPDX-License-Identifier: Apache-2.0
//! `aisme-forensicd --tail <wal-dir>` (`F2.WS.07`).
//!
//! The cold path reading what the hot path wrote. The cursor is the whole
//! design: one offset in a file beside the WAL, written **after** the record it
//! accounts for has been printed. Written before, a crash between the write and
//! the print loses a record in silence — which is exactly the failure this
//! task's done-condition names. Written after, a crash costs a **repeat**, and
//! a repeat is visible while a loss is not.

use std::path::{Path, PathBuf};

use aisme_core::wal::{self, SEGMENT_HEADER_SIZE};
use aisme_ebpf_common::{Payload, RawEvent};

/// How far the reader has got: which segment, and where in it.
///
/// Both halves are needed. An offset alone would be read into whichever segment
/// happened to be newest after a roll, which is a silent skip of everything the
/// previous one still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The segment index, as `segment-<index>.wal` names it.
    pub segment: u64,
    /// The byte offset of the first record not yet printed.
    pub offset: usize,
}

impl Cursor {
    /// The start of a segment: after its header, never at byte zero.
    const fn start_of(segment: u64) -> Cursor {
        Cursor {
            segment,
            offset: SEGMENT_HEADER_SIZE,
        }
    }
}

/// Where the cursor lives. Beside the WAL, so a directory is self-describing:
/// what was written and how far it has been read travel together.
#[must_use]
pub fn cursor_path(dir: &Path) -> PathBuf {
    dir.join(".forensicd-cursor")
}

/// Parse a cursor file's contents.
///
/// # Errors
///
/// Anything that is not `<segment> <offset>`. A cursor file that exists and
/// cannot be read is **not** treated as absent: absent means "from the
/// beginning", and reading a corrupt cursor as absent would silently re-print
/// the whole WAL while reporting nothing wrong.
pub fn parse_cursor(text: &str) -> Result<Cursor, String> {
    let mut parts = text.split_whitespace();
    let (Some(segment), Some(offset), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("cursor is not `<segment> <offset>`: {text:?}"));
    };
    Ok(Cursor {
        segment: segment
            .parse()
            .map_err(|e| format!("cursor segment {segment:?}: {e}"))?,
        offset: offset
            .parse()
            .map_err(|e| format!("cursor offset {offset:?}: {e}"))?,
    })
}

/// Read the cursor, or start at the oldest segment there is.
///
/// # Errors
///
/// A cursor file that exists and does not parse.
pub fn read_cursor(dir: &Path) -> Result<Cursor, String> {
    match std::fs::read_to_string(cursor_path(dir)) {
        Ok(text) => parse_cursor(&text),
        // Absent is a value here and it has a meaning: nothing has been read,
        // so start at the oldest segment present. That is the honest default
        // and it is stated rather than inferred from a zero.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(Cursor::start_of(oldest_segment(dir).unwrap_or(0)))
        }
        Err(e) => Err(format!("cursor: {e}")),
    }
}

/// Write the cursor. Called **after** the record it accounts for was printed.
///
/// # Errors
///
/// The write. A cursor that cannot be persisted is fatal: continuing would
/// print records the next run prints again, without bound.
pub fn write_cursor(dir: &Path, cursor: Cursor) -> Result<(), String> {
    std::fs::write(
        cursor_path(dir),
        format!("{} {}\n", cursor.segment, cursor.offset),
    )
    .map_err(|e| format!("cursor: {e}"))
}

/// The segment indices present, ascending.
fn segments(dir: &Path) -> Vec<u64> {
    let mut found: Vec<u64> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let index = name.strip_prefix("segment-")?.strip_suffix(".wal")?;
            index.parse().ok()
        })
        .collect();
    found.sort_unstable();
    found
}

fn oldest_segment(dir: &Path) -> Option<u64> {
    segments(dir).first().copied()
}

fn newest_segment(dir: &Path) -> Option<u64> {
    segments(dir).last().copied()
}

/// One record, as one line.
///
/// Enough for `aisme`'s own line to be a **filter over this** rather than a
/// second formatter that can disagree with it.
#[must_use]
pub fn render(event: &RawEvent) -> String {
    let kind = event.kind.decode().map_or_else(
        |unknown| format!("unknown:{:#06x}", unknown.0 .0),
        |k| format!("{k:?}"),
    );
    let mut line = format!(
        "seq={} ts={} tgid={} pid={} kind={kind}",
        event.seq, event.ts_ns, event.tgid, event.pid
    );
    if let Some(Payload::File(file)) = event.payload() {
        use std::fmt::Write as _;
        let len = usize::from(file.path_len).min(file.path.len());
        // `write!` into the buffer rather than `push_str(&format!(…))`: one
        // allocation instead of two on a line printed once per record.
        let _ = write!(line, " path={}", String::from_utf8_lossy(&file.path[..len]));
    }
    if event.truncated() {
        line.push_str(" truncated");
    }
    line
}

/// Tail the WAL in `dir` from the cursor, printing one line per record.
///
/// `once` stops when the reader has caught up instead of waiting for more,
/// which is what a test and a one-shot dump want; without it this follows.
///
/// # Errors
///
/// A cursor that cannot be read or written, or a segment this binary cannot
/// read. A *torn tail* is not an error: it is the normal state of a file being
/// appended to, and it is waited for.
pub fn tail(dir: &Path, once: bool) -> Result<(), String> {
    let mut cursor = read_cursor(dir)?;
    loop {
        let path = wal_segment_path(dir, cursor.segment);
        match std::fs::read(&path) {
            Ok(bytes) => {
                cursor = drain(dir, &bytes, cursor)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The cursor names a segment that is not there. If a later one
                // exists the WAL rolled past us, and skipping to it would lose
                // whatever this one held — so it is refused, not clamped.
                if let Some(newest) = newest_segment(dir) {
                    if newest > cursor.segment {
                        return Err(format!(
                            "segment {} is gone and {newest} exists: the WAL rolled past this cursor",
                            cursor.segment
                        ));
                    }
                }
                if once {
                    return Ok(());
                }
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }

        // Caught up with this segment. Only now may the next one be opened: a
        // roll is followed by offset, never by name, or the records still
        // unread behind it are dropped.
        if newest_segment(dir).is_some_and(|newest| newest > cursor.segment) {
            cursor = Cursor::start_of(cursor.segment + 1);
            write_cursor(dir, cursor)?;
            continue;
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Print every whole record from `cursor` onward, moving the cursor after each.
fn drain(dir: &Path, bytes: &[u8], mut cursor: Cursor) -> Result<Cursor, String> {
    if cursor.offset > bytes.len() {
        // Clamping here would silently skip whatever sat between, so the
        // mismatch is named instead.
        return Err(format!(
            "cursor offset {} is past the end of segment {} ({} bytes)",
            cursor.offset,
            cursor.segment,
            bytes.len()
        ));
    }
    loop {
        match wal::read_record(bytes, cursor.offset) {
            Ok((event, next)) => {
                println!("{}", render(&event));
                // AFTER the print. A crash here costs a repeat, never a loss.
                cursor.offset = next;
                write_cursor(dir, cursor)?;
            }
            // A partial record is the normal state of a file being appended to,
            // not a fault: the offset does not move, so the next pass re-reads
            // it whole.
            Err(wal::WalError::Truncated { .. }) => return Ok(cursor),
            Err(e) => return Err(format!("segment {}: {e:?}", cursor.segment)),
        }
    }
}

/// `segment-<index>.wal`, the name `WalSink` writes.
fn wal_segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(format!("segment-{index:012}.wal"))
}

/// Parse the arguments and tail. Returns the exit code.
pub fn run(args: &[String]) -> u8 {
    let once = args.iter().any(|a| a == "--once");
    let Some(dir) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: aisme-forensicd --tail <wal-dir> [--once]");
        return 1;
    };
    match tail(Path::new(dir), once) {
        Ok(()) => 0,
        Err(problem) => {
            eprintln!("aisme-forensicd: {problem}");
            1
        }
    }
}

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{parse_cursor, render, Cursor};
    use aisme_ebpf_common::{EventKind, RawEvent};

    #[test]
    fn a_cursor_round_trips_and_a_malformed_one_is_named() {
        assert_eq!(
            parse_cursor("3 1024\n").unwrap(),
            Cursor {
                segment: 3,
                offset: 1024
            }
        );
        // Not silently treated as absent: that would re-print the whole WAL
        // while reporting nothing wrong.
        assert!(parse_cursor("").is_err());
        assert!(parse_cursor("3").is_err());
        assert!(parse_cursor("3 1024 5").is_err());
        assert!(parse_cursor("three 1024").is_err());
    }

    #[test]
    fn a_line_carries_what_a_filter_needs() {
        let mut event = RawEvent::ZERO;
        event.seq = 7;
        event.tgid = 42;
        event.pid = 43;
        event.kind = EventKind::FileOpen.code();
        let line = render(&event);
        assert!(line.contains("seq=7"), "{line}");
        assert!(line.contains("tgid=42"), "{line}");
        assert!(line.contains("FileOpen"), "{line}");
    }
}
