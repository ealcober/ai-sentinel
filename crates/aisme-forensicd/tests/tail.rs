// SPDX-License-Identifier: Apache-2.0
//! `aisme-forensicd --tail` end to end (`F2.WS.07`).
//!
//! The binary is the process under test. The WAL it reads is built here with
//! the production encoders — `SegmentHeader::encode` and `encode_record` — so a
//! format change breaks these tests rather than letting them pass against a
//! shape nothing writes.

use std::path::{Path, PathBuf};
use std::process::Command;

use aisme_core::policy::PolicyGeneration;
use aisme_core::wal::{self, SegmentHeader};
use aisme_ebpf_common::{EventKind, RawEvent};

fn forensicd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aisme-forensicd"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aisme-tail-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(format!("segment-{index:012}.wal"))
}

/// A segment with `first..first+count` in it, written the way `WalSink` does.
fn write_segment(dir: &Path, index: u64, first: u64, count: u64) {
    let mut bytes = SegmentHeader::local(index, first, Some(PolicyGeneration(1)))
        .encode()
        .to_vec();
    for seq in first..first + count {
        bytes.extend_from_slice(&wal::encode_record(&event(seq)));
    }
    std::fs::write(segment_path(dir, index), bytes).unwrap();
}

fn append_records(dir: &Path, index: u64, first: u64, count: u64) {
    let mut bytes = std::fs::read(segment_path(dir, index)).unwrap();
    for seq in first..first + count {
        bytes.extend_from_slice(&wal::encode_record(&event(seq)));
    }
    std::fs::write(segment_path(dir, index), bytes).unwrap();
}

fn event(seq: u64) -> RawEvent {
    let mut e = RawEvent::ZERO;
    e.seq = seq;
    e.tgid = 100;
    e.pid = 100;
    e.kind = EventKind::FileOpen.code();
    e
}

/// The sequence numbers a run printed, in order.
fn seqs(stdout: &str) -> Vec<u64> {
    stdout
        .lines()
        .filter_map(|l| {
            l.strip_prefix("seq=")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect()
}

fn tail_once(dir: &Path) -> String {
    let out = forensicd()
        .args(["--tail", dir.to_str().unwrap(), "--once"])
        .output()
        .expect("forensicd");
    assert!(
        out.status.success(),
        "tail failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A second run reads what the first did not, and nothing it already read.
#[test]
fn a_resumed_tail_reads_every_record_exactly_once() {
    let dir = tmpdir("resume");
    write_segment(&dir, 0, 1, 4);

    // No cursor yet: from the beginning.
    assert_eq!(seqs(&tail_once(&dir)), vec![1, 2, 3, 4]);

    append_records(&dir, 0, 5, 6);
    assert_eq!(
        seqs(&tail_once(&dir)),
        vec![5, 6, 7, 8, 9, 10],
        "the second run re-read records the first had already printed"
    );

    // And a third run with nothing new prints nothing.
    assert!(seqs(&tail_once(&dir)).is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// The done-condition: killed mid-stream, it resumes with zero loss.
///
/// The cursor is written *after* each print, so a kill can cost at most the one
/// record whose line reached stdout before its cursor write did — a repeat,
/// which is visible. A loss would not be.
#[test]
fn a_killed_tail_loses_nothing() {
    let dir = tmpdir("killed");
    write_segment(&dir, 0, 1, 40);

    let mut child = forensicd()
        .args(["--tail", dir.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("forensicd");
    // Long enough to drain 40 records and enter the follow sleep.
    std::thread::sleep(std::time::Duration::from_millis(400));
    child.kill().expect("kill");
    let first = child.wait_with_output().expect("wait");
    let first = seqs(&String::from_utf8_lossy(&first.stdout));
    assert!(!first.is_empty(), "the killed run printed nothing at all");

    let second = seqs(&tail_once(&dir));

    let mut union = first.clone();
    union.extend(&second);
    union.sort_unstable();
    let repeats = union.len() - {
        let mut u = union.clone();
        u.dedup();
        u.len()
    };
    union.dedup();
    assert_eq!(
        union,
        (1..=40).collect::<Vec<u64>>(),
        "records were lost across the kill"
    );
    assert!(
        repeats <= 1,
        "a kill cost {repeats} repeats; at most one is the cursor's window"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A half-written record is the normal state of a file being appended to.
#[test]
fn a_partial_record_is_waited_for_and_not_skipped() {
    let dir = tmpdir("partial");
    write_segment(&dir, 0, 1, 2);
    // Half of the third record.
    let whole = wal::encode_record(&event(3));
    let mut bytes = std::fs::read(segment_path(&dir, 0)).unwrap();
    bytes.extend_from_slice(&whole[..whole.len() / 2]);
    std::fs::write(segment_path(&dir, 0), &bytes).unwrap();

    assert_eq!(seqs(&tail_once(&dir)), vec![1, 2], "a torn tail was read");

    // Complete it: the record must now arrive whole, not be skipped.
    bytes.truncate(bytes.len() - whole.len() / 2);
    bytes.extend_from_slice(&whole);
    std::fs::write(segment_path(&dir, 0), &bytes).unwrap();
    assert_eq!(seqs(&tail_once(&dir)), vec![3]);
    std::fs::remove_dir_all(&dir).ok();
}

/// A roll is followed by offset: the reader finishes what it holds first.
#[test]
fn a_roll_is_followed_only_after_the_current_segment_is_drained() {
    let dir = tmpdir("roll");
    write_segment(&dir, 0, 1, 3);
    write_segment(&dir, 1, 4, 3);
    assert_eq!(
        seqs(&tail_once(&dir)),
        vec![1, 2, 3, 4, 5, 6],
        "the newer segment was opened before the older one was drained"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A cursor past the end is refused, never clamped: clamping skips whatever sat
/// between in silence.
#[test]
fn a_cursor_past_the_end_is_refused() {
    let dir = tmpdir("past");
    write_segment(&dir, 0, 1, 2);
    std::fs::write(dir.join(".forensicd-cursor"), "0 999999\n").unwrap();

    let out = forensicd()
        .args(["--tail", dir.to_str().unwrap(), "--once"])
        .output()
        .expect("forensicd");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("past the end"), "{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

/// A cursor that exists and does not parse is not read as absent.
#[test]
fn a_malformed_cursor_is_refused_rather_than_treated_as_absent() {
    let dir = tmpdir("malformed");
    write_segment(&dir, 0, 1, 2);
    std::fs::write(dir.join(".forensicd-cursor"), "banana\n").unwrap();

    let out = forensicd()
        .args(["--tail", dir.to_str().unwrap(), "--once"])
        .output()
        .expect("forensicd");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "a corrupt cursor re-printed the WAL"
    );
    std::fs::remove_dir_all(&dir).ok();
}
