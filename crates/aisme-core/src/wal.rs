// SPDX-License-Identifier: Apache-2.0
//! The write-ahead log's format and replay (`F1.RT.05`).
//!
//! `forensicd` resumes by offset, so the format's job is to make an offset
//! meaningful after a crash: a segment is a header followed by fixed
//! 320-byte records, and a reader that stops at the first record it cannot
//! trust keeps everything before it. Nothing here does I/O — the mapping,
//! the `fsync` policy and the 64 MB rotation are the daemon's (L3); what
//! lives in L1 is the layout, the header, and the replay that has to agree
//! with the writer byte for byte.
//!
//! **On `rkyv`.** The plan names it, and for a variable-shaped record it
//! would be the right answer: zero-copy access without a parse. `RawEvent`
//! is already `repr(C)`, fixed at 320 bytes and layout-asserted for both
//! targets (`F1.EV.03`), so an archived form would be a copy of the bytes
//! plus a dependency, and the zero-copy read is a cast. The deviation is
//! recorded in the plan's `F1.RT.05` row rather than left as a silent
//! difference between the plan and the code.

use aisme_ebpf_common::{RawEvent, RAW_EVENT_SIZE, WIRE_VERSION};

use crate::policy::PolicyGeneration;

/// A segment starts with this.
pub const SEGMENT_MAGIC: [u8; 8] = *b"AISMEWAL";

/// Header: magic (8) · wire version (1) · pad (3) · schema hash (8) ·
/// segment number (8) · first sequence (8) · policy generation (8) = 44,
/// rounded to 48 so records stay 8-aligned.
pub const SEGMENT_HEADER_SIZE: usize = 48;

/// §F1.6: 64 MB segments.
pub const SEGMENT_BYTES: usize = 64 * 1024 * 1024;

/// How many records fit in one segment.
#[must_use]
pub const fn records_per_segment() -> usize {
    (SEGMENT_BYTES - SEGMENT_HEADER_SIZE) / RAW_EVENT_SIZE
}

/// What a segment header says about the writer that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    /// The writer's wire version (§3.6).
    pub wire_version: u8,
    /// The writer's layout hash (`F1.EV.02`): a definition that changed
    /// without its version bump is caught here too.
    pub schema_hash: u64,
    /// Which segment this is.
    pub segment: u64,
    /// The sequence number of its first record.
    pub first_seq: u64,
    /// The policy generation in force when it opened.
    pub generation: PolicyGeneration,
}

impl SegmentHeader {
    /// A header for this binary's wire.
    #[must_use]
    pub fn local(segment: u64, first_seq: u64, generation: PolicyGeneration) -> SegmentHeader {
        SegmentHeader {
            wire_version: WIRE_VERSION,
            schema_hash: aisme_ebpf_common::SCHEMA_HASH,
            segment,
            first_seq,
            generation,
        }
    }

    /// The header's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_SIZE] {
        let mut out = [0u8; SEGMENT_HEADER_SIZE];
        out[..8].copy_from_slice(&SEGMENT_MAGIC);
        out[8] = self.wire_version;
        out[12..20].copy_from_slice(&self.schema_hash.to_le_bytes());
        out[20..28].copy_from_slice(&self.segment.to_le_bytes());
        out[28..36].copy_from_slice(&self.first_seq.to_le_bytes());
        out[36..44].copy_from_slice(&self.generation.0.to_le_bytes());
        out
    }

    /// Read a header.
    ///
    /// # Errors
    ///
    /// [`WalError`] when the bytes are not a segment header, or are one this
    /// binary cannot read.
    pub fn decode(bytes: &[u8]) -> Result<SegmentHeader, WalError> {
        if bytes.len() < SEGMENT_HEADER_SIZE {
            return Err(WalError::Truncated {
                offset: 0,
                needed: SEGMENT_HEADER_SIZE,
                got: bytes.len(),
            });
        }
        if bytes[..8] != SEGMENT_MAGIC {
            return Err(WalError::NotASegment);
        }
        let at = |i: usize| {
            u64::from_le_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
                bytes[i + 4],
                bytes[i + 5],
                bytes[i + 6],
                bytes[i + 7],
            ])
        };
        Ok(SegmentHeader {
            wire_version: bytes[8],
            schema_hash: at(12),
            segment: at(20),
            first_seq: at(28),
            generation: PolicyGeneration(at(36)),
        })
    }

    /// Whether this binary can read the segment's records (§3.6: skip
    /// unknown segments, warn, do not corrupt).
    ///
    /// # Errors
    ///
    /// [`WalError::ForeignWire`] with both versions and hashes.
    pub fn readable(&self) -> Result<(), WalError> {
        if self.wire_version != WIRE_VERSION || self.schema_hash != aisme_ebpf_common::SCHEMA_HASH {
            return Err(WalError::ForeignWire {
                theirs: (self.wire_version, self.schema_hash),
                ours: (WIRE_VERSION, aisme_ebpf_common::SCHEMA_HASH),
            });
        }
        Ok(())
    }
}

/// Why replay stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalError {
    /// The bytes do not begin a segment.
    NotASegment,
    /// A record or the header is cut short — the crash case: everything
    /// before `offset` is good.
    Truncated {
        /// Where the incomplete record starts.
        offset: usize,
        /// Bytes it needed.
        needed: usize,
        /// Bytes there were.
        got: usize,
    },
    /// The segment was written by another wire (§3.6).
    ForeignWire {
        /// The writer's version and layout hash.
        theirs: (u8, u64),
        /// This binary's.
        ours: (u8, u64),
    },
}

impl core::fmt::Display for WalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalError::NotASegment => write!(f, "not a WAL segment"),
            WalError::Truncated { offset, needed, got } => write!(
                f,
                "record at {offset} is cut short ({got} of {needed} bytes): everything before it is intact"
            ),
            WalError::ForeignWire { theirs, ours } => write!(
                f,
                "segment written at wire {} schema {:#018x}; this binary reads wire {} schema {:#018x} — skipped, not parsed",
                theirs.0, theirs.1, ours.0, ours.1
            ),
        }
    }
}

impl core::error::Error for WalError {}

/// Append a record to a segment's bytes. The caller owns the storage — a
/// mapping in `agentd`, a `Vec` in a test — and the fsync policy.
pub fn append(segment: &mut Vec<u8>, event: &RawEvent) {
    segment.extend_from_slice(&encode_record(event));
}

/// One record's bytes.
#[must_use]
pub fn encode_record(event: &RawEvent) -> [u8; RAW_EVENT_SIZE] {
    event.to_bytes()
}

/// The record at `offset`, and where the next one starts.
///
/// # Errors
///
/// [`WalError::Truncated`] when the segment ends inside the record — which
/// is what a crash leaves behind, and why it names the offset.
pub fn read_record(segment: &[u8], offset: usize) -> Result<(RawEvent, usize), WalError> {
    let end = offset + RAW_EVENT_SIZE;
    if segment.len() < end {
        return Err(WalError::Truncated {
            offset,
            needed: RAW_EVENT_SIZE,
            got: segment.len().saturating_sub(offset),
        });
    }
    let mut bytes = [0u8; RAW_EVENT_SIZE];
    bytes.copy_from_slice(&segment[offset..end]);
    let event = RawEvent::from_bytes(bytes);
    Ok((event, end))
}

/// Replay a segment from `offset`, stopping at the first record it cannot
/// trust. Returns the events read and the offset to resume from — which is
/// **before** the bad record, so a torn tail is re-read, never skipped.
///
/// # Errors
///
/// The header's, when the segment is not this binary's to read.
pub fn replay(segment: &[u8], from: usize, out: &mut Vec<RawEvent>) -> Result<Resume, WalError> {
    let header = SegmentHeader::decode(segment)?;
    header.readable()?;
    let mut offset = from.max(SEGMENT_HEADER_SIZE);
    let mut torn = None;
    loop {
        match read_record(segment, offset) {
            Ok((event, next)) => {
                out.push(event);
                offset = next;
            }
            Err(WalError::Truncated { got: 0, .. }) => break,
            Err(e) => {
                torn = Some(e);
                break;
            }
        }
    }
    Ok(Resume {
        header,
        next_offset: offset,
        torn,
    })
}

/// Where a replay stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    /// The segment's header.
    pub header: SegmentHeader,
    /// The offset to resume from: the start of the first record not read.
    pub next_offset: usize,
    /// The torn tail, when there was one.
    pub torn: Option<WalError>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisme_ebpf_common::EventKind;

    fn segment(events: usize) -> Vec<u8> {
        let mut bytes = SegmentHeader::local(3, 100, PolicyGeneration(7))
            .encode()
            .to_vec();
        for i in 0..events {
            let mut event = RawEvent::ZERO;
            event.kind = EventKind::FileOpen.into();
            event.seq = 100 + i as u64;
            append(&mut bytes, &event);
        }
        bytes
    }

    #[test]
    fn a_segment_replays_to_the_end_and_says_where_to_resume() {
        let bytes = segment(5);
        let mut out = Vec::new();
        let resume = replay(&bytes, 0, &mut out).unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].seq, 100);
        assert_eq!(out[4].seq, 104);
        assert_eq!(resume.header.segment, 3);
        assert_eq!(resume.header.first_seq, 100);
        assert_eq!(resume.header.generation, PolicyGeneration(7));
        assert_eq!(resume.next_offset, SEGMENT_HEADER_SIZE + 5 * RAW_EVENT_SIZE);
        assert_eq!(resume.torn, None);
        // Resuming from that offset reads nothing new, which is what makes
        // an offset a resume point rather than a hint.
        let mut again = Vec::new();
        let resume2 = replay(&bytes, resume.next_offset, &mut again).unwrap();
        assert!(again.is_empty());
        assert_eq!(resume2.next_offset, resume.next_offset);
    }

    #[test]
    fn a_torn_tail_keeps_everything_before_it_and_is_re_read_not_skipped() {
        let mut bytes = segment(3);
        bytes.truncate(bytes.len() - 100); // the crash: a record half written
        let mut out = Vec::new();
        let resume = replay(&bytes, 0, &mut out).unwrap();
        assert_eq!(out.len(), 2, "the two whole records survive");
        assert_eq!(resume.next_offset, SEGMENT_HEADER_SIZE + 2 * RAW_EVENT_SIZE);
        assert!(matches!(
            resume.torn,
            Some(WalError::Truncated { got: 220, .. })
        ));
        // The resume offset points *at* the torn record, so a writer that
        // finishes it later is read, not skipped.
        assert!(resume.next_offset < bytes.len());
    }

    #[test]
    fn a_segment_from_another_wire_is_skipped_with_both_versions_named() {
        let mut bytes = segment(1);
        bytes[8] = WIRE_VERSION + 1;
        let mut out = Vec::new();
        let err = replay(&bytes, 0, &mut out).unwrap_err();
        assert!(matches!(err, WalError::ForeignWire { .. }));
        assert!(err.to_string().contains("skipped, not parsed"));
        assert!(out.is_empty(), "nothing from a segment we cannot read");
        // A drifted schema at the same version is refused too.
        let mut drifted = segment(1);
        drifted[12] ^= 0xFF;
        assert!(matches!(
            replay(&drifted, 0, &mut Vec::new()),
            Err(WalError::ForeignWire { .. })
        ));
        // Bytes too short to be a header are truncated, not "not a
        // segment": a torn first write and a wrong file are different
        // problems, and the reader says which it is.
        assert!(matches!(
            replay(b"not a wal", 0, &mut Vec::new()),
            Err(WalError::Truncated { offset: 0, .. })
        ));
        let long_enough = [b'x'; SEGMENT_HEADER_SIZE];
        assert_eq!(
            replay(&long_enough, 0, &mut Vec::new()),
            Err(WalError::NotASegment)
        );
    }

    #[test]
    fn a_record_round_trips_byte_for_byte_and_the_segment_size_is_the_plans() {
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::SockConnect.into();
        event.seq = 42;
        event.taint = 0b101;
        let bytes = encode_record(&event);
        let (back, next) = read_record(&bytes, 0).unwrap();
        assert_eq!(back.seq, 42);
        assert_eq!(back.taint, 0b101);
        assert_eq!(back.kind, event.kind);
        assert_eq!(next, RAW_EVENT_SIZE);
        assert_eq!(SEGMENT_BYTES, 64 * 1024 * 1024);
        assert_eq!(records_per_segment(), 209_715, "measured, not estimated");
    }
}
