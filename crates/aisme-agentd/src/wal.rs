// SPDX-License-Identifier: Apache-2.0
//! `WalSink`: the hot loop's durable end (`F2.WS.02`, `F1.RT.05`).
//!
//! The record format, the segment header and the replay reader live in
//! `aisme-core::wal`, which has no I/O by `A-01`. What lives here is the file:
//! opening a segment, appending to it, fsyncing it and rolling to the next one.
//! `forensicd` reads what this writes, by offset, which is `F2.WS.07`.
//!
//! **Durability is per batch, not per event.** A tick's events are written and
//! then fsynced once, so the cost is one fsync per tick rather than one per
//! event, and the window a crash can lose is exactly one tick — which the
//! engine's own report already names.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aisme_core::error::{Error, Result};
use aisme_core::policy::PolicyGeneration;
use aisme_core::sensor::{EventBatch, EventSink};
use aisme_core::wal::{self, SEGMENT_BYTES};
use aisme_ebpf_common::RAW_EVENT_SIZE;

/// Appends events to a segment file, rolling when it is full.
pub struct WalSink {
    dir: PathBuf,
    file: File,
    /// Which segment is open; the file is `segment-<index>.wal`.
    index: u64,
    /// Bytes written to the open segment, header included.
    written: usize,
    /// The `seq` the next segment's header will declare as its first.
    next_seq: u64,
    /// The policy generation the header records, so a reader knows which
    /// policy was in force for the events in it.
    /// Shared with the control plane, and **read at each segment roll** rather
    /// than captured once. The loader publishes and then tells the daemon; a
    /// sink that had copied the value at startup would stamp `None` on every
    /// segment for the life of the process.
    generation: crate::ipc::GenerationCell,
    /// Reused across batches: a sink that allocated per tick would break the
    /// hot loop's invariant (`I-22`) from the far end.
    buf: Vec<u8>,
    /// Batches written and fsynced.
    pub batches: u64,
    /// Events written.
    pub events: u64,
    /// Segments rolled.
    pub rolls: u64,
}

impl WalSink {
    /// Open `dir`, starting a fresh segment.
    ///
    /// # Errors
    ///
    /// `Failed` with the path when the directory or the file cannot be made.
    pub fn create(dir: &Path, generation: Option<PolicyGeneration>) -> Result<WalSink> {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::failed(format!("wal dir {}: {e}", dir.display())))?;
        let mut sink = WalSink {
            dir: dir.to_path_buf(),
            // Replaced by `open_segment` before anything is written; a `File`
            // has no meaningful empty value, so the first one is opened here.
            file: Self::open_file(dir, 0)?,
            index: 0,
            written: 0,
            next_seq: 0,
            generation: std::sync::Arc::new(std::sync::Mutex::new(generation)),
            // One tick's worth of records, so a full batch is one `write_all`.
            buf: Vec::with_capacity(512 * RAW_EVENT_SIZE),
            batches: 0,
            events: 0,
            rolls: 0,
        };
        sink.write_header()?;
        Ok(sink)
    }

    /// The path of segment `index` under `dir`.
    #[must_use]
    pub fn segment_path(dir: &Path, index: u64) -> PathBuf {
        dir.join(format!("segment-{index:012}.wal"))
    }

    fn open_file(dir: &Path, index: u64) -> Result<File> {
        let path = Self::segment_path(dir, index);
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|e| Error::failed(format!("wal segment {}: {e}", path.display())))
    }

    /// Write the current segment's header. Every segment starts with one, so a
    /// reader that opens any file knows the wire version, the schema hash and
    /// the policy generation before it reads a record.
    fn write_header(&mut self) -> Result<()> {
        // A poisoned lock is taken anyway: the alternative is refusing to open
        // a segment because a control-plane request panicked, which loses
        // events over a number.
        let told = match self.generation.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let header = wal::SegmentHeader::local(self.index, self.next_seq, told);
        let bytes = header.encode();
        self.file
            .write_all(&bytes)
            .map_err(|e| Error::failed(format!("wal header: {e}")))?;
        self.written = bytes.len();
        Ok(())
    }

    /// Close the open segment and start the next one.
    fn roll(&mut self) -> Result<()> {
        // The finished segment is fsynced before the next is opened: a reader
        // that sees segment N+1 must be able to trust segment N is complete.
        self.file
            .sync_all()
            .map_err(|e| Error::failed(format!("wal fsync on roll: {e}")))?;
        self.index += 1;
        self.rolls += 1;
        self.file = Self::open_file(&self.dir, self.index)?;
        self.write_header()
    }

    /// The cell the control plane writes when the loader publishes.
    #[must_use]
    pub fn generation_cell(&self) -> crate::ipc::GenerationCell {
        std::sync::Arc::clone(&self.generation)
    }

    /// The segment file currently being appended to.
    #[must_use]
    pub fn current_segment(&self) -> PathBuf {
        Self::segment_path(&self.dir, self.index)
    }
}

impl EventSink for WalSink {
    fn append(&mut self, batch: &EventBatch) -> Result<()> {
        let events = batch.as_slice();
        if events.is_empty() {
            // Nothing to write, and nothing to fsync: an empty tick must not
            // cost a disk round trip, or an idle daemon would fsync forever.
            return Ok(());
        }
        if self.written + events.len() * RAW_EVENT_SIZE > SEGMENT_BYTES {
            self.roll()?;
        }
        self.buf.clear();
        for event in events {
            wal::append(&mut self.buf, event);
        }
        self.file
            .write_all(&self.buf)
            .map_err(|e| Error::failed(format!("wal append: {e}")))?;
        // Per batch, which is per tick. `F2.WS.07`'s reader resumes from an
        // offset, and an offset it can trust is one that was fsynced.
        self.file
            .sync_all()
            .map_err(|e| Error::failed(format!("wal fsync: {e}")))?;
        self.written += self.buf.len();
        self.batches += 1;
        self.events += events.len() as u64;
        if let Some(last) = events.last() {
            self.next_seq = last.seq.saturating_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aisme_ebpf_common::{EventKind, RawEvent};

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aisme-wal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn batch_of(seqs: &[u64]) -> EventBatch {
        let mut batch = EventBatch::with_capacity(seqs.len().max(1));
        for seq in seqs {
            let mut event = RawEvent::ZERO;
            event.kind = EventKind::FileOpen.into();
            event.seq = *seq;
            batch.push(event).unwrap();
        }
        batch
    }

    /// What the sink writes, the core's own reader reads back — the same
    /// records, in order. Anything less means the two halves of the WAL agree
    /// only by inspection.
    #[test]
    fn what_the_sink_writes_the_replayer_reads_back() {
        let dir = tmpdir("roundtrip");
        let mut sink = WalSink::create(&dir, Some(PolicyGeneration(7))).unwrap();
        sink.append(&batch_of(&[1, 2, 3])).unwrap();
        sink.append(&batch_of(&[4, 5])).unwrap();

        let bytes = std::fs::read(sink.current_segment()).unwrap();
        let header = wal::SegmentHeader::decode(&bytes).unwrap();
        header
            .readable()
            .expect("this binary can read what it wrote");
        assert_eq!(header.generation, Some(PolicyGeneration(7)));

        // A segment opened before any publication says it does not know, and
        // decodes as unknown rather than as generation 0 — the two are
        // different answers and a forensic reader needs them to stay different.
        let unknown = aisme_core::wal::SegmentHeader::local(1, 0, None);
        let decoded = aisme_core::wal::SegmentHeader::decode(&unknown.encode()).unwrap();
        assert_eq!(decoded.generation, None);
        assert_ne!(decoded.generation, Some(PolicyGeneration(0)));

        let mut out = Vec::new();
        let resume = wal::replay(&bytes, wal::SEGMENT_HEADER_SIZE, &mut out).unwrap();
        assert_eq!(
            out.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5],
            "every record, in the order it was appended"
        );
        assert_eq!(
            resume.next_offset,
            bytes.len(),
            "the reader consumed all of it"
        );
        assert!(
            resume.torn.is_none(),
            "a fsynced batch is never a torn tail"
        );
        assert_eq!(sink.events, 5);
        assert_eq!(sink.batches, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty tick costs no disk round trip. An idle daemon fsyncing on every
    /// tick would spend its budget on nothing.
    #[test]
    fn an_empty_batch_writes_nothing_and_does_not_fsync() {
        let dir = tmpdir("empty");
        let mut sink = WalSink::create(&dir, Some(PolicyGeneration(1))).unwrap();
        let before = std::fs::metadata(sink.current_segment()).unwrap().len();
        sink.append(&batch_of(&[])).unwrap();
        let after = std::fs::metadata(sink.current_segment()).unwrap().len();
        assert_eq!(before, after, "the header and nothing else");
        assert_eq!(sink.batches, 0, "an empty tick is not a batch");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every segment opens with a header, so a reader that picks up any file
    /// knows the wire version, the schema hash and the policy generation before
    /// it reads a record.
    #[test]
    fn a_rolled_segment_starts_with_its_own_header_and_the_next_seq() {
        let dir = tmpdir("roll");
        let mut sink = WalSink::create(&dir, Some(PolicyGeneration(3))).unwrap();
        sink.append(&batch_of(&[10, 11])).unwrap();
        sink.roll().unwrap();
        sink.append(&batch_of(&[12])).unwrap();

        assert_eq!(sink.rolls, 1);
        let first = std::fs::read(WalSink::segment_path(&dir, 0)).unwrap();
        let second = std::fs::read(WalSink::segment_path(&dir, 1)).unwrap();
        let h0 = wal::SegmentHeader::decode(&first).unwrap();
        let h1 = wal::SegmentHeader::decode(&second).unwrap();
        assert_eq!(h0.first_seq, 0);
        assert_eq!(
            h1.first_seq, 12,
            "the new segment declares the seq it starts at, not zero"
        );
        assert_eq!(
            h1.generation,
            Some(PolicyGeneration(3)),
            "the policy carries over"
        );

        let mut out = Vec::new();
        wal::replay(&second, wal::SEGMENT_HEADER_SIZE, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, 12);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
