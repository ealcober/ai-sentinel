// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! `RawEvent`: the single most important type in the system (plan §F1.1).
//!
//! The same `#[repr(C)]` struct is shared between eBPF and user space (`H-04`);
//! nothing is serialized on the hot path. Fixed 320-byte total, no pointers,
//! strings as inline bounded arrays, append-only fields (§3.6).

use crate::kind::KindCode;
use crate::payload::{EventPayload, Payload, PAYLOAD_SIZE};

/// The wire-format version this crate describes. Read by §3.6 on both sides
/// of every pairing; `F1.EV.02` refuses to attach a program whose byte differs.
pub const WIRE_VERSION: u8 = 1;

/// The size of a `RawEvent`, which every ring-buffer slot and WAL record holds.
pub const RAW_EVENT_SIZE: usize = 320;

/// `flags` bit: an inline string in the payload did not fit and was cut.
pub const FLAG_TRUNCATED: u8 = 1 << 0;

/// An outcome as it travels on the wire: the bare `u8`. See [`KindCode`] for
/// why the wire carries a code rather than the enum.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutcomeCode(pub u8);

impl OutcomeCode {
    /// The outcome this code names, or the code back when unknown.
    ///
    /// # Errors
    ///
    /// [`UnknownOutcome`] carries the code.
    pub const fn decode(self) -> Result<Outcome, UnknownOutcome> {
        Ok(match self.0 {
            0 => Outcome::Observed,
            1 => Outcome::Allowed,
            2 => Outcome::Warned,
            3 => Outcome::Escalated,
            4 => Outcome::Denied,
            _ => return Err(UnknownOutcome(self)),
        })
    }
}

impl From<Outcome> for OutcomeCode {
    fn from(outcome: Outcome) -> Self {
        Self(outcome as u8)
    }
}

/// A wire code this binary has no outcome for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownOutcome(pub OutcomeCode);

/// What happened to the event, in §B.10 order. Distinct from the policy
/// [`crate::verdict::Verdict`]: a verdict is what the policy said, an outcome
/// is what the enforcer did with it — `Observed` when there was no decision
/// at all, which is most events.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Recorded; no decision was involved.
    Observed = 0,
    /// A decision allowed it.
    Allowed = 1,
    /// Allowed with a `warn` notice.
    Warned = 2,
    /// Held for adjudication.
    Escalated = 3,
    /// Denied in kernel or by the adjudicator.
    Denied = 4,
}

/// One observed event, as the kernel writes it and user space reads it.
///
/// Layout, `repr(C)`, no hidden padding: three `u64` (24) · five `u32` (20) ·
/// `kind` (2) · `outcome` (1) · `flags` (1) · `wire_version` (1) ·
/// `reserved` (15) = 64, then the 256-byte payload at offset 64. Asserted
/// below; `F1.EV.03` asserts every offset.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawEvent {
    /// `bpf_ktime_get_boot_ns` — boot-monotonic; the only clock used for order.
    pub ts_ns: u64,
    /// Per-CPU monotonic; gives total order per producer.
    pub seq: u64,
    /// The monitored session.
    pub session_id: u64,
    /// The thread.
    pub pid: u32,
    /// The thread group (what user space calls the process).
    pub tgid: u32,
    /// The parent thread group.
    pub ppid: u32,
    /// Real uid.
    pub uid: u32,
    /// Taint bitflags (`H-13`); the algebra lives in `aisme-core` (`F1.ON.04`).
    pub taint: u32,
    /// What happened — a code on the wire, decoded with [`KindCode::decode`].
    pub kind: KindCode,
    /// What became of it — a code on the wire, decoded with
    /// [`OutcomeCode::decode`].
    pub outcome: OutcomeCode,
    /// `FLAG_*` bits.
    pub flags: u8,
    /// [`WIRE_VERSION`] of the producer; §3.6 reads it before anything else.
    pub wire_version: u8,
    /// Pads the header to 64 bytes; new header fields consume it.
    pub reserved: [u8; 15],
    /// The range-determined payload.
    pub payload: EventPayload,
}

impl RawEvent {
    /// All zeroes, stamped with this crate's wire version. `kind` is zero,
    /// which decodes to no variant: a slot nobody wrote is never mistaken for
    /// an event.
    pub const ZERO: RawEvent = RawEvent {
        ts_ns: 0,
        seq: 0,
        session_id: 0,
        pid: 0,
        tgid: 0,
        ppid: 0,
        uid: 0,
        taint: 0,
        kind: KindCode(0),
        outcome: OutcomeCode(0),
        flags: 0,
        wire_version: WIRE_VERSION,
        reserved: [0; 15],
        payload: EventPayload::ZERO,
    };

    /// The payload viewed through the kind's range, or `None` when the code
    /// is outside every reserved range and nothing can be said about it.
    #[must_use]
    pub fn payload(&self) -> Option<Payload<'_>> {
        self.kind.range().map(|range| self.payload.view(range))
    }

    /// Whether `flags` carries [`FLAG_TRUNCATED`].
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }
}

/// The fixed size and alignment, checked when the crate compiles for either
/// target. The header is 64 bytes exactly, so the payload starts 8-aligned.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<RawEvent>() == RAW_EVENT_SIZE);
    assert!(RAW_EVENT_SIZE == 64 + PAYLOAD_SIZE);
    assert!(align_of::<RawEvent>() == 8);
    assert!(size_of::<KindCode>() == 2);
    assert!(size_of::<OutcomeCode>() == 1);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::{EventKind, Range};

    #[test]
    fn the_zero_event_is_not_an_event() {
        let event = RawEvent::ZERO;
        assert_eq!(event.wire_version, WIRE_VERSION);
        assert!(event.kind.decode().is_err());
        assert_eq!(
            event.payload().map(|_| ()),
            Some(()),
            "range Meta is reserved, so it views"
        );
        assert!(!event.truncated());
    }

    #[test]
    fn outcomes_decode_in_b10_order() {
        let all = [
            Outcome::Observed,
            Outcome::Allowed,
            Outcome::Warned,
            Outcome::Escalated,
            Outcome::Denied,
        ];
        for pair in all.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        for outcome in all {
            assert_eq!(OutcomeCode::from(outcome).decode(), Ok(outcome));
        }
        assert_eq!(OutcomeCode(5).decode(), Err(UnknownOutcome(OutcomeCode(5))));
    }

    #[test]
    fn a_kernel_written_event_with_a_kind_this_binary_does_not_know_is_still_readable() {
        // The skew case §3.6 wants detected, not misparsed: the bytes arrive
        // as bytes, the kind decodes to an error, the range still classifies.
        let mut bytes = [0u8; RAW_EVENT_SIZE];
        bytes[44..46].copy_from_slice(&0x1FFFu16.to_le_bytes());
        bytes[46] = 9; // an outcome this binary does not know either
        bytes[47] = FLAG_TRUNCATED;
        bytes[48] = WIRE_VERSION + 1;
        // SAFETY: `RawEvent` is `repr(C)`, exactly `RAW_EVENT_SIZE` bytes, and
        // every field is an integer, an integer newtype or the all-integer
        // payload union, so every bit pattern is a valid `RawEvent`.
        let event: RawEvent = unsafe { core::mem::transmute(bytes) };
        assert_eq!(event.kind, KindCode(0x1FFF));
        assert!(event.kind.decode().is_err());
        assert_eq!(event.kind.range(), Some(Range::Process));
        assert!(matches!(event.payload(), Some(Payload::Process(_))));
        assert!(event.outcome.decode().is_err());
        assert!(event.truncated());
        assert_ne!(event.wire_version, WIRE_VERSION);
    }

    #[test]
    fn a_known_kind_reads_back_through_its_range() {
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::FileOpen.into();
        event.outcome = Outcome::Denied.into();
        event.payload.file.inode = 99;
        assert_eq!(event.kind.decode(), Ok(EventKind::FileOpen));
        assert_eq!(event.outcome.decode(), Ok(Outcome::Denied));
        match event.payload() {
            Some(Payload::File(file)) => assert_eq!(file.inode, 99),
            other => panic!("wrong view: {other:?}"),
        }
    }
}
