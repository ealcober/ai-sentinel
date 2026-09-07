// SPDX-License-Identifier: Apache-2.0
//! Ordering across producers with different clocks (`F1.ON.03`; consumed by
//! `F5.CO.03`).
//!
//! Annex A.3: ordering uses Lamport/vector clocks normalized to boot-monotonic
//! time; wall-clock is metadata, never used for ordering. Producers — the BPF
//! ring, uprobes, the cooperative tailer, a mobile tunnel — stamp events from
//! clocks that differ by an offset the adapter measures (that measurement is
//! I/O and lives with the adapter). This module is the pure part:
//!
//! - [`ClockDomain`] turns a producer's raw timestamp into [`BootNs`].
//! - [`Stamp`] is the total order every event gets: boot time, then producer,
//!   then the producer's own sequence — deterministic, and the same on replay.
//! - [`VectorClock`] answers *happens-before or concurrent* for two events
//!   whose boot times fall inside the skew bound, where the timestamp alone
//!   cannot order them honestly. Bounded to [`MAX_PRODUCERS`], heap-free.

use core::cmp::Ordering;

use aisme_core::ontology::BootNs;

/// How many producers one engine may have. A `u8` id, a fixed-size vector.
pub const MAX_PRODUCERS: usize = 16;

/// A producer of events: one clock domain, one sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProducerId(u8);

impl ProducerId {
    /// A producer id below [`MAX_PRODUCERS`].
    #[must_use]
    pub const fn new(id: u8) -> Option<ProducerId> {
        if (id as usize) < MAX_PRODUCERS {
            Some(ProducerId(id))
        } else {
            None
        }
    }

    /// The id.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A producer's clock, as an offset from boot-monotonic time.
///
/// `offset_ns` is *boot minus source* at calibration: a source whose clock
/// reads ahead of boot time has a negative offset. The BPF ring's
/// `bpf_ktime_get_boot_ns` has offset zero by definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockDomain {
    offset_ns: i64,
}

impl ClockDomain {
    /// The boot clock itself.
    pub const BOOT: ClockDomain = ClockDomain { offset_ns: 0 };

    /// A domain at `offset_ns` from boot time.
    #[must_use]
    pub const fn with_offset(offset_ns: i64) -> ClockDomain {
        ClockDomain { offset_ns }
    }

    /// The offset.
    #[must_use]
    pub const fn offset_ns(self) -> i64 {
        self.offset_ns
    }

    /// A raw source timestamp as boot time. Saturates rather than wraps: a
    /// timestamp before boot is boot, not a huge number in the future.
    #[must_use]
    pub const fn normalize(self, raw_ns: u64) -> BootNs {
        match raw_ns.checked_add_signed(self.offset_ns) {
            Some(shifted) => BootNs(shifted),
            None if self.offset_ns < 0 => BootNs(0),
            None => BootNs(u64::MAX),
        }
    }
}

/// The total order every event gets. `Ord` is derived in field order, which
/// is the order that matters: boot time first, then producer, then the
/// producer's own sequence — so two events with the same boot time from the
/// same producer are ordered by their ring order, and from different
/// producers by producer id, deterministically, on every replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stamp {
    /// Normalized time.
    pub ts: BootNs,
    /// Who produced it.
    pub producer: ProducerId,
    /// The producer's `RawEvent::seq`.
    pub seq: u64,
}

impl Stamp {
    /// Whether the timestamps of two stamps are too close, given the skew
    /// bound between their producers' clocks, for `ts` alone to order them.
    /// Same-producer stamps are never ambiguous: the ring's order is exact.
    #[must_use]
    pub const fn ambiguous_with(self, other: Stamp, skew_ns: u64) -> bool {
        if self.producer.0 == other.producer.0 {
            return false;
        }
        self.ts.0.abs_diff(other.ts.0) <= skew_ns
    }
}

/// What a vector clock says about two events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Causality {
    /// The first happened before the second.
    Before,
    /// The second happened before the first.
    After,
    /// Neither: concurrent, and no clock can say more.
    Concurrent,
    /// The same clock: the same event, or one that observed nothing new.
    Equal,
}

/// A vector clock over at most [`MAX_PRODUCERS`] producers.
///
/// `tick` on a producer's own events; `merge` when a producer observes
/// another's state (a pipe, a UNIX socket, a parent–child hand-off);
/// [`VectorClock::compare`] then answers happens-before without a timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct VectorClock {
    counts: [u64; MAX_PRODUCERS],
}

impl VectorClock {
    /// All zeros.
    pub const ZERO: VectorClock = VectorClock {
        counts: [0; MAX_PRODUCERS],
    };

    /// A local event at `producer`.
    pub fn tick(&mut self, producer: ProducerId) -> &mut VectorClock {
        let slot = &mut self.counts[usize::from(producer.0)];
        *slot = slot.saturating_add(1);
        self
    }

    /// Observe another clock: component-wise maximum.
    pub fn merge(&mut self, other: &VectorClock) -> &mut VectorClock {
        for (mine, theirs) in self.counts.iter_mut().zip(other.counts) {
            *mine = (*mine).max(theirs);
        }
        self
    }

    /// The count for one producer.
    #[must_use]
    pub const fn get(&self, producer: ProducerId) -> u64 {
        self.counts[producer.0 as usize]
    }

    /// Happens-before, in both directions, or neither.
    #[must_use]
    pub fn compare(&self, other: &VectorClock) -> Causality {
        let mut less = false;
        let mut greater = false;
        for (a, b) in self.counts.iter().zip(other.counts) {
            match a.cmp(&b) {
                Ordering::Less => less = true,
                Ordering::Greater => greater = true,
                Ordering::Equal => {}
            }
        }
        match (less, greater) {
            (false, false) => Causality::Equal,
            (true, false) => Causality::Before,
            (false, true) => Causality::After,
            (true, true) => Causality::Concurrent,
        }
    }
}

/// Order two events: by vector clock where it decides, by stamp where the
/// timestamps are outside the skew bound, and *concurrent* — said so, not
/// guessed — when neither can.
///
/// This is the function `F5.CO.03` builds on: it never manufactures an order
/// from two clocks that cannot support one.
#[must_use]
pub fn order(a: (Stamp, &VectorClock), b: (Stamp, &VectorClock), skew_ns: u64) -> Causality {
    match a.1.compare(b.1) {
        Causality::Concurrent | Causality::Equal => {
            if a.0 == b.0 {
                Causality::Equal
            } else if a.0.ambiguous_with(b.0, skew_ns) {
                Causality::Concurrent
            } else if a.0 < b.0 {
                Causality::Before
            } else {
                Causality::After
            }
        }
        decided => decided,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn producer(id: u8) -> ProducerId {
        match ProducerId::new(id) {
            Some(p) => p,
            None => panic!("test producer out of range"),
        }
    }

    #[test]
    fn producers_are_bounded() {
        assert!(ProducerId::new(15).is_some());
        assert!(ProducerId::new(16).is_none());
    }

    #[test]
    fn normalization_shifts_and_saturates() {
        assert_eq!(ClockDomain::BOOT.normalize(1_000), BootNs(1_000));
        let behind = ClockDomain::with_offset(500);
        assert_eq!(behind.normalize(1_000), BootNs(1_500));
        let ahead = ClockDomain::with_offset(-2_000);
        assert_eq!(ahead.normalize(1_000), BootNs(0), "before boot is boot");
        assert_eq!(
            ClockDomain::with_offset(i64::MAX).normalize(u64::MAX),
            BootNs(u64::MAX)
        );
    }

    #[test]
    fn the_stamp_order_is_time_then_producer_then_sequence() {
        let s = |ts, p, seq| Stamp {
            ts: BootNs(ts),
            producer: producer(p),
            seq,
        };
        let mut stamps = [s(5, 1, 9), s(5, 0, 2), s(3, 1, 1), s(5, 0, 1), s(5, 1, 3)];
        stamps.sort();
        assert_eq!(
            stamps,
            [s(3, 1, 1), s(5, 0, 1), s(5, 0, 2), s(5, 1, 3), s(5, 1, 9)]
        );
        // Deterministic on replay: the same sort twice.
        let mut again = stamps;
        again.reverse();
        again.sort();
        assert_eq!(again, stamps);
    }

    #[test]
    fn ambiguity_needs_different_producers_within_the_skew() {
        let a = Stamp {
            ts: BootNs(1_000),
            producer: producer(0),
            seq: 1,
        };
        let same_producer = Stamp {
            ts: BootNs(1_001),
            producer: producer(0),
            seq: 2,
        };
        let other_close = Stamp {
            ts: BootNs(1_050),
            producer: producer(1),
            seq: 1,
        };
        let other_far = Stamp {
            ts: BootNs(2_000),
            producer: producer(1),
            seq: 2,
        };
        assert!(!a.ambiguous_with(same_producer, 100));
        assert!(a.ambiguous_with(other_close, 100));
        assert!(!a.ambiguous_with(other_far, 100));
        assert!(other_close.ambiguous_with(a, 50), "symmetric, at the bound");
    }

    #[test]
    fn vector_clocks_decide_happens_before_and_concurrency() {
        let (p0, p1) = (producer(0), producer(1));
        let mut a = VectorClock::ZERO;
        a.tick(p0);
        let mut b = a;
        b.tick(p0); // b observed a and moved on
        assert_eq!(a.compare(&b), Causality::Before);
        assert_eq!(b.compare(&a), Causality::After);
        assert_eq!(a.compare(&a), Causality::Equal);
        let mut c = VectorClock::ZERO;
        c.tick(p1); // c knows nothing of a
        assert_eq!(a.compare(&c), Causality::Concurrent);
        // Merge: c observes b, then ticks — now after both.
        c.merge(&b).tick(p1);
        assert_eq!(b.compare(&c), Causality::Before);
        assert_eq!(c.get(p0), 2);
        assert_eq!(c.get(p1), 2);
        // Saturation rather than wrap.
        let mut top = VectorClock::ZERO;
        top.counts[0] = u64::MAX;
        top.tick(p0);
        assert_eq!(top.get(p0), u64::MAX);
    }

    #[test]
    fn order_never_manufactures_an_order_from_clocks_that_cannot_support_one() {
        let (p0, p1) = (producer(0), producer(1));
        let stamp = |ts, p, seq| Stamp {
            ts: BootNs(ts),
            producer: p,
            seq,
        };
        let mut va = VectorClock::ZERO;
        va.tick(p0);
        let mut vb = VectorClock::ZERO;
        vb.tick(p1);
        // Concurrent by vector clock, inside the skew: concurrent, said so.
        assert_eq!(
            order((stamp(1_000, p0, 1), &va), (stamp(1_040, p1, 1), &vb), 100),
            Causality::Concurrent
        );
        // Concurrent by vector clock, outside the skew: the stamps decide.
        assert_eq!(
            order((stamp(1_000, p0, 1), &va), (stamp(5_000, p1, 1), &vb), 100),
            Causality::Before
        );
        assert_eq!(
            order((stamp(5_000, p1, 1), &vb), (stamp(1_000, p0, 1), &va), 100),
            Causality::After
        );
        // Decided by vector clock, even against the timestamps: causality
        // beats a skewed clock.
        let mut vc = va;
        vc.merge(&vb).tick(p1);
        assert_eq!(
            order((stamp(9_000, p0, 1), &va), (stamp(1_000, p1, 2), &vc), 100),
            Causality::Before
        );
        // Same stamp, same clock: the same event.
        assert_eq!(
            order((stamp(1, p0, 1), &va), (stamp(1, p0, 1), &va), 100),
            Causality::Equal
        );
    }
}
