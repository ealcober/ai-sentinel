// SPDX-License-Identifier: Apache-2.0
//! Bounded backpressure (`F1.RT.04`): a fixed ring, drops that are counted,
//! and a drop that becomes an event.
//!
//! §3.4 gives each sensor its own thread handing batches to the hot loop; the
//! queue between them is **fixed** and never grows. Under overload the choice
//! is between memory that grows without bound and events that are lost, and a
//! daemon with a 50 MB budget cannot choose the first. So events are dropped,
//! and — this is the part that matters — **the drop is recorded**: the count
//! rides out as a `DropNotice` event (`EventKind::DropNotice`, `MetaPayload`)
//! and as `aisme.events.dropped`, so the forensic record shows a gap rather
//! than a quiet stretch (`I-17`).
//!
//! Single producer, single consumer, no locks, no allocation after `new`.

use aisme_ebpf_common::{EventKind, MetaPayload, RawEvent};

/// A bounded ring of events.
pub struct EventRing {
    slots: Vec<RawEvent>,
    capacity: usize,
    head: usize,
    len: usize,
    dropped: u64,
    dropped_reported: u64,
}

impl EventRing {
    /// A ring of `capacity` events, allocated here and never again.
    ///
    /// # Panics
    ///
    /// When `capacity` is zero: a ring that holds nothing drops everything,
    /// which is a configuration mistake rather than a policy.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> EventRing {
        assert!(capacity > 0, "an event ring holds at least one event");
        EventRing {
            slots: vec![RawEvent::ZERO; capacity],
            capacity,
            head: 0,
            len: 0,
            dropped: 0,
            dropped_reported: 0,
        }
    }

    /// Offer an event. Returns whether it was taken; a refusal is counted.
    ///
    /// The **oldest** event is never overwritten: an overloaded ring keeps
    /// what it already has and refuses what is new, so a burst cannot erase
    /// the beginning of the story it interrupted.
    pub fn push(&mut self, event: RawEvent) -> bool {
        if self.len == self.capacity {
            self.dropped += 1;
            return false;
        }
        let tail = (self.head + self.len) % self.capacity;
        self.slots[tail] = event;
        self.len += 1;
        true
    }

    /// Take the oldest event.
    pub fn pop(&mut self) -> Option<RawEvent> {
        if self.len == 0 {
            return None;
        }
        let event = self.slots[self.head];
        self.head = (self.head + 1) % self.capacity;
        self.len -= 1;
        Some(event)
    }

    /// Events held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many it holds at most.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Events refused since the ring was made — `aisme.events.dropped`.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The drops not yet carried out as a notice.
    #[must_use]
    pub const fn unreported_drops(&self) -> u64 {
        self.dropped - self.dropped_reported
    }

    /// A `DropNotice` for the drops since the last notice, or `None` when
    /// there are none. Calling it marks them reported, so a gap is announced
    /// once and its size is never double-counted.
    ///
    /// The notice is an event like any other: it goes through the same
    /// pipeline into the same WAL, which is what makes the gap part of the
    /// record instead of a line in a log nobody keeps (`I-17`).
    pub fn drop_notice(&mut self, session_id: u64, ts_ns: u64, seq: u64) -> Option<RawEvent> {
        let dropped = self.unreported_drops();
        if dropped == 0 {
            return None;
        }
        self.dropped_reported = self.dropped;
        let mut event = RawEvent::ZERO;
        event.kind = EventKind::DropNotice.into();
        event.session_id = session_id;
        event.ts_ns = ts_ns;
        event.seq = seq;
        event.payload.meta = MetaPayload {
            capability_level: 0,
            reason: 0,
            pad0: [0; 6],
            dropped,
            policy_generation: 0,
            gap_start_ns: 0,
            gap_end_ns: ts_ns,
            reserved: [0; 216],
        };
        Some(event)
    }
}

impl core::fmt::Debug for EventRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventRing")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("dropped", &self.dropped)
            .field("dropped_reported", &self.dropped_reported)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> RawEvent {
        let mut event = RawEvent::ZERO;
        event.seq = seq;
        event.kind = EventKind::FileOpen.into();
        event
    }

    #[test]
    fn a_full_ring_refuses_the_new_and_keeps_the_old() {
        let mut ring = EventRing::with_capacity(3);
        assert!(ring.push(event(1)));
        assert!(ring.push(event(2)));
        assert!(ring.push(event(3)));
        assert!(!ring.push(event(4)), "full");
        assert!(!ring.push(event(5)));
        assert_eq!(ring.dropped(), 2);
        assert_eq!(ring.len(), 3);
        // The beginning of the story survives the burst that interrupted it.
        assert_eq!(ring.pop().map(|e| e.seq), Some(1));
        assert_eq!(ring.pop().map(|e| e.seq), Some(2));
        assert!(ring.push(event(6)), "room again");
        assert_eq!(ring.pop().map(|e| e.seq), Some(3));
        assert_eq!(ring.pop().map(|e| e.seq), Some(6));
        assert!(ring.pop().is_none());
        assert!(ring.is_empty());
    }

    #[test]
    fn the_ring_never_grows() {
        let mut ring = EventRing::with_capacity(8);
        let slots = ring.slots.capacity();
        for i in 0..10_000 {
            if !ring.push(event(i)) && i % 3 == 0 {
                let _ = ring.pop();
            }
        }
        assert_eq!(ring.slots.capacity(), slots);
        // One pop for every third refusal, so roughly two thirds of the
        // pushes are refused; the exact number is measured, not guessed.
        assert_eq!(ring.dropped(), 6_662);
        assert!(ring.len() <= 8);
    }

    #[test]
    fn a_gap_is_announced_once_and_carries_its_size() {
        let mut ring = EventRing::with_capacity(1);
        ring.push(event(1));
        for i in 0..5 {
            ring.push(event(i));
        }
        assert_eq!(ring.unreported_drops(), 5);
        let notice = ring.drop_notice(7, 1_234, 99).expect("a gap is announced");
        assert_eq!(notice.kind.decode(), Ok(EventKind::DropNotice));
        assert_eq!(notice.session_id, 7);
        assert_eq!(notice.ts_ns, 1_234);
        match notice.payload() {
            Some(aisme_ebpf_common::Payload::Meta(meta)) => {
                assert_eq!(
                    meta.dropped, 5,
                    "the size of the gap, not merely that there was one"
                );
                assert_eq!(meta.gap_end_ns, 1_234);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(ring.unreported_drops(), 0);
        assert!(ring.drop_notice(7, 2_000, 100).is_none(), "announced once");
        // A later burst is a new gap, and its size is only the new drops.
        ring.pop();
        ring.push(event(9));
        ring.push(event(10));
        let notice = ring.drop_notice(7, 3_000, 101).expect("a new gap");
        match notice.payload() {
            Some(aisme_ebpf_common::Payload::Meta(meta)) => assert_eq!(meta.dropped, 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(ring.dropped(), 6, "the total keeps counting");
    }

    #[test]
    #[should_panic(expected = "at least one event")]
    fn a_ring_that_holds_nothing_is_a_mistake() {
        let _ = EventRing::with_capacity(0);
    }
}
