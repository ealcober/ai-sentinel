// SPDX-License-Identifier: Apache-2.0
//! `Sensor`: anything that produces observed events (plan §3.2).
//!
//! Knows nothing about policy. One thread per sensor (§3.4); each hands
//! [`EventBatch`]es to the hot loop. `poll` MUST NOT allocate and MUST NOT
//! block beyond its budget — the batch is preallocated to its capacity and
//! refuses when full.

use core::time::Duration;

use aisme_ebpf_common::RawEvent;

use crate::capability::CapabilitySet;
use crate::error::Result;
use crate::ontology::SessionId;

/// How a sensor is started.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SensorConfig {
    /// Events per batch the sensor should aim for (§3.3: 32–512).
    pub batch_capacity: usize,
    /// The sessions of interest, when the sensor filters at the source;
    /// empty means every session it can see.
    pub sessions: Vec<SessionId>,
}

impl SensorConfig {
    /// §3.3's middle of the road.
    pub const DEFAULT_BATCH: usize = 128;

    /// A config for `batch_capacity` events, every session.
    #[must_use]
    pub fn with_batch(batch_capacity: usize) -> SensorConfig {
        SensorConfig {
            batch_capacity,
            sessions: Vec::new(),
        }
    }
}

impl Default for SensorConfig {
    fn default() -> SensorConfig {
        SensorConfig::with_batch(SensorConfig::DEFAULT_BATCH)
    }
}

/// A fixed-capacity batch of events. Allocated once; never grows.
#[derive(Clone, Debug)]
pub struct EventBatch {
    events: Vec<RawEvent>,
    dropped: u64,
}

impl EventBatch {
    /// A batch that holds `capacity` events, allocated here.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> EventBatch {
        EventBatch {
            events: Vec::with_capacity(capacity),
            dropped: 0,
        }
    }

    /// How many it holds at most.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.events.capacity()
    }

    /// How many it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Room left.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.capacity() - self.len()
    }

    /// Add an event. A full batch refuses — and counts the refusal — rather
    /// than grow; the producer keeps the event for the next poll or reports
    /// it dropped (`F1.RT.04`).
    ///
    /// # Errors
    ///
    /// [`BatchFull`] — a marker, not the event: returning the 320-byte
    /// `RawEvent` by value would put it on every caller's error path.
    /// The producer still holds it.
    pub fn push(&mut self, event: RawEvent) -> core::result::Result<(), BatchFull> {
        if self.events.len() == self.events.capacity() {
            self.dropped += 1;
            return Err(BatchFull);
        }
        self.events.push(event);
        Ok(())
    }

    /// The events, mutably — the ingest stage edits them in place.
    ///
    /// Canonicalization rewrites a path inside the event it arrived in
    /// (`F2.WS.02`), which is what keeps the hot loop free of a second buffer
    /// and therefore free of an allocation.
    pub fn as_mut_slice(&mut self) -> &mut [RawEvent] {
        &mut self.events
    }

    /// The events.
    #[must_use]
    pub fn as_slice(&self) -> &[RawEvent] {
        &self.events
    }

    /// Empty it for the next poll; the capacity stays.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Pushes refused since the batch was made.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.dropped
    }
}

/// The batch had no room. The producer keeps the event for the next poll,
/// or reports it dropped (`F1.RT.04`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchFull;

/// A sensor's state, as it reports it. Drives the `DEGRADED` state machine
/// (`F1.PA.05`) and `aisme.capability.level`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SensorHealth {
    /// Attached and producing.
    Healthy,
    /// Attached, with one documented function lost (`I-19`).
    Degraded {
        /// What was lost, in the words the UI shows.
        lost: String,
    },
    /// Not attached: nothing it covers is covered.
    Detached {
        /// Why, as far as the sensor knows.
        reason: String,
    },
}

/// Anything that produces observed events. Knows nothing about policy.
pub trait Sensor: Send {
    /// Attach and begin producing.
    ///
    /// # Errors
    ///
    /// The platform's refusal, classified.
    fn start(&mut self, cfg: &SensorConfig) -> Result<()>;

    /// Drain up to `out.remaining()` events, returning within `budget`.
    /// MUST NOT allocate. MUST NOT block beyond `budget`. Returns how many
    /// were added.
    ///
    /// # Errors
    ///
    /// `Detached` when the sensor lost its attachment; the engine degrades.
    fn poll(&mut self, out: &mut EventBatch, budget: Duration) -> Result<usize>;

    /// What this sensor found the platform able to do.
    fn capabilities(&self) -> CapabilitySet;

    /// Drives the `DEGRADED` state machine and `aisme.capability.level`.
    fn health(&self) -> SensorHealth;

    /// Detach.
    ///
    /// # Errors
    ///
    /// Rare; a sensor that cannot stop says so.
    fn stop(&mut self) -> Result<()>;
}

/// Finds sessions to monitor: agent processes, declared sessions, provider
/// flows from outside any lineage (`DT-15`).
pub trait SessionDiscovery: Send {
    /// Append every candidate found since the last scan.
    fn scan(&mut self, out: &mut Vec<SessionCandidate>);
}

/// A process that may be an agent session.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCandidate {
    /// The thread group.
    pub tgid: u32,
    /// Its parent.
    pub ppid: u32,
    /// The executable.
    pub exe_path: String,
    /// Why it is a candidate.
    pub reason: DiscoveryReason,
}

/// Why a process is a session candidate.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiscoveryReason {
    /// A known agent binary (`DT-10`'s profiles).
    KnownAgent,
    /// A flow to a catalogued provider from outside any session lineage
    /// (`DT-15`).
    ProviderFlow,
    /// It declared itself, through `aisme run` or the SDK.
    Declared,
}

/// Where events go after the hot loop: the WAL.
pub trait EventSink: Send {
    /// Append a batch. Crash-safe by the WAL's own contract (`F1.RT.05`).
    ///
    /// # Errors
    ///
    /// `Failed` with the detail; the engine counts and continues.
    fn append(&mut self, batch: &EventBatch) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_never_grows_and_counts_what_it_refused() {
        let mut batch = EventBatch::with_capacity(2);
        let cap = batch.capacity();
        assert!(batch.push(RawEvent::ZERO).is_ok());
        assert!(batch.push(RawEvent::ZERO).is_ok());
        assert!(batch.push(RawEvent::ZERO).is_err());
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.remaining(), 0);
        assert_eq!(batch.refused(), 1);
        assert_eq!(batch.capacity(), cap);
        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.capacity(), cap);
        assert_eq!(batch.refused(), 1, "the count survives a clear");
    }

    fn object_safe(_: &mut dyn Sensor, _: &mut dyn SessionDiscovery, _: &mut dyn EventSink) {}

    #[test]
    fn the_traits_are_object_safe() {
        let _: fn(&mut dyn Sensor, &mut dyn SessionDiscovery, &mut dyn EventSink) = object_safe;
        assert_eq!(SensorConfig::default().batch_capacity, 128);
    }
}
