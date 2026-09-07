// SPDX-License-Identifier: Apache-2.0
//! Self-observability (`F1.RT.06`): the counters the daemon keeps about
//! itself, and the names §5.6.2 gives them.
//!
//! A security daemon that cannot say how much it dropped, how much it is
//! using and what tier it is serving is asking to be trusted on its word.
//! These are the values `F5.OB.*` exports over OTLP and `verify-budgets`
//! reads; the names live here so the exporter and the gate cannot spell them
//! differently.
//!
//! **No labels with unbounded cardinality** (§5.6.3): nothing in this file
//! carries a path, a session id or a command line. The measurement of RSS and
//! CPU is the daemon's — reading `/proc` is I/O — and arrives through
//! [`Metrics::observe_process`].

/// The metric names of §5.6.2 this task owns. One place, so a rename is one
/// edit and `verify-docs` can check the list against the plan.
pub mod names {
    /// Events drained from the sensors.
    pub const EVENTS_RECEIVED: &str = "aisme.events.received";
    /// Events the ring refused. Alert if > 0 (§5.6.2).
    pub const EVENTS_DROPPED: &str = "aisme.events.dropped";
    /// The session's deterministic risk (`DT-09`).
    pub const SESSION_RISK: &str = "aisme.session.risk";
    /// The tier, as an ordinal: 0 `DEGRADED`, 1 L1, 2 L2-, 3 L2, 4 L3.
    pub const CAPABILITY_LEVEL: &str = "aisme.capability.level";
    /// Resident set size, per process.
    pub const DAEMON_RSS_BYTES: &str = "aisme.daemon.rss_bytes";
    /// CPU as a ratio of one core, per process.
    pub const DAEMON_CPU_RATIO: &str = "aisme.daemon.cpu_ratio";
    /// Process nodes with no `executed_as` parent.
    pub const CORRELATION_UNMATCHED: &str = "aisme.correlation.unmatched";
    /// Detector findings.
    pub const DETECT_FINDINGS: &str = "aisme.detect.findings";
}

/// What the daemon knows about itself right now.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Metrics {
    /// `aisme.events.received`.
    pub events_received: u64,
    /// `aisme.events.dropped` — the ring's refusals plus the batch's.
    pub events_dropped: u64,
    /// Events whose kind this binary does not know (`I-17`).
    pub events_unknown_kind: u64,
    /// Events from another wire (§3.6).
    pub events_wire_mismatch: u64,
    /// `aisme.detect.findings`.
    pub findings: u64,
    /// `aisme.correlation.unmatched`.
    pub correlation_unmatched: u64,
    /// `aisme.session.risk`, in thousandths.
    pub session_risk_milli: u32,
    /// `aisme.capability.level`; `None` until the tier has been observed.
    /// Not `0`: zero is `DEGRADED`, and a daemon that has not looked yet is
    /// not a degraded daemon — the test that caught this is the reason the
    /// field is an `Option`.
    pub capability_level: Option<u8>,
    /// Ring occupancy when it was last read, and its capacity.
    pub queue_depth: usize,
    /// The ring's capacity, so a depth means something.
    pub queue_capacity: usize,
    /// `aisme.daemon.rss_bytes`; `None` until the daemon measures it.
    pub rss_bytes: Option<u64>,
    /// `aisme.daemon.cpu_ratio` in thousandths of one core; `None` until
    /// measured. An unmeasured value is absent, never zero — a zero would
    /// read as "using nothing" (general rule 9).
    pub cpu_milli: Option<u32>,
}

impl Metrics {
    /// Fold one tick's report in.
    pub fn observe_tick(&mut self, report: &crate::engine::TickReport) {
        self.events_received += report.drained as u64;
        self.events_unknown_kind += report.unknown_kind as u64;
        self.events_wire_mismatch += report.wire_mismatch as u64;
        self.findings += report.findings as u64;
    }

    /// Fold the ring's state in: its total drops (not a delta) and its
    /// occupancy.
    pub fn observe_ring(&mut self, ring: &crate::ring::EventRing) {
        self.events_dropped = ring.dropped();
        self.queue_depth = ring.len();
        self.queue_capacity = ring.capacity();
    }

    /// Fold the engine's session state in.
    pub fn observe_state(&mut self, state: &crate::detect::SessionState) {
        self.session_risk_milli = state.risk_milli;
    }

    /// Fold the degradation state in.
    pub fn observe_tier(&mut self, state: &crate::tier::State) {
        self.capability_level = Some(state.metric());
    }

    /// What the daemon measured about its own process. I/O is the caller's.
    pub const fn observe_process(&mut self, rss_bytes: u64, cpu_milli: u32) {
        self.rss_bytes = Some(rss_bytes);
        self.cpu_milli = Some(cpu_milli);
    }

    /// Queue pressure in percent, or `None` when there is no queue to speak
    /// of.
    #[must_use]
    pub fn queue_pressure_pct(&self) -> Option<u8> {
        if self.queue_capacity == 0 {
            return None;
        }
        let pct = self.queue_depth * 100 / self.queue_capacity;
        u8::try_from(pct).ok()
    }

    /// Whether anything here should be shouted about: a drop, a gap in the
    /// taxonomy, a foreign wire, or `DEGRADED`. §5.6.2 alerts on the first.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.events_dropped > 0
            || self.events_wire_mismatch > 0
            || self.events_unknown_kind > 0
            || matches!(self.capability_level, Some(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::TickReport;
    use crate::ring::EventRing;
    use crate::tier::{State, Tier};
    use aisme_ebpf_common::RawEvent;

    #[test]
    fn a_tick_a_ring_and_a_tier_fold_into_one_snapshot() {
        let mut metrics = Metrics::default();
        metrics.observe_tick(&TickReport {
            drained: 128,
            unknown_kind: 2,
            wire_mismatch: 1,
            interned: 100,
            findings: 3,
            sensor_errors: 0,
        });
        metrics.observe_tick(&TickReport {
            drained: 64,
            ..TickReport::default()
        });
        assert_eq!(metrics.events_received, 192);
        assert_eq!(metrics.events_unknown_kind, 2);
        assert_eq!(metrics.events_wire_mismatch, 1);
        assert_eq!(metrics.findings, 3);

        let mut ring = EventRing::with_capacity(4);
        for _ in 0..6 {
            ring.push(RawEvent::ZERO);
        }
        metrics.observe_ring(&ring);
        assert_eq!(metrics.events_dropped, 2);
        assert_eq!(metrics.queue_depth, 4);
        assert_eq!(metrics.queue_pressure_pct(), Some(100));

        metrics.observe_tier(&State::Serving(Tier::L2));
        assert_eq!(metrics.capability_level, Some(3));
        metrics.observe_tier(&State::Degraded {
            tier: Tier::L2,
            lost: "probes detached".into(),
        });
        assert_eq!(
            metrics.capability_level,
            Some(0),
            "DEGRADED is 0, whatever the tier"
        );
    }

    #[test]
    fn an_unmeasured_process_reads_as_absent_not_as_zero() {
        let mut metrics = Metrics::default();
        assert_eq!(metrics.rss_bytes, None);
        assert_eq!(metrics.cpu_milli, None);
        assert_eq!(
            metrics.capability_level, None,
            "not looked at is not DEGRADED"
        );
        assert!(!metrics.needs_attention());
        assert_eq!(
            metrics.queue_pressure_pct(),
            None,
            "no queue, no percentage"
        );
        metrics.observe_process(41 * 1024 * 1024, 25);
        assert_eq!(metrics.rss_bytes, Some(41 * 1024 * 1024));
        assert_eq!(metrics.cpu_milli, Some(25));
    }

    #[test]
    fn attention_is_needed_for_every_kind_of_silence() {
        assert!(!Metrics::default().needs_attention());
        for metrics in [
            Metrics {
                events_dropped: 1,
                ..Metrics::default()
            },
            Metrics {
                events_wire_mismatch: 1,
                ..Metrics::default()
            },
            Metrics {
                events_unknown_kind: 1,
                ..Metrics::default()
            },
            Metrics {
                capability_level: Some(0),
                events_received: 1,
                ..Metrics::default()
            },
        ] {
            assert!(metrics.needs_attention(), "{metrics:?}");
        }
    }

    #[test]
    fn the_names_are_the_ones_5_6_2_lists() {
        let plan = include_str!("../../../docs/01_phase5_implementation_plan.md");
        for name in [
            names::EVENTS_RECEIVED,
            names::EVENTS_DROPPED,
            names::SESSION_RISK,
            names::CAPABILITY_LEVEL,
            names::DAEMON_RSS_BYTES,
            names::DAEMON_CPU_RATIO,
            names::CORRELATION_UNMATCHED,
            names::DETECT_FINDINGS,
        ] {
            assert!(plan.contains(name), "{name} is not in the plan's catalogue");
        }
    }
}
