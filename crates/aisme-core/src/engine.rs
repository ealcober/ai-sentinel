// SPDX-License-Identifier: Apache-2.0
//! The hot loop (`F1.RT.03`): drain → intern → correlate → detect → sink.
//!
//! §3.3 steps 5–10, as one function that allocates nothing in steady state.
//! Everything it needs is owned and preallocated when the engine is built:
//! the batch, the interner's arena, the graph, the findings buffer. A `tick`
//! therefore does no `malloc`, which is what keeps the T-tel budget (30 µs
//! per batch) and the 50 MB RSS budget from depending on an allocator's mood
//! — `tests/hot_loop_allocations.rs` measures it with a counting allocator
//! and fails on the first byte.
//!
//! The engine is pure in the sense that matters here: it calls trait
//! methods and holds no I/O of its own, so the whole pipeline runs on
//! `MockSensor` + `NullEnforcer` + `MemorySink` with no kernel (§3.2).

use core::time::Duration;

use aisme_ebpf_common::{Outcome, Payload, Range, RawEvent, WIRE_VERSION};

use crate::detect::{DetectorSet, Finding, GraphDelta, SessionState};
use crate::error::Result;
use crate::intern::Interner;
use crate::risk::{RiskEvent, SessionRisk, Weights};
use crate::sensor::{EventBatch, EventSink, Sensor};
use crate::taint::Taint;

/// What one tick did. Counters only — the engine reports, it does not log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Events drained from all sensors.
    pub drained: usize,
    /// Events whose kind this binary does not know: recorded, not
    /// interpreted (`I-17`).
    pub unknown_kind: usize,
    /// Events whose producer speaks another wire version (§3.6).
    pub wire_mismatch: usize,
    /// Strings interned this tick.
    pub interned: usize,
    /// Findings raised.
    pub findings: usize,
    /// Sensors that reported an error and were skipped this tick.
    pub sensor_errors: usize,
}

/// Everything the loop owns, allocated once.
pub struct Engine {
    sensors: Vec<Box<dyn Sensor>>,
    sink: Box<dyn EventSink>,
    detectors: DetectorSet,
    batch: EventBatch,
    interner: Interner,
    risk: SessionRisk,
    state: SessionState,
    findings: Vec<Finding>,
    totals: TickReport,
}

impl Engine {
    /// Build the engine, allocating everything it will need.
    ///
    /// `batch_capacity` is §3.3's 32–512; the interner is the plan's path
    /// interner (`F1.EV.04`).
    #[must_use]
    pub fn new(
        sensors: Vec<Box<dyn Sensor>>,
        sink: Box<dyn EventSink>,
        detectors: DetectorSet,
        batch_capacity: usize,
    ) -> Engine {
        Engine {
            sensors,
            sink,
            detectors,
            batch: EventBatch::with_capacity(batch_capacity),
            interner: Interner::for_paths(),
            risk: SessionRisk::new(Weights::DEFAULT, 0),
            state: SessionState::default(),
            findings: Vec::with_capacity(DetectorSet::MAX_FINDINGS_PER_TICK),
            totals: TickReport::default(),
        }
    }

    /// One pass: drain every sensor, intern what the events carry, update
    /// taint and risk, run the detectors, append to the sink.
    ///
    /// Allocates nothing after the first tick: the batch, the arena and the
    /// findings buffer are reused, and every error path counts rather than
    /// formats.
    ///
    /// # Errors
    ///
    /// The sink's, when it cannot take a batch. A sensor's error is counted
    /// and the tick continues: one detached sensor is not the end of
    /// observation (`I-19`).
    pub fn tick(&mut self, budget: Duration, now_ns: u64) -> Result<TickReport> {
        let mut report = TickReport::default();
        self.batch.clear();
        for sensor in &mut self.sensors {
            match sensor.poll(&mut self.batch, budget) {
                Ok(n) => report.drained += n,
                Err(_) => report.sensor_errors += 1,
            }
        }
        self.state.now_ns = now_ns;
        for event in self.batch.as_slice() {
            classify(event, &mut report);
            if let Some(kind) = interned_string(event) {
                if self.interner.intern(kind).is_ok() {
                    report.interned += 1;
                }
            }
            if let Some(risk_event) = risk_event_of(event) {
                self.state.risk_milli = self.risk.observe(risk_event, now_ns);
            }
            self.state.taint = self.state.taint.union(Taint::from_bits(event.taint));
        }
        self.findings.clear();
        let delta = GraphDelta::default();
        self.detectors
            .observe_into(&delta, &self.state, &mut self.findings);
        report.findings = self.findings.len();
        self.sink.append(&self.batch)?;
        self.totals.drained += report.drained;
        self.totals.unknown_kind += report.unknown_kind;
        self.totals.wire_mismatch += report.wire_mismatch;
        self.totals.interned += report.interned;
        self.totals.findings += report.findings;
        self.totals.sensor_errors += report.sensor_errors;
        Ok(report)
    }

    /// Everything the engine has seen since it was built.
    #[must_use]
    pub const fn totals(&self) -> TickReport {
        self.totals
    }

    /// The session state the detectors see.
    #[must_use]
    pub const fn state(&self) -> &SessionState {
        &self.state
    }

    /// The interner, for the consumers that resolve a `StrId`.
    #[must_use]
    pub const fn interner(&self) -> &Interner {
        &self.interner
    }

    /// The findings of the last tick.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Start every sensor.
    ///
    /// # Errors
    ///
    /// The first sensor that refuses to start.
    pub fn start(&mut self, cfg: &crate::sensor::SensorConfig) -> Result<()> {
        for sensor in &mut self.sensors {
            sensor.start(cfg)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("sensors", &self.sensors.len())
            .field("totals", &self.totals)
            .finish_non_exhaustive()
    }
}

/// Count what this binary cannot interpret, rather than guess (`I-17`, §3.6).
fn classify(event: &RawEvent, report: &mut TickReport) {
    if event.wire_version != WIRE_VERSION {
        report.wire_mismatch += 1;
    }
    if event.kind.decode().is_err() {
        report.unknown_kind += 1;
    }
}

/// The inline string an event carries, if any — borrowed from the event, so
/// no allocation.
fn interned_string(event: &RawEvent) -> Option<&[u8]> {
    Some(match event.payload()? {
        Payload::File(file) => &file.path[..usize::from(file.path_len).min(file.path.len())],
        Payload::Process(process) => {
            &process.exe[..usize::from(process.exe_len).min(process.exe.len())]
        }
        _ => return None,
    })
}

/// What an event contributes to the session's risk, if anything.
fn risk_event_of(event: &RawEvent) -> Option<RiskEvent> {
    match event.kind.range()? {
        Range::Hazard | Range::Introspection => Some(RiskEvent::ClassShift),
        Range::Decision if event.outcome == Outcome::Denied.into() => Some(RiskEvent::Deny),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MemorySink, MockSensor};
    use crate::sensor::SensorConfig;
    use aisme_ebpf_common::EventKind;

    fn engine() -> Engine {
        Engine::new(
            vec![Box::new(MockSensor::with_every_kind())],
            Box::new(MemorySink::new()),
            DetectorSet::new(),
            64,
        )
    }

    #[test]
    fn a_tick_drains_classifies_and_sinks() {
        let mut engine = engine();
        engine.start(&SensorConfig::default()).unwrap();
        let first = engine.tick(Duration::ZERO, 1_000).unwrap();
        assert_eq!(first.drained, 55, "the catalogue trace, in one batch of 64");
        assert_eq!(first.unknown_kind, 0);
        assert_eq!(first.wire_mismatch, 0);
        assert_eq!(first.sensor_errors, 0);
        let second = engine.tick(Duration::ZERO, 2_000).unwrap();
        assert_eq!(second.drained, 0, "the trace is exhausted");
        assert_eq!(engine.totals().drained, 55);
    }

    #[test]
    fn an_unknown_kind_and_a_wire_mismatch_are_counted_not_dropped() {
        let mut odd = RawEvent::ZERO;
        odd.kind = aisme_ebpf_common::KindCode(0x1FFF);
        let mut newer = RawEvent::ZERO;
        newer.kind = EventKind::FileOpen.into();
        newer.wire_version = WIRE_VERSION + 1;
        let mut engine = Engine::new(
            vec![Box::new(MockSensor::new(vec![odd, newer]))],
            Box::new(MemorySink::new()),
            DetectorSet::new(),
            8,
        );
        engine.start(&SensorConfig::default()).unwrap();
        let report = engine.tick(Duration::ZERO, 1).unwrap();
        assert_eq!(report.drained, 2);
        assert_eq!(report.unknown_kind, 1);
        assert_eq!(report.wire_mismatch, 1);
    }

    #[test]
    fn a_detached_sensor_is_counted_and_the_others_still_drain() {
        let detached =
            MockSensor::with_every_kind().with_health(crate::sensor::SensorHealth::Detached {
                reason: "probe removed".into(),
            });
        let mut engine = Engine::new(
            vec![
                Box::new(detached),
                Box::new(MockSensor::new(vec![RawEvent::ZERO])),
            ],
            Box::new(MemorySink::new()),
            DetectorSet::new(),
            8,
        );
        engine.start(&SensorConfig::default()).unwrap();
        let report = engine.tick(Duration::ZERO, 1).unwrap();
        assert_eq!(report.sensor_errors, 1);
        assert_eq!(
            report.drained, 1,
            "one detached sensor is not the end of observation"
        );
    }

    #[test]
    fn paths_are_interned_and_hazards_move_the_risk() {
        let mut file = RawEvent::ZERO;
        file.kind = EventKind::FileOpen.into();
        let mut path = aisme_ebpf_common::FilePayload {
            inode: 1,
            dev: 1,
            size: 0,
            flags: 0,
            mode: 0,
            path_class: 0,
            pad0: 0,
            path_len: 9,
            path: [0; 200],
            reserved: [0; 20],
        };
        path.path[..9].copy_from_slice(b"/etc/pass");
        file.payload.file = path;
        let mut hazard = RawEvent::ZERO;
        hazard.kind = EventKind::MemfdCreate.into();
        let mut engine = Engine::new(
            vec![Box::new(MockSensor::new(vec![file, hazard]))],
            Box::new(MemorySink::new()),
            DetectorSet::new(),
            8,
        );
        engine.start(&SensorConfig::default()).unwrap();
        let report = engine.tick(Duration::ZERO, 5_000).unwrap();
        assert_eq!(report.interned, 1);
        assert!(engine.state().risk_milli > 0, "a hazard is a class shift");
        assert_eq!(engine.state().now_ns, 5_000);
    }
}
