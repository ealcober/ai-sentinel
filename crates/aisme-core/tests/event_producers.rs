// SPDX-License-Identifier: Apache-2.0
//! `F1.EV.03`, last clause: every `EventKind` variant is produced by at
//! least one producer in the suite. An unproduced variant is dead weight or
//! a missing producer, and either way it is named here.
//!
//! The producer is `MockSensor`'s catalogue trace (`F1.PA.02`), whose
//! `CATALOGUE` is an explicit list rather than an iteration over
//! `EventKind::ALL` — a check that generates its own expectation can never
//! fail. Adding a variant to the taxonomy without producing it anywhere
//! fails this test. F3's kernel producers and `F1.SIM.01`'s traces extend
//! the set; they do not replace it.

use std::collections::BTreeSet;
use std::time::Duration;

use aisme_core::sensor::{EventBatch, Sensor, SensorConfig};
use aisme_core::MockSensor;
use aisme_ebpf_common::{EventKind, KindCode};

/// The kinds the suite's producers actually emit, drained through the
/// `Sensor` trait rather than read from the fixture: the check follows the
/// production path.
fn produced() -> BTreeSet<u16> {
    let mut sensor = MockSensor::with_every_kind();
    sensor.start(&SensorConfig::default()).unwrap();
    let mut batch = EventBatch::with_capacity(256);
    let mut seen = BTreeSet::new();
    while sensor.poll(&mut batch, Duration::ZERO).unwrap() > 0 {
        for event in batch.as_slice() {
            seen.insert(event.kind.0);
        }
        batch.clear();
    }
    seen
}

#[test]
fn every_kind_is_produced_by_the_suite() {
    let produced = produced();
    let unproduced: Vec<EventKind> = EventKind::ALL
        .into_iter()
        .filter(|kind| !produced.contains(&kind.code().0))
        .collect();
    assert!(
        unproduced.is_empty(),
        "{} of {} kinds are produced by no one — dead weight or a missing producer: {unproduced:?}",
        unproduced.len(),
        EventKind::ALL.len()
    );
}

#[test]
fn the_producers_emit_nothing_the_taxonomy_does_not_name() {
    for code in produced() {
        assert!(
            KindCode(code).decode().is_ok(),
            "producer emitted {code:#06x}, which decodes to no variant"
        );
    }
}
