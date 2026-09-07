// SPDX-License-Identifier: Apache-2.0
//! `F1.EV.03`, last clause: every `EventKind` variant is produced by at least
//! one producer in the suite. An unproduced variant is dead weight or a
//! missing producer, and either way it is named here.
//!
//! In F1 the producers are `MockSensor`'s recorded traces (`F1.PA.02`) and
//! `aisme-agentsim` (`F1.SIM.01`); the kernel producers arrive in F3. Until
//! the first of them exists the check has nothing to count, so it is ignored
//! with that reason rather than passing on an empty list — an absence read as
//! coverage is exactly what general rule 9 forbids.

use aisme_ebpf_common::EventKind;

/// What the suite's producers emit. `F1.PA.02` replaces this with the kinds
/// its recorded traces carry; `F1.SIM.01` extends it; F3 completes it.
const PRODUCED: &[EventKind] = &[];

#[test]
#[ignore = "F1.PA.02: no producer exists in the suite before MockSensor; the check runs once it does"]
fn every_kind_is_produced_by_the_suite() {
    let unproduced: Vec<EventKind> = EventKind::ALL
        .into_iter()
        .filter(|kind| !PRODUCED.contains(kind))
        .collect();
    assert!(
        unproduced.is_empty(),
        "{} of {} kinds are produced by no one — dead weight or a missing producer: {unproduced:?}",
        unproduced.len(),
        EventKind::ALL.len()
    );
}
