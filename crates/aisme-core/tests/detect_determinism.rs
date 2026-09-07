// SPDX-License-Identifier: Apache-2.0
//! `F1.DT.01`: the detectors are deterministic — same input, same findings,
//! on every target.
//!
//! Annex G.0 says detectors are pure functions with no platform variants,
//! "which is why they can be tested once, on CI, for every target". This is
//! that test. It cannot run the other targets from here, so what it proves
//! is the property that makes cross-target equality follow: the pass depends
//! on nothing but its arguments — not on iteration order, not on a clock,
//! not on a hash seed, not on the order detectors were added.

use aisme_core::detect::{Detector, DetectorSet, Finding, GraphDelta, Plane, SessionState};
use aisme_core::ontology::{DetectorId, EvidenceRefs, NodeId, Severity};
use aisme_core::taint::Taint;

/// A detector that answers from the state alone — which is all a pure
/// detector may do.
struct Threshold {
    dt: DetectorId,
    planes: &'static [Plane],
    fires_above_milli: u32,
}

impl Detector for Threshold {
    fn id(&self) -> DetectorId {
        self.dt
    }

    fn planes(&self) -> &'static [Plane] {
        self.planes
    }

    fn observe(&self, _delta: &GraphDelta<'_>, state: &SessionState) -> Option<Finding> {
        (state.risk_milli > self.fires_above_milli).then(|| {
            Finding::new(self.dt, Severity::High, "over the threshold").with_evidence(
                [NodeId(u64::from(state.risk_milli))]
                    .into_iter()
                    .collect::<EvidenceRefs>(),
            )
        })
    }
}

fn set() -> DetectorSet {
    DetectorSet::new()
        .with(Box::new(Threshold {
            dt: DetectorId::new(2).unwrap(),
            planes: &[Plane::Context, Plane::Action],
            fires_above_milli: 1_000,
        }))
        .with(Box::new(Threshold {
            dt: DetectorId::new(7).unwrap(),
            planes: &[Plane::Action],
            fires_above_milli: 2_000,
        }))
        .with(Box::new(Threshold {
            dt: DetectorId::new(9).unwrap(),
            planes: &[Plane::Intent, Plane::Action, Plane::Context],
            fires_above_milli: 5_000,
        }))
}

fn state(risk_milli: u32) -> SessionState {
    // `SessionState` is `#[non_exhaustive]`, so it is built and then filled:
    // a consumer outside the crate cannot construct it literally, which is
    // the point — a field added later must not break every caller.
    let mut state = SessionState::default();
    state.risk_milli = risk_milli;
    state.taint = Taint::SECRET_MATERIAL;
    state.now_ns = 1_234_567;
    state
}

fn at(now_ns: u64, risk_milli: u32) -> SessionState {
    let mut state = state(risk_milli);
    state.now_ns = now_ns;
    state
}

fn findings(risk_milli: u32) -> Vec<(u8, Severity, Vec<u64>)> {
    set()
        .observe(&GraphDelta::default(), &state(risk_milli))
        .into_iter()
        .map(|f| {
            (
                f.dt.number(),
                f.severity,
                f.evidence.iter().map(|n| n.0).collect(),
            )
        })
        .collect()
}

#[test]
fn the_same_input_gives_the_same_findings_every_time() {
    let first = findings(3_000);
    for _ in 0..100 {
        assert_eq!(findings(3_000), first);
    }
    assert_eq!(
        first,
        [
            (2, Severity::High, vec![3_000]),
            (7, Severity::Medium, vec![3_000])
        ],
        "and DT-07's single plane caps it at warn (G.0)"
    );
}

#[test]
fn the_answer_depends_on_the_input_and_on_nothing_else() {
    // Different input, different answer — otherwise the determinism above
    // would be the determinism of a constant.
    assert!(findings(0).is_empty());
    assert_eq!(findings(1_500).len(), 1);
    assert_eq!(findings(3_000).len(), 2);
    assert_eq!(findings(9_000).len(), 3);
    // The pass reads no clock: the same risk at a different `now_ns` is the
    // same answer.
    let early = set().observe(&GraphDelta::default(), &at(1, 3_000));
    let late = set().observe(&GraphDelta::default(), &at(u64::MAX, 3_000));
    assert_eq!(early.len(), late.len());
    assert_eq!(early[0].dt.number(), late[0].dt.number());
    assert_eq!(early[0].severity, late[0].severity);
}

#[test]
fn the_order_findings_arrive_in_is_the_catalogues_not_the_insertion_racings() {
    // Catalogue order is the order detectors were added, and it is stable:
    // two sets built the same way answer identically, and a set built in
    // another order answers with the same *findings*, in its own order.
    let reversed = DetectorSet::new()
        .with(Box::new(Threshold {
            dt: DetectorId::new(9).unwrap(),
            planes: &[Plane::Intent, Plane::Action, Plane::Context],
            fires_above_milli: 5_000,
        }))
        .with(Box::new(Threshold {
            dt: DetectorId::new(2).unwrap(),
            planes: &[Plane::Context, Plane::Action],
            fires_above_milli: 1_000,
        }));
    let mut ids: Vec<u8> = reversed
        .observe(&GraphDelta::default(), &state(9_000))
        .iter()
        .map(|f| f.dt.number())
        .collect();
    assert_eq!(ids, [9, 2]);
    ids.sort_unstable();
    let mut catalogue: Vec<u8> = findings(9_000).iter().map(|(dt, _, _)| *dt).collect();
    catalogue.retain(|dt| *dt != 7);
    catalogue.sort_unstable();
    assert_eq!(
        ids, catalogue,
        "the same detectors fire, whatever the order"
    );
}
