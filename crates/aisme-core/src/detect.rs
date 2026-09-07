// SPDX-License-Identifier: Apache-2.0
//! The detector interface (`F1.DT.01`; Annex G.0).
//!
//! A detector is a **pure function** `fn observe(&GraphDelta, &SessionState)
//! -> Option<Finding>`: no I/O, no clock of its own, no platform. That is
//! what lets the Annex G catalogue be tested once, on CI, for every target
//! (§3.2's last paragraph), and what makes a finding reproducible from a
//! recorded trace.
//!
//! Three rules travel with the interface:
//!
//! - **A single-plane signal is a `warn` at most** (G.0). A detector that
//!   joins only one plane may not raise `High` or `Critical`; the composition
//!   caps it, so a detector cannot promote itself by writing a larger number.
//! - **Ordered composition.** Detectors run in catalogue order and every one
//!   of them runs: a finding does not stop the list, because two detectors
//!   firing on the same delta is evidence, not a conflict.
//! - **Absence is not evidence** (`DT-10`'s FP-control column). A detector
//!   that has no profile for what it is looking at returns `None`; returning
//!   a finding because something is *unknown* is how a false positive is
//!   born.

use crate::ontology::{
    DetectorId, EvidenceRefs, InstructionSignals, Node, NodeId, PermissionGroup, SessionId,
    Severity,
};
use crate::taint::Taint;
use aisme_ebpf_common::Verdict;

/// Which signal planes a detector joins (G.0: intent, action, context).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Plane {
    /// Prompts, chain-of-thought, tool calls (F4, F9).
    Intent,
    /// File, exec, socket (F3 kernel, F10 tunnel).
    Action,
    /// What the agent read, with provenance — `File.taint`, `ToolResult`.
    Context,
}

/// What changed in the graph since the last pass: the detectors' input.
///
/// Borrowed, not owned: the correlate step builds it on the stack in the hot
/// loop, and a detector that wanted to keep something would have to copy it
/// deliberately.
#[derive(Clone, Copy, Debug, Default)]
pub struct GraphDelta<'a> {
    /// Nodes added, with their ids.
    pub added: &'a [(NodeId, Node)],
    /// Edges added.
    pub edges: &'a [crate::ontology::Edge],
    /// The verdict this delta carried, when it came from a decision.
    pub verdict: Option<Verdict>,
    /// The group the decision was about.
    pub group: Option<PermissionGroup>,
}

/// What the session looked like when the delta arrived.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionState {
    /// The session.
    pub session_id: SessionId,
    /// Boot-monotonic now, in nanoseconds — passed in, never read: a
    /// detector that read a clock would not be reproducible from a trace.
    pub now_ns: u64,
    /// The agent's accumulated taint.
    pub taint: Taint,
    /// The current risk score in thousandths (`DT-09`).
    pub risk_milli: u32,
    /// Instruction-bearing signals seen in this session so far.
    pub signals: InstructionSignals,
    /// Tool calls since the last instruction-bearing input — `DT-02`'s
    /// "within k tool calls" window.
    pub tool_calls_since_untrusted_input: u32,
    /// Denies the session has already collected (`DT-05`'s precondition).
    pub denies: u32,
}

/// A detector's output, before the composition caps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Which detector.
    pub dt: DetectorId,
    /// How serious the detector thinks it is.
    pub severity: Severity,
    /// What it saw.
    pub evidence: EvidenceRefs,
    /// One sentence, for the prompt and the timeline.
    pub summary: String,
}

impl Finding {
    /// A finding with no evidence yet.
    #[must_use]
    pub fn new(dt: DetectorId, severity: Severity, summary: impl Into<String>) -> Finding {
        Finding {
            dt,
            severity,
            evidence: EvidenceRefs::default(),
            summary: summary.into(),
        }
    }

    /// With the nodes it rests on.
    #[must_use]
    pub fn with_evidence(mut self, evidence: EvidenceRefs) -> Finding {
        self.evidence = evidence;
        self
    }

    /// As an ontology node (`F1.ON.06`), for the graph and the WAL.
    #[must_use]
    pub fn as_node(&self, suppressed_by: Option<crate::intern::StrId>) -> Node {
        Node::Finding {
            dt: self.dt,
            severity: self.severity,
            evidence_refs: self.evidence,
            suppressed_by,
        }
    }
}

/// One detector of the Annex G catalogue.
pub trait Detector: Send + Sync {
    /// Which detector this is.
    fn id(&self) -> DetectorId;

    /// The planes it joins. One plane caps its severity at `Medium`
    /// (G.0: "a single-plane signal is a `warn` at most").
    fn planes(&self) -> &'static [Plane];

    /// Look at one delta. Pure: same inputs, same answer, on every target.
    fn observe(&self, delta: &GraphDelta<'_>, state: &SessionState) -> Option<Finding>;
}

/// The catalogue, in order.
#[derive(Default)]
pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> DetectorSet {
        DetectorSet::default()
    }

    /// Append a detector. Catalogue order is the order they were added, and
    /// it does not affect the outcome — every detector sees every delta.
    #[must_use]
    pub fn with(mut self, detector: Box<dyn Detector>) -> DetectorSet {
        self.detectors.push(detector);
        self
    }

    /// How many.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Whether none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run every detector over one delta, in order, capping each finding at
    /// what its planes allow. Every detector runs: a finding does not end
    /// the pass.
    #[must_use]
    pub fn observe(&self, delta: &GraphDelta<'_>, state: &SessionState) -> Vec<Finding> {
        self.detectors
            .iter()
            .filter_map(|d| {
                d.observe(delta, state).map(|mut finding| {
                    debug_assert_eq!(finding.dt, d.id(), "a detector filed under another's id");
                    let cap = severity_cap(d.planes());
                    if finding.severity > cap {
                        finding.severity = cap;
                    }
                    finding
                })
            })
            .collect()
    }
}

impl core::fmt::Debug for DetectorSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DetectorSet")
            .field("len", &self.detectors.len())
            .finish()
    }
}

/// G.0's cap: a single-plane signal is a `warn` at most.
#[must_use]
pub fn severity_cap(planes: &[Plane]) -> Severity {
    if planes.len() <= 1 {
        Severity::Medium
    } else {
        Severity::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed {
        dt: DetectorId,
        planes: &'static [Plane],
        finding: Option<Severity>,
    }

    impl Detector for Fixed {
        fn id(&self) -> DetectorId {
            self.dt
        }
        fn planes(&self) -> &'static [Plane] {
            self.planes
        }
        fn observe(&self, _delta: &GraphDelta<'_>, _state: &SessionState) -> Option<Finding> {
            self.finding
                .map(|severity| Finding::new(self.dt, severity, "fixture"))
        }
    }

    fn detector(n: u8, planes: &'static [Plane], finding: Option<Severity>) -> Box<dyn Detector> {
        Box::new(Fixed {
            dt: DetectorId::new(n).unwrap(),
            planes,
            finding,
        })
    }

    #[test]
    fn a_single_plane_detector_cannot_raise_above_warn() {
        let set = DetectorSet::new()
            .with(detector(7, &[Plane::Action], Some(Severity::Critical)))
            .with(detector(
                2,
                &[Plane::Context, Plane::Action],
                Some(Severity::Critical),
            ));
        let findings = set.observe(&GraphDelta::default(), &SessionState::default());
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Medium, "capped by G.0");
        assert_eq!(
            findings[1].severity,
            Severity::Critical,
            "two planes, uncapped"
        );
        assert_eq!(
            severity_cap(&[]),
            Severity::Medium,
            "no plane is not a licence"
        );
    }

    #[test]
    fn every_detector_runs_and_order_is_the_catalogues() {
        let set = DetectorSet::new()
            .with(detector(
                1,
                &[Plane::Context, Plane::Intent],
                Some(Severity::High),
            ))
            .with(detector(4, &[Plane::Intent, Plane::Action], None))
            .with(detector(13, &[Plane::Action], Some(Severity::Low)));
        let findings = set.observe(&GraphDelta::default(), &SessionState::default());
        let ids: Vec<u8> = findings.iter().map(|f| f.dt.number()).collect();
        assert_eq!(
            ids,
            [1, 13],
            "a finding does not stop the pass; a None is simply absent"
        );
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn a_finding_becomes_the_ontology_node_it_will_be_recorded_as() {
        let evidence: EvidenceRefs = [NodeId(1), NodeId(2)].into_iter().collect();
        let finding = Finding::new(
            DetectorId::new(2).unwrap(),
            Severity::High,
            "injection then class shift",
        )
        .with_evidence(evidence);
        match finding.as_node(None) {
            Node::Finding {
                dt,
                severity,
                evidence_refs,
                suppressed_by,
            } => {
                assert_eq!(dt.number(), 2);
                assert_eq!(severity, Severity::High);
                assert_eq!(evidence_refs.iter().count(), 2);
                assert_eq!(suppressed_by, None);
            }
            other => panic!("{other:?}"),
        }
    }
}
