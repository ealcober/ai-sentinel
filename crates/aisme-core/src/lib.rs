// SPDX-License-Identifier: Apache-2.0
//! The engine: ontology, the three traits, policy IR, taint algebra, detectors.
//!
//! This crate has no I/O, no async runtime, no `cfg(target_os)` and no platform
//! dependency. That single rule is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK (plan §3.1, rule `A-01`).

pub mod adjudicate;
pub mod capability;
pub mod detect;
pub mod enforce;
pub mod engine;
pub mod error;
pub mod intern;
pub mod labels;
pub mod ladder;
pub mod mock;
pub mod ontology;
pub mod policy;
pub mod ring;
pub mod risk;
pub mod sensor;
pub mod taint;
pub mod tier;
pub mod wal;
pub mod weights;

pub use adjudicate::{
    AdjudicationChannel, Adjudicator, BoxFuture, Escalation, GrantCeiling, PolicyDocument,
    PolicySource, Warning,
};
pub use capability::{CapabilitySet, KeyHw, SentinelCapabilities};
pub use detect::{Detector, DetectorSet, Finding, GraphDelta, Plane, SessionState};
pub use enforce::{EnforcementTier, Enforcer, EscalationId, SuspendScope, SuspendToken};
pub use engine::{Engine, TickReport};
pub use error::{Error, ErrorKind, Result};
pub use intern::{Interner, InternerStats, StrId, TooLong};
pub use labels::{LabelError, TreeLabels};
pub use ladder::{Adjudication, AdjudicatorLadder, Refusal};
pub use mock::{
    catalogue_trace, CountingSink, MemorySink, MockSensor, NullEnforcer, PolicyAdjudicator,
    CATALOGUE,
};
pub use ontology::{
    BootNs, DetectorId, Digest, Edge, EdgeKind, EvidenceRefs, InstructionSignals, Node, NodeId,
    NodeKind, PathClass, PermissionGroup, ResultOrigin, SessionId, Severity, SuppressionOrigin,
};
pub use ring::EventRing;
pub use risk::{RiskEvent, SessionRisk, Weights};
pub use sensor::{
    BatchFull, EventBatch, EventSink, Sensor, SensorConfig, SensorHealth, SessionCandidate,
    SessionDiscovery,
};
pub use taint::{DecayPolicy, Declassification, Declassified, Taint};
pub use tier::{degradations, tier_of, Degradation, State, Tier, Transition};
pub use wal::{replay, SegmentHeader, WalError};
pub use weights::{SignatureVerifier, SignedWeights, WeightsError};
