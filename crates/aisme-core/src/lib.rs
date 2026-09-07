// SPDX-License-Identifier: Apache-2.0
//! The engine: ontology, the three traits, policy IR, taint algebra, detectors.
//!
//! This crate has no I/O, no async runtime, no `cfg(target_os)` and no platform
//! dependency. That single rule is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK (plan §3.1, rule `A-01`).

pub mod adjudicate;
pub mod capability;
pub mod enforce;
pub mod error;
pub mod intern;
pub mod labels;
pub mod ontology;
pub mod policy;
pub mod sensor;
pub mod taint;

pub use adjudicate::{
    AdjudicationChannel, Adjudicator, BoxFuture, Escalation, GrantCeiling, PolicyDocument,
    PolicySource, Warning,
};
pub use capability::{CapabilitySet, KeyHw, SentinelCapabilities};
pub use enforce::{EnforcementTier, Enforcer, EscalationId, SuspendScope, SuspendToken};
pub use error::{Error, ErrorKind, Result};
pub use intern::{Interner, InternerStats, StrId, TooLong};
pub use labels::{LabelError, TreeLabels};
pub use ontology::{
    BootNs, DetectorId, Digest, Edge, EdgeKind, EvidenceRefs, InstructionSignals, Node, NodeId,
    NodeKind, PathClass, PermissionGroup, ResultOrigin, SessionId, Severity, SuppressionOrigin,
};
pub use sensor::{
    BatchFull, EventBatch, EventSink, Sensor, SensorConfig, SensorHealth, SessionCandidate,
    SessionDiscovery,
};
pub use taint::{DecayPolicy, Declassification, Declassified, Taint};
