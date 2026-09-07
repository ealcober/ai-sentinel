// SPDX-License-Identifier: Apache-2.0
//! The composition root (`F1.PA.06`; plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in the workspace permitted to name a concrete adapter
//! or use `cfg(target_os)`.** Everything above it is written against the
//! `aisme-core` traits, which is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK; `cargo xtask verify-layering` fails on a
//! `cfg(target_os)` anywhere else.
//!
//! In F1 the only implementations that exist are the platform-free ones
//! (`F1.PA.02`). The adapters arrive with their phases — `aisme-linux` in
//! F3, `sentinel-core` in F10, `aisme-sdkhost` in F9 — and each is added
//! here, behind the `cfg` its platform needs, without changing a line above.

use aisme_core::adjudicate::Adjudicator;
use aisme_core::capability::CapabilitySet;
use aisme_core::enforce::Enforcer;
use aisme_core::ladder::AdjudicatorLadder;
use aisme_core::mock::{MockSensor, NullEnforcer, PolicyAdjudicator};
use aisme_core::sensor::Sensor;
use aisme_core::tier::{tier_of, Tier};
use aisme_ebpf_common::Verdict;

/// What the platform probes measured. The probe itself is an adapter's
/// (`F3.LD.*` on Linux); until one exists this reports nothing present,
/// which is the honest answer and yields tier L1.
#[must_use]
pub fn probe() -> CapabilitySet {
    #[cfg(target_os = "linux")]
    {
        // F3.LD.01 replaces this with the real probe: securityfs, /proc/config.gz,
        // the Landlock ABI syscall, an attach test for the connect hook. Until
        // then nothing is claimed present.
        CapabilitySet::NONE
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows is served by WSL2 (ADR-02) and mobile by AI Sentinel; a
        // native build of `agentd` on another OS has no sensors at all.
        CapabilitySet::NONE
    }
}

/// The sensors for this platform and this capability set.
#[must_use]
pub fn sensors(caps: &CapabilitySet) -> Vec<Box<dyn Sensor>> {
    let mut sensors: Vec<Box<dyn Sensor>> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // F3.PT.*: BpfSensor when the tier supports it, UprobeSensor for TLS,
        // CooperativeSensor for JSONL tailing. None exists yet.
        let _ = caps;
    }
    if sensors.is_empty() {
        // Never zero sensors: an engine with no producer would report a quiet
        // machine, which is an absence read as "nothing happened" (I-16).
        // The mock produces nothing and says so through its health.
        sensors.push(Box::new(MockSensor::new(Vec::new())));
    }
    sensors
}

/// The enforcers for this platform and this capability set.
#[must_use]
pub fn enforcers(caps: &CapabilitySet) -> Vec<Box<dyn Enforcer>> {
    let mut enforcers: Vec<Box<dyn Enforcer>> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // F3.EN.*: LsmEnforcer at L3, LandlockEnforcer and
        // CgroupConnectEnforcer at L2, SeccompEnforcer for T1, FreezerEnforcer
        // for T2 — each gated on the capability it needs.
        let _ = caps;
    }
    if enforcers.is_empty() {
        // Observe-only is a real tier (L1), not a failure to start (I-19).
        enforcers.push(Box::new(NullEnforcer::new()));
    }
    enforcers
}

/// The adjudicator ladder for this platform.
///
/// `PolicyAdjudicator` is always last and always present, so a question
/// always has an answer (§7 tier 5). Its default is `deny`: the escalate
/// class's timeout default (§2.20.5).
#[must_use]
pub fn adjudicators(caps: &CapabilitySet) -> AdjudicatorLadder {
    let mut adjudicators: Vec<Box<dyn Adjudicator>> = Vec::new();
    // F8's uiagent supplies Modal and Notification; `aisme run` supplies
    // Terminal (F8.CLI.*); a paired device supplies Remote (F11), and only
    // when one is reachable.
    let _ = caps.local_ui_attached;
    let _ = caps.remote_devices;
    adjudicators.push(Box::new(PolicyAdjudicator::new(Verdict::Deny)));
    AdjudicatorLadder::from(adjudicators)
}

/// The tier this composition serves, derived from the probe (`F1.PA.04`).
#[must_use]
pub fn tier(caps: &CapabilitySet) -> Tier {
    tier_of(caps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisme_core::adjudicate::AdjudicationChannel;
    use aisme_core::enforce::EnforcementTier;

    #[test]
    fn the_composition_always_yields_a_sensor_an_enforcer_and_an_answer() {
        let caps = probe();
        assert_eq!(sensors(&caps).len(), 1);
        let enforcers = enforcers(&caps);
        assert_eq!(enforcers.len(), 1);
        assert_eq!(enforcers[0].tier(), EnforcementTier::Observe);
        let ladder = adjudicators(&caps);
        assert_eq!(ladder.channels(), [AdjudicationChannel::Policy]);
        assert!(!ladder.is_empty(), "there is always an answer");
    }

    #[test]
    fn a_platform_with_nothing_measured_is_l1_not_a_failure_to_start() {
        assert_eq!(tier(&probe()), Tier::L1);
        assert_eq!(tier(&CapabilitySet::NONE), Tier::L1);
    }
}
