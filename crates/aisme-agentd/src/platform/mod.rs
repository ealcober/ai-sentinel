// SPDX-License-Identifier: Apache-2.0
//! The composition root (`F1.PA.06`; plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in the workspace permitted to name a concrete adapter
//! or use `cfg(target_os)`.** Everything above it is written against the
//! `aisme-core` traits, which is what lets one engine serve Linux, WSL2,
//! Android, iOS and the SDK; `cargo xtask verify-layering` fails on a
//! `cfg(target_os)` anywhere else.
//!
//! The adapters arrive with their phases — `aisme-linux`'s `BpfSensor` in
//! `F2.WS.01`, the rest of it in F3, `sentinel-core` in F10, `aisme-sdkhost`
//! in F9 — and each is added here, behind the `cfg` its platform needs,
//! without changing a line above.

use aisme_core::adjudicate::Adjudicator;
use aisme_core::capability::CapabilitySet;
use aisme_core::enforce::Enforcer;
use aisme_core::ladder::AdjudicatorLadder;
use aisme_core::mock::{MockSensor, NullEnforcer, PolicyAdjudicator};
use aisme_core::sensor::{Sensor, SensorConfig};
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

/// Load the BPF sensor on this kernel and report what happened, in the words
/// the reader needs: accepted with its capabilities, or refused with the
/// platform's own message. Returns the process exit code — 0 accepted, 1
/// refused — so a guest run can be read by a script as well as by a person.
#[cfg(target_os = "linux")]
pub fn load_sensor_report() -> i32 {
    use aisme_core::sensor::{Sensor as _, SensorConfig};
    let mut sensor = aisme_linux::BpfSensor::new();
    match sensor.start(&SensorConfig::default()) {
        Ok(()) => {
            let caps = sensor.capabilities();
            println!("load-sensor: ACCEPTED");
            println!("  ringbuf: {}", caps.ringbuf);
            println!("  health: {:?}", sensor.health());
            // Detach immediately: this is a question, not a session.
            if let Err(e) = sensor.stop() {
                println!("  stop: {} ({:?})", e.detail, e.kind);
            }
            0
        }
        Err(e) => {
            // The reason is the product of this command. A bare "failed" would
            // make the run useless on the one kernel where it matters most.
            println!("load-sensor: REFUSED ({:?})", e.kind);
            println!("  {}", e.detail);
            1
        }
    }
}

/// Not Linux: there is no sensor to load, and saying so beats a silent zero.
#[cfg(not(target_os = "linux"))]
pub fn load_sensor_report() -> i32 {
    println!("load-sensor: UNSUPPORTED (this build has no Linux adapter)");
    1
}

/// The sensors for this platform and this capability set.
#[must_use]
pub fn sensors(caps: &CapabilitySet) -> Vec<Box<dyn Sensor>> {
    let mut sensors: Vec<Box<dyn Sensor>> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // `F2.WS.01`. The gate is `caps.ringbuf`, and it is load-bearing twice
        // over. It is the honest condition — the sensor needs
        // `BPF_MAP_TYPE_RINGBUF` and refuses the perf-buffer fallback, which
        // is `F3.PT.*`'s — and it is what keeps `I-12` intact: `probe()`
        // reports nothing present until `F3.LD.01`, so no BPF load is
        // attempted on a host running the test suite. The in-VM composition
        // (`F2.WS.10`) passes a capability set that was actually measured.
        if caps.ringbuf {
            let mut bpf = aisme_linux::BpfSensor::new();
            match bpf.start(&SensorConfig::default()) {
                Ok(()) => sensors.push(Box::new(bpf)),
                Err(e) => {
                    // The daemon still starts (`I-19`) — the mock below covers
                    // — but the reason is never swallowed: a sensor that
                    // silently did not attach is a machine reported quiet.
                    eprintln!("aisme: BpfSensor did not attach: {}", e.detail);
                }
            }
        }
        // F3.PT.*: UprobeSensor for TLS, CooperativeSensor for JSONL tailing.
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
// A panic *is* the failure report in a test, so the two lints the daemon
// denies are allowed here — and only here, which is the point: the denial
// covers the code that runs in production (§3.5, F1.RT.08).
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// `I-12` in the test suite, not only in the invariant list: this runs on
    /// a developer's host, so nothing here may touch the kernel. `probe()`
    /// reports nothing present until `F3.LD.01`, and `sensors()` only reaches
    /// `BpfSensor` when `ringbuf` was measured — so the composition under test
    /// loads no BPF program. If someone later makes the sensor unconditional,
    /// this test is where it shows: the composition would try a real load and
    /// the count below would move on a machine with `CAP_BPF`.
    #[test]
    fn nothing_measured_means_no_bpf_load_is_attempted_on_the_host() {
        let caps = probe();
        assert!(
            !caps.ringbuf,
            "probe() must not claim what it did not measure"
        );
        let sensors = sensors(&caps);
        assert_eq!(sensors.len(), 1, "the mock alone");
        assert!(
            matches!(
                sensors[0].health(),
                aisme_core::sensor::SensorHealth::Detached { .. }
                    | aisme_core::sensor::SensorHealth::Healthy
            ),
            "the mock reports its own state; what matters is that it is the mock"
        );
        assert!(!sensors[0].capabilities().ringbuf);
    }

    #[test]
    fn a_platform_with_nothing_measured_is_l1_not_a_failure_to_start() {
        assert_eq!(tier(&probe()), Tier::L1);
        assert_eq!(tier(&CapabilitySet::NONE), Tier::L1);
    }
}
