// SPDX-License-Identifier: Apache-2.0
//! `MockSensor`, `NullEnforcer`, `PolicyAdjudicator` (`F1.PA.02`).
//!
//! Together they run the complete pipeline with no kernel, no platform and
//! no I/O — §3.2's first consequence, and what lets every correlation,
//! taint, compression and policy test of Part IV run in milliseconds. They
//! are not test-only code: `PolicyAdjudicator` is the default adjudicator,
//! always present in the ladder, and `NullEnforcer` is what an observe-only
//! tier composes with.
//!
//! These are the suite's **producers**, which is what `F1.EV.03`'s last
//! clause needs: [`catalogue_trace`] is an explicit list of every
//! `EventKind`, so adding a variant to the taxonomy without producing it
//! anywhere fails that check.

use core::time::Duration;

use aisme_ebpf_common::{EventKind, RawEvent, Verdict};

use crate::adjudicate::{
    AdjudicationChannel, Adjudicator, BoxFuture, Escalation, GrantCeiling, Warning,
};
use crate::capability::CapabilitySet;
use crate::enforce::{EnforcementTier, Enforcer, EscalationId, SuspendScope, SuspendToken};
use crate::error::{Error, Result};
use crate::policy::{CompiledPolicy, PolicyGeneration};
use crate::sensor::{EventBatch, EventSink, Sensor, SensorConfig, SensorHealth};

/// A sensor that replays a recorded trace. No kernel, no threads, no clock:
/// `poll` hands out the next events and stops when the trace runs out.
#[derive(Clone, Debug)]
pub struct MockSensor {
    trace: Vec<RawEvent>,
    next: usize,
    started: bool,
    capabilities: CapabilitySet,
    health: SensorHealth,
}

impl MockSensor {
    /// Replay `trace`.
    #[must_use]
    pub fn new(trace: Vec<RawEvent>) -> MockSensor {
        MockSensor {
            trace,
            next: 0,
            started: false,
            capabilities: CapabilitySet::NONE,
            health: SensorHealth::Healthy,
        }
    }

    /// Replay a trace carrying one event of every `EventKind`
    /// ([`catalogue_trace`]).
    #[must_use]
    pub fn with_every_kind() -> MockSensor {
        MockSensor::new(catalogue_trace())
    }

    /// Report these capabilities instead of none.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilitySet) -> MockSensor {
        self.capabilities = capabilities;
        self
    }

    /// Report this health — for the tests of the degradation state machine.
    #[must_use]
    pub fn with_health(mut self, health: SensorHealth) -> MockSensor {
        self.health = health;
        self
    }

    /// Events not yet handed out.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.trace.len() - self.next
    }
}

impl Sensor for MockSensor {
    fn start(&mut self, _cfg: &SensorConfig) -> Result<()> {
        self.started = true;
        Ok(())
    }

    fn poll(&mut self, out: &mut EventBatch, _budget: Duration) -> Result<usize> {
        if !self.started {
            return Err(Error::new(
                crate::error::ErrorKind::Invalid,
                "MockSensor::poll before start",
            ));
        }
        if let SensorHealth::Detached { reason } = &self.health {
            return Err(Error::new(
                crate::error::ErrorKind::Detached,
                reason.clone(),
            ));
        }
        let mut added = 0;
        while self.next < self.trace.len() && out.push(self.trace[self.next]).is_ok() {
            self.next += 1;
            added += 1;
        }
        Ok(added)
    }

    fn capabilities(&self) -> CapabilitySet {
        self.capabilities
    }

    fn health(&self) -> SensorHealth {
        self.health.clone()
    }

    fn stop(&mut self) -> Result<()> {
        self.started = false;
        Ok(())
    }
}

/// An enforcer that renders nothing effective and says so: tier `Observe`.
/// It still takes policy, so the composition and the generation counter are
/// exercised without a platform.
#[derive(Clone, Debug, Default)]
pub struct NullEnforcer {
    generation: PolicyGeneration,
    responded: Vec<(EscalationId, Verdict)>,
    suspensions: u64,
    live: Vec<SuspendToken>,
}

impl NullEnforcer {
    /// A fresh one.
    #[must_use]
    pub fn new() -> NullEnforcer {
        NullEnforcer::default()
    }

    /// The generation last published.
    #[must_use]
    pub const fn generation(&self) -> PolicyGeneration {
        self.generation
    }

    /// Every answer it was given, in order.
    #[must_use]
    pub fn responses(&self) -> &[(EscalationId, Verdict)] {
        &self.responded
    }

    /// Suspensions still outstanding.
    #[must_use]
    pub fn live_suspensions(&self) -> usize {
        self.live.len()
    }
}

impl Enforcer for NullEnforcer {
    fn publish(&mut self, _policy: &CompiledPolicy) -> Result<PolicyGeneration> {
        self.generation = self.generation.next();
        Ok(self.generation)
    }

    fn respond(&mut self, id: EscalationId, v: Verdict) -> Result<()> {
        // Idempotent, as the trait requires: the same id answered twice is
        // recorded once.
        if !self.responded.iter().any(|(seen, _)| *seen == id) {
            self.responded.push((id, v));
        }
        Ok(())
    }

    fn suspend(&mut self, _scope: SuspendScope) -> Result<SuspendToken> {
        self.suspensions += 1;
        let token = SuspendToken(self.suspensions);
        self.live.push(token);
        Ok(token)
    }

    fn resume(&mut self, tok: SuspendToken) -> Result<()> {
        match self.live.iter().position(|t| *t == tok) {
            Some(i) => {
                self.live.remove(i);
                Ok(())
            }
            None => Err(Error::new(
                crate::error::ErrorKind::Invalid,
                format!("no live suspension {tok:?}"),
            )),
        }
    }

    fn tier(&self) -> EnforcementTier {
        EnforcementTier::Observe
    }
}

/// The adjudicator that is always present: it asks no one and applies the
/// session default at once (§2.20.5's zero-budget row). Its ceiling is the
/// lowest, because it grants nothing a human did not already write.
#[derive(Clone, Debug)]
pub struct PolicyAdjudicator {
    default_verdict: Verdict,
    asked: u64,
    warned: u64,
}

impl PolicyAdjudicator {
    /// Answer escalations with `default_verdict` — the session default for
    /// the group, which the composition supplies.
    #[must_use]
    pub fn new(default_verdict: Verdict) -> PolicyAdjudicator {
        PolicyAdjudicator {
            default_verdict,
            asked: 0,
            warned: 0,
        }
    }

    /// How many questions it answered.
    #[must_use]
    pub const fn asked(&self) -> u64 {
        self.asked
    }

    /// How many warnings it took.
    #[must_use]
    pub const fn warned(&self) -> u64 {
        self.warned
    }
}

impl Default for PolicyAdjudicator {
    /// `deny`: the escalate class's timeout default (§2.20.5), so a
    /// composition that forgets to configure it fails closed.
    fn default() -> PolicyAdjudicator {
        PolicyAdjudicator::new(Verdict::Deny)
    }
}

impl Adjudicator for PolicyAdjudicator {
    fn channel(&self) -> AdjudicationChannel {
        AdjudicationChannel::Policy
    }

    fn budget(&self) -> Duration {
        AdjudicationChannel::Policy.budget(false)
    }

    fn notify(&mut self, _w: &Warning) {
        self.warned += 1;
    }

    fn ask(&mut self, _req: &Escalation) -> BoxFuture<'_, Verdict> {
        self.asked += 1;
        let verdict = self.default_verdict;
        Box::pin(async move { verdict })
    }

    fn max_grant(&self) -> GrantCeiling {
        GrantCeiling::POLICY
    }
}

/// A sink that keeps what it was given, for the tests that read it back.
#[derive(Clone, Debug, Default)]
pub struct MemorySink {
    events: Vec<RawEvent>,
}

impl MemorySink {
    /// A fresh one.
    #[must_use]
    pub fn new() -> MemorySink {
        MemorySink::default()
    }

    /// What it holds.
    #[must_use]
    pub fn events(&self) -> &[RawEvent] {
        &self.events
    }
}

impl EventSink for MemorySink {
    fn append(&mut self, batch: &EventBatch) -> Result<()> {
        self.events.extend_from_slice(batch.as_slice());
        Ok(())
    }
}

/// Every kind, written out — the list `F1.EV.03`'s producer-coverage check
/// compares against `EventKind::ALL`.
///
/// Deliberately **not** built by iterating `EventKind::ALL`: a check that
/// generates its own expectation can never fail. Adding a variant to the
/// taxonomy without producing it here fails
/// `every_kind_is_produced_by_the_suite`, which is exactly the question the
/// plan asks — dead weight, or a missing producer?
pub const CATALOGUE: [EventKind; 55] = [
    EventKind::SessionStart,
    EventKind::SessionEnd,
    EventKind::CapabilityChange,
    EventKind::CoverageGap,
    EventKind::DropNotice,
    EventKind::PolicyGeneration,
    EventKind::DegradedEnter,
    EventKind::DegradedLeave,
    EventKind::ProcFork,
    EventKind::ProcExec,
    EventKind::ProcExit,
    EventKind::ProcSetuid,
    EventKind::ProcCgroupMove,
    EventKind::FileOpen,
    EventKind::FileWrite,
    EventKind::FileUnlink,
    EventKind::FileRename,
    EventKind::FileTruncate,
    EventKind::FileChmod,
    EventKind::FileLink,
    EventKind::FileMount,
    EventKind::SockConnect,
    EventKind::SockAccept,
    EventKind::SockSend,
    EventKind::SockClose,
    EventKind::DnsQuery,
    EventKind::FlowOpen,
    EventKind::FlowClose,
    EventKind::MemfdCreate,
    EventKind::ExecveAt,
    EventKind::PreloadEnv,
    EventKind::PtraceAttach,
    EventKind::ProcessVmRw,
    EventKind::MapsRead,
    EventKind::BpfCall,
    EventKind::PerfEventOpen,
    EventKind::SelfObservation,
    EventKind::Prompt,
    EventKind::ChainOfThought,
    EventKind::ToolCall,
    EventKind::ToolResult,
    EventKind::ToolManifest,
    EventKind::InferenceTurn,
    EventKind::VerdictIssued,
    EventKind::EscalationRaised,
    EventKind::EscalationResolved,
    EventKind::GrantCreated,
    EventKind::GrantExpired,
    EventKind::GrantRevoked,
    EventKind::SuppressionHit,
    EventKind::ScopeWidenAttempt,
    EventKind::FindingRaised,
    EventKind::SessionRiskChanged,
    EventKind::MerkleBlockClosed,
    EventKind::RootAnchored,
];

/// One event of every kind in [`CATALOGUE`], sequenced and timestamped so a
/// consumer sees a well-formed stream.
#[must_use]
pub fn catalogue_trace() -> Vec<RawEvent> {
    CATALOGUE
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            let mut event = RawEvent::ZERO;
            event.kind = (*kind).into();
            event.seq = i as u64;
            event.ts_ns = 1_000 + (i as u64) * 1_000;
            event.session_id = 1;
            event.pid = 100;
            event.tgid = 100;
            event
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mock_sensor_replays_its_trace_in_batches_and_then_stops() {
        let mut sensor = MockSensor::with_every_kind();
        let mut batch = EventBatch::with_capacity(20);
        assert!(
            sensor.poll(&mut batch, Duration::ZERO).is_err(),
            "poll before start"
        );
        sensor.start(&SensorConfig::default()).unwrap();
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 20);
        assert_eq!(sensor.remaining(), 35);
        batch.clear();
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 20);
        batch.clear();
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 15);
        batch.clear();
        assert_eq!(
            sensor.poll(&mut batch, Duration::ZERO).unwrap(),
            0,
            "trace exhausted"
        );
        assert_eq!(sensor.capabilities(), CapabilitySet::NONE);
        sensor.stop().unwrap();
    }

    #[test]
    fn a_detached_mock_reports_detached_rather_than_an_empty_poll() {
        // An empty poll from a detached sensor is an absence read as "no
        // events", which is how a protection outage goes unnoticed.
        let mut sensor = MockSensor::with_every_kind().with_health(SensorHealth::Detached {
            reason: "probe removed".into(),
        });
        sensor.start(&SensorConfig::default()).unwrap();
        let mut batch = EventBatch::with_capacity(4);
        let err = sensor.poll(&mut batch, Duration::ZERO).unwrap_err();
        assert_eq!(err.kind, crate::error::ErrorKind::Detached);
        assert!(batch.is_empty());
    }

    #[test]
    fn the_null_enforcer_counts_generations_and_is_idempotent_on_respond() {
        let mut enforcer = NullEnforcer::new();
        let policy = CompiledPolicy {
            settings: crate::policy::Settings::DEFAULT,
            rules: Vec::new(),
            grants: Vec::new(),
            suppressions: Vec::new(),
        };
        assert_eq!(enforcer.publish(&policy).unwrap(), PolicyGeneration(1));
        assert_eq!(enforcer.publish(&policy).unwrap(), PolicyGeneration(2));
        enforcer.respond(EscalationId(7), Verdict::Deny).unwrap();
        enforcer.respond(EscalationId(7), Verdict::Allow).unwrap();
        assert_eq!(enforcer.responses(), [(EscalationId(7), Verdict::Deny)]);
        let token = enforcer.suspend(SuspendScope::Process { tgid: 3 }).unwrap();
        assert_eq!(enforcer.live_suspensions(), 1);
        enforcer.resume(token).unwrap();
        assert_eq!(enforcer.live_suspensions(), 0);
        assert!(enforcer.resume(token).is_err(), "resumed twice");
        assert_eq!(enforcer.tier(), EnforcementTier::Observe);
    }

    #[test]
    fn the_policy_adjudicator_answers_at_once_and_grants_nothing() {
        let mut adjudicator = PolicyAdjudicator::default();
        assert_eq!(adjudicator.channel(), AdjudicationChannel::Policy);
        assert_eq!(adjudicator.budget(), Duration::ZERO);
        assert_eq!(
            AdjudicationChannel::Policy.on_timeout(),
            crate::adjudicate::TimeoutDefault::SessionDefault
        );
        assert!(!adjudicator
            .max_grant()
            .permits_allow(crate::ontology::Severity::Medium));
        let escalation = Escalation {
            id: EscalationId(1),
            session_id: crate::ontology::SessionId(1),
            group: crate::ontology::PermissionGroup::Credentials,
            rule_id: "credentials-ask".into(),
            severity: crate::ontology::Severity::High,
            summary: "read ~/.aws/credentials".into(),
            declared_intent: None,
        };
        let verdict = futures_lite_block_on(adjudicator.ask(&escalation));
        assert_eq!(verdict, Verdict::Deny, "the default fails closed");
        adjudicator.notify(&Warning {
            session_id: crate::ontology::SessionId(1),
            rule_id: "persistence-config".into(),
            severity: crate::ontology::Severity::Low,
            summary: "wrote .git/hooks/pre-commit".into(),
        });
        assert_eq!((adjudicator.asked(), adjudicator.warned()), (1, 1));
        let mut allowing = PolicyAdjudicator::new(Verdict::Allow);
        assert_eq!(
            futures_lite_block_on(allowing.ask(&escalation)),
            Verdict::Allow
        );
    }

    /// Drive a future to completion without a runtime: `aisme-core` has
    /// none, and these futures never pend.
    fn futures_lite_block_on<T>(mut future: BoxFuture<'_, T>) -> T {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(|_| RawWaker::new(&(), &VTABLE), |_| {}, |_| {}, |_| {});
        // SAFETY: the vtable's clone returns an equivalent waker and the
        // other operations are no-ops, so every requirement of `RawWaker` is
        // met by construction.
        let waker = unsafe { Waker::from_raw(RawWaker::new(&(), &VTABLE)) };
        match future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("a PolicyAdjudicator future never pends"),
        }
    }

    #[test]
    fn the_memory_sink_keeps_what_it_is_given() {
        let mut sensor = MockSensor::with_every_kind();
        sensor.start(&SensorConfig::default()).unwrap();
        let mut batch = EventBatch::with_capacity(64);
        sensor.poll(&mut batch, Duration::ZERO).unwrap();
        let mut sink = MemorySink::new();
        sink.append(&batch).unwrap();
        assert_eq!(sink.events().len(), CATALOGUE.len());
        assert_eq!(sink.events()[0].kind.decode(), Ok(EventKind::SessionStart));
    }
}
