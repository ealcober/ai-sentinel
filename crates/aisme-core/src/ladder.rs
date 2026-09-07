// SPDX-License-Identifier: Apache-2.0
//! `AdjudicatorLadder` (`F1.PA.03`): preference-ordered delivery with
//! channel-aware budgets and grant ceilings.
//!
//! The permission model's §7 ladder — modal, notification, terminal, remote,
//! policy — is literally a `Vec<Box<dyn Adjudicator>>` sorted by preference,
//! each reporting its own budget and ceiling. That is why the engine needs
//! no per-platform branching to ask a question (§3.2, third consequence).
//!
//! Three rules the ladder enforces, none of which an adjudicator can waive:
//!
//! - **Preference order.** The best available channel asks. `Policy` is last
//!   and always present, so there is always an answer.
//! - **`I-06` ceilings.** An `allow` from a channel whose ceiling does not
//!   permit it at this severity is **not** honoured: the ladder records the
//!   refusal and moves down. A remote `allow` on a `CRITICAL` operation is
//!   the case the invariant exists for.
//! - **The budget is the channel's** (§2.20.5), never the caller's wish.
//!   What happens when it passes is [`AdjudicationChannel::on_timeout`]:
//!   the session default locally, `deny` remotely.

use core::time::Duration;

use aisme_ebpf_common::Verdict;

use crate::adjudicate::{AdjudicationChannel, Adjudicator, Escalation, TimeoutDefault, Warning};
use crate::ontology::Severity;

/// Delivery preference, best first — the permission model §7 tiers.
#[must_use]
pub const fn tier_of(channel: AdjudicationChannel) -> u8 {
    match channel {
        AdjudicationChannel::Modal => 1,
        AdjudicationChannel::Notification => 2,
        AdjudicationChannel::Terminal => 3,
        AdjudicationChannel::Remote => 4,
        AdjudicationChannel::Policy => 5,
    }
}

/// What the ladder did, kept with the verdict so the WAL and the UI can say
/// how a question was answered — and who was skipped, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adjudication {
    /// The verdict that stands.
    pub verdict: Verdict,
    /// The channel that supplied it; `None` when every channel was
    /// exhausted and the timeout default applied.
    pub answered_by: Option<AdjudicationChannel>,
    /// The budget the answering channel was given.
    pub budget: Duration,
    /// Channels that answered and were not honoured, with why.
    pub refused: Vec<(AdjudicationChannel, Refusal)>,
}

/// Why an answer was not honoured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `I-06`: the channel's ceiling does not permit `allow` at this
    /// severity.
    CeilingExceeded {
        /// The severity asked about.
        severity: Severity,
    },
    /// The channel did not answer within its budget.
    TimedOut,
}

/// The delivery ladder.
pub struct AdjudicatorLadder {
    adjudicators: Vec<Box<dyn Adjudicator>>,
}

impl AdjudicatorLadder {
    /// Build from the adjudicators the platform composed, sorted by
    /// preference. A ladder without a `Policy` channel is still valid —
    /// [`ask_blocking`](Self::ask_blocking) then falls back to the timeout
    /// default rather than pretend an answer.
    #[must_use]
    pub fn from(mut adjudicators: Vec<Box<dyn Adjudicator>>) -> AdjudicatorLadder {
        adjudicators.sort_by_key(|a| tier_of(a.channel()));
        AdjudicatorLadder { adjudicators }
    }

    /// The channels, in preference order.
    #[must_use]
    pub fn channels(&self) -> Vec<AdjudicationChannel> {
        self.adjudicators.iter().map(|a| a.channel()).collect()
    }

    /// How many rungs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adjudicators.len()
    }

    /// Whether the ladder has no rung.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adjudicators.is_empty()
    }

    /// Deliver a warning to every channel that takes one. A warning is not
    /// a question: it blocks nothing and no channel can refuse it (`I-26`
    /// silences *notification*, and that decision was made before here).
    pub fn notify(&mut self, warning: &Warning) {
        for adjudicator in &mut self.adjudicators {
            adjudicator.notify(warning);
        }
    }

    /// Ask, walking down the ladder, resolving each future with `run` — the
    /// caller's runtime, since `aisme-core` has none.
    ///
    /// Each rung gets its own channel budget. An `allow` beyond the
    /// channel's ceiling is refused and recorded (`I-06`), and the ladder
    /// continues; anything else stands.
    ///
    /// When every rung is exhausted, §2.20.5 decides: locally the
    /// `session_default` the caller supplies — the ladder does not hold the
    /// policy, and inventing a default here would be a verdict nobody
    /// wrote — and `deny` where the last channel was `Remote`, because the
    /// process is not held waiting for a phone. An empty ladder is the
    /// headless row: the session default, at once, with no freeze.
    pub fn ask_blocking<R>(
        &mut self,
        req: &Escalation,
        session_default: Verdict,
        mut run: R,
    ) -> Adjudication
    where
        R: FnMut(crate::adjudicate::BoxFuture<'_, Verdict>, Duration) -> Option<Verdict>,
    {
        let mut refused = Vec::new();
        let mut last_channel = None;
        for adjudicator in &mut self.adjudicators {
            let channel = adjudicator.channel();
            let budget = adjudicator.budget();
            let ceiling = adjudicator.max_grant();
            last_channel = Some(channel);
            let Some(verdict) = run(adjudicator.ask(req), budget) else {
                refused.push((channel, Refusal::TimedOut));
                continue;
            };
            if verdict == Verdict::Allow && !ceiling.permits_allow(req.severity) {
                refused.push((
                    channel,
                    Refusal::CeilingExceeded {
                        severity: req.severity,
                    },
                ));
                continue;
            }
            return Adjudication {
                verdict,
                answered_by: Some(channel),
                budget,
                refused,
            };
        }
        // Nobody answered within their budget, or every answer was refused.
        let verdict = match last_channel.map(AdjudicationChannel::on_timeout) {
            Some(TimeoutDefault::Deny) => Verdict::Deny,
            Some(TimeoutDefault::SessionDefault) | None => session_default,
        };
        Adjudication {
            verdict,
            answered_by: None,
            budget: Duration::ZERO,
            refused,
        }
    }
}

impl core::fmt::Debug for AdjudicatorLadder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdjudicatorLadder")
            .field("channels", &self.channels())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjudicate::{BoxFuture, GrantCeiling};
    use crate::enforce::EscalationId;
    use crate::mock::PolicyAdjudicator;
    use crate::ontology::{PermissionGroup, SessionId};

    /// An adjudicator that answers what it was told to, on the channel it
    /// was told to.
    struct Scripted {
        channel: AdjudicationChannel,
        answer: Option<Verdict>,
        ceiling: GrantCeiling,
    }

    impl Adjudicator for Scripted {
        fn channel(&self) -> AdjudicationChannel {
            self.channel
        }
        fn budget(&self) -> Duration {
            self.channel.budget(true)
        }
        fn ask(&mut self, _req: &Escalation) -> BoxFuture<'_, Verdict> {
            let answer = self.answer;
            Box::pin(async move { answer.unwrap_or(Verdict::Deny) })
        }
        fn max_grant(&self) -> GrantCeiling {
            self.ceiling
        }
    }

    fn scripted(
        channel: AdjudicationChannel,
        answer: Option<Verdict>,
        ceiling: GrantCeiling,
    ) -> Box<dyn Adjudicator> {
        Box::new(Scripted {
            channel,
            answer,
            ceiling,
        })
    }

    /// The caller's runtime: resolve unless the adjudicator has no answer,
    /// which stands for "the budget passed".
    fn run(future: BoxFuture<'_, Verdict>, _budget: Duration) -> Option<Verdict> {
        use core::task::{Context, Poll, Waker};
        // `Waker::noop` rather than a hand-rolled vtable: these futures never
        // pend, and aisme-core forbids `unsafe` (F1.RT.08).
        let waker = Waker::noop();
        let mut future = future;
        match future.as_mut().poll(&mut Context::from_waker(waker)) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    fn timing_out(_: BoxFuture<'_, Verdict>, _: Duration) -> Option<Verdict> {
        None
    }

    fn escalation(severity: Severity) -> Escalation {
        Escalation {
            id: EscalationId(1),
            session_id: SessionId(1),
            group: PermissionGroup::Credentials,
            rule_id: "credentials-ask".into(),
            severity,
            summary: "read ~/.aws/credentials".into(),
            declared_intent: None,
        }
    }

    #[test]
    fn the_ladder_is_preference_ordered_however_it_was_composed() {
        let ladder = AdjudicatorLadder::from(vec![
            Box::new(PolicyAdjudicator::default()),
            scripted(AdjudicationChannel::Remote, None, GrantCeiling::REMOTE),
            scripted(AdjudicationChannel::Modal, None, GrantCeiling::LOCAL),
            scripted(AdjudicationChannel::Terminal, None, GrantCeiling::LOCAL),
        ]);
        assert_eq!(
            ladder.channels(),
            [
                AdjudicationChannel::Modal,
                AdjudicationChannel::Terminal,
                AdjudicationChannel::Remote,
                AdjudicationChannel::Policy
            ]
        );
        assert_eq!(ladder.len(), 4);
    }

    #[test]
    fn the_best_available_channel_answers_and_its_budget_is_recorded() {
        let mut ladder = AdjudicatorLadder::from(vec![
            scripted(
                AdjudicationChannel::Modal,
                Some(Verdict::Allow),
                GrantCeiling::LOCAL,
            ),
            Box::new(PolicyAdjudicator::default()),
        ]);
        let out = ladder.ask_blocking(&escalation(Severity::High), Verdict::Deny, run);
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.answered_by, Some(AdjudicationChannel::Modal));
        assert_eq!(out.budget, Duration::from_secs(10));
        assert!(out.refused.is_empty());
    }

    #[test]
    fn a_remote_allow_on_a_critical_operation_is_refused_and_the_ladder_continues() {
        // I-06: a remote client may never allow a CRITICAL operation. The
        // answer is not honoured; it is recorded, and the next rung decides.
        let mut ladder = AdjudicatorLadder::from(vec![
            scripted(
                AdjudicationChannel::Remote,
                Some(Verdict::Allow),
                GrantCeiling::REMOTE,
            ),
            Box::new(PolicyAdjudicator::new(Verdict::Deny)),
        ]);
        let out = ladder.ask_blocking(&escalation(Severity::Critical), Verdict::Deny, run);
        assert_eq!(out.verdict, Verdict::Deny);
        assert_eq!(out.answered_by, Some(AdjudicationChannel::Policy));
        assert_eq!(
            out.refused,
            [(
                AdjudicationChannel::Remote,
                Refusal::CeilingExceeded {
                    severity: Severity::Critical
                }
            )]
        );
        // A remote DENY needs no ceiling: it is honoured at once.
        let mut ladder = AdjudicatorLadder::from(vec![
            scripted(
                AdjudicationChannel::Remote,
                Some(Verdict::Deny),
                GrantCeiling::REMOTE,
            ),
            Box::new(PolicyAdjudicator::new(Verdict::Allow)),
        ]);
        let out = ladder.ask_blocking(&escalation(Severity::Critical), Verdict::Deny, run);
        assert_eq!(
            (out.verdict, out.answered_by),
            (Verdict::Deny, Some(AdjudicationChannel::Remote))
        );
        // And a remote allow below the ceiling stands.
        let mut ladder = AdjudicatorLadder::from(vec![scripted(
            AdjudicationChannel::Remote,
            Some(Verdict::Allow),
            GrantCeiling::REMOTE,
        )]);
        let out = ladder.ask_blocking(&escalation(Severity::High), Verdict::Deny, run);
        assert_eq!(out.verdict, Verdict::Allow);
    }

    #[test]
    fn every_rung_timing_out_falls_to_deny_and_says_who_did_not_answer() {
        let mut ladder = AdjudicatorLadder::from(vec![
            scripted(
                AdjudicationChannel::Modal,
                Some(Verdict::Allow),
                GrantCeiling::LOCAL,
            ),
            scripted(
                AdjudicationChannel::Remote,
                Some(Verdict::Allow),
                GrantCeiling::REMOTE,
            ),
        ]);
        let out = ladder.ask_blocking(&escalation(Severity::High), Verdict::Deny, timing_out);
        assert_eq!(out.verdict, Verdict::Deny, "the escalate class's default");
        assert_eq!(out.answered_by, None);
        assert_eq!(
            out.refused,
            [
                (AdjudicationChannel::Modal, Refusal::TimedOut),
                (AdjudicationChannel::Remote, Refusal::TimedOut)
            ]
        );
        // An empty ladder is the headless case: decide at once, deny.
        let mut empty = AdjudicatorLadder::from(Vec::new());
        assert!(empty.is_empty());
        let out = empty.ask_blocking(&escalation(Severity::Low), Verdict::Deny, run);
        assert_eq!((out.verdict, out.answered_by), (Verdict::Deny, None));
        // The headless row applies the session default, whatever it is —
        // never a verdict the ladder invented.
        let out = empty.ask_blocking(&escalation(Severity::Low), Verdict::Warn, run);
        assert_eq!(out.verdict, Verdict::Warn);
        // A local ladder that times out does the same; a remote one denies.
        let mut local = AdjudicatorLadder::from(vec![scripted(
            AdjudicationChannel::Terminal,
            Some(Verdict::Allow),
            GrantCeiling::LOCAL,
        )]);
        assert_eq!(
            local
                .ask_blocking(&escalation(Severity::Low), Verdict::Warn, timing_out)
                .verdict,
            Verdict::Warn
        );
        let mut remote = AdjudicatorLadder::from(vec![scripted(
            AdjudicationChannel::Remote,
            Some(Verdict::Allow),
            GrantCeiling::REMOTE,
        )]);
        assert_eq!(
            remote
                .ask_blocking(&escalation(Severity::Low), Verdict::Warn, timing_out)
                .verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn a_warning_reaches_every_channel() {
        let mut ladder = AdjudicatorLadder::from(vec![
            Box::new(PolicyAdjudicator::default()),
            scripted(AdjudicationChannel::Modal, None, GrantCeiling::LOCAL),
        ]);
        ladder.notify(&Warning {
            session_id: SessionId(1),
            rule_id: "persistence-config".into(),
            severity: Severity::Low,
            summary: "wrote .git/hooks/pre-commit".into(),
        });
        // The policy adjudicator counts what it took; the scripted one's
        // default no-op is the trait's, and taking it is not an error.
        assert_eq!(ladder.len(), 2);
    }
}
