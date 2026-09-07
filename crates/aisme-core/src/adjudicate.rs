// SPDX-License-Identifier: Apache-2.0
//! `Adjudicator`: anything that can answer "allow or deny?" — human or
//! machine (plan §3.2; budgets §2.20.5; ceilings `I-06`).

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use aisme_ebpf_common::Verdict;

use crate::enforce::EscalationId;
use crate::ontology::{PermissionGroup, SessionId, Severity};

/// A boxed future, so a trait may be async without naming a runtime —
/// `aisme-core` has none (§3.1).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How the question reaches whoever answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdjudicationChannel {
    /// A desktop modal.
    Modal,
    /// A toast / freedesktop / UN notification.
    Notification,
    /// The terminal of `aisme run`.
    Terminal,
    /// A paired mobile device.
    Remote,
    /// The policy itself: no human, no wait.
    Policy,
}

impl AdjudicationChannel {
    /// §2.20.5's freeze budget for this channel: local 10 s when the UI is
    /// focused, 20 s when it is not; remote 3 s; policy 0 s. Never exceeds
    /// the T2 hard timeout.
    #[must_use]
    pub const fn budget(self, ui_focused: bool) -> Duration {
        match self {
            AdjudicationChannel::Modal
            | AdjudicationChannel::Notification
            | AdjudicationChannel::Terminal => {
                if ui_focused {
                    Duration::from_secs(10)
                } else {
                    Duration::from_secs(20)
                }
            }
            AdjudicationChannel::Remote => Duration::from_secs(3),
            AdjudicationChannel::Policy => Duration::ZERO,
        }
    }

    /// What a timed-out question defaults to on this channel: the session
    /// default policy locally, `deny` remotely (the process is not held
    /// waiting for a phone), the static policy at once with no adjudicator.
    #[must_use]
    pub const fn on_timeout(self) -> TimeoutDefault {
        match self {
            AdjudicationChannel::Remote => TimeoutDefault::Deny,
            _ => TimeoutDefault::SessionDefault,
        }
    }
}

/// What applies when the budget passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutDefault {
    /// The session's default verdict for the group.
    SessionDefault,
    /// Deny, and release the freeze; the answer arrives post hoc.
    Deny,
}

/// The most an adjudicator may grant (`I-06`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantCeiling {
    /// Whether it may allow a `CRITICAL`-class operation at all. Remote
    /// adjudicators never may.
    pub may_allow_critical: bool,
    /// The highest severity it may answer `allow` to.
    pub max_allow_severity: Severity,
}

impl GrantCeiling {
    /// A local human: everything a prompt may grant (never `I-05`, which no
    /// prompt reaches).
    pub const LOCAL: GrantCeiling = GrantCeiling {
        may_allow_critical: true,
        max_allow_severity: Severity::Critical,
    };
    /// A paired device: `deny` freely, `allow` signed and never `CRITICAL`.
    pub const REMOTE: GrantCeiling = GrantCeiling {
        may_allow_critical: false,
        max_allow_severity: Severity::High,
    };
    /// The policy itself answers only what the policy already says.
    pub const POLICY: GrantCeiling = GrantCeiling {
        may_allow_critical: false,
        max_allow_severity: Severity::Low,
    };

    /// Whether `allow` is within this ceiling for a question of `severity`.
    #[must_use]
    pub fn permits_allow(self, severity: Severity) -> bool {
        severity <= self.max_allow_severity
            && (severity != Severity::Critical || self.may_allow_critical)
    }
}

/// A question for an adjudicator.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Escalation {
    /// The escalation being answered.
    pub id: EscalationId,
    /// The session.
    pub session_id: SessionId,
    /// The group.
    pub group: PermissionGroup,
    /// The rule that escalated (`decided_by`).
    pub rule_id: String,
    /// Deterministic policy severity — never the Observer's opinion alone.
    pub severity: Severity,
    /// What the prompt shows: the action, in words.
    pub summary: String,
    /// The agent's own declared intent, when captured.
    pub declared_intent: Option<String>,
}

/// A non-blocking notice for `Verdict::Warn`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The session.
    pub session_id: SessionId,
    /// The rule (`decided_by`).
    pub rule_id: String,
    /// Severity.
    pub severity: Severity,
    /// What happened, in words.
    pub summary: String,
}

/// Anything that can answer "allow or deny?" — human or machine.
pub trait Adjudicator: Send {
    /// Which channel this is.
    fn channel(&self) -> AdjudicationChannel;

    /// Channel-aware budget (§2.20.5). Never exceeds the T2 hard timeout.
    fn budget(&self) -> Duration;

    /// Non-blocking notice for `Verdict::Warn`. Default: no-op.
    fn notify(&mut self, _w: &Warning) {}

    /// MUST resolve within budget or yield the channel's timeout default
    /// (§2.20.5; `deny` for the escalate class).
    fn ask(&mut self, req: &Escalation) -> BoxFuture<'_, Verdict>;

    /// Capability cap: a remote adjudicator may never allow `CRITICAL`
    /// (`I-06`).
    fn max_grant(&self) -> GrantCeiling;
}

/// Where policy text comes from.
pub trait PolicySource: Send {
    /// The current policy document.
    ///
    /// # Errors
    ///
    /// `Failed` with the detail; the engine keeps the last good generation.
    fn load(&mut self) -> crate::error::Result<PolicyDocument>;
}

/// Policy text and where it came from. The compiler parses it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDocument {
    /// The AISME-PL source.
    pub source: String,
    /// Where it was read from, for diagnostics.
    pub origin: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_the_2_20_5_table() {
        assert_eq!(
            AdjudicationChannel::Modal.budget(true),
            Duration::from_secs(10)
        );
        assert_eq!(
            AdjudicationChannel::Terminal.budget(false),
            Duration::from_secs(20)
        );
        assert_eq!(
            AdjudicationChannel::Remote.budget(true),
            Duration::from_secs(3)
        );
        assert_eq!(AdjudicationChannel::Policy.budget(false), Duration::ZERO);
        assert_eq!(
            AdjudicationChannel::Remote.on_timeout(),
            TimeoutDefault::Deny
        );
        assert_eq!(
            AdjudicationChannel::Modal.on_timeout(),
            TimeoutDefault::SessionDefault
        );
    }

    #[test]
    fn a_remote_ceiling_never_allows_critical() {
        assert!(GrantCeiling::LOCAL.permits_allow(Severity::Critical));
        assert!(!GrantCeiling::REMOTE.permits_allow(Severity::Critical));
        assert!(GrantCeiling::REMOTE.permits_allow(Severity::High));
        assert!(!GrantCeiling::POLICY.permits_allow(Severity::Medium));
        assert!(GrantCeiling::POLICY.permits_allow(Severity::Low));
    }

    fn object_safe(_: &mut dyn Adjudicator, _: &mut dyn PolicySource) {}

    #[test]
    fn the_trait_is_object_safe() {
        let _: fn(&mut dyn Adjudicator, &mut dyn PolicySource) = object_safe;
    }
}
