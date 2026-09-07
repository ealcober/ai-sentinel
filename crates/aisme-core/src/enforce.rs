// SPDX-License-Identifier: Apache-2.0
//! `Enforcer`: anything that can render a decision effective (plan §3.2).

use crate::error::Result;
use crate::ontology::SessionId;
use crate::policy::{CompiledPolicy, PolicyGeneration};
use aisme_ebpf_common::Verdict;

/// An escalation raised by an enforcer, answered through `respond`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EscalationId(pub u64);

/// What to hold pending slow adjudication (T2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SuspendScope {
    /// The whole session cgroup.
    Session(SessionId),
    /// One thread group.
    Process {
        /// The thread group.
        tgid: u32,
    },
}

/// A suspension in effect, to be resumed exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SuspendToken(pub u64);

/// How much an enforcer can do on this platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EnforcementTier {
    /// Records; renders nothing effective.
    Observe,
    /// Some verdicts in kernel, the rest escalate (L2, L2-).
    Partial,
    /// Every verdict in kernel (L3).
    Full,
}

/// Anything that can render a decision effective.
pub trait Enforcer: Send {
    /// Atomically publish compiled policy to wherever decisions are made;
    /// readers never see a torn policy (§3.6).
    ///
    /// # Errors
    ///
    /// A rule this backend cannot express is refused here, named (`F1.PL.08`).
    fn publish(&mut self, policy: &CompiledPolicy) -> Result<PolicyGeneration>;

    /// Answer an escalation this enforcer raised. Idempotent.
    ///
    /// # Errors
    ///
    /// `Invalid` for an id it does not hold.
    fn respond(&mut self, id: EscalationId, v: Verdict) -> Result<()>;

    /// Halt a scope pending slow adjudication (T2). Bounded, cancellable.
    ///
    /// # Errors
    ///
    /// `Unsupported` where the platform has no freezer; the ladder then
    /// answers within T1 or applies the default.
    fn suspend(&mut self, scope: SuspendScope) -> Result<SuspendToken>;

    /// Release a suspension.
    ///
    /// # Errors
    ///
    /// `Invalid` for a token already resumed.
    fn resume(&mut self, tok: SuspendToken) -> Result<()>;

    /// What this enforcer can do here.
    fn tier(&self) -> EnforcementTier;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_safe(_: &mut dyn Enforcer) {}

    #[test]
    fn tiers_are_ordered_and_the_trait_is_object_safe() {
        assert!(EnforcementTier::Observe < EnforcementTier::Partial);
        assert!(EnforcementTier::Partial < EnforcementTier::Full);
        let _: fn(&mut dyn Enforcer) = object_safe;
    }
}
