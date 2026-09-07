// SPDX-License-Identifier: Apache-2.0
//! The service tier a capability set yields, and the degradation state
//! machine over it (`F1.PA.04`, `F1.PA.05`; Annex D.1, §2.23).
//!
//! The tier is **derived, never configured**: it is a function of what the
//! probes measured, so the banner (`F8.UI.07`), the metric
//! `aisme.capability.level` and the enforcement composition cannot disagree
//! about what the machine can do (`I-16`). Every transition is announced
//! (`I-19`): a tier that changed silently is a protection change nobody saw.

use crate::capability::CapabilitySet;

/// The service tiers of Annex D.1, ordered by what they can enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// Observation only: no in-kernel deny, no escalation trap.
    L1 = 1,
    /// Seccomp-only enforcement: every watched path decision traps
    /// (`seccomp_unotify`) and T2 can freeze.
    L2Minus = 2,
    /// In-kernel file deny (Landlock) **and** in-kernel network deny
    /// (cgroup `sock_addr`), plus the L2- escalation path.
    L2 = 3,
    /// Everything L2 has, plus the BPF-LSM layer.
    L3 = 4,
}

impl Tier {
    /// Every tier, weakest first.
    pub const ALL: [Tier; 4] = [Tier::L1, Tier::L2Minus, Tier::L2, Tier::L3];

    /// The name the UI and the metric use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::L1 => "L1",
            Tier::L2Minus => "L2-",
            Tier::L2 => "L2",
            Tier::L3 => "L3",
        }
    }

    /// `aisme.capability.level`'s ordinal: 0 is `DEGRADED`, so the tiers
    /// start at 1 (§4.4).
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
}

/// The tier this capability set yields, by Annex D.1's rows.
///
/// Each step needs everything the step below it needs. Note what the rows
/// actually say, because it is easy to read the tier off one capability:
/// **BTF is not what separates L1 from L2-** — `seccomp_unotify` and the
/// cgroup v2 freezer are, since without them nothing can trap or hold a
/// decision. BTF and the ring buffer change how *observation* works
/// (`BTFHub` fallback, perf buffer), not what can be enforced.
#[must_use]
pub fn tier_of(caps: &CapabilitySet) -> Tier {
    // L2-: something can trap a decision and something can hold it.
    let can_escalate = caps.seccomp_unotify && caps.cgroup_v2_freeze;
    // L2: in-kernel deny for files and for the network.
    let can_deny_in_kernel = caps.landlock_abi > 0 && caps.cgroup_sock_addr;
    if can_escalate && can_deny_in_kernel && caps.bpf_lsm {
        Tier::L3
    } else if can_escalate && can_deny_in_kernel {
        Tier::L2
    } else if can_escalate {
        Tier::L2Minus
    } else {
        Tier::L1
    }
}

/// What a capability set costs, in the words `I-19` requires: one documented
/// function per missing capability. Empty when nothing is missing at this
/// tier.
#[must_use]
pub fn degradations(caps: &CapabilitySet) -> Vec<&'static str> {
    let mut lost = Vec::new();
    if !caps.seccomp_unotify {
        lost.push("no seccomp_unotify: a decision cannot be trapped in flight; the escalate class applies policy without asking (T1 lost)");
    }
    if !caps.cgroup_v2_freeze {
        lost.push("no cgroup v2 freezer: a scope cannot be held for slow adjudication (T2 lost; timeout-deny instead)");
    }
    if caps.landlock_abi == 0 {
        lost.push("no Landlock: file denies are not in kernel; they arrive one syscall late through seccomp");
    }
    if !caps.cgroup_sock_addr {
        lost.push("no cgroup connect hook: egress denies are not in kernel (Network Slam lost)");
    }
    if !caps.bpf_lsm {
        lost.push("no BPF-LSM: the L3 layer is absent; enforcement is Landlock plus seccomp");
    }
    if !caps.btf {
        lost.push("no BTF: CO-RE needs the BTFHub fallback; kernel struct offsets are not self-describing");
    }
    if !caps.ringbuf {
        lost.push("no BPF ring buffer: events arrive through the perf buffer, with its copy and its ordering");
    }
    if !caps.tpm {
        lost.push("no TPM: forensic blocks are software-signed and external anchoring carries non-repudiation");
    }
    lost
}

/// The engine's declared state: a tier, or `DEGRADED` when something that
/// was working stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Serving at this tier.
    Serving(Tier),
    /// One capability was lost while running: keep serving, announce loudly
    /// (§3.5's degrade row).
    Degraded {
        /// The tier still served.
        tier: Tier,
        /// What was lost, in the words the UI shows.
        lost: String,
    },
}

impl State {
    /// The tier either way — `DEGRADED` is a state, not a tier.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        match self {
            State::Serving(tier) | State::Degraded { tier, .. } => *tier,
        }
    }

    /// `aisme.capability.level`: 0 when degraded, else the tier's ordinal.
    #[must_use]
    pub const fn metric(&self) -> u8 {
        match self {
            State::Serving(tier) => tier.ordinal(),
            State::Degraded { .. } => 0,
        }
    }
}

/// A transition worth announcing. Every one of these is a change in what the
/// product protects, so none of them is silent (`I-16`, `I-19`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// Where it came from.
    pub from: State,
    /// Where it went.
    pub to: State,
    /// The sentence the UI, the log and the SIEM get.
    pub message: String,
}

/// The degradation state machine.
#[derive(Clone, Debug)]
pub struct Degradation {
    state: State,
}

impl Degradation {
    /// Start from what the probes measured.
    #[must_use]
    pub fn starting_at(caps: &CapabilitySet) -> Degradation {
        Degradation {
            state: State::Serving(tier_of(caps)),
        }
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Re-probe: the capability set changed. Returns the transition when the
    /// state changed, and `None` when it did not — nothing is announced
    /// twice.
    pub fn observe(&mut self, caps: &CapabilitySet) -> Option<Transition> {
        self.transition(State::Serving(tier_of(caps)))
    }

    /// Something that was working stopped: enter `DEGRADED`, keeping the
    /// tier, and say what was lost.
    pub fn lose(&mut self, lost: impl Into<String>) -> Option<Transition> {
        self.transition(State::Degraded {
            tier: self.state.tier(),
            lost: lost.into(),
        })
    }

    /// It came back: leave `DEGRADED` at the tier the probes now support.
    pub fn recover(&mut self, caps: &CapabilitySet) -> Option<Transition> {
        self.transition(State::Serving(tier_of(caps)))
    }

    fn transition(&mut self, to: State) -> Option<Transition> {
        if to == self.state {
            return None;
        }
        let from = core::mem::replace(&mut self.state, to.clone());
        Some(Transition {
            message: announce(&from, &to),
            from,
            to,
        })
    }
}

fn announce(from: &State, to: &State) -> String {
    match (from, to) {
        (State::Serving(a), State::Serving(b)) if b < a => format!(
            "capability tier fell from {} to {}: enforcement is weaker than it was, and the banner says so",
            a.as_str(),
            b.as_str()
        ),
        (State::Serving(a), State::Serving(b)) => {
            format!("capability tier rose from {} to {}", a.as_str(), b.as_str())
        }
        (_, State::Degraded { tier, lost }) => format!(
            "DEGRADED at tier {}: {lost} — still serving, and this is not a silent loss",
            tier.as_str()
        ),
        (State::Degraded { tier, .. }, State::Serving(b)) => format!(
            "recovered from DEGRADED at tier {} to {}",
            tier.as_str(),
            b.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A set that reaches `tier`, and no further.
    fn caps_for(tier: Tier) -> CapabilitySet {
        let mut caps = CapabilitySet {
            btf: true,
            ringbuf: true,
            uprobe: true,
            ..CapabilitySet::NONE
        };
        if tier >= Tier::L2Minus {
            caps.seccomp_unotify = true;
            caps.cgroup_v2_freeze = true;
        }
        if tier >= Tier::L2 {
            caps.landlock_abi = 4;
            caps.cgroup_sock_addr = true;
        }
        if tier >= Tier::L3 {
            caps.bpf_lsm = true;
        }
        caps
    }

    #[test]
    fn the_tier_follows_annex_d_and_not_a_single_capability() {
        for tier in Tier::ALL {
            assert_eq!(tier_of(&caps_for(tier)), tier, "{tier:?}");
        }
        // BTF is not what separates L1 from L2-: a kernel with BTF but no
        // way to trap a decision enforces nothing.
        let btf_only = CapabilitySet {
            btf: true,
            ringbuf: true,
            ..CapabilitySet::NONE
        };
        assert_eq!(tier_of(&btf_only), Tier::L1);
        // Landlock without the escalation path is still L1: an in-kernel
        // file deny with nothing to trap the escalate class is not L2.
        let landlock_only = CapabilitySet {
            landlock_abi: 4,
            cgroup_sock_addr: true,
            ..CapabilitySet::NONE
        };
        assert_eq!(tier_of(&landlock_only), Tier::L1);
        // Half of L2 is L2-: Landlock without the connect hook cannot deny
        // egress in kernel.
        let mut half = caps_for(Tier::L2);
        half.cgroup_sock_addr = false;
        assert_eq!(tier_of(&half), Tier::L2Minus);
        // BPF-LSM without L2's primitives does not make L3.
        let mut lsm_only = caps_for(Tier::L2Minus);
        lsm_only.bpf_lsm = true;
        assert_eq!(tier_of(&lsm_only), Tier::L2Minus);
        assert_eq!(tier_of(&CapabilitySet::NONE), Tier::L1);
    }

    #[test]
    fn every_missing_capability_names_the_function_it_costs() {
        let none = degradations(&CapabilitySet::NONE);
        assert_eq!(none.len(), 8, "{none:#?}");
        assert!(none.iter().any(|l| l.contains("T1 lost")));
        assert!(none.iter().any(|l| l.contains("Network Slam lost")));
        let mut full = caps_for(Tier::L3);
        full.tpm = true;
        assert_eq!(degradations(&full), Vec::<&str>::new());
        // WSL2: L2, and the two it costs are named.
        let wsl2 = caps_for(Tier::L2);
        let lost = degradations(&wsl2);
        assert_eq!(lost.len(), 2);
        assert!(lost[0].contains("BPF-LSM"));
        assert!(lost[1].contains("TPM"));
    }

    #[test]
    fn transitions_are_announced_once_and_never_silently() {
        let l3 = caps_for(Tier::L3);
        let mut machine = Degradation::starting_at(&l3);
        assert_eq!(machine.state(), &State::Serving(Tier::L3));
        assert_eq!(machine.state().metric(), 4);
        assert!(machine.observe(&l3).is_none(), "no change, no announcement");

        let fall = machine
            .observe(&caps_for(Tier::L2))
            .expect("a tier change is announced");
        assert!(
            fall.message.contains("fell from L3 to L2"),
            "{}",
            fall.message
        );
        assert!(fall.message.contains("weaker"));

        let lost = machine
            .lose("probes detached")
            .expect("degrading is announced");
        assert!(
            lost.message.starts_with("DEGRADED at tier L2"),
            "{}",
            lost.message
        );
        assert!(lost.message.contains("not a silent loss"));
        assert_eq!(
            machine.state().tier(),
            Tier::L2,
            "DEGRADED is a state, not a tier"
        );
        assert_eq!(machine.state().metric(), 0, "aisme.capability.level 0");
        assert!(
            machine.lose("probes detached").is_none(),
            "the same loss is not announced twice"
        );

        let back = machine
            .recover(&caps_for(Tier::L2))
            .expect("recovery is announced");
        assert!(
            back.message.contains("recovered from DEGRADED"),
            "{}",
            back.message
        );
        assert_eq!(machine.state(), &State::Serving(Tier::L2));
        let rise = machine.observe(&l3).unwrap();
        assert!(rise.message.contains("rose from L2 to L3"));
    }
}
