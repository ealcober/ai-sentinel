// SPDX-License-Identifier: Apache-2.0
//! `PolicyBackend`: one IR, five targets (`F1.PL.03`; Annex B §B.9).
//!
//! The IR lives here; the backends live in the adapters (L2) and implement
//! the trait. What this module owns is the part every backend must declare
//! and the compiler must check locally, rule by rule: which match keys the
//! target can express, and its **monotone map** from the verdict order into
//! the verdicts it can enforce. §B.9 makes that map load-bearing — because
//! the order is a chain and `f` preserves it, `f(max S) = max f(S)`, so the
//! compiler applies `f` per rule before combining and the result is
//! provably the same as combining first. [`VerdictMap::homomorphic`] is
//! that proof, run over every pair.

use aisme_ebpf_common::Verdict;

use super::compile::{CompiledPolicy, CompiledRule};

/// A generation of published policy: §3.6's monotonic counter. Readers use
/// the last good one and never see a torn policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PolicyGeneration(pub u64);

impl PolicyGeneration {
    /// The next generation.
    #[must_use]
    pub const fn next(self) -> PolicyGeneration {
        PolicyGeneration(self.0.saturating_add(1))
    }
}

/// The five targets of §B.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// The BPF policy trie (tier L3).
    BpfTrie,
    /// A Landlock ruleset (tier L2, files; TCP ports from ABI 4).
    Landlock,
    /// The cgroup `sock_addr` allowlist (tier L2, network).
    CgroupConnect,
    /// The mobile trie in `sentinel-core`.
    Sentinel,
    /// The Windows minifilter trie — `[POST]`, specified in Annex F.
    Windows,
}

impl BackendKind {
    /// Every target, in §B.9 column order.
    pub const ALL: [BackendKind; 5] = [
        BackendKind::BpfTrie,
        BackendKind::Landlock,
        BackendKind::CgroupConnect,
        BackendKind::Sentinel,
        BackendKind::Windows,
    ];

    /// The §B.9 row label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            BackendKind::BpfTrie => "BPF trie (L3)",
            BackendKind::Landlock => "Landlock",
            BackendKind::CgroupConnect => "cgroup connect",
            BackendKind::Sentinel => "Sentinel",
            BackendKind::Windows => "Windows `[POST]`",
        }
    }
}

/// Which way a backend degrades a verdict it cannot enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Degradation {
    /// The verdict is enforced as written.
    Exact,
    /// Fail closed: a stricter verdict than written.
    Upward,
    /// Fail open: a weaker verdict than written. Refused for `escalate` and
    /// `deny` unless the rule says `degrade_open` (§B.9; `F1.PL.08`).
    Downward,
}

/// A backend's map from the verdict order into what it can enforce, indexed
/// by `Verdict as usize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerdictMap(pub [Verdict; 4]);

impl VerdictMap {
    /// The identity: every verdict as written.
    pub const IDENTITY: VerdictMap = VerdictMap([
        Verdict::Allow,
        Verdict::Warn,
        Verdict::Escalate,
        Verdict::Deny,
    ]);

    /// `f(v)`.
    #[must_use]
    pub const fn apply(self, v: Verdict) -> Verdict {
        self.0[v as usize]
    }

    /// Order-preserving: `a ≤ b ⇒ f(a) ≤ f(b)`. §B.9's requirement, and what
    /// `verify-docs` checks on the plan's table.
    #[must_use]
    pub fn is_monotone(self) -> bool {
        self.0.windows(2).all(|w| w[0] <= w[1])
    }

    /// `f(max S) = max f(S)` for every pair — the lattice homomorphism §B.9
    /// relies on. Holds for every monotone map on a chain; checked rather
    /// than trusted.
    #[must_use]
    pub fn homomorphic(self) -> bool {
        Verdict::ALL.iter().all(|&a| {
            Verdict::ALL
                .iter()
                .all(|&b| self.apply(a.combine(b)) == self.apply(a).combine(self.apply(b)))
        })
    }

    /// How `v` fares under this map.
    #[must_use]
    pub const fn degradation(self, v: Verdict) -> Degradation {
        let f = self.apply(v);
        if (f as u8) == (v as u8) {
            Degradation::Exact
        } else if (f as u8) > (v as u8) {
            Degradation::Upward
        } else {
            Degradation::Downward
        }
    }
}

/// What one target can express: §B.9 as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// The target.
    pub kind: BackendKind,
    /// The match keys the target can evaluate. A rule with any other key is
    /// not this backend's to enforce (`F1.PL.08` says so per rule).
    pub keys: &'static [&'static str],
    /// The verdict map.
    pub map: VerdictMap,
    /// A caveat §B.9 attaches, shown in the tier-specific message.
    pub caveat: Option<&'static str>,
}

const PATH_KEYS: [&str; 3] = ["path_under", "path_glob", "path_class"];
const NET_KEYS: [&str; 4] = ["dest_in", "dest_not_in", "port_in", "proto"];
const EXEC_KEYS: [&str; 2] = ["exec_class", "exec_path"];
const TAINT_KEYS: [&str; 3] = ["taint_any", "taint_all", "not_declassified"];
const TOOL_KEYS: [&str; 3] = ["tool_name", "origin", "instruction_bearing"];
const SESSION_KEYS: [&str; 3] = ["scope_rel", "age_lt", "first_of_kind"];

const BPF_KEYS: [&str; 15] = concat_keys::<15>(&[
    &PATH_KEYS,
    &NET_KEYS,
    &EXEC_KEYS,
    &TAINT_KEYS,
    &SESSION_KEYS,
]);
const LANDLOCK_KEYS: [&str; 6] = [
    "path_under",
    "path_glob",
    "path_class",
    "exec_class",
    "exec_path",
    "port_in",
];
const CGROUP_KEYS: [&str; 7] = concat_keys::<7>(&[&NET_KEYS, &TAINT_KEYS]);
const SENTINEL_KEYS: [&str; 13] =
    concat_keys::<13>(&[&PATH_KEYS, &NET_KEYS, &TAINT_KEYS, &TOOL_KEYS]);
const WINDOWS_KEYS: [&str; 15] = concat_keys::<15>(&[
    &PATH_KEYS,
    &NET_KEYS,
    &EXEC_KEYS,
    &TAINT_KEYS,
    &SESSION_KEYS,
]);

const fn concat_keys<const N: usize>(groups: &[&[&'static str]]) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    let mut g = 0;
    while g < groups.len() {
        let mut k = 0;
        while k < groups[g].len() {
            out[i] = groups[g][k];
            i += 1;
            k += 1;
        }
        g += 1;
    }
    assert!(i == N, "key group sizes do not add up to N");
    out
}

impl BackendCapabilities {
    /// §B.9's row for a target. The maps are the plan's table verbatim; a
    /// test reads that table out of the plan and compares.
    #[must_use]
    pub const fn of(kind: BackendKind) -> BackendCapabilities {
        use Verdict::{Allow, Deny};
        match kind {
            BackendKind::BpfTrie => BackendCapabilities {
                kind,
                keys: &BPF_KEYS,
                map: VerdictMap::IDENTITY,
                caveat: None,
            },
            BackendKind::Landlock => BackendCapabilities {
                kind,
                keys: &LANDLOCK_KEYS,
                map: VerdictMap([Allow, Allow, Deny, Deny]),
                caveat: Some(
                    "Landlock: TCP ports only (ABI ≥ 4), no address matching and no UDP (F0.VER.20); warn is allow with the notice delivered in parallel; escalate fails closed as deny",
                ),
            },
            BackendKind::CgroupConnect => BackendCapabilities {
                kind,
                keys: &CGROUP_KEYS,
                map: VerdictMap([Allow, Allow, Deny, Deny]),
                caveat: Some("cgroup connect: taint keys via the session map; warn is allow with the notice in parallel; escalate fails closed as deny"),
            },
            BackendKind::Sentinel => BackendCapabilities {
                kind,
                keys: &SENTINEL_KEYS,
                map: VerdictMap::IDENTITY,
                caveat: Some("Sentinel: path keys are SDK-reported, not kernel-observed"),
            },
            BackendKind::Windows => BackendCapabilities {
                kind,
                keys: &WINDOWS_KEYS,
                map: VerdictMap::IDENTITY,
                caveat: Some("Windows: [POST], specified in Annex F, not implemented"),
            },
        }
    }

    /// Whether this backend evaluates a match key.
    #[must_use]
    pub fn supports_key(&self, key: &str) -> bool {
        self.keys.contains(&key)
    }
}

/// A compiled policy could not be lowered for a target. The per-rule
/// refusals with their tier-specific messages are `F1.PL.08`; this is the
/// shape they arrive in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LowerError {
    /// The target.
    pub backend: BackendKind,
    /// The rule, when one is at fault.
    pub rule_id: Option<String>,
    /// What the backend said.
    pub message: String,
}

impl core::fmt::Display for LowerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: ", self.backend.name())?;
        if let Some(id) = &self.rule_id {
            write!(f, "rule \"{id}\": ")?;
        }
        f.write_str(&self.message)
    }
}

impl core::error::Error for LowerError {}

/// Why a backend will not take a rule (`F1.PL.08`). Tier-specific: the
/// message names the backend, the rule, and the key or verdict at fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// A match key the target cannot evaluate; the rule is enforced by
    /// another backend or in user space, and the composition (`F1.PA.06`)
    /// has to find which.
    UnsupportedKey {
        /// The key.
        key: &'static str,
    },
    /// The target would enforce a weaker verdict than written for an
    /// `escalate` or `deny`, and the rule does not say `degrade_open`.
    DowngradeRefused {
        /// As written.
        written: Verdict,
        /// What the target would enforce.
        would_enforce: Verdict,
    },
}

/// One rule the target takes, with what it will actually enforce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lowered {
    /// The rule.
    pub rule_id: String,
    /// As written.
    pub written: Verdict,
    /// As the target enforces it, `f(written)`.
    pub enforced: Verdict,
    /// Which way, if any.
    pub degradation: Degradation,
}

/// What a target will do with a compiled policy: every rule accounted for,
/// accepted with its enforced verdict or rejected with its reason. Nothing
/// is dropped without a line here — §B.9's answer to `AppArmor`'s silently
/// ignored `priority`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LoweringPlan {
    /// Rules the target enforces, in policy order.
    pub accepted: Vec<Lowered>,
    /// Rules the target will not take, each with its reason.
    pub rejected: Vec<(String, Rejection)>,
}

impl LoweringPlan {
    /// The accepted rules whose verdict the map changed — the compiler names
    /// every one of these, never substitutes silently.
    pub fn changed(&self) -> impl Iterator<Item = &Lowered> + '_ {
        self.accepted
            .iter()
            .filter(|l| l.degradation != Degradation::Exact)
    }

    /// Decide one rule against a target's capabilities.
    fn consider(caps: &BackendCapabilities, rule: &CompiledRule) -> Result<Lowered, Rejection> {
        let keys = rule
            .predicate
            .terms
            .iter()
            .chain(rule.except.iter().flat_map(|e| e.terms.iter()))
            .map(super::compile::Term::name);
        for key in keys {
            if !caps.supports_key(key) {
                return Err(Rejection::UnsupportedKey { key });
            }
        }
        let enforced = caps.map.apply(rule.verdict);
        let degradation = caps.map.degradation(rule.verdict);
        if degradation == Degradation::Downward
            && matches!(rule.verdict, Verdict::Escalate | Verdict::Deny)
            && !rule.degrade_open
        {
            return Err(Rejection::DowngradeRefused {
                written: rule.verdict,
                would_enforce: enforced,
            });
        }
        Ok(Lowered {
            rule_id: rule.id.clone(),
            written: rule.verdict,
            enforced,
            degradation,
        })
    }

    /// Every rule of `policy` against `caps`.
    #[must_use]
    pub fn of(caps: &BackendCapabilities, policy: &CompiledPolicy) -> LoweringPlan {
        let mut plan = LoweringPlan::default();
        for rule in &policy.rules {
            match LoweringPlan::consider(caps, rule) {
                Ok(lowered) => plan.accepted.push(lowered),
                Err(rejection) => plan.rejected.push((rule.id.clone(), rejection)),
            }
        }
        plan
    }

    /// The tier-specific messages, one per rejected rule and one per
    /// changed verdict, ready to print.
    #[must_use]
    pub fn messages(&self, caps: &BackendCapabilities) -> Vec<String> {
        let name = caps.kind.name();
        let caveat = caps.caveat.map_or(String::new(), |c| format!(" ({c})"));
        let mut out = Vec::with_capacity(self.rejected.len() + self.accepted.len());
        for (id, rejection) in &self.rejected {
            out.push(match rejection {
                Rejection::UnsupportedKey { key } => {
                    format!("{name}: rule \"{id}\" rejected — cannot evaluate `{key}`{caveat}")
                }
                Rejection::DowngradeRefused { written, would_enforce } => format!(
                    "{name}: rule \"{id}\" rejected — would enforce {would_enforce:?} for {written:?}, a downward degradation the rule does not accept (say `degrade_open = true` to fail open){caveat}"
                ),
            });
        }
        for l in self.changed() {
            out.push(format!(
                "{name}: rule \"{}\" enforced as {:?} for {:?} ({})",
                l.rule_id,
                l.enforced,
                l.written,
                match l.degradation {
                    Degradation::Upward => "fail closed",
                    Degradation::Downward => "fail open, as the map declares",
                    Degradation::Exact => "exact",
                }
            ));
        }
        out
    }
}

/// One target for the IR. Implemented in the adapters (`aisme-linux`,
/// `sentinel-core`, …); `aisme-core` names none of them.
pub trait PolicyBackend {
    /// What `lower` produces: a BPF map image, a Landlock ruleset
    /// description, a trie for the tunnel — whatever the target loads.
    type Artifact;

    /// Which target.
    fn kind(&self) -> BackendKind;

    /// What it can express. The default is §B.9's row; a backend that
    /// measured itself narrower (an older Landlock ABI, say) overrides.
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::of(self.kind())
    }

    /// What this target will do with `policy`, rule by rule: the check
    /// `lower` performs first, exposed so the composition can ask before
    /// building anything.
    fn plan(&self, policy: &CompiledPolicy) -> LoweringPlan {
        LoweringPlan::of(&self.capabilities(), policy)
    }

    /// Lower a compiled policy to the target's artifact. A rule the target
    /// cannot express is an error, never a silent drop.
    ///
    /// # Errors
    ///
    /// [`LowerError`], naming the rule where one is at fault.
    fn lower(&self, policy: &CompiledPolicy) -> Result<Self::Artifact, LowerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_map_is_monotone_and_a_homomorphism() {
        for kind in BackendKind::ALL {
            let caps = BackendCapabilities::of(kind);
            assert!(caps.map.is_monotone(), "{kind:?}");
            assert!(caps.map.homomorphic(), "{kind:?}");
            assert_eq!(caps.kind, kind);
        }
        // And a map that is not monotone is not a homomorphism either — the
        // property is not vacuous.
        let broken = VerdictMap([
            Verdict::Deny,
            Verdict::Allow,
            Verdict::Escalate,
            Verdict::Deny,
        ]);
        assert!(!broken.is_monotone());
        assert!(!broken.homomorphic());
    }

    #[test]
    fn degradation_directions_are_as_b9_declares() {
        let landlock = BackendCapabilities::of(BackendKind::Landlock).map;
        assert_eq!(landlock.degradation(Verdict::Allow), Degradation::Exact);
        assert_eq!(landlock.degradation(Verdict::Warn), Degradation::Downward);
        assert_eq!(
            landlock.degradation(Verdict::Escalate),
            Degradation::Upward,
            "fail closed"
        );
        assert_eq!(landlock.degradation(Verdict::Deny), Degradation::Exact);
        let cgroup = BackendCapabilities::of(BackendKind::CgroupConnect).map;
        assert_eq!(cgroup.apply(Verdict::Escalate), Verdict::Deny);
        assert_eq!(
            BackendCapabilities::of(BackendKind::BpfTrie).map,
            VerdictMap::IDENTITY
        );
    }

    #[test]
    fn key_support_follows_the_matrix() {
        let landlock = BackendCapabilities::of(BackendKind::Landlock);
        assert!(landlock.supports_key("path_under"));
        assert!(landlock.supports_key("port_in"), "TCP ports from ABI 4");
        assert!(!landlock.supports_key("dest_in"), "no address matching");
        assert!(
            !landlock.supports_key("proto"),
            "no UDP means no proto choice"
        );
        assert!(!landlock.supports_key("taint_any"));
        let cgroup = BackendCapabilities::of(BackendKind::CgroupConnect);
        assert!(cgroup.supports_key("dest_not_in"));
        assert!(cgroup.supports_key("not_declassified"));
        assert!(!cgroup.supports_key("path_under"));
        let bpf = BackendCapabilities::of(BackendKind::BpfTrie);
        assert!(!bpf.supports_key("tool_name"), "user space only");
        assert!(BackendCapabilities::of(BackendKind::Sentinel).supports_key("instruction_bearing"));
        for kind in BackendKind::ALL {
            let keys = BackendCapabilities::of(kind).keys;
            assert!(
                !keys.contains(&""),
                "{kind:?}: a key group did not fill its slot"
            );
        }
    }

    #[test]
    fn the_maps_are_the_plans_table_verbatim() {
        // The same table verify-docs checks for monotonicity, read from the
        // plan itself, so code and plan cannot drift apart unnoticed.
        let plan = include_str!("../../../../docs/01_phase5_implementation_plan.md");
        let start = plan
            .find("| Backend | `allow` | `warn` | `escalate` | `deny` |")
            .expect("§B.9 map table");
        let rows: Vec<Vec<Verdict>> = plan[start..]
            .lines()
            .skip(2)
            .take_while(|l| l.starts_with('|'))
            .map(|l| {
                l.split('|')
                    .skip(2)
                    .take(4)
                    .map(|cell| {
                        let word = cell
                            .split_whitespace()
                            .next()
                            .unwrap_or("")
                            .trim_matches('*');
                        match word {
                            "allow" => Verdict::Allow,
                            "warn" => Verdict::Warn,
                            "escalate" => Verdict::Escalate,
                            "deny" => Verdict::Deny,
                            other => panic!("unexpected cell {other:?}"),
                        }
                    })
                    .collect()
            })
            .collect();
        assert_eq!(rows.len(), 5);
        for (kind, row) in BackendKind::ALL.iter().zip(rows) {
            assert_eq!(
                BackendCapabilities::of(*kind).map.0.to_vec(),
                row,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn generations_only_go_up() {
        let g = PolicyGeneration(7);
        assert_eq!(g.next(), PolicyGeneration(8));
        assert!(g < g.next());
        assert_eq!(
            PolicyGeneration(u64::MAX).next(),
            PolicyGeneration(u64::MAX)
        );
    }
}
