// SPDX-License-Identifier: Apache-2.0
//! The diagnostics §B.10 makes cheap (`F1.PL.09`).
//!
//! Because the effective verdict is `max` over the matching rules and the
//! order is a chain, three questions have static answers:
//!
//! - **Over-blocking triage.** For each rule, which other rules' effective
//!   verdict it raises wherever both match. This feeds `test-benign`: a
//!   benign-corpus block is explained by the rule at the top of this list.
//!   The overlap test errs long — a pair that *may* share an input is listed
//!   — because a triage list that omits the culprit is worse than one with
//!   a spare entry.
//! - **Shadowed allows** — an `allow` wholly inside a broader `deny` — are
//!   the compiler's `Unreachable` error (`F1.PL.02`); this module does not
//!   repeat it.
//! - **Strictness across versions.** `R ⊆ R'` implies `V_R ≤ V_R'`, so a
//!   policy that contains every rule of another, each at least as strict,
//!   is at least as strict everywhere. The claim is sound only when proven,
//!   so [`at_least_as_strict`] reports every old rule it cannot cover and
//!   every new grant, and claims nothing while any remains.

use aisme_ebpf_common::Verdict;

use super::compile::{CompiledPolicy, CompiledRule, Predicate, Term};

/// What one rule raises: the other rules whose effective verdict it lifts
/// wherever both match an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raises {
    /// The raising rule.
    pub rule_id: String,
    /// Its verdict.
    pub verdict: Verdict,
    /// The rules it raises, each with the verdict it would otherwise give,
    /// strictest first.
    pub over: Vec<(String, Verdict)>,
}

/// For every rule, the rules it raises. Empty entries are omitted.
#[must_use]
pub fn over_blocking(policy: &CompiledPolicy) -> Vec<Raises> {
    let mut out = Vec::new();
    for r in &policy.rules {
        let mut over: Vec<(String, Verdict)> = policy
            .rules
            .iter()
            .filter(|s| {
                s.id != r.id && s.verdict < r.verdict && r.predicate.may_overlap(&s.predicate)
            })
            .map(|s| (s.id.clone(), s.verdict))
            .collect();
        if over.is_empty() {
            continue;
        }
        over.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.push(Raises {
            rule_id: r.id.clone(),
            verdict: r.verdict,
            over,
        });
    }
    out
}

/// Why `new` could not be proven at least as strict as `old`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Weakening {
    /// An old rule with no new rule that includes its match at a verdict
    /// at least as strict.
    Uncovered {
        /// The old rule.
        rule_id: String,
        /// Its verdict.
        verdict: Verdict,
        /// The new rule of the same id, if any, and what it says now.
        replaced_by: Option<(String, Verdict)>,
    },
    /// A grant `new` has and `old` does not: it answers escalations `old`
    /// would have asked about.
    NewGrant {
        /// The grant.
        grant_id: String,
    },
}

/// Whether `new` is at least as strict as `old` for every input: `Ok(())`
/// when proven, else every reason it could not be.
///
/// # Errors
///
/// The [`Weakening`]s, one per uncovered old rule and per new grant. A
/// policy that adds rules and changes nothing else is proven; one that
/// relaxes a verdict, narrows a match or removes a rule is not — and
/// "not proven" is what is reported, never "weaker".
pub fn at_least_as_strict(
    new: &CompiledPolicy,
    old: &CompiledPolicy,
) -> Result<(), Vec<Weakening>> {
    let mut weak = Vec::new();
    for o in &old.rules {
        let covered = new
            .rules
            .iter()
            .any(|n| n.verdict >= o.verdict && covers(n, o));
        if !covered {
            weak.push(Weakening::Uncovered {
                rule_id: o.id.clone(),
                verdict: o.verdict,
                replaced_by: new
                    .rules
                    .iter()
                    .find(|n| n.id == o.id)
                    .map(|n| (n.id.clone(), n.verdict)),
            });
        }
    }
    for g in &new.grants {
        if !old.grants.iter().any(|og| og.id == g.id) {
            weak.push(Weakening::NewGrant {
                grant_id: g.id.clone(),
            });
        }
    }
    if weak.is_empty() {
        Ok(())
    } else {
        Err(weak)
    }
}

/// `n` matches everything `o` matches: `o`'s match is included in `n`'s,
/// and `n` carves out no more than `o` does.
fn covers(n: &CompiledRule, o: &CompiledRule) -> bool {
    o.predicate.included_in(&n.predicate)
        && match (&n.except, &o.except) {
            (None, _) => true,
            (Some(ne), Some(oe)) => ne.included_in(oe),
            (Some(_), None) => false,
        }
}

impl Predicate {
    /// Whether some input may satisfy both predicates. `false` only when a
    /// key present in both is provably disjoint; anything else is `true`.
    #[must_use]
    pub fn may_overlap(&self, other: &Predicate) -> bool {
        for mine in &self.terms {
            for theirs in &other.terms {
                if provably_disjoint(mine, theirs) {
                    return false;
                }
            }
        }
        true
    }
}

fn provably_disjoint(a: &Term, b: &Term) -> bool {
    match (a, b) {
        (Term::PathUnder(x), Term::PathUnder(y)) => x
            .iter()
            .all(|p| y.iter().all(|q| !under(p, q) && !under(q, p))),
        (Term::PathUnder(prefixes), Term::PathGlob(globs))
        | (Term::PathGlob(globs), Term::PathUnder(prefixes)) => {
            // A glob with a literal head that is neither under nor above
            // every prefix cannot meet it; a head-less glob (`**/x`) can.
            globs.iter().all(|g| {
                let head = literal_head(g);
                !head.is_empty() && prefixes.iter().all(|p| !under(head, p) && !under(p, head))
            })
        }
        (Term::PathClass(x), Term::PathClass(y)) | (Term::Origin(x), Term::Origin(y)) => {
            disjoint(x, y)
        }
        (Term::ExecClass(x), Term::ExecClass(y))
        | (Term::ExecPath(x), Term::ExecPath(y))
        | (Term::Proto(x), Term::Proto(y))
        | (Term::ToolName(x), Term::ToolName(y))
        | (Term::ScopeRel(x), Term::ScopeRel(y))
        | (Term::DestIn(x), Term::DestIn(y)) => disjoint(x, y),
        (Term::PortIn(x), Term::PortIn(y)) => disjoint(x, y),
        (Term::NotDeclassified(x), Term::NotDeclassified(y))
        | (Term::InstructionBearing(x), Term::InstructionBearing(y))
        | (Term::FirstOfKind(x), Term::FirstOfKind(y)) => x != y,
        // taint_any / taint_all / dest_not_in / age_lt / cross-key pairs:
        // an input can satisfy both, or it cannot be ruled out.
        _ => false,
    }
}

fn disjoint<T: PartialEq>(x: &[T], y: &[T]) -> bool {
    x.iter().all(|a| !y.contains(a))
}

fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn literal_head(glob: &str) -> &str {
    let end = glob.find(['*', '?', '[']).unwrap_or(glob.len());
    let head = &glob[..end];
    match head.rfind('/') {
        Some(0) => "/",
        Some(i) => &head[..i],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_is_refuted_only_by_a_shared_key_that_is_provably_disjoint() {
        let etc = Predicate {
            terms: vec![Term::PathUnder(vec!["/etc".into()])],
        };
        let home = Predicate {
            terms: vec![Term::PathUnder(vec!["/home".into()])],
        };
        let hosts = Predicate {
            terms: vec![Term::PathGlob(vec!["/etc/hosts*".into()])],
        };
        let env = Predicate {
            terms: vec![Term::PathGlob(vec!["**/.env".into()])],
        };
        let taint = Predicate {
            terms: vec![Term::TaintAny(crate::taint::Taint::SECRET_MATERIAL)],
        };
        assert!(!etc.may_overlap(&home));
        assert!(etc.may_overlap(&hosts));
        assert!(
            !home.may_overlap(&hosts),
            "the glob's head is under /etc, not /home"
        );
        assert!(
            home.may_overlap(&env),
            "a head-less glob reaches everywhere"
        );
        assert!(
            etc.may_overlap(&taint),
            "no shared key: cannot be ruled out"
        );
        let tcp = Predicate {
            terms: vec![Term::Proto(vec!["Tcp".into()])],
        };
        let udp = Predicate {
            terms: vec![Term::Proto(vec!["Udp".into()])],
        };
        assert!(!tcp.may_overlap(&udp));
    }
}
