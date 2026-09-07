// SPDX-License-Identifier: Apache-2.0
//! Evaluation with provenance (`F1.PL.10`; §B.10).
//!
//! `V(e) = max { verdict(r) : r matches e }`, `allow` when nothing matches.
//! The combining step records **`decided_by`** — the rule that supplied the
//! maximum — and carries it on the verdict into the WAL and the UI, the way
//! `seccomp(2)` keeps `*match` beside the winning action: a verdict nobody
//! can attribute is a verdict nobody trusts. Ties go to the first rule in
//! canonical order (by id), so replay attributes the same rule every time.
//!
//! A live grant of the event's group whose scope matches answers an
//! `escalate` with `allow`, recorded as `granted_by`. A suppression whose
//! match holds is recorded as `suppressed_by` and changes nothing else
//! (`I-26`): the verdict, the record, the enforcement are what they were.

use aisme_ebpf_common::Verdict;

use super::compile::{CompiledPolicy, Predicate, Term};
use crate::ontology::{PathClass, PermissionGroup, Proto, ResultOrigin};
use crate::taint::Taint;

/// What is known about one event, per match key. Absent facts match no
/// term on that key: a rule about paths does not match an event that has
/// none, and an absence is never read as a value.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EventFacts<'a> {
    /// The permission group the event was classified into; only rules of
    /// this group apply.
    pub group: Option<PermissionGroup>,
    /// Canonical path.
    pub path: Option<&'a str>,
    /// The path's class.
    pub path_class: Option<PathClass>,
    /// The executable's class (`"package-manager"`, …).
    pub exec_class: Option<&'a str>,
    /// The executable's path.
    pub exec_path: Option<&'a str>,
    /// The destination, as the allowlist spells it (host or CIDR literal).
    pub dest: Option<&'a str>,
    /// The destination port.
    pub port: Option<u16>,
    /// The transport.
    pub proto: Option<Proto>,
    /// The process's taint.
    pub taint: Option<Taint>,
    /// Whether a declassification is in effect.
    pub declassified: Option<bool>,
    /// The tool's name.
    pub tool_name: Option<&'a str>,
    /// A `ToolResult`'s origin.
    pub origin: Option<ResultOrigin>,
    /// Whether the input carries instructions.
    pub instruction_bearing: Option<bool>,
    /// Scope relative to the session.
    pub scope_rel: Option<&'a str>,
    /// Age of the thing touched, seconds.
    pub age_s: Option<u64>,
    /// First action of its class in this session.
    pub first_of_kind: Option<bool>,
}

/// The verdict and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The effective verdict.
    pub verdict: Verdict,
    /// The rule that supplied the maximum; `None` when no rule matched.
    pub decided_by: Option<String>,
    /// The grant that answered an escalation, when one did.
    pub granted_by: Option<String>,
    /// The suppression (by position) that silences notification, when one
    /// matched. Notification only.
    pub suppressed_by: Option<usize>,
    /// How many rules matched: the evaluation's own audit.
    pub matched: usize,
}

/// Evaluate one event against a compiled policy.
#[must_use]
pub fn evaluate(policy: &CompiledPolicy, facts: &EventFacts<'_>) -> Decision {
    let mut verdict = Verdict::Allow;
    let mut decided_by = None;
    let mut matched = 0;
    for rule in &policy.rules {
        if facts.group.is_some_and(|g| g != rule.group)
            || !matches(&rule.predicate, rule.except.as_ref(), facts)
        {
            continue;
        }
        matched += 1;
        // Strictly greater: on a tie the earlier rule, in canonical order,
        // keeps the attribution.
        if decided_by.is_none() || rule.verdict > verdict {
            verdict = rule.verdict;
            decided_by = Some(rule.id.clone());
        }
        if verdict.is_terminal() {
            break;
        }
    }
    let mut granted_by = None;
    if verdict == Verdict::Escalate {
        if let Some(grant) = policy.grants.iter().find(|g| {
            facts.group.is_none_or(|group| group == g.group) && matches(&g.predicate, None, facts)
        }) {
            verdict = Verdict::Allow;
            granted_by = Some(grant.id.clone());
        }
    }
    let suppressed_by = policy
        .suppressions
        .iter()
        .position(|s| matches(&s.predicate, None, facts));
    Decision {
        verdict,
        decided_by,
        granted_by,
        suppressed_by,
        matched,
    }
}

/// `predicate` holds and `except`, if any, does not.
fn matches(predicate: &Predicate, except: Option<&Predicate>, facts: &EventFacts<'_>) -> bool {
    predicate.terms.iter().all(|t| term_matches(t, facts))
        && !except.is_some_and(|e| e.terms.iter().all(|t| term_matches(t, facts)))
}

fn term_matches(term: &Term, facts: &EventFacts<'_>) -> bool {
    match term {
        Term::PathUnder(prefixes) => facts
            .path
            .is_some_and(|p| prefixes.iter().any(|q| under(p, q))),
        Term::PathGlob(globs) => facts
            .path
            .is_some_and(|p| globs.iter().any(|g| glob_match(g, p))),
        Term::PathClass(classes) => facts
            .path_class
            .is_some_and(|c| classes.contains(&(c as u8))),
        Term::ExecClass(classes) => facts
            .exec_class
            .is_some_and(|c| classes.iter().any(|x| x == c)),
        Term::ExecPath(globs) => facts
            .exec_path
            .is_some_and(|p| globs.iter().any(|g| glob_match(g, p))),
        Term::DestIn(dests) => facts.dest.is_some_and(|d| dests.iter().any(|x| x == d)),
        Term::DestNotIn(dests) => facts.dest.is_some_and(|d| !dests.iter().any(|x| x == d)),
        Term::PortIn(ports) => facts.port.is_some_and(|p| ports.contains(&p)),
        Term::Proto(protos) => facts
            .proto
            .is_some_and(|p| protos.iter().any(|x| *x == format!("{p:?}"))),
        Term::TaintAny(t) => facts.taint.is_some_and(|x| x.intersects(*t)),
        Term::TaintAll(t) => facts.taint.is_some_and(|x| x.contains(*t)),
        Term::NotDeclassified(want) => facts.declassified.is_some_and(|d| d != *want),
        Term::ToolName(names) => facts
            .tool_name
            .is_some_and(|n| names.iter().any(|x| x == n)),
        Term::Origin(origins) => facts.origin.is_some_and(|o| origins.contains(&(o as u8))),
        Term::InstructionBearing(want) => facts.instruction_bearing.is_some_and(|b| b == *want),
        Term::ScopeRel(scopes) => facts
            .scope_rel
            .is_some_and(|s| scopes.iter().any(|x| x == s)),
        Term::AgeLt(limit) => facts.age_s.is_some_and(|a| a < *limit),
        Term::FirstOfKind(want) => facts.first_of_kind.is_some_and(|b| b == *want),
    }
}

fn under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// A path glob: `**` spans components, `*` and `?` stay inside one, `[…]`
/// is a character class. Bounded by the compiler's glob budget, so the
/// backtracking here is bounded too.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let comps: Vec<&str> = path.split('/').collect();
    segments_match(&pat, &comps)
}

fn segments_match(pat: &[&str], comps: &[&str]) -> bool {
    match pat.split_first() {
        None => comps.is_empty(),
        Some((&"**", rest)) => (0..=comps.len()).any(|skip| segments_match(rest, &comps[skip..])),
        Some((first, rest)) => match comps.split_first() {
            Some((comp, tail)) => {
                component_match(first.as_bytes(), comp.as_bytes()) && segments_match(rest, tail)
            }
            None => false,
        },
    }
}

fn component_match(pat: &[u8], text: &[u8]) -> bool {
    match pat.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| component_match(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && component_match(rest, &text[1..]),
        Some((b'[', rest)) => {
            let Some(close) = rest.iter().position(|&b| b == b']') else {
                return !text.is_empty() && text[0] == b'[' && component_match(rest, &text[1..]);
            };
            let (class, after) = (&rest[..close], &rest[close + 1..]);
            !text.is_empty() && class_match(class, text[0]) && component_match(after, &text[1..])
        }
        Some((&c, rest)) => !text.is_empty() && text[0] == c && component_match(rest, &text[1..]),
    }
}

fn class_match(class: &[u8], c: u8) -> bool {
    let (negate, class) = match class.split_first() {
        Some((b'!', rest)) => (true, rest),
        _ => (false, class),
    };
    let mut i = 0;
    let mut hit = false;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            if class[i] <= c && c <= class[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if class[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    hit != negate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_span_components_only_with_double_star() {
        assert!(glob_match("**/.env", "/home/u/proj/.env"));
        assert!(glob_match("**/.env", ".env"));
        assert!(
            !glob_match("*/.env", "/home/u/.env"),
            "`*` stays in one component"
        );
        assert!(glob_match("/home/*/.env", "/home/u/.env"));
        assert!(glob_match(".git/hooks/*", ".git/hooks/pre-commit"));
        assert!(!glob_match(".git/hooks/*", ".git/hooks/a/b"));
        assert!(glob_match("~/.ssh/id_*", "~/.ssh/id_ed25519"));
        assert!(glob_match("/etc/**", "/etc/a/b/c"));
        assert!(glob_match("/etc/**", "/etc"), "`**` may match nothing");
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
        assert!(glob_match("[a-c]x", "bx"));
        assert!(!glob_match("[!a-c]x", "bx"));
        assert!(glob_match("[!a-c]x", "dx"));
        assert!(!glob_match("/etc/hosts", "/etc/hostsfile"));
    }
}
