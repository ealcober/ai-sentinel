// SPDX-License-Identifier: Apache-2.0
//! The canonical bytes of a [`CompiledPolicy`] (`F1.PL.05`; §B.2 `PL-03`).
//!
//! Same source, same session, same bytes — so policy generations are
//! comparable, diffable and hashable. The encoding is a plain length-
//! prefixed little-endian layout over the IR, which is already canonical
//! (rules by id, terms by key, values sorted and deduplicated): nothing here
//! depends on iteration order, hashing, or the order the source was written
//! in. [`digest`] is BLAKE3 over those bytes, the hash §2.18 chose.

use super::compile::{CompiledPolicy, CompiledRule, Predicate, Term};

/// The encoding's own version byte, first in the stream. Bumped when the
/// layout changes; a reader that sees another value refuses.
pub const POLICY_ENCODING_VERSION: u8 = 1;

/// A 32-byte BLAKE3 digest of a policy's canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyDigest(pub [u8; 32]);

impl core::fmt::Debug for PolicyDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PolicyDigest(")?;
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

/// The canonical bytes.
#[must_use]
pub fn encode(policy: &CompiledPolicy) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + policy.rules.len() * 128);
    out.push(POLICY_ENCODING_VERSION);
    out.extend_from_slice(&policy.settings.learning_mode_days.to_le_bytes());
    out.extend_from_slice(&policy.settings.grant_ttl_days.to_le_bytes());
    out.push(u8::from(policy.settings.strict));
    put_u32(&mut out, policy.rules.len());
    for rule in &policy.rules {
        put_rule(&mut out, rule);
    }
    out
}

/// BLAKE3 over [`encode`].
#[must_use]
pub fn digest(policy: &CompiledPolicy) -> PolicyDigest {
    PolicyDigest(*blake3::hash(&encode(policy)).as_bytes())
}

fn put_rule(out: &mut Vec<u8>, rule: &CompiledRule) {
    put_str(out, &rule.id);
    out.push(rule.group as u8);
    out.push(rule.verdict as u8);
    out.push(u8::from(rule.promptable));
    out.push(u8::from(rule.suppressible));
    out.extend_from_slice(&rule.taint.bits().to_le_bytes());
    out.push(rule.severity_floor.map_or(0, |s| s as u8));
    put_str(out, rule.event.as_deref().unwrap_or(""));
    put_predicate(out, &rule.predicate);
    match &rule.except {
        Some(except) => {
            out.push(1);
            put_predicate(out, except);
        }
        None => out.push(0),
    }
}

fn put_predicate(out: &mut Vec<u8>, predicate: &Predicate) {
    put_u32(out, predicate.terms.len());
    for term in &predicate.terms {
        put_str(out, term.name());
        match term {
            Term::PathUnder(v)
            | Term::PathGlob(v)
            | Term::ExecClass(v)
            | Term::ExecPath(v)
            | Term::DestIn(v)
            | Term::DestNotIn(v)
            | Term::Proto(v)
            | Term::ToolName(v)
            | Term::ScopeRel(v) => {
                put_u32(out, v.len());
                for s in v {
                    put_str(out, s);
                }
            }
            Term::PathClass(v) | Term::Origin(v) => {
                put_u32(out, v.len());
                out.extend_from_slice(v);
            }
            Term::PortIn(v) => {
                put_u32(out, v.len());
                for p in v {
                    out.extend_from_slice(&p.to_le_bytes());
                }
            }
            Term::TaintAny(t) | Term::TaintAll(t) => out.extend_from_slice(&t.bits().to_le_bytes()),
            Term::NotDeclassified(b) | Term::InstructionBearing(b) | Term::FirstOfKind(b) => {
                out.push(u8::from(*b));
            }
            Term::AgeLt(n) => out.extend_from_slice(&n.to_le_bytes()),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, n: usize) {
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len());
    out.extend_from_slice(s.as_bytes());
}
