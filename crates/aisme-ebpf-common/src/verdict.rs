// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! The four verdicts and their order (plan Annex B §B.10, normative).
//!
//! `allow < warn < escalate < deny` — a chain, not a partial order. The
//! effective verdict of an event is the maximum over the rules that match it,
//! which is order-independent because `max` on a chain is commutative,
//! associative and idempotent. The kernel-side trie (F3) stores this byte and
//! combines with the same `max`, so the type lives in the wire crate.

/// A policy verdict, declared in §B.10 order so the derived `Ord` *is* the
/// normative order.
///
/// Deliberately exhaustive: §B.10 says a verdict not comparable to every
/// existing one may not be added, and adding one at all needs an ADR — so a
/// consumer that matches all four and breaks when a fifth appears is doing
/// its job.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// Permitted, silently.
    Allow = 0,
    /// Permitted, with a non-blocking notice (`Adjudicator::notify`).
    Warn = 1,
    /// Held for a human or machine answer within the channel's budget.
    Escalate = 2,
    /// Refused — in kernel where the tier allows, `EPERM`/`EACCES`.
    Deny = 3,
}

impl Verdict {
    /// The four verdicts, in order.
    pub const ALL: [Verdict; 4] = [
        Verdict::Allow,
        Verdict::Warn,
        Verdict::Escalate,
        Verdict::Deny,
    ];

    /// The verdict when no rule matches (§B.10).
    pub const DEFAULT: Verdict = Verdict::Allow;

    /// The wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The verdict a byte names, if any — the only sound way back from the
    /// kernel's trie.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Verdict> {
        Some(match code {
            0 => Verdict::Allow,
            1 => Verdict::Warn,
            2 => Verdict::Escalate,
            3 => Verdict::Deny,
            _ => return None,
        })
    }

    /// §B.10 combining: the stricter of two. `const`, so the kernel-side code
    /// can fold with it.
    #[must_use]
    pub const fn combine(self, other: Verdict) -> Verdict {
        if (other as u8) > (self as u8) {
            other
        } else {
            self
        }
    }

    /// Whether evaluation may stop here. Only `deny`, the top of the chain:
    /// `allow` and `warn` are not terminal, and a later rule can always raise
    /// them (§B.10).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Verdict::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_is_the_b10_chain() {
        assert!(Verdict::Allow < Verdict::Warn);
        assert!(Verdict::Warn < Verdict::Escalate);
        assert!(Verdict::Escalate < Verdict::Deny);
        for (i, v) in Verdict::ALL.iter().enumerate() {
            assert_eq!(v.code() as usize, i);
            assert_eq!(Verdict::from_code(v.code()), Some(*v));
        }
        assert_eq!(Verdict::from_code(4), None);
    }

    #[test]
    fn combining_is_max_and_order_independent() {
        for a in Verdict::ALL {
            for b in Verdict::ALL {
                assert_eq!(a.combine(b), a.max(b));
                assert_eq!(a.combine(b), b.combine(a));
                assert_eq!(a.combine(a), a);
                for c in Verdict::ALL {
                    assert_eq!(a.combine(b).combine(c), a.combine(b.combine(c)));
                }
            }
        }
        // No rule matching: allow. Any rule matching: at least its verdict.
        let folded = [Verdict::Warn, Verdict::Allow, Verdict::Escalate]
            .iter()
            .fold(Verdict::DEFAULT, |acc, v| acc.combine(*v));
        assert_eq!(folded, Verdict::Escalate);
    }

    #[test]
    fn only_deny_is_terminal() {
        for v in Verdict::ALL {
            assert_eq!(v.is_terminal(), v == Verdict::Deny);
        }
    }
}
