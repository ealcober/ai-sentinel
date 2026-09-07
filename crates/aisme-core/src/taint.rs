// SPDX-License-Identifier: Apache-2.0
//! The taint categories (plan §2.14, `H-13` as corrected).
//!
//! A category bitmask, not a single bit: which *kind* of sensitive data a
//! process or file has touched decides what its egress means. The propagation
//! and declassification algebra is `F1.ON.04`; this file is the type and its
//! bits, which the wire carries as `RawEvent::taint`.

/// A set of taint categories. Same bits as `RawEvent::taint`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Taint(u32);

impl Taint {
    /// Nothing.
    pub const EMPTY: Taint = Taint(0);
    /// Private keys, `.env`, tokens, keychain.
    pub const SECRET_MATERIAL: Taint = Taint(1 << 0);
    /// Downloaded content, third-party repos, web output.
    pub const UNTRUSTED_INPUT: Taint = Taint(1 << 1);
    /// Executable written by the agent in this session.
    pub const GENERATED_CODE: Taint = Taint(1 << 2);
    /// Already egressed to a non-allowed destination.
    pub const EXTERNAL_EGRESS: Taint = Taint(1 << 3);
    /// Read the OS credential store.
    pub const CREDENTIAL_ACCESS: Taint = Taint(1 << 4);

    /// Every defined category, in bit order.
    pub const ALL: [Taint; 5] = [
        Taint::SECRET_MATERIAL,
        Taint::UNTRUSTED_INPUT,
        Taint::GENERATED_CODE,
        Taint::EXTERNAL_EGRESS,
        Taint::CREDENTIAL_ACCESS,
    ];

    /// The bits, for the wire.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// From the wire. Unknown bits are kept, not dropped: a newer producer's
    /// category is still a category, and `F1.ON.04` treats an unknown bit as
    /// tainted rather than clean.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Taint {
        Taint(bits)
    }

    /// Whether every category in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Taint) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any category in `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Taint) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Taint) -> Taint {
        Taint(self.0 | other.0)
    }

    /// This set without `other`.
    #[must_use]
    pub const fn without(self, other: Taint) -> Taint {
        Taint(self.0 & !other.0)
    }

    /// Whether nothing is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for Taint {
    type Output = Taint;
    fn bitor(self, rhs: Taint) -> Taint {
        self.union(rhs)
    }
}

impl core::fmt::Debug for Taint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const NAMES: [&str; 5] = [
            "SECRET_MATERIAL",
            "UNTRUSTED_INPUT",
            "GENERATED_CODE",
            "EXTERNAL_EGRESS",
            "CREDENTIAL_ACCESS",
        ];
        write!(f, "Taint(")?;
        let mut first = true;
        for (category, name) in Taint::ALL.iter().zip(NAMES) {
            if self.contains(*category) {
                write!(f, "{}{name}", if first { "" } else { " | " })?;
                first = false;
            }
        }
        let unknown = self.0 & !0x1F;
        if unknown != 0 {
            write!(f, "{}{unknown:#x}", if first { "" } else { " | " })?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_distinct_bits_in_2_14_order() {
        for (i, category) in Taint::ALL.iter().enumerate() {
            assert_eq!(category.bits(), 1 << i);
        }
        let all = Taint::ALL.iter().fold(Taint::EMPTY, |acc, c| acc | *c);
        assert_eq!(all.bits(), 0x1F);
        assert!(all.contains(Taint::SECRET_MATERIAL | Taint::EXTERNAL_EGRESS));
        assert!(!Taint::SECRET_MATERIAL.contains(all));
        assert!(Taint::SECRET_MATERIAL.intersects(all));
        assert_eq!(all.without(Taint::UNTRUSTED_INPUT).bits(), 0x1D);
    }

    #[test]
    fn unknown_bits_survive_the_round_trip_and_are_shown() {
        let t = Taint::from_bits(1 << 9 | 1);
        assert_eq!(t.bits(), 1 << 9 | 1);
        assert_eq!(format!("{t:?}"), "Taint(SECRET_MATERIAL | 0x200)");
        assert_eq!(format!("{:?}", Taint::EMPTY), "Taint()");
    }
}
