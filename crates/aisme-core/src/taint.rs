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

/// The propagation and declassification algebra (`F1.ON.04`): pure
/// functions over [`Taint`], in the order §2.14 states them. The policy (F7)
/// decides *when* each applies; nothing here does I/O or reads a clock.
impl Taint {
    /// Categories that never decay within a process's lifetime.
    pub const PERSISTENT: Taint = Taint(
        Taint::SECRET_MATERIAL.0
            | Taint::GENERATED_CODE.0
            | Taint::EXTERNAL_EGRESS.0
            | Taint::CREDENTIAL_ACCESS.0,
    );

    /// Categories that expire after [`DecayPolicy::untrusted_input_ttl_ns`]
    /// without related activity.
    pub const DECAYING: Taint = Taint::UNTRUSTED_INPUT;

    /// The categories whose egress the Network Slam gates.
    pub const SLAM_TRIGGERS: Taint = Taint(Taint::SECRET_MATERIAL.0 | Taint::CREDENTIAL_ACCESS.0);

    /// `fork`/`clone`/`execve`: the child inherits everything, unknown bits
    /// included — a category this binary does not name is still a category.
    #[must_use]
    pub const fn inherit(parent: Taint) -> Taint {
        parent
    }

    /// A pipe or UNIX socket between two processes of the same session: the
    /// receiver acquires the sender's categories. Whether the two are in the
    /// same session is the caller's fact; the algebra is the union.
    #[must_use]
    pub const fn on_ipc(receiver: Taint, sender: Taint) -> Taint {
        receiver.union(sender)
    }

    /// A write by a process labels the file with the writer's categories.
    #[must_use]
    pub const fn label_on_write(file: Taint, writer: Taint) -> Taint {
        file.union(writer)
    }

    /// A read of a labelled file taints the reader with the file's label.
    #[must_use]
    pub const fn on_read(reader: Taint, file: Taint) -> Taint {
        reader.union(file)
    }

    /// A network fetch — `git clone`, `curl -o`, a package install — labels
    /// the target tree root as untrusted input. The fetching process carries
    /// the same label, since its output is the fetch.
    #[must_use]
    pub const fn label_on_fetch(root: Taint) -> Taint {
        root.union(Taint::UNTRUSTED_INPUT)
    }

    /// What survives at `now`, given when the process last did something
    /// related: the decaying categories expire, the persistent ones do not.
    #[must_use]
    pub const fn decay(self, last_activity_ns: u64, now_ns: u64, policy: DecayPolicy) -> Taint {
        let idle = now_ns.saturating_sub(last_activity_ns);
        if idle > policy.untrusted_input_ttl_ns {
            self.without(Taint::DECAYING)
        } else {
            self
        }
    }

    /// Explicit declassification: release `categories` for `reason`, which
    /// the caller records as a `declassified_by` edge. Returns what remains
    /// and the record. Nothing else in the algebra removes a category.
    #[must_use]
    pub const fn declassify(
        self,
        categories: Taint,
        reason: Declassification,
    ) -> (Taint, Declassified) {
        let released = Taint(self.0 & categories.0);
        (self.without(categories), Declassified { released, reason })
    }

    /// The Network Slam's compound condition, §2.14: a slam-triggering
    /// category is present **and** the destination is outside the session
    /// allowlist **and** no declassification is in effect. Taint alone never
    /// fires it, which is the whole correction of `H-13`.
    #[must_use]
    pub const fn slam_condition(self, destination_allowlisted: bool, declassified: bool) -> bool {
        self.intersects(Taint::SLAM_TRIGGERS) && !destination_allowlisted && !declassified
    }
}

/// How long the decaying categories live without related activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecayPolicy {
    /// `UNTRUSTED_INPUT`'s time to live. §2.14 default: 300 s.
    pub untrusted_input_ttl_ns: u64,
}

impl DecayPolicy {
    /// §2.14's default: 300 seconds.
    pub const DEFAULT: DecayPolicy = DecayPolicy {
        untrusted_input_ttl_ns: 300 * 1_000_000_000,
    };
}

impl Default for DecayPolicy {
    fn default() -> DecayPolicy {
        DecayPolicy::DEFAULT
    }
}

/// The three explicit declassifications §2.14 admits. A permission grant is
/// **not** one of them (owner decision): it answers the file question only,
/// and egress stays gated by the compound condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Declassification {
    /// The secret file belongs to the workspace and is in `.gitignore`, and
    /// the network destination is in the project allowlist.
    GitignoredToAllowlisted,
    /// The user marked the path as trusted in the UI.
    UserTrustedPath,
    /// The write targets a local file inside the workspace — not exfiltration.
    LocalWriteInsideWorkspace,
}

/// What a declassification released, and why — the `declassified_by` edge's
/// content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declassified {
    /// The categories actually released (those that were set).
    pub released: Taint,
    /// The justification.
    pub reason: Declassification,
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
    fn propagation_is_inheritance_and_union_in_every_direction() {
        let secret = Taint::SECRET_MATERIAL;
        let untrusted = Taint::UNTRUSTED_INPUT;
        assert_eq!(Taint::inherit(secret | untrusted), secret | untrusted);
        assert_eq!(Taint::on_ipc(Taint::EMPTY, secret), secret);
        assert_eq!(Taint::label_on_write(Taint::EMPTY, secret), secret);
        assert_eq!(Taint::on_read(untrusted, secret), secret | untrusted);
        assert_eq!(Taint::label_on_fetch(Taint::EMPTY), untrusted);
        // A category this binary does not name still propagates.
        let unknown = Taint::from_bits(1 << 20);
        assert_eq!(Taint::inherit(unknown), unknown);
        assert!(Taint::on_read(Taint::EMPTY, unknown).contains(unknown));
    }

    #[test]
    fn only_untrusted_input_decays_and_only_after_the_ttl() {
        let policy = DecayPolicy::DEFAULT;
        let all = Taint::ALL.iter().fold(Taint::EMPTY, |acc, c| acc | *c);
        let ttl = policy.untrusted_input_ttl_ns;
        assert_eq!(ttl, 300_000_000_000, "§2.14: 300 s");
        assert_eq!(
            all.decay(0, ttl, policy),
            all,
            "at the bound it still holds"
        );
        assert_eq!(
            all.decay(0, ttl + 1, policy),
            all.without(Taint::UNTRUSTED_INPUT)
        );
        assert_eq!(
            Taint::SECRET_MATERIAL.decay(0, u64::MAX, policy),
            Taint::SECRET_MATERIAL
        );
        // Activity resets the clock: last_activity later than now is idle 0.
        assert_eq!(all.decay(ttl * 2, ttl, policy), all);
        assert_eq!(Taint::PERSISTENT | Taint::DECAYING, all);
    }

    #[test]
    fn declassification_is_explicit_and_recorded_and_a_grant_is_not_one() {
        let taint = Taint::SECRET_MATERIAL | Taint::UNTRUSTED_INPUT;
        let (left, record) = taint.declassify(
            Taint::SECRET_MATERIAL | Taint::GENERATED_CODE,
            Declassification::GitignoredToAllowlisted,
        );
        assert_eq!(left, Taint::UNTRUSTED_INPUT);
        assert_eq!(record.released, Taint::SECRET_MATERIAL, "only what was set");
        assert_eq!(record.reason, Declassification::GitignoredToAllowlisted);
        // A grant answers the file question only: no function here takes one,
        // and the taint a process carries into a granted read is what it
        // carries out.
        assert_eq!(Taint::on_read(taint, Taint::EMPTY), taint);
    }

    #[test]
    fn the_slam_fires_on_the_compound_condition_never_on_taint_alone() {
        let secret = Taint::SECRET_MATERIAL;
        assert!(secret.slam_condition(false, false));
        assert!(Taint::CREDENTIAL_ACCESS.slam_condition(false, false));
        assert!(
            !secret.slam_condition(true, false),
            "allowlisted destination"
        );
        assert!(!secret.slam_condition(false, true), "declassified");
        assert!(
            !Taint::UNTRUSTED_INPUT.slam_condition(false, false),
            "not a slam trigger"
        );
        assert!(!Taint::EMPTY.slam_condition(false, false));
        // The §2.14 workflows that must not break: .env read by the test
        // runner, then npm install against the registry — allowlisted.
        let test_runner = Taint::on_read(Taint::EMPTY, secret);
        assert!(!test_runner.slam_condition(true, false));
    }

    #[test]
    fn unknown_bits_survive_the_round_trip_and_are_shown() {
        let t = Taint::from_bits(1 << 9 | 1);
        assert_eq!(t.bits(), 1 << 9 | 1);
        assert_eq!(format!("{t:?}"), "Taint(SECRET_MATERIAL | 0x200)");
        assert_eq!(format!("{:?}", Taint::EMPTY), "Taint()");
    }
}
