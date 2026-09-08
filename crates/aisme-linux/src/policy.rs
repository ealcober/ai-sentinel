// SPDX-License-Identifier: Apache-2.0
//! `BpfTrieBackend`: a compiled policy as bytes a `BPF_MAP_TYPE_LPM_TRIE` will
//! accept (`F2.WS.04`).
//!
//! **Nothing in the kernel reads this map at F2.** The seam being proven is
//! *compile → artefact → atomic publish*; kernel-side evaluation is F3's, and
//! the plan's "Why each seam matters" table says so. Publishing to a map nobody
//! reads looks wasteful until one asks what the alternative proves: a
//! user-space double buffer would show the compiler produces bytes, not that it
//! produces bytes a BPF map accepts — and the key layout, the value size and
//! the update semantics are exactly where a compiler's output meets reality.

use aisme_core::policy::{BackendKind, CompiledPolicy, LowerError, PolicyBackend, Term};
use aisme_ebpf_common::Verdict;

/// Bytes of path an LPM trie key carries.
///
/// The wire's own bound (`FilePayload::path` is 200 bytes), so a path that
/// cannot be a key could not have been an event either.
pub const TRIE_PATH_BYTES: usize = 200;

/// Entries each policy trie holds.
///
/// Matches `AISME_POLICY_A` and `AISME_POLICY_B` in `crates/aisme-ebpf`, which
/// declare `with_max_entries(1024, 0)`. The two numbers are the same fact in
/// two crates that cannot see each other, so a policy that would not fit is
/// **refused at lowering** with both numbers rather than truncated: a truncated
/// policy denies less than the one the operator wrote, which is the dangerous
/// direction.
pub const POLICY_TRIE_ENTRIES: usize = 1024;

/// One entry: an LPM trie key and the verdict it carries.
///
/// `repr(C)` and in this order because that is the layout the kernel reads —
/// `bpf_lpm_trie_key` is `{ u32 prefixlen; u8 data[]; }` — so the struct is the
/// key, not a description of one.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrieEntry {
    /// Significant **bits** of `path`, which is what LPM matches on.
    pub prefix_len: u32,
    /// The prefix, NUL-padded.
    pub path: [u8; TRIE_PATH_BYTES],
    /// The verdict's wire byte (§B.10).
    pub verdict: u8,
}

impl TrieEntry {
    /// The key half, as the kernel expects it: `prefixlen` then `data`.
    #[must_use]
    pub fn key_bytes(&self) -> [u8; 4 + TRIE_PATH_BYTES] {
        let mut out = [0u8; 4 + TRIE_PATH_BYTES];
        out[..4].copy_from_slice(&self.prefix_len.to_ne_bytes());
        out[4..].copy_from_slice(&self.path);
        out
    }
}

/// What `lower` produces: the entries, in policy order.
///
/// Order matters even though a trie is order-independent on lookup, because the
/// **publisher** writes them in this order and a reader comparing two images
/// compares two sequences.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrieImage {
    /// The entries.
    pub entries: Vec<TrieEntry>,
}

/// The policy maps' object, embedded when `cargo xtask build-ebpf` produced one.
#[cfg(policy_object_present)]
const POLICY_OBJECT: &[u8] = include_bytes!(env!("AISME_POLICY_OBJECT"));
/// No object was built; the probe says so and names the command.
#[cfg(not(policy_object_present))]
const POLICY_OBJECT: &[u8] = &[];

/// Load the policy maps on this kernel and say what happened (`F2.WS.04`).
///
/// A separate object with no programs, so the answer is about the maps and
/// nothing else. Returns the map names it created, or the loader's failure with
/// **every link of its cause** — a wrapper whose `Display` is a constant is how
/// one real failure became "aya cannot parse this toolchain's BTF", which is a
/// cause asserted rather than established.
///
/// # Errors
///
/// `Unsupported` when the object is absent or the kernel refuses it.
pub fn load_policy_maps() -> aisme_core::error::Result<Vec<String>> {
    use aisme_core::error::Error;
    if POLICY_OBJECT.is_empty() {
        return Err(Error::unsupported(
            "no policy object is embedded; run `cargo xtask build-ebpf` and rebuild",
        ));
    }
    let ebpf = aya::EbpfLoader::new()
        .load(POLICY_OBJECT)
        .map_err(|e| Error::unsupported(crate::sensor::error_chain(&e)))?;
    let mut names: Vec<String> = ebpf.maps().map(|(name, _)| name.to_owned()).collect();
    names.sort();
    Ok(names)
}

/// Lowers a compiled policy into LPM trie entries.
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfTrieBackend;

impl PolicyBackend for BpfTrieBackend {
    type Artifact = TrieImage;

    fn kind(&self) -> BackendKind {
        BackendKind::BpfTrie
    }

    fn lower(&self, policy: &CompiledPolicy) -> Result<TrieImage, LowerError> {
        let plan = self.plan(policy);
        // A rule the target cannot express is an error, never a silent drop
        // (`F1.PL.08`). The plan already decided; `lower` refuses on its word
        // rather than making the judgement a second time and possibly
        // differently.
        if let Some((rule_id, rejection)) = plan.rejected.first() {
            return Err(LowerError {
                backend: BackendKind::BpfTrie,
                rule_id: Some(rule_id.clone()),
                message: format!("{rejection:?}"),
            });
        }

        let mut image = TrieImage::default();
        for rule in &policy.rules {
            let enforced = plan
                .accepted
                .iter()
                .find(|l| l.rule_id == rule.id)
                .map_or(rule.verdict, |l| l.enforced);
            for term in &rule.predicate.terms {
                // Only prefixes become trie keys. A glob is accepted by the
                // plan and matched elsewhere; putting a `*` in a trie key would
                // make the map claim a match it cannot perform.
                if let Term::PathUnder(prefixes) = term {
                    for prefix in prefixes {
                        image.entries.push(entry_for(prefix, enforced)?);
                    }
                }
            }
        }
        if image.entries.len() > POLICY_TRIE_ENTRIES {
            return Err(LowerError {
                backend: BackendKind::BpfTrie,
                rule_id: None,
                message: format!(
                    "{} prefixes exceed the {POLICY_TRIE_ENTRIES}-entry policy trie; publishing \
                     part of a policy would deny less than the one written",
                    image.entries.len()
                ),
            });
        }
        Ok(image)
    }
}

/// One prefix as a trie entry.
fn entry_for(prefix: &str, verdict: Verdict) -> Result<TrieEntry, LowerError> {
    let bytes = prefix.as_bytes();
    if bytes.len() > TRIE_PATH_BYTES {
        // Truncating would make the key match a *shorter* prefix — a broader
        // rule than the one written — so the only honest answer is to refuse.
        return Err(LowerError {
            backend: BackendKind::BpfTrie,
            rule_id: None,
            message: format!(
                "path prefix of {} bytes exceeds the {TRIE_PATH_BYTES}-byte trie key; \
                 truncating it would widen the rule",
                bytes.len()
            ),
        });
    }
    let mut path = [0u8; TRIE_PATH_BYTES];
    path[..bytes.len()].copy_from_slice(bytes);
    Ok(TrieEntry {
        // Bits, not bytes: LPM matches bit-wise, and a prefix of N bytes is
        // 8N significant bits.
        prefix_len: u32::try_from(bytes.len() * 8).unwrap_or(u32::MAX),
        path,
        verdict: verdict.code(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisme_core::policy::{compile, parse, Bindings};

    /// The policy an operator edits, compiled by the real compiler.
    const SKELETON: &str = include_str!("../../../deploy/policy/skeleton.aisme");

    fn skeleton() -> CompiledPolicy {
        let policy =
            parse(SKELETON).unwrap_or_else(|e| panic!("the shipped policy parses: {e:#?}"));
        let bindings = Bindings::new().with("workspace", "/home/u/proj");
        compile(&policy, &bindings)
            .unwrap_or_else(|e| panic!("the shipped policy compiles: {e:#?}"))
    }

    /// The file that ships is the file that compiles. A skeleton policy nobody
    /// compiles is a document, not a policy.
    #[test]
    fn the_shipped_policy_file_compiles_with_the_real_compiler() {
        let compiled = skeleton();
        let ids: Vec<&str> = compiled.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["deny-shadow", "escalate-aws", "scope-writes"]);
        assert_eq!(compiled.settings.learning_mode_days, 7);
    }

    /// Every rule of the shipped policy is accounted for: accepted with the
    /// verdict this target will enforce, or rejected by name. Nothing is
    /// dropped in silence.
    #[test]
    fn the_bpf_trie_accounts_for_every_rule_of_the_shipped_policy() {
        let compiled = skeleton();
        let plan = BpfTrieBackend.plan(&compiled);
        assert!(
            plan.rejected.is_empty(),
            "the L3 trie takes all three: {:?}",
            plan.rejected
        );
        assert_eq!(plan.accepted.len(), compiled.rules.len());
        // The trie is the exact backend (§B.9): it enforces what was written.
        for lowered in &plan.accepted {
            assert_eq!(
                lowered.written, lowered.enforced,
                "rule {} was rewritten",
                lowered.rule_id
            );
        }
        assert_eq!(plan.changed().count(), 0);
    }

    /// Lowering produces keys the kernel's layout accepts, with the verdict of
    /// the rule that produced them.
    #[test]
    fn lowering_the_shipped_policy_yields_prefix_keys_with_their_verdicts() {
        let compiled = skeleton();
        let image = BpfTrieBackend.lower(&compiled).expect("it lowers");
        // Two `path_under` terms: /etc/shadow and the bound workspace. The
        // glob rule contributes no trie key, which is the point of only
        // lowering prefixes.
        assert_eq!(image.entries.len(), 2, "{image:?}");
        assert!(
            image.entries.len() <= POLICY_TRIE_ENTRIES,
            "the shipped policy is publishable, not merely lowerable"
        );

        let shadow = image
            .entries
            .iter()
            .find(|e| e.path.starts_with(b"/etc/shadow"))
            .expect("the denied prefix is a key");
        assert_eq!(shadow.verdict, Verdict::Deny.code());
        assert_eq!(
            shadow.prefix_len,
            u32::try_from("/etc/shadow".len() * 8).expect("a short constant"),
            "LPM matches bits, not bytes"
        );

        let key = shadow.key_bytes();
        assert_eq!(key.len(), 4 + TRIE_PATH_BYTES);
        assert_eq!(&key[..4], &shadow.prefix_len.to_ne_bytes());
        assert_eq!(&key[4..15], b"/etc/shadow");
    }

    /// The key this backend produces is the key the kernel reads. `aya_ebpf`'s
    /// `Key<K>` is `#[repr(C)] { prefix_len: u32, data: K }`
    /// (`aya-ebpf-0.2.1/src/maps/lpm_trie.rs:24`), and `TrieEntry` is that
    /// followed by the verdict byte. Pinned here because the two live in crates
    /// that cannot see each other, and nothing else would notice them drifting.
    #[test]
    fn the_entry_layout_is_the_kernels_lpm_key_followed_by_the_verdict() {
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(offset_of!(TrieEntry, prefix_len), 0);
        assert_eq!(offset_of!(TrieEntry, path), 4);
        assert_eq!(offset_of!(TrieEntry, verdict), 4 + TRIE_PATH_BYTES);
        assert_eq!(align_of::<TrieEntry>(), 4, "a u32 first, then bytes");
        assert!(size_of::<TrieEntry>() > 4 + TRIE_PATH_BYTES);

        let entry = entry_for("/etc", Verdict::Deny).expect("short enough");
        let key = entry.key_bytes();
        assert_eq!(key.len(), 4 + TRIE_PATH_BYTES, "prefix_len then data");
        assert_eq!(&key[..4], &32u32.to_ne_bytes(), "four bytes is 32 bits");
        assert_eq!(&key[4..8], b"/etc");
    }

    /// A policy that does not fit the trie is refused, with both numbers.
    /// Publishing part of it would enforce less than the operator wrote.
    #[test]
    fn a_policy_larger_than_the_trie_is_refused_with_both_numbers() {
        let mut compiled = skeleton();
        let prefixes: Vec<String> = (0..=POLICY_TRIE_ENTRIES)
            .map(|i| format!("/p{i}"))
            .collect();
        let mut oversized = compiled
            .rules
            .first()
            .cloned()
            .expect("the policy has rules");
        oversized.predicate.terms = vec![Term::PathUnder(prefixes)];
        compiled.rules = vec![oversized];

        let err = BpfTrieBackend
            .lower(&compiled)
            .expect_err("it must not publish a partial policy");
        assert!(
            err.message.contains(&POLICY_TRIE_ENTRIES.to_string()),
            "{err}"
        );
        assert!(
            err.message.contains(&(POLICY_TRIE_ENTRIES + 1).to_string()),
            "the message names what was asked for too: {err}"
        );
    }

    /// A prefix longer than the key is refused, not truncated: a truncated key
    /// matches a shorter prefix, which is a *broader* rule than the one
    /// written — the policy would silently become more permissive.
    #[test]
    fn a_prefix_too_long_for_the_key_is_refused_rather_than_truncated() {
        let long = format!("/{}", "a".repeat(TRIE_PATH_BYTES));
        let err = entry_for(&long, Verdict::Deny).expect_err("refused");
        assert_eq!(err.backend, BackendKind::BpfTrie);
        assert!(err.message.contains("would widen the rule"), "{err}");
    }
}
