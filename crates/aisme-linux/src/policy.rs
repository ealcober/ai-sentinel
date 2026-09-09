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

use aisme_core::policy::{
    BackendKind, CompiledPolicy, LowerError, PolicyBackend, PolicyGeneration, Term,
};
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
    /// A lookup key for `path`: every bit significant, so the kernel returns
    /// the **longest stored prefix** that matches rather than an exact hit.
    ///
    /// A lookup whose `prefix_len` were the path's own length would ask for a
    /// rule of exactly that shape and miss the broader rule that actually
    /// covers it — which is the whole point of an LPM trie.
    #[must_use]
    pub fn lookup(path: &str) -> TrieEntry {
        let mut bytes = [0u8; TRIE_PATH_BYTES];
        let src = path.as_bytes();
        let n = src.len().min(TRIE_PATH_BYTES);
        bytes[..n].copy_from_slice(&src[..n]);
        TrieEntry {
            prefix_len: u32::try_from(TRIE_PATH_BYTES * 8).unwrap_or(u32::MAX),
            path: bytes,
            verdict: 0,
        }
    }

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

// ---------------------------------------------------------------------------
// Publication (`F2.WS.04`; `docs/06` points 3 and 4)
// ---------------------------------------------------------------------------

/// Where the maps are pinned so they outlive the loader.
///
/// A BPF map is owned by an fd and dies with the last one, so a loader that
/// creates the maps and exits destroys them. `bpffs` holds a reference, which
/// is what lets the privileged half be `Type=oneshot` instead of a process
/// holding `CAP_BPF` for the machine's uptime.
///
/// `agentd` is handed no descriptor to these, readable or writable: passing one
/// over `SCM_RIGHTS` would leave its empty `CapabilityBoundingSet=` decorative,
/// the capability gone and the authority kept (`F1.RT.07`, `docs/06` point 3).
pub const PIN_DIR: &str = "/sys/fs/bpf/aisme";

/// The two tries and the meta array, by the names the object declares.
pub const MAP_POLICY_A: &str = "AISME_POLICY_A";
/// The idle half of the double buffer, whichever it is at the time.
pub const MAP_POLICY_B: &str = "AISME_POLICY_B";
/// `[generation, active_index]`.
pub const MAP_POLICY_META: &str = "AISME_POLICY_META";

/// `meta[0]` — the generation in force.
pub const META_GENERATION: u32 = 0;
/// `meta[1]` — which trie is active. **Written last; that write is the
/// publication.**
pub const META_ACTIVE_INDEX: u32 = 1;

/// The three maps, opened from their pins.
struct PolicyMaps {
    a: aya::maps::LpmTrie<aya::maps::MapData, [u8; TRIE_PATH_BYTES], u8>,
    b: aya::maps::LpmTrie<aya::maps::MapData, [u8; TRIE_PATH_BYTES], u8>,
    meta: aya::maps::Array<aya::maps::MapData, u64>,
}

fn pin_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(PIN_DIR).join(name)
}

/// Create the pin directory, or say why it could not be created.
///
/// A missing `bpffs` is **not** a reason to fall back to staying resident: that
/// would turn the privilege split off on exactly the machines whose
/// configuration is unusual. It is a named failure instead.
fn ensure_pin_dir() -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;
    use std::os::unix::fs::PermissionsExt as _;
    let bpffs = std::path::Path::new("/sys/fs/bpf");
    if !bpffs.is_dir() {
        return Err(Error::unsupported(
            "/sys/fs/bpf is not mounted; mount -t bpf bpffs /sys/fs/bpf (the loader will not stay resident instead)",
        ));
    }
    let dir = std::path::Path::new(PIN_DIR);
    if !dir.is_dir() {
        std::fs::create_dir(dir)
            .map_err(|e| Error::unsupported(format!("cannot create {PIN_DIR}: {e}")))?;
    }
    // 0700: a world-writable pin directory would hand the authority back to
    // anyone on the machine, which is the same defect as passing agentd a
    // writable fd, by another route.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::unsupported(format!("cannot set mode 0700 on {PIN_DIR}: {e}")))
}

/// Open the three maps, pinning them from the sensor's object the first time.
///
/// The maps live in the sensor's own object (`crates/aisme-ebpf`), in the
/// legacy `maps` section: `BPF_MAP_TYPE_ARRAY_OF_MAPS` exists at the pinned
/// `aya-ebpf 0.2.1` only as a BTF map, and this toolchain's BTF is unreadable
/// to `aya-obj 0.3.0` (`docs/06` point 1, measured on 6.8 and 5.4).
///
/// Loading that object also loads its programs, so on a kernel that refuses one
/// — 5.4 refuses `BPF_MAP_TYPE_RINGBUF` — the first publication fails with that
/// kernel's own reason. That is the stated degradation, not a defect here:
/// `docs/05` point 1 hands 5.4's perf-buffer path to `F3.PT.*`.
fn open_maps() -> aisme_core::error::Result<PolicyMaps> {
    use aisme_core::error::Error;
    use aya::maps::{Array, LpmTrie, Map, MapData};

    ensure_pin_dir()?;
    if !pin_path(MAP_POLICY_META).exists() {
        if crate::sensor::OBJECT.is_empty() {
            return Err(Error::unsupported(
                "no BPF object is embedded; run `cargo xtask build-ebpf` and rebuild",
            ));
        }
        let mut ebpf = aya::EbpfLoader::new()
            .load(crate::sensor::OBJECT)
            .map_err(|e| Error::unsupported(crate::sensor::error_chain(&e)))?;
        for name in [MAP_POLICY_A, MAP_POLICY_B, MAP_POLICY_META] {
            let map = ebpf
                .take_map(name)
                .ok_or_else(|| Error::unsupported(format!("the object declares no {name}")))?;
            map.pin(pin_path(name))
                .map_err(|e| Error::unsupported(format!("cannot pin {name}: {e}")))?;
        }
    }
    let open = |name: &str| -> aisme_core::error::Result<MapData> {
        MapData::from_pin(pin_path(name))
            .map_err(|e| Error::unsupported(format!("cannot open pinned {name}: {e}")))
    };
    let as_trie = |data: MapData, name: &str| {
        // `try_from` takes the `Map` enum, not the bare data: the variant is
        // what asserts the kind, and a pin opened as the wrong kind fails here
        // rather than at the first lookup.
        LpmTrie::try_from(Map::LpmTrie(data))
            .map_err(|e| Error::unsupported(format!("{name} is not an LPM trie: {e}")))
    };
    Ok(PolicyMaps {
        a: as_trie(open(MAP_POLICY_A)?, MAP_POLICY_A)?,
        b: as_trie(open(MAP_POLICY_B)?, MAP_POLICY_B)?,
        meta: Array::try_from(Map::Array(open(MAP_POLICY_META)?))
            .map_err(|e| Error::unsupported(format!("{MAP_POLICY_META} is not an array: {e}")))?,
    })
}

/// Open the three maps from their pins, creating nothing.
///
/// A reader must never create a map: doing so would hand it an empty policy it
/// would then read as "nothing is denied". Absent pins are an error here.
///
/// # Errors
///
/// When the pins are not there, or are not the kinds they should be.
fn open_pinned() -> aisme_core::error::Result<PolicyMaps> {
    use aisme_core::error::Error;
    use aya::maps::{Array, LpmTrie, Map, MapData};

    let open = |name: &str| -> aisme_core::error::Result<MapData> {
        MapData::from_pin(pin_path(name))
            .map_err(|e| Error::unsupported(format!("cannot open pinned {name}: {e}")))
    };
    let as_trie = |data: MapData, name: &str| {
        LpmTrie::try_from(Map::LpmTrie(data))
            .map_err(|e| Error::unsupported(format!("{name} is not an LPM trie: {e}")))
    };
    Ok(PolicyMaps {
        a: as_trie(open(MAP_POLICY_A)?, MAP_POLICY_A)?,
        b: as_trie(open(MAP_POLICY_B)?, MAP_POLICY_B)?,
        meta: Array::try_from(Map::Array(open(MAP_POLICY_META)?))
            .map_err(|e| Error::unsupported(format!("{MAP_POLICY_META} is not an array: {e}")))?,
    })
}

/// What one pass of a reader saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// `meta[0]` as read.
    pub generation: u64,
    /// `meta[1]` as read — the trie the verdict below came from.
    pub index: u64,
    /// The verdict byte the trie held for the key, or `None` if it held none.
    pub verdict: Option<u8>,
}

/// A reader of the published policy, holding the maps open.
///
/// Reopening the pins per sample would measure `openat`, not the publisher.
pub struct PolicyReader {
    maps: PolicyMaps,
}

impl PolicyReader {
    /// Open the pinned maps for reading.
    ///
    /// # Errors
    ///
    /// When the pins are absent or of the wrong kind.
    pub fn open() -> aisme_core::error::Result<PolicyReader> {
        Ok(PolicyReader {
            maps: open_pinned()?,
        })
    }

    /// One pass, in the order a kernel-side reader would take it.
    ///
    /// **Index first, then the trie it names, then the generation.** That order
    /// is what the staleness argument is about: between the two lookups the
    /// publisher may swap, and what the reader then sees is a *complete* older
    /// policy, because the trie it is reading is the one the publisher has
    /// stopped writing. It never sees a half-filled trie, because the
    /// half-filled one is the one it is not reading.
    ///
    /// # Errors
    ///
    /// When a map read fails. A key that is simply absent is `verdict: None`,
    /// not an error — that is a policy answer, not a failure.
    pub fn read(&self, key: &TrieEntry) -> aisme_core::error::Result<Sample> {
        use aisme_core::error::Error;
        use aya::maps::lpm_trie::Key;

        let index = self
            .maps
            .meta
            .get(&META_ACTIVE_INDEX, 0)
            .map_err(|e| Error::unsupported(format!("cannot read the active index: {e}")))?;
        let trie = if index == 0 {
            &self.maps.a
        } else {
            &self.maps.b
        };
        let verdict = trie.get(&Key::new(key.prefix_len, key.path), 0).ok();
        let generation = self
            .maps
            .meta
            .get(&META_GENERATION, 0)
            .map_err(|e| Error::unsupported(format!("cannot read the generation: {e}")))?;
        Ok(Sample {
            generation,
            index,
            verdict,
        })
    }
}

/// Publish a lowered policy, and return the generation it became.
///
/// **The order is the property, not a description of the code.** With two named
/// tries and an index a reader takes two lookups — `meta[1]`, then the trie it
/// names — and the publisher may swap between them. The argument that this is
/// staleness and never tearing: the publisher only ever writes the **idle**
/// trie, and only ever swaps **after** it is complete, so a reader that catches
/// a swap reads a *complete* older policy. The window is one lookup, and it
/// errs toward the previous policy — safe when a policy tightens, a late allow
/// when it loosens. `ARRAY_OF_MAPS` gave this structurally and is unavailable
/// here; the price is recorded rather than discovered in F3.
///
/// `meta[1]` is written **last**. Everything before it is invisible.
///
/// # Errors
///
/// Anything that stops the publication before step 5, in which case the active
/// policy is untouched and its generation is unchanged.
pub fn publish(image: &TrieImage) -> aisme_core::error::Result<PolicyGeneration> {
    use aisme_core::error::Error;
    use aya::maps::lpm_trie::Key;

    if image.entries.len() > POLICY_TRIE_ENTRIES {
        return Err(Error::unsupported(format!(
            "policy has {} entries and the trie holds {POLICY_TRIE_ENTRIES}",
            image.entries.len()
        )));
    }
    let mut maps = open_maps()?;

    // 1. Read the active index. A fresh map reads 0, and 0 is a valid index:
    //    the meaning of "no publication yet" lives in the generation, which is
    //    then 0 and becomes 1 below.
    let active = maps
        .meta
        .get(&META_ACTIVE_INDEX, 0)
        .map_err(|e| Error::unsupported(format!("cannot read the active index: {e}")))?;
    let generation = maps
        .meta
        .get(&META_GENERATION, 0)
        .map_err(|e| Error::unsupported(format!("cannot read the generation: {e}")))?;
    let idle = u64::from(active == 0);

    // 2. Clear and fill the *idle* trie. Clearing the active one is the torn
    //    read this whole mechanism exists to avoid.
    let trie = if idle == 0 { &mut maps.a } else { &mut maps.b };
    let stale: Vec<Key<[u8; TRIE_PATH_BYTES]>> = trie
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::unsupported(format!("cannot read the idle trie: {e}")))?;
    for key in stale {
        trie.remove(&key)
            .map_err(|e| Error::unsupported(format!("cannot clear the idle trie: {e}")))?;
    }
    for (n, entry) in image.entries.iter().enumerate() {
        trie.insert(&Key::new(entry.prefix_len, entry.path), entry.verdict, 0)
            .map_err(|e| {
                // The generation that was NOT published, so an operator knows
                // what is still in force rather than what was attempted.
                Error::unsupported(format!(
                    "entry {n} refused ({e}); generation {generation} is still in force"
                ))
            })?;
    }

    // 3. The generation, then the index. Monotonic and never reused: a
    //    generation that went backwards would make a WAL segment header
    //    ambiguous about which policy produced a decision.
    let next = generation + 1;
    maps.meta
        .set(META_GENERATION, next, 0)
        .map_err(|e| Error::unsupported(format!("cannot write the generation: {e}")))?;
    // 4. THE PUBLICATION.
    maps.meta
        .set(META_ACTIVE_INDEX, idle, 0)
        .map_err(|e| Error::unsupported(format!("cannot publish: {e}")))?;
    Ok(PolicyGeneration(next))
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
