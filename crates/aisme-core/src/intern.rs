// SPDX-License-Identifier: Apache-2.0
//! The string interner (`F1.EV.04`): `StrId`, a fixed arena, LRU eviction.
//!
//! Strings reach user space as inline bounded arrays in the payload (plan
//! §F1.1) and are interned here at ingest, so the causal graph carries a
//! `u32` per path instead of the path. Three properties are load-bearing:
//!
//! - **Bounded memory, no growth.** Every byte the interner will ever own is
//!   allocated when it is built — the arena, the slot table, the index — and
//!   nothing is allocated afterwards. When it is full, the least recently used
//!   entry is evicted and counted. The hot loop's zero-allocation property
//!   (`F1.RT.03`) rests on this.
//! - **A stale id is reported, not resolved.** An evicted slot is reused, so an
//!   id issued before the eviction must not resolve to whatever moved in; the
//!   id carries the slot's generation and [`Interner::resolve`] returns `None`
//!   on a mismatch. Reading an absence as a value is general rule 9's defect;
//!   here it would put the wrong path in a forensic record.
//! - **Deterministic.** Same inputs in the same order, same ids, same
//!   evictions — the replay tests depend on it.
//!
//! Entries are bytes, not `str`: kernel paths carry no encoding guarantee.

/// A handle to an interned string: the slot in the low 16 bits, the slot's
/// generation in the high 16. Zero is never issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StrId(u32);

impl StrId {
    /// The handle that names nothing; no interned string ever gets it.
    pub const NONE: StrId = StrId(0);

    /// The raw value, for the wire and the WAL.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// A handle from its raw value. Whether it still resolves is the
    /// interner's to say.
    #[must_use]
    pub const fn from_raw(raw: u32) -> StrId {
        StrId(raw)
    }

    const fn new(slot: u16, generation: u16) -> StrId {
        StrId((generation as u32) << 16 | slot as u32)
    }

    const fn slot(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    const fn generation(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// The string offered was longer than a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong {
    /// The string's length.
    pub len: usize,
    /// The most a slot holds.
    pub max: usize,
}

impl core::fmt::Display for TooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "string of {} bytes exceeds the interner's slot of {} bytes",
            self.len, self.max
        )
    }
}

impl core::error::Error for TooLong {}

/// What the interner has done, for self-observability (`F1.RT.06`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InternerStats {
    /// Entries currently held.
    pub len: usize,
    /// Slots in total; `len` never exceeds it.
    pub capacity: usize,
    /// Interns that found the string already present.
    pub hits: u64,
    /// Interns that stored a new string.
    pub misses: u64,
    /// Entries evicted to make room.
    pub evictions: u64,
    /// Bytes of arena in use by live entries.
    pub bytes_in_use: usize,
}

const NONE: u16 = u16::MAX;
/// The index entry for a free bucket.
const EMPTY: u16 = u16::MAX;

/// A bounded, LRU-evicting interner over fixed-size slots.
pub struct Interner {
    /// `capacity × slot_bytes`, allocated once.
    arena: Vec<u8>,
    slot_bytes: usize,
    /// Per-slot metadata, allocated once.
    len: Vec<u16>,
    generation: Vec<u16>,
    hash: Vec<u64>,
    /// LRU list over slots: `prev` towards most recent, `next` towards least.
    prev: Vec<u16>,
    next: Vec<u16>,
    head: u16,
    tail: u16,
    /// Slots never used yet, handed out before any eviction.
    free: Vec<u16>,
    /// Open-addressing index: bucket → slot, power-of-two sized, linear probing
    /// with backward-shift deletion so it never accumulates tombstones.
    index: Vec<u16>,
    index_mask: usize,
    stats: InternerStats,
}

impl Interner {
    /// The plan's path interner: 16 384 slots of 256 bytes — the payload's
    /// longest inline string is 200 — for 4 MiB of arena.
    #[must_use]
    pub fn for_paths() -> Interner {
        Interner::with_capacity(16 * 1024, 256)
    }

    /// `capacity` slots of `slot_bytes` each. Everything is allocated here.
    ///
    /// # Panics
    ///
    /// When `capacity` is zero or exceeds `u16::MAX - 1`, or `slot_bytes` is
    /// zero or exceeds `u16::MAX`: the id packs the slot in 16 bits.
    #[must_use]
    pub fn with_capacity(capacity: usize, slot_bytes: usize) -> Interner {
        assert!(
            (1..usize::from(u16::MAX)).contains(&capacity),
            "capacity must be 1..=65534, got {capacity}"
        );
        assert!(
            (1..=usize::from(u16::MAX)).contains(&slot_bytes),
            "slot_bytes must be 1..=65535, got {slot_bytes}"
        );
        // At most half full, so probe sequences stay short and the table
        // never needs to grow.
        let index_len = (capacity * 2).next_power_of_two();
        #[allow(clippy::cast_possible_truncation)] // capacity < u16::MAX, checked above
        let free: Vec<u16> = (0..capacity as u16).rev().collect();
        Interner {
            arena: vec![0; capacity * slot_bytes],
            slot_bytes,
            len: vec![0; capacity],
            // Generation 1 on first use, so a raw zero never resolves.
            generation: vec![1; capacity],
            hash: vec![0; capacity],
            prev: vec![NONE; capacity],
            next: vec![NONE; capacity],
            head: NONE,
            tail: NONE,
            free,
            index: vec![EMPTY; index_len],
            index_mask: index_len - 1,
            stats: InternerStats {
                capacity,
                ..InternerStats::default()
            },
        }
    }

    /// Intern `bytes`, returning its handle. An existing entry is touched as
    /// most recently used; a new one evicts the least recently used when
    /// every slot is taken.
    ///
    /// # Errors
    ///
    /// [`TooLong`] when `bytes` exceeds a slot; nothing is stored.
    pub fn intern(&mut self, bytes: &[u8]) -> Result<StrId, TooLong> {
        if bytes.len() > self.slot_bytes {
            return Err(TooLong {
                len: bytes.len(),
                max: self.slot_bytes,
            });
        }
        let hash = fnv1a_64(bytes);
        if let Some(slot) = self.find(hash, bytes) {
            self.stats.hits += 1;
            self.touch(slot);
            return Ok(StrId::new(slot, self.generation[usize::from(slot)]));
        }
        self.stats.misses += 1;
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => self.evict_tail(),
        };
        let s = usize::from(slot);
        let start = s * self.slot_bytes;
        self.arena[start..start + bytes.len()].copy_from_slice(bytes);
        #[allow(clippy::cast_possible_truncation)] // bytes.len() <= slot_bytes <= u16::MAX
        {
            self.len[s] = bytes.len() as u16;
        }
        self.hash[s] = hash;
        self.index_insert(hash, slot);
        self.push_front(slot);
        self.stats.len += 1;
        self.stats.bytes_in_use += bytes.len();
        Ok(StrId::new(slot, self.generation[s]))
    }

    /// The bytes behind a handle, or `None` when the handle is stale — its
    /// slot was evicted and reused since it was issued — or was never issued.
    #[must_use]
    pub fn resolve(&self, id: StrId) -> Option<&[u8]> {
        let s = usize::from(id.slot());
        if id == StrId::NONE
            || s >= self.stats.capacity
            || self.generation[s] != id.generation()
            || self.len[s] == 0 && !self.is_live(id.slot())
        {
            return None;
        }
        let start = s * self.slot_bytes;
        Some(&self.arena[start..start + usize::from(self.len[s])])
    }

    /// What the interner has done so far.
    #[must_use]
    pub const fn stats(&self) -> InternerStats {
        self.stats
    }

    /// Entries currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stats.len
    }

    /// Whether nothing is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stats.len == 0
    }

    fn is_live(&self, slot: u16) -> bool {
        self.head == slot || self.prev[usize::from(slot)] != NONE
    }

    fn slot_bytes_of(&self, slot: u16) -> &[u8] {
        let s = usize::from(slot);
        let start = s * self.slot_bytes;
        &self.arena[start..start + usize::from(self.len[s])]
    }

    /// The home bucket of a hash. Masked to `index_mask`, which is a `usize`,
    /// so the narrowing cast cannot truncate anything the mask kept.
    #[allow(clippy::cast_possible_truncation)]
    fn home(&self, hash: u64) -> usize {
        (hash & self.index_mask as u64) as usize
    }

    fn find(&self, hash: u64, bytes: &[u8]) -> Option<u16> {
        let mut bucket = self.home(hash);
        loop {
            let slot = self.index[bucket];
            if slot == EMPTY {
                return None;
            }
            if self.hash[usize::from(slot)] == hash && self.slot_bytes_of(slot) == bytes {
                return Some(slot);
            }
            bucket = (bucket + 1) & self.index_mask;
        }
    }

    fn index_insert(&mut self, hash: u64, slot: u16) {
        let mut bucket = self.home(hash);
        while self.index[bucket] != EMPTY {
            bucket = (bucket + 1) & self.index_mask;
        }
        self.index[bucket] = slot;
    }

    /// Remove `slot` from the index, shifting later entries of the probe run
    /// back so no tombstone is left behind.
    fn index_remove(&mut self, slot: u16) {
        let mut hole = self.home(self.hash[usize::from(slot)]);
        while self.index[hole] != slot {
            hole = (hole + 1) & self.index_mask;
        }
        // Walk the rest of the probe run. An entry whose home bucket lies in
        // the cyclic interval (hole, j] must stay where it is — moving it
        // before its home would make it unfindable — but the scan goes on
        // past it, because a later entry may still be able to fill the hole.
        // Stopping at the first fixed entry is the bug this replaces: it left
        // live entries stranded behind the hole, and `intern` then stored
        // them again, evicting something else to do it.
        let mut j = hole;
        loop {
            j = (j + 1) & self.index_mask;
            let candidate = self.index[j];
            if candidate == EMPTY {
                break;
            }
            let its_home = self.home(self.hash[usize::from(candidate)]);
            let fixed = if hole <= j {
                hole < its_home && its_home <= j
            } else {
                hole < its_home || its_home <= j
            };
            if fixed {
                continue;
            }
            self.index[hole] = candidate;
            hole = j;
        }
        self.index[hole] = EMPTY;
    }

    fn evict_tail(&mut self) -> u16 {
        let slot = self.tail;
        debug_assert_ne!(slot, NONE, "evicting from an empty interner");
        self.unlink(slot);
        self.index_remove(slot);
        let s = usize::from(slot);
        self.stats.len -= 1;
        self.stats.bytes_in_use -= usize::from(self.len[s]);
        self.stats.evictions += 1;
        // A new generation, never zero, so every id issued for the old
        // occupant stops resolving.
        self.generation[s] = match self.generation[s].wrapping_add(1) {
            0 => 1,
            g => g,
        };
        self.len[s] = 0;
        slot
    }

    fn touch(&mut self, slot: u16) {
        if self.head != slot {
            self.unlink(slot);
            self.push_front(slot);
        }
    }

    fn push_front(&mut self, slot: u16) {
        let s = usize::from(slot);
        self.prev[s] = NONE;
        self.next[s] = self.head;
        if self.head != NONE {
            self.prev[usize::from(self.head)] = slot;
        }
        self.head = slot;
        if self.tail == NONE {
            self.tail = slot;
        }
    }

    fn unlink(&mut self, slot: u16) {
        let s = usize::from(slot);
        let (p, n) = (self.prev[s], self.next[s]);
        if p == NONE {
            self.head = n;
        } else {
            self.next[usize::from(p)] = n;
        }
        if n == NONE {
            self.tail = p;
        } else {
            self.prev[usize::from(n)] = p;
        }
        self.prev[s] = NONE;
        self.next[s] = NONE;
    }
}

impl core::fmt::Debug for Interner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Interner")
            .field("slot_bytes", &self.slot_bytes)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// FNV-1a: dependency-free and deterministic, which the replay tests need;
/// the index compares bytes after the hash, so collisions cost a compare.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_bytes_get_the_same_id_and_different_bytes_do_not() {
        let mut interner = Interner::with_capacity(8, 32);
        let a = interner.intern(b"/etc/passwd").unwrap();
        let b = interner.intern(b"/etc/shadow").unwrap();
        assert_ne!(a, b);
        assert_eq!(interner.intern(b"/etc/passwd").unwrap(), a);
        assert_eq!(interner.resolve(a), Some(&b"/etc/passwd"[..]));
        assert_eq!(interner.resolve(b), Some(&b"/etc/shadow"[..]));
        assert_eq!(interner.len(), 2);
        assert_eq!(interner.stats().hits, 1);
        assert_eq!(interner.stats().misses, 2);
    }

    #[test]
    fn memory_is_bounded_and_evictions_are_counted() {
        let mut interner = Interner::with_capacity(16, 16);
        let arena_cap = interner.arena.capacity();
        let index_cap = interner.index.capacity();
        for i in 0..1000u32 {
            interner.intern(&i.to_le_bytes()).unwrap();
        }
        assert_eq!(interner.len(), 16);
        assert_eq!(interner.stats().evictions, 1000 - 16);
        assert_eq!(interner.stats().bytes_in_use, 16 * 4);
        // Nothing grew: every allocation happened in `with_capacity`.
        assert_eq!(interner.arena.capacity(), arena_cap);
        assert_eq!(interner.index.capacity(), index_cap);
        assert!(interner.free.is_empty());
        // The survivors are exactly the last sixteen, all resolvable.
        for i in 984..1000u32 {
            let id = interner.intern(&i.to_le_bytes()).unwrap();
            assert_eq!(interner.resolve(id), Some(&i.to_le_bytes()[..]));
        }
        assert_eq!(
            interner.stats().evictions,
            1000 - 16,
            "re-interning survivors evicts nothing"
        );
    }

    #[test]
    fn a_stale_id_resolves_to_nothing_not_to_the_new_occupant() {
        let mut interner = Interner::with_capacity(2, 8);
        let old = interner.intern(b"old").unwrap();
        interner.intern(b"other").unwrap();
        // Evicts "old", the least recently used; its slot is reused.
        let newer = interner.intern(b"new").unwrap();
        assert_eq!(old.slot(), newer.slot(), "the slot was reused");
        assert_ne!(old, newer, "the generation differs");
        assert_eq!(interner.resolve(old), None);
        assert_eq!(interner.resolve(newer), Some(&b"new"[..]));
        // Raw zero, and a slot past the end, are absences too.
        assert_eq!(interner.resolve(StrId::NONE), None);
        assert_eq!(interner.resolve(StrId::from_raw(1 << 16 | 7)), None);
    }

    #[test]
    fn touching_keeps_an_entry_alive_across_evictions() {
        let mut interner = Interner::with_capacity(3, 8);
        let keep = interner.intern(b"keep").unwrap();
        interner.intern(b"a").unwrap();
        interner.intern(b"b").unwrap();
        for i in 0..20u8 {
            assert_eq!(
                interner.intern(b"keep").unwrap(),
                keep,
                "still the same entry"
            );
            interner.intern(&[i]).unwrap();
        }
        assert_eq!(interner.resolve(keep), Some(&b"keep"[..]));
        assert_eq!(interner.len(), 3);
    }

    #[test]
    fn too_long_is_refused_and_stores_nothing() {
        let mut interner = Interner::with_capacity(4, 8);
        let err = interner.intern(&[b'x'; 9]).unwrap_err();
        assert_eq!(err, TooLong { len: 9, max: 8 });
        assert!(interner.is_empty());
        assert_eq!(interner.stats().misses, 0);
        assert_eq!(interner.intern(&[b'x'; 8]).map(|_| ()), Ok(()));
    }

    #[test]
    fn the_index_stays_consistent_through_many_evictions() {
        // Backward-shift deletion under load: every live entry must remain
        // findable, and no evicted entry may.
        let mut interner = Interner::with_capacity(64, 8);
        let mut live: Vec<(u32, StrId)> = Vec::new();
        for i in 0..5000u32 {
            let id = interner.intern(&i.to_le_bytes()).unwrap();
            live.push((i, id));
            if live.len() > 64 {
                live.remove(0);
            }
            for &(j, jid) in &live {
                assert_eq!(
                    interner.resolve(jid),
                    Some(&j.to_le_bytes()[..]),
                    "at {i}, entry {j}"
                );
                assert_eq!(interner.intern(&j.to_le_bytes()).unwrap(), jid);
            }
        }
        assert_eq!(interner.stats().evictions, 5000 - 64);
    }

    #[test]
    fn ids_are_deterministic_across_runs() {
        let run = || {
            let mut interner = Interner::with_capacity(8, 16);
            (0..100u32)
                .map(|i| {
                    interner
                        .intern(format!("p{}", i % 12).as_bytes())
                        .unwrap()
                        .raw()
                })
                .collect::<Vec<u32>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn for_paths_is_the_plans_shape() {
        let interner = Interner::for_paths();
        assert_eq!(interner.stats().capacity, 16 * 1024);
        assert_eq!(interner.arena.len(), 16 * 1024 * 256);
        assert!(interner.arena.len() <= 4 * 1024 * 1024);
    }
}
