// SPDX-License-Identifier: Apache-2.0
//! `RealpathResolver`: the Linux end of `aisme-core::resolve::PathResolver`
//! (`F2.WS.02`).
//!
//! Resolution is `open(O_PATH)` followed by `readlink("/proc/self/fd/N")`,
//! which is what the kernel itself would say the path is. It is done here and
//! not in `aisme-core` because it is I/O, and `A-01` keeps I/O out of L1.
//!
//! **Every buffer is fixed and owned by the resolver**, so a resolution
//! allocates nothing: `std::fs::canonicalize` would be shorter and returns a
//! freshly allocated `PathBuf` on every call, which is an allocation per event
//! on the hot path and `I-22` does not allow one.

use aisme_core::resolve::PathResolver;

/// The longest path this resolver handles, which is the wire's own bound:
/// `FilePayload::path` is 200 bytes, so nothing longer can arrive or be
/// returned.
const MAX_PATH: usize = 200;

/// `/proc/self/fd/` plus a decimal descriptor.
const PROC_FD_MAX: usize = b"/proc/self/fd/".len() + 20;

/// One remembered resolution.
struct Entry {
    /// The path as the caller wrote it, which is the only key available.
    key: [u8; MAX_PATH],
    key_len: u16,
    /// What it resolved to.
    val: [u8; MAX_PATH],
    val_len: u16,
    /// Monotonic tick of the last hit; the smallest is evicted.
    used: u64,
    /// Whether this slot holds anything.
    live: bool,
}

/// What the resolver did, for the metric that would otherwise be a silent zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverCounts {
    /// Answered from the cache.
    pub hits: u64,
    /// Resolved by asking the kernel.
    pub misses: u64,
    /// The kernel could not resolve it; the event keeps `FLAG_PATH_UNRESOLVED`.
    pub unresolved: u64,
    /// Entries dropped to make room. An unbounded cache is a slow leak on a
    /// 50 MB budget and a silent one, so the evictions are counted.
    pub evictions: u64,
}

/// Canonical paths, with a bounded cache.
pub struct RealpathResolver {
    entries: Vec<Entry>,
    clock: u64,
    counts: ResolverCounts,
    scratch: [u8; PROC_FD_MAX],
}

impl RealpathResolver {
    /// The cache a session's working set needs.
    ///
    /// 1024 entries at 400 bytes of key and value is ~410 KB, which is what an
    /// agent's file working set looks like — `npm ci` touches thousands of
    /// paths but re-touches a few hundred. The size lives here, in a named
    /// constructor with its reasoning, exactly as `Interner::for_paths()` does:
    /// `budgets.toml` sizes processes and latencies, not caches, and putting
    /// one policy in two places is how they drift apart.
    #[must_use]
    pub fn for_sessions() -> RealpathResolver {
        RealpathResolver::with_capacity(1024)
    }

    /// `capacity` entries, all allocated here and never again.
    ///
    /// # Panics
    ///
    /// When `capacity` is zero: a resolver that can remember nothing would
    /// resolve every event and report a 0% hit rate that looks like a bug.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> RealpathResolver {
        assert!(capacity > 0, "a cache of zero entries is not a cache");
        let mut entries = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            entries.push(Entry {
                key: [0; MAX_PATH],
                key_len: 0,
                val: [0; MAX_PATH],
                val_len: 0,
                used: 0,
                live: false,
            });
        }
        RealpathResolver {
            entries,
            clock: 0,
            counts: ResolverCounts::default(),
            scratch: [0; PROC_FD_MAX],
        }
    }

    /// What this resolver has done since it was built.
    #[must_use]
    pub const fn counts(&self) -> ResolverCounts {
        self.counts
    }

    /// Ask the kernel. `None` when the path does not resolve — it was unlinked,
    /// it never existed, or a component is not searchable.
    fn ask_kernel(&mut self, path: &[u8], out: &mut [u8]) -> Option<usize> {
        // A NUL is needed for the syscall and the wire never carries one.
        let mut c_path = [0u8; MAX_PATH + 1];
        if path.len() > MAX_PATH || path.contains(&0) {
            return None;
        }
        c_path[..path.len()].copy_from_slice(path);

        // SAFETY: `c_path` is NUL-terminated and lives for the call. `O_PATH`
        // opens the file *description* without reading it, so this observes
        // and never modifies the target — which is what `T4.5.06` asserts of
        // the whole product.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr().cast::<libc::c_char>(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }

        let n = write_proc_fd(&mut self.scratch, fd);
        // SAFETY: `scratch` is NUL-terminated by `write_proc_fd` and `out` is a
        // caller-owned buffer of the length passed. `readlink` writes at most
        // that many bytes and never a NUL.
        let len = unsafe {
            libc::readlink(
                self.scratch.as_ptr().cast::<libc::c_char>(),
                out.as_mut_ptr().cast::<libc::c_char>(),
                out.len(),
            )
        };
        // SAFETY: `fd` came from `open` above and is not used again.
        unsafe { libc::close(fd) };
        let _ = n;

        let len = usize::try_from(len).ok()?;
        // `readlink` truncates silently when the buffer is short, and a
        // truncated path names a different file. Refusing is the only honest
        // answer: the event keeps `FLAG_PATH_UNRESOLVED`.
        if len == 0 || len >= out.len() {
            return None;
        }
        Some(len)
    }

    /// The slot holding `key`, if any.
    fn find(&self, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.live && usize::from(e.key_len) == key.len() && &e.key[..key.len()] == key
        })
    }

    /// A free slot, or the least recently used one — counting the eviction.
    fn slot_for(&mut self) -> usize {
        if let Some(i) = self.entries.iter().position(|e| !e.live) {
            return i;
        }
        let victim = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.used)
            .map_or(0, |(i, _)| i);
        self.counts.evictions += 1;
        victim
    }
}

/// Write `/proc/self/fd/<fd>\0` into `buf`, returning its length.
///
/// Hand-written because `format!` allocates and this is the hot path.
fn write_proc_fd(buf: &mut [u8; PROC_FD_MAX], fd: i32) -> usize {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = fd.unsigned_abs();
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            v /= 10;
            n += 1;
        }
    }
    let mut i = PREFIX.len();
    for d in digits[..n].iter().rev() {
        buf[i] = *d;
        i += 1;
    }
    buf[i] = 0;
    i
}

impl PathResolver for RealpathResolver {
    fn resolve(&mut self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len == 0 || len > buf.len() {
            return None;
        }
        self.clock += 1;
        let mut key = [0u8; MAX_PATH];
        let klen = len.min(MAX_PATH);
        key[..klen].copy_from_slice(&buf[..klen]);

        if let Some(i) = self.find(&key[..klen]) {
            self.counts.hits += 1;
            self.entries[i].used = self.clock;
            let vlen = usize::from(self.entries[i].val_len);
            buf[..vlen].copy_from_slice(&self.entries[i].val[..vlen]);
            return Some(vlen);
        }

        let mut out = [0u8; MAX_PATH];
        let Some(vlen) = self.ask_kernel(&key[..klen], &mut out) else {
            self.counts.unresolved += 1;
            return None;
        };
        self.counts.misses += 1;
        let i = self.slot_for();
        let clock = self.clock;
        let e = &mut self.entries[i];
        e.key[..klen].copy_from_slice(&key[..klen]);
        e.key_len = u16::try_from(klen).unwrap_or(u16::MAX);
        e.val[..vlen].copy_from_slice(&out[..vlen]);
        e.val_len = u16::try_from(vlen).unwrap_or(u16::MAX);
        e.used = clock;
        e.live = true;
        buf[..vlen].copy_from_slice(&out[..vlen]);
        Some(vlen)
    }
}

/// A path as `std` sees it, for the tests to build fixtures with.
#[cfg(test)]
fn bytes_of(path: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aisme-res-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("tmp");
        d
    }

    /// The production path, against a real symlink on a real filesystem: the
    /// resolver must answer with the target, not the link.
    #[test]
    fn a_symlink_resolves_to_its_target() {
        let d = tmpdir("link");
        let target = d.join("target");
        fs::write(&target, b"x").expect("write");
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let mut r = RealpathResolver::with_capacity(4);
        let raw = bytes_of(&link);
        let mut buf = [0u8; MAX_PATH];
        buf[..raw.len()].copy_from_slice(&raw);
        let n = r.resolve(&mut buf, raw.len()).expect("resolvable");
        assert_eq!(&buf[..n], bytes_of(&target).as_slice());
        assert_eq!(r.counts().misses, 1);
        assert_eq!(r.counts().hits, 0);
        let _ = fs::remove_dir_all(&d);
    }

    /// A path that does not exist has no canonical form, and the resolver says
    /// so rather than echoing the input — which would claim it canonicalized.
    #[test]
    fn a_missing_path_is_unresolved_not_echoed() {
        let d = tmpdir("gone");
        let gone = d.join("never-existed");
        let mut r = RealpathResolver::with_capacity(4);
        let raw = bytes_of(&gone);
        let mut buf = [0u8; MAX_PATH];
        buf[..raw.len()].copy_from_slice(&raw);
        assert_eq!(r.resolve(&mut buf, raw.len()), None);
        assert_eq!(r.counts().unresolved, 1);
        assert_eq!(&buf[..raw.len()], raw.as_slice(), "the buffer is untouched");
        let _ = fs::remove_dir_all(&d);
    }

    /// The second ask for the same path comes from the cache, and gives the
    /// same answer. A cache that returns something else is worse than none.
    #[test]
    fn the_second_ask_is_a_hit_with_the_same_answer() {
        let d = tmpdir("hit");
        let target = d.join("t");
        fs::write(&target, b"x").expect("write");
        let mut r = RealpathResolver::with_capacity(4);
        let raw = bytes_of(&target);

        let mut first = [0u8; MAX_PATH];
        first[..raw.len()].copy_from_slice(&raw);
        let a = r.resolve(&mut first, raw.len()).expect("resolvable");

        let mut second = [0u8; MAX_PATH];
        second[..raw.len()].copy_from_slice(&raw);
        let b = r.resolve(&mut second, raw.len()).expect("cached");

        assert_eq!(&first[..a], &second[..b]);
        assert_eq!(r.counts().misses, 1);
        assert_eq!(r.counts().hits, 1);
        let _ = fs::remove_dir_all(&d);
    }

    /// N distinct paths through a cache of M evict exactly N − M times, and the
    /// cache never grows: the whole point of bounding it.
    #[test]
    fn n_paths_through_a_cache_of_m_evict_exactly_n_minus_m() {
        let dir = tmpdir("evict");
        let cache_size = 4usize;
        let paths = 10usize;
        let mut resolver = RealpathResolver::with_capacity(cache_size);
        let capacity_before = resolver.entries.capacity();
        for i in 0..paths {
            let file = dir.join(format!("f{i}"));
            fs::write(&file, b"x").expect("write");
            let raw = bytes_of(&file);
            let mut buf = [0u8; MAX_PATH];
            buf[..raw.len()].copy_from_slice(&raw);
            resolver.resolve(&mut buf, raw.len()).expect("resolvable");
        }
        assert_eq!(resolver.counts().misses, paths as u64);
        assert_eq!(
            resolver.counts().evictions,
            (paths - cache_size) as u64,
            "exactly the overflow, no more and no fewer"
        );
        assert_eq!(
            resolver.entries.len(),
            cache_size,
            "the cache does not grow"
        );
        assert_eq!(resolver.entries.capacity(), capacity_before);
        let _ = fs::remove_dir_all(&dir);
    }

    /// `/proc/self/fd/<n>` is written without allocating; the arithmetic is
    /// hand-rolled, so it is checked.
    #[test]
    fn the_proc_path_is_written_correctly_for_every_shape_of_descriptor() {
        let mut buf = [0u8; PROC_FD_MAX];
        for (fd, want) in [
            (0, "/proc/self/fd/0"),
            (7, "/proc/self/fd/7"),
            (10, "/proc/self/fd/10"),
            (1234, "/proc/self/fd/1234"),
        ] {
            let n = write_proc_fd(&mut buf, fd);
            assert_eq!(&buf[..n], want.as_bytes(), "fd {fd}");
            assert_eq!(buf[n], 0, "NUL-terminated for the syscall");
        }
    }
}
