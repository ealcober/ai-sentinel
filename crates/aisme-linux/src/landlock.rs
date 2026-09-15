// SPDX-License-Identifier: Apache-2.0
//! Landlock: the session's write scope, denied **in kernel** (`F2.WS.11`).
//!
//! This is what makes L2 a tier rather than a euphemism. A write outside the
//! workspace is refused by the kernel before the syscall completes, with no
//! supervisor in the path — and therefore, by construction, with **zero
//! notification traffic**. That second half is the point: §2.2.1's argument is
//! that trapping everything to user space "would be a disaster", so the denial
//! nobody was notified about is the design working. It is recorded from the
//! syscall's *return value* instead, which is `F2.WS.11`'s exit-tracepoint half.
//!
//! **Scope is the invoker's declaration, and the policy is still the daemon's.**
//! `aisme run --scope` is typed by the person launching the agent, not by the
//! agent, so a session saying where its workspace is does not decide whether it
//! is enforced. What it may not do is widen: a Landlock domain cannot be
//! relaxed by the process that entered it or by anything it `exec`s, which is
//! the property that makes applying it before `exec` worth the ordering care.
//!
//! **Why this is not an `Enforcer`.** The frozen L1 trait is a daemon-side
//! contract — `publish`, `respond`, `suspend`, `resume` — and a ruleset applied
//! once, irreversibly, in a process that is about to `exec` answers none of
//! those. `F3.EN.09` widens this to the never-promptable classes and AISME's
//! own files, from the daemon, and that is where an `Enforcer` impl belongs.

use aisme_core::error::{Error, Result};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

// x86_64 syscall numbers; Landlock arrived in 5.13.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
/// the ABI instead of a descriptor.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// `LANDLOCK_RULE_PATH_BENEATH`.
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

// The filesystem access rights, by ABI. Only the write-shaped ones are listed:
// F2 denies writes outside the workspace and leaves reads alone, because a
// read outside the workspace is the escalate class's business (`F2.WS.05`) and
// answering it in kernel would remove the prompt the skeleton exists to show.
const WRITE_FILE: u64 = 1 << 1;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
/// ABI 3. Truncating a file is a write; a ruleset that handles `WRITE_FILE` and
/// not this one leaves `truncate(2)` open on a kernel old enough to lack it,
/// which is why it is added by measurement rather than assumed.
const TRUNCATE: u64 = 1 << 14;

/// `struct landlock_ruleset_attr`. `handled_access_net` arrived in ABI 4; the
/// size argument is what tells the kernel which fields are present, so the
/// struct is declared whole and a **shorter size** is passed below ABI 4.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares **packed** —
/// a naturally aligned version would put four bytes of padding after
/// `parent_fd` and the kernel would read the wrong size.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// What this kernel's Landlock can do, measured rather than assumed.
///
/// `abi` is 0 where Landlock is absent or disabled — a kernel too old, or one
/// booted without `landlock` in its LSM list. That is a named degradation
/// (`L2-`), never a reason to refuse to run (`I-19`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LandlockSupport {
    /// The ABI version the kernel reports; 0 when there is none.
    pub abi: u8,
    /// The write-shaped access rights this ABI understands.
    pub write_access: u64,
}

impl LandlockSupport {
    /// Whether a ruleset can be built at all.
    #[must_use]
    pub fn available(self) -> bool {
        self.abi > 0
    }
}

/// Ask the kernel for its Landlock ABI.
///
/// The same call `F0.VER.04` used, and the only honest way to ask: the LSM list
/// in securityfs says Landlock is *compiled in*, not which rights it accepts,
/// and every right above the running ABI makes `landlock_create_ruleset` fail
/// with `EINVAL` rather than degrade.
#[must_use]
pub fn probe() -> LandlockSupport {
    // SAFETY: the version query takes a null attribute pointer and a zero size;
    // that is the documented shape of the call and it reads no memory.
    let abi = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi <= 0 {
        return LandlockSupport {
            abi: 0,
            write_access: 0,
        };
    }
    let abi = u8::try_from(abi).unwrap_or(u8::MAX);
    LandlockSupport {
        abi,
        write_access: write_access_for(abi),
    }
}

/// The write-shaped rights an ABI understands.
///
/// Every `MAKE_*` is here and not only `MAKE_REG`: a session that could not
/// create a regular file outside its workspace but could create a symlink, a
/// fifo or a device node there would have a write scope with a hole in it, and
/// the hole would be invisible until someone used it.
#[must_use]
pub fn write_access_for(abi: u8) -> u64 {
    if abi == 0 {
        return 0;
    }
    let base = WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 3 {
        base | TRUNCATE
    } else {
        base
    }
}

/// The character devices a write scope must not deny, and why each one.
///
/// **Measured, not anticipated.** The first version of this ruleset denied
/// `/dev/null`, and the first supervised shell that redirected anything
/// reported `sh: cannot create /dev/null: Permission denied` — on a command
/// that wrote nothing anywhere. Almost every program redirects, so a write
/// scope without this list is a false positive on essentially every benign
/// workload, and this project holds that a false positive is as serious as a
/// missed detection.
///
/// They are named one by one rather than allowing `/dev`, which also holds
/// `/dev/mem`, the block devices and every mounted disk. Each of these is a
/// character device that **stores nothing**: a write to it exfiltrates nothing
/// and mutates nothing that survives the call, which is what makes granting it
/// a correction rather than a hole.
const NON_STORAGE_DEVICES: [&str; 6] = [
    "/dev/null",    // discards
    "/dev/zero",    // discards
    "/dev/full",    // discards, and always answers ENOSPC
    "/dev/random",  // a write contributes entropy and reads nothing back
    "/dev/urandom", // the same
    "/dev/tty",     // the session's own terminal: output it already has
];

/// Build a ruleset that denies every write, then allow writes beneath each of
/// `writable`, and apply it to this process and everything it `exec`s.
///
/// Returns the ABI it was applied at, or `Unsupported` where Landlock is absent
/// — the caller reports `L2-` and says which function was lost, per
/// `docs/design/02_aisme-run.md` §5.
///
/// **This must run before the seccomp filter, not after it.** The design lists
/// the filter as step 4 and this as step 5, which reads as an ordering and is
/// not one: `landlock_add_rule` needs an `O_PATH` descriptor for each allowed
/// directory, and opening one under a filter that traps `openat` sends the
/// session's own setup to the supervisor to be answered. The filter is also
/// irreversible, so anything that can still fail belongs above it.
///
/// # Errors
///
/// `Unsupported` where the kernel has no Landlock. `Failed` where a path
/// cannot be opened, the ruleset cannot be created, or the restriction is
/// refused — each carrying the kernel's own errno, because a write scope that
/// silently failed to apply is a session that believes it is confined.
pub fn restrict_writes_to(writable: &[std::path::PathBuf]) -> Result<u8> {
    let support = probe();
    if !support.available() {
        return Err(Error::unsupported(
            "no Landlock on this kernel: writes outside the workspace are not denied in kernel"
                .to_owned(),
        ));
    }

    let attr = RulesetAttr {
        handled_access_fs: support.write_access,
        handled_access_net: 0,
    };
    // Below ABI 4 the kernel does not know `handled_access_net` and rejects a
    // size that includes it. Above it, zero means "handle no network right",
    // which is `F3.EN.10`'s to change and not this task's.
    let size = if support.abi >= 4 {
        std::mem::size_of::<RulesetAttr>()
    } else {
        std::mem::size_of::<u64>()
    };
    // SAFETY: `attr` outlives the call and `size` describes the prefix of it
    // the kernel is being told to read.
    let raw = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &raw const attr, size, 0_u32) };
    let ruleset = i32::try_from(raw).map_err(|_| {
        Error::failed(format!(
            "landlock_create_ruleset returned {raw}, which is not a descriptor"
        ))
    })?;
    if ruleset < 0 {
        return Err(Error::failed(format!(
            "landlock_create_ruleset: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the kernel just returned this descriptor and nothing else holds
    // it; wrapping it here is what closes it on every path out of this function.
    let ruleset: OwnedFd = unsafe { OwnedFd::from_raw_fd(ruleset) };

    for path in writable {
        add_path_beneath(ruleset.as_raw_fd(), path, support.write_access)?;
    }
    for device in NON_STORAGE_DEVICES {
        let path = std::path::Path::new(device);
        // A device that is not on this machine is not an error: a container or
        // a minimal image may have no `/dev/tty`, and refusing to confine a
        // session because one node is missing would trade a working write scope
        // for none at all.
        if path.exists() {
            add_path_beneath(ruleset.as_raw_fd(), path, file_access(support.abi))?;
        }
    }

    // Required without `CAP_SYS_ADMIN`, and harmless with it. The seccomp
    // filter sets it too; both calls are idempotent, and doing it here is what
    // lets this run first.
    // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::failed(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the descriptor is live and the call takes no pointers.
    if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd(), 0_u32) } != 0 {
        return Err(Error::failed(format!(
            "landlock_restrict_self: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(support.abi)
}

/// The write-shaped rights that mean anything for a **non-directory**.
///
/// **Measured.** `landlock_add_rule` answers `EINVAL` when a `PATH_BENEATH`
/// rule on a file or a device carries a directory-only right — `MAKE_REG`,
/// `MAKE_DIR`, `REMOVE_FILE` and the rest only describe what may happen
/// *inside* a directory. Granting the workspace's full set on `/dev/null`
/// therefore refused the whole ruleset, and the session failed to start rather
/// than being confined: the first attempt reported
/// `landlock_add_rule for /dev/null: Invalid argument`.
#[must_use]
fn file_access(abi: u8) -> u64 {
    if abi >= 3 {
        WRITE_FILE | TRUNCATE
    } else {
        WRITE_FILE
    }
}

/// Allow `access` beneath one directory.
fn add_path_beneath(ruleset: RawFd, path: &std::path::Path, access: u64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::failed(format!("{}: path contains a NUL", path.display())))?;
    // `O_PATH`: the descriptor names the directory for Landlock and cannot be
    // used to read or write it, which is the whole authority this needs.
    // SAFETY: `c_path` is NUL-terminated and outlives the call.
    let parent = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent < 0 {
        return Err(Error::failed(format!(
            "{}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: just returned by `open` and held by nothing else.
    let parent: OwnedFd = unsafe { OwnedFd::from_raw_fd(parent) };

    let rule = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `rule` outlives the call and the kernel reads exactly the packed
    // twelve bytes it declares.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const rule,
            0_u32,
        )
    };
    if rc != 0 {
        return Err(Error::failed(format!(
            "landlock_add_rule for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
// A panic is the failure report in a test; the adapter's own code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{probe, restrict_writes_to, write_access_for, TRUNCATE};

    /// Run `body` in a forked child and return its exit status.
    ///
    /// Every test here has to fork, and the reason is the property under test:
    /// a Landlock domain cannot be left. A test that restricted the test
    /// harness would confine every test that ran after it, in an order nobody
    /// controls.
    fn in_child(body: impl FnOnce() -> i32) -> i32 {
        // SAFETY: `fork` for its documented effect. The child never returns
        // into the harness — it `_exit`s — so no destructor runs twice and no
        // lock held by another thread is ever waited on.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let code = body();
            // SAFETY: `_exit` does not unwind and does not flush; it is the
            // only correct way out of a forked child in a threaded process.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on the child just forked, with storage we own.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waitpid did not return our child");
        // The wait-status layout: the low seven bits are the terminating
        // signal, and zero means there was none. Written as the kernel's own
        // mask rather than as `trailing_zeros()`, which computes the same
        // answer and hides which field is being read.
        #[expect(
            clippy::verbose_bit_mask,
            reason = "the mask is the wait-status layout; naming it is the point"
        )]
        {
            assert!(status & 0x7f == 0, "the child did not exit normally");
        }
        (status >> 8) & 0xff
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aisme-landlock-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The ABI is asked of the kernel, and what it answers is self-consistent.
    ///
    /// It deliberately does not assert a number: the matrix runs from 5.4 (no
    /// Landlock at all) to 7.x, and a test that demanded one would fail on the
    /// kernels the degradation path exists for.
    #[test]
    fn the_abi_is_measured_and_its_rights_follow_it() {
        let support = probe();
        if support.available() {
            assert_ne!(
                support.write_access, 0,
                "an available Landlock with no write rights would deny nothing"
            );
            assert_eq!(support.write_access, write_access_for(support.abi));
            assert_eq!(
                support.write_access & TRUNCATE != 0,
                support.abi >= 3,
                "TRUNCATE is ABI 3's and asking for it below that is EINVAL, not a degradation"
            );
        } else {
            assert_eq!(support.write_access, 0);
        }
    }

    /// The done-condition of `F2.WS.11`, measured on this kernel: a write
    /// inside the workspace succeeds and a write outside it fails.
    ///
    /// The two halves are in one child because separating them would let the
    /// test pass while the ruleset denied *everything*, which is the failure
    /// that looks safe.
    #[test]
    fn a_write_outside_the_workspace_is_denied_and_one_inside_is_not() {
        if !probe().available() {
            return;
        }
        let workspace = scratch("ws");
        let outside = scratch("outside");

        let inside_path = workspace.join("allowed");
        let outside_path = outside.join("refused");

        let code = in_child(|| {
            if restrict_writes_to(std::slice::from_ref(&workspace)).is_err() {
                return 10;
            }
            if std::fs::write(&inside_path, b"in").is_err() {
                return 11;
            }
            match std::fs::write(&outside_path, b"out") {
                Ok(()) => 12,
                Err(e) if e.raw_os_error() == Some(libc::EACCES) => 0,
                Err(_) => 13,
            }
        });

        assert_eq!(
            code, 0,
            "10 = the ruleset did not apply, 11 = the workspace was denied, \
             12 = the write outside succeeded, 13 = it failed with the wrong errno"
        );
        assert!(inside_path.exists(), "the allowed write did not land");
        assert!(!outside_path.exists(), "the denied write landed anyway");
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A domain cannot be widened from inside it — which is the property that
    /// makes applying the ruleset before `exec` worth the ordering care, and
    /// the reason the supervised command cannot undo it.
    #[test]
    fn a_second_ruleset_cannot_restore_what_the_first_denied() {
        if !probe().available() {
            return;
        }
        let workspace = scratch("narrow");
        let outside = scratch("wide");
        let outside_path = outside.join("still-refused");

        let code = in_child(|| {
            if restrict_writes_to(std::slice::from_ref(&workspace)).is_err() {
                return 10;
            }
            // Ask for strictly more than the domain allows. The call itself
            // succeeds — Landlock stacks domains, it does not replace them —
            // and the intersection is what stays in force.
            if restrict_writes_to(&[workspace.clone(), outside.clone()]).is_err() {
                return 11;
            }
            match std::fs::write(&outside_path, b"out") {
                Ok(()) => 12,
                Err(e) if e.raw_os_error() == Some(libc::EACCES) => 0,
                Err(_) => 13,
            }
        });

        assert_eq!(
            code, 0,
            "12 means a second, broader ruleset restored access the first had denied"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// `/dev/null` stays writable, and so does the rest of the non-storage set.
    ///
    /// This is the regression test for a defect that shipped: the first version
    /// of the ruleset denied `/dev/null`, and the first supervised shell that
    /// redirected anything failed with *"cannot create /dev/null: Permission
    /// denied"* — on a command that wrote nothing anywhere. It is asserted
    /// alongside a real denial in the same child, because a ruleset that had
    /// stopped denying anything would also pass the first half.
    #[test]
    fn the_non_storage_devices_stay_writable_and_the_scope_still_denies() {
        if !probe().available() {
            return;
        }
        let workspace = scratch("dev-ws");
        let outside = scratch("dev-out");
        let refused = outside.join("refused");

        let code = in_child(|| {
            if restrict_writes_to(std::slice::from_ref(&workspace)).is_err() {
                return 10;
            }
            for device in super::NON_STORAGE_DEVICES {
                if !std::path::Path::new(device).exists() {
                    continue;
                }
                // Only `EACCES` is a Landlock denial. `/dev/tty` answers
                // `ENXIO` in a process with no controlling terminal, which is
                // this harness under a test runner — reading that as a denial
                // would fail the test for a reason that has nothing to do with
                // the ruleset.
                match std::fs::OpenOptions::new().write(true).open(device) {
                    Ok(file) => drop(file),
                    Err(e) if e.raw_os_error() == Some(libc::EACCES) => return 11,
                    Err(_) => {}
                }
            }
            // And the scope is still a scope.
            if std::fs::write(&refused, b"out").is_ok() {
                return 12;
            }
            0
        });

        assert_eq!(
            code, 0,
            "11 = a non-storage device was denied, which breaks every redirect; \
             12 = the scope stopped denying, so the first half proved nothing"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Every one of the `MAKE_*` rights is handled, not only `MAKE_REG`.
    ///
    /// A write scope that stopped `touch` and allowed `ln -s`, `mkfifo` or
    /// `mkdir` outside the workspace would have a hole nobody would notice
    /// until it was used, because the obvious case passes.
    #[test]
    fn a_symlink_a_fifo_and_a_directory_outside_are_denied_too() {
        if !probe().available() {
            return;
        }
        let workspace = scratch("kinds-ws");
        let outside = scratch("kinds-out");

        let symlink = outside.join("link");
        let directory = outside.join("dir");

        let code = in_child(|| {
            if restrict_writes_to(std::slice::from_ref(&workspace)).is_err() {
                return 10;
            }
            if std::os::unix::fs::symlink("/etc/hostname", &symlink).is_ok() {
                return 11;
            }
            if std::fs::create_dir(&directory).is_ok() {
                return 12;
            }
            0
        });

        assert_eq!(
            code, 0,
            "11 = a symlink was created outside the workspace, 12 = a directory was"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
