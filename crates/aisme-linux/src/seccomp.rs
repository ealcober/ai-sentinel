// SPDX-License-Identifier: Apache-2.0
//! The seccomp capability probe (`F2.WS.05`).
//!
//! Two flags, feature-tested and never version-tested: a backport makes `uname`
//! wrong in one direction and a vendor kernel in the other.
//!
//! * `seccomp_unotify` — a syscall can be **trapped**. `SECCOMP_FILTER_FLAG_NEW_LISTENER`,
//!   kernel ≥ 5.0.
//! * `seccomp_addfd` — a decision can be **delivered** without the target
//!   re-resolving the path (`I-28`). `SECCOMP_IOCTL_NOTIF_ADDFD`, kernel ≥ 5.9.
//!
//! They are separate because trapping and answering are different capabilities:
//! 5.4 has the first and not the second, measured on the matrix (`F0.VM.02`),
//! and a kernel that can only ever answer *deny* does not keep L2-'s promise.
//!
//! **The probe runs in a forked child.** A seccomp filter is irreversible: a
//! process that installs one to ask a question wears it for life. The child
//! installs, asks, and `_exit`s with the answer; between `fork` and `_exit` it
//! calls only `prctl`, `seccomp`, `ioctl` and `_exit`, which is what makes it
//! safe in a process that has threads.

/// What this kernel can do with the seccomp notifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeccompSupport {
    /// A syscall can be trapped.
    pub unotify: bool,
    /// A trapped syscall's *allow* can be answered with a validated descriptor.
    pub addfd: bool,
}

/// `SECCOMP_RET_ALLOW` — the probe's filter permits everything, because the
/// question is whether a *listener* can be created, not what it would trap.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `BPF_RET | BPF_K`.
const BPF_RET_K: u16 = 0x06;

/// The child's exit codes, which are the answer.
const EXIT_NONE: i32 = 0;
const EXIT_UNOTIFY: i32 = 1;
const EXIT_UNOTIFY_ADDFD: i32 = 2;

/// Ask this kernel, in a child that will wear the filter.
///
/// Returns everything false when the child could not be created or did not
/// answer: an unmeasurable capability is reported absent, never assumed
/// present. Absent is the conservative direction — the escalate class degrades
/// to deny and says so (`I-28`) — so an honest failure costs function and never
/// safety.
#[must_use]
pub fn probe() -> SeccompSupport {
    // SAFETY: `fork` is called for its documented effect. The child below
    // restricts itself to async-signal-safe calls (`prctl`, `seccomp`, `ioctl`,
    // `close`, `_exit`) and never returns into Rust, which is what makes this
    // sound in a process that has threads.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => SeccompSupport::default(),
        0 => {
            // SAFETY: the child. `probe_in_child` performs only the calls named
            // above and `_exit` never unwinds.
            unsafe { probe_in_child() }
        }
        _ => {
            let mut status = 0;
            // SAFETY: waiting on the child we just forked, with a valid pointer
            // to storage we own.
            let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            if waited != pid || !wif_exited(status) {
                return SeccompSupport::default();
            }
            match wexit_status(status) {
                EXIT_UNOTIFY => SeccompSupport {
                    unotify: true,
                    addfd: false,
                },
                EXIT_UNOTIFY_ADDFD => SeccompSupport {
                    unotify: true,
                    addfd: true,
                },
                _ => SeccompSupport::default(),
            }
        }
    }
}

/// `WIFEXITED` and `WEXITSTATUS`, which `libc` exposes as functions that are
/// not `const` on every target; written out so the probe does not depend on
/// which.
const fn wif_exited(status: i32) -> bool {
    // `WIFEXITED`: the low seven bits are the terminating signal, and zero
    // means there was none. Written as the kernel's own mask rather than as
    // `trailing_zeros() >= 7`, which computes the same answer and hides which
    // field is being read.
    #[expect(
        clippy::verbose_bit_mask,
        reason = "the mask is the wait-status layout; naming it is the point"
    )]
    {
        status & 0x7f == 0
    }
}

const fn wexit_status(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// The child half: install a permissive filter with a listener, then ask the
/// listener whether it knows `ADDFD`.
///
/// # Safety
///
/// Must be called only in a freshly forked child that will not return into
/// Rust. It never returns: every path ends in `_exit`.
unsafe fn probe_in_child() -> ! {
    // Required without `CAP_SYS_ADMIN`, and harmless with it.
    // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        // SAFETY: `_exit` in a forked child.
        unsafe { libc::_exit(EXIT_NONE) };
    }

    let insn = libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    };
    let prog = libc::sock_fprog {
        len: 1,
        filter: std::ptr::addr_of!(insn).cast_mut(),
    };

    // SAFETY: `seccomp(SECCOMP_SET_MODE_FILTER, …)` with a `sock_fprog` that
    // lives for the duration of the call and a one-instruction filter that
    // returns ALLOW. `NEW_LISTENER` makes the return value the notify fd.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            std::ptr::addr_of!(prog),
        )
    };
    if listener < 0 {
        // SAFETY: `_exit` in a forked child.
        unsafe { libc::_exit(EXIT_NONE) };
    }

    // The discriminator is EFAULT, not ENOTTY — measured on the matrix
    // 2026-09-07 after the first version got it backwards. The notify fd is an
    // anon inode with its own ioctl handler, so an unknown command falls to
    // that handler's `default:` arm and returns EINVAL; the VFS's ENOTTY, which
    // is what a file with no handler at all would give, is unreachable. A rule
    // written as `absent if ENOTTY` therefore answers "present" on every
    // kernel — an absence read as a value, in the check written to avoid one.
    //
    // A kernel that has ADDFD reaches `copy_from_user` and rejects the NULL
    // with EFAULT. Measured: 5.4 EINVAL, 5.10/5.15/6.1/6.8/7.0 EFAULT.
    //
    // SAFETY: an ioctl on the listener we just created, with a NULL argument
    // that the kernel is expected to reject rather than dereference.
    let errno = unsafe {
        *libc::__errno_location() = 0;
        libc::ioctl(
            libc::c_int::try_from(listener).unwrap_or(-1),
            libc::SECCOMP_IOCTL_NOTIF_ADDFD,
            std::ptr::null_mut::<libc::c_void>(),
        );
        *libc::__errno_location()
    };
    let code = if errno == libc::EFAULT {
        EXIT_UNOTIFY_ADDFD
    } else {
        EXIT_UNOTIFY
    };
    // SAFETY: `_exit` in a forked child; the listener fd dies with it.
    unsafe { libc::_exit(code) }
}

#[cfg(test)]
// A panic is the failure report in a test; the adapter's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{probe, wexit_status, wif_exited};

    #[test]
    fn the_wait_status_helpers_agree_with_the_macros() {
        // Exited with 2.
        assert!(wif_exited(2 << 8));
        assert_eq!(wexit_status(2 << 8), 2);
        // Killed by a signal: not an exit, and its code is not an answer.
        assert!(!wif_exited(9));
    }

    /// The probe runs, answers, and **leaves this process unfiltered** — which
    /// is the whole reason it forks. If the filter were installed here, the
    /// second call would be made by a process that already wears one.
    #[test]
    fn probing_twice_gives_the_same_answer_and_filters_nothing() {
        let first = probe();
        let second = probe();
        assert_eq!(
            first, second,
            "the probe changed its own process: {first:?} then {second:?}"
        );
        // A kernel that answers ADDFD must also answer unotify; the reverse is
        // 5.4, which is a real row of the matrix.
        assert!(
            !first.addfd || first.unotify,
            "addfd without unotify is not a kernel: {first:?}"
        );
        eprintln!("seccomp on this host: {first:?}");
    }
}
