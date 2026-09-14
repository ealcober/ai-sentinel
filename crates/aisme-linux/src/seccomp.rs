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

// ---------------------------------------------------------------------------
// The listener: trapping an `openat` and answering it (`F2.WS.05`)
// ---------------------------------------------------------------------------

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// `SECCOMP_RET_USER_NOTIF` — the syscall is held and the supervisor is asked.
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// The audit arch this build traps for.
///
/// Checked in the filter before the syscall number is read, and it is a
/// security check rather than a formality: syscall numbers differ between
/// personalities, so a filter that read `nr` without pinning `arch` would trap
/// one number on x86-64 and a different syscall entirely under i386.
#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
/// As above, for aarch64.
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;

/// Classic-BPF opcodes, by their kernel names.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K_OP: u16 = 0x06;
/// `offsetof(struct seccomp_data, nr)`.
const SECCOMP_DATA_NR: u32 = 0;
/// `offsetof(struct seccomp_data, arch)`.
const SECCOMP_DATA_ARCH: u32 = 4;

/// Install the escalate-class filter on **this** process and return the
/// listener.
///
/// One syscall is trapped — `openat`, which is what glibc's `open()` issues and
/// what F2's sensor watches — and everything else is allowed. The filter is
/// irreversible and inherited across `exec`, which is why it is installed in
/// `aisme run`'s pre-exec hook: after `exec` there is a window, and a window is
/// what this design has none of.
///
/// **A supervisor that dies denies, and the kernel does that for us**: a
/// `USER_NOTIF` syscall whose listener has closed returns `ENOSYS` to the
/// target. There is no default action of ours to get wrong.
///
/// # Errors
///
/// `Unsupported` when `PR_SET_NO_NEW_PRIVS` or `seccomp(2)` refuses, with the
/// kernel's own errno — a kernel without the notifier is a named degradation,
/// not a panic.
pub fn install_openat_filter() -> aisme_core::error::Result<OwnedFd> {
    use aisme_core::error::Error;

    // Required without CAP_SYS_ADMIN, and harmless with it. Without it the
    // kernel refuses to install any filter at all.
    // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(Error::unsupported(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 0: load arch. 1: if it is not ours, allow (jump 3 → index 5).
    // 2: load nr.   3: if it is not openat, allow (jump 1 → index 5).
    // 4: trap.      5: allow.
    let filter = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH,
        },
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 3,
            k: NATIVE_AUDIT_ARCH,
        },
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR,
        },
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            // `try_from`, not `as`: a truncated syscall number would trap a
            // different call than the one this filter names, and it would do
            // it silently.
            k: u32::try_from(libc::SYS_openat).unwrap_or(u32::MAX),
        },
        libc::sock_filter {
            code: BPF_RET_K_OP,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
        libc::sock_filter {
            code: BPF_RET_K_OP,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap_or(u16::MAX),
        filter: filter.as_ptr().cast_mut(),
    };

    // SAFETY: `prog` and the `filter` it points at outlive the call, and the
    // program is the six instructions above. `NEW_LISTENER` makes the return
    // value the notify fd rather than 0.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            std::ptr::addr_of!(prog),
        )
    };
    let listener = RawFd::try_from(listener)
        .map_err(|_| Error::unsupported("seccomp returned a listener that is not a descriptor"))?;
    if listener < 0 {
        return Err(Error::unsupported(format!(
            "seccomp(SET_MODE_FILTER, NEW_LISTENER): {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the kernel just gave us this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(listener) })
}

/// One held syscall, as the supervisor sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The kernel's cookie for this notification. It is **not** an index: it is
    /// checked with `ID_VALID` before every answer, because a target that died
    /// frees the id for reuse and answering into a reused one would decide
    /// somebody else's syscall.
    pub id: u64,
    /// The thread that made the call.
    pub pid: u32,
    /// The syscall number.
    pub nr: i32,
    /// Its six arguments, unread. **Nothing here may decide anything on its
    /// own**: the path argument is a pointer into the target's memory, which
    /// the target can rewrite after we read it (`I-28`).
    pub args: [u64; 6],
}

/// Wait for the next held syscall.
///
/// # Errors
///
/// The ioctl's errno. `ENOENT` means the target died while we waited, which is
/// ordinary and not a fault.
pub fn recv(listener: BorrowedFd<'_>) -> aisme_core::error::Result<Notification> {
    use aisme_core::error::Error;

    // SAFETY: a zeroed `seccomp_notif` is the documented input; the kernel
    // fills it. The struct comes from `libc`, so its layout is the kernel's.
    let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    // SAFETY: the ioctl writes into `req`, which we own and which outlives it.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV,
            std::ptr::addr_of_mut!(req),
        )
    };
    if rc != 0 {
        return Err(Error::unsupported(format!(
            "NOTIF_RECV: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(Notification {
        id: req.id,
        pid: req.pid,
        nr: req.data.nr,
        args: req.data.args,
    })
}

/// Whether the notification is still live.
///
/// Called before **every** answer. A target that died frees its id, and the
/// kernel may hand the same id to another notification; answering into a reused
/// id would decide a syscall nobody asked us about.
#[must_use]
pub fn id_valid(listener: BorrowedFd<'_>, id: u64) -> bool {
    let mut id = id;
    // SAFETY: the ioctl reads the u64 we point at and writes nothing.
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
            std::ptr::addr_of_mut!(id),
        ) == 0
    }
}

/// Fail the held syscall with `errno`.
///
/// **This is the only answer F2 gives.** `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is
/// never used to permit a syscall that carries a path: the kernel re-resolves
/// the string *after* the decision, so a rename of any directory component —
/// by any process on the machine, inside the session or not — changes what the
/// human authorized (`I-28`, `H-01`). The allow path delivers a descriptor the
/// supervisor opened and validated, and it arrives with the rest of `F2.WS.05`.
///
/// # Errors
///
/// The ioctl's errno, except a stale id, which is reported as success: the
/// syscall it named is already gone, and that is the outcome we wanted.
pub fn respond_deny(
    listener: BorrowedFd<'_>,
    id: u64,
    errno: i32,
) -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;

    if !id_valid(listener, id) {
        return Ok(());
    }
    let resp = libc::seccomp_notif_resp {
        id,
        val: 0,
        // The kernel wants the *negated* errno here, as a syscall return does.
        error: -errno,
        flags: 0,
    };
    // SAFETY: the ioctl reads `resp`, which we own and which outlives it.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND,
            std::ptr::addr_of!(resp),
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        // The target died between ID_VALID and here. Its syscall is gone, which
        // is the outcome we wanted, so it is not a failure of ours.
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(Error::unsupported(format!("NOTIF_SEND: {e}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Carrying the listener to the supervisor (`F2.WS.05`)
// ---------------------------------------------------------------------------

/// Send one descriptor over a Unix socket with `SCM_RIGHTS`.
///
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` hands the notify fd to the process that
/// installed the filter — `aisme run`, which `exec`s the instant after — while
/// the loop that answers it lives in `agentd`. Every other way of bridging that
/// gap costs more: keeping the fd means the `fork` that would give up the pid,
/// the terminal and an unskippable chain, and `pidfd_getfd` from the daemon
/// needs `PTRACE_MODE_ATTACH`, which Yama's default scope refuses for a
/// non-descendant.
///
/// **This is not the descriptor `docs/06` point 3 refused.** That was a
/// *writable policy map*, which would hand the daemon authority the privilege
/// split exists to remove. A notify fd hands it exactly the authority it must
/// have — answer one held syscall, for one session — and it cannot change what
/// the kernel enforces.
///
/// # Errors
///
/// The `sendmsg` errno.
pub fn send_fd(socket: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;

    // SCM_RIGHTS needs at least one byte of ordinary data; the byte itself
    // carries nothing.
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: 1,
    };
    // SAFETY: `CMSG_SPACE` is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(size_of::<RawFd>()).unwrap_or(4)) };
    let mut control = vec![0u8; space as usize];

    // SAFETY: a zeroed `msghdr` is the documented starting point; every field
    // used below is set before the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len() as _;

    // SAFETY: `msg.msg_control` points at `control`, which is large enough for
    // one `SCM_RIGHTS` header carrying one descriptor, and outlives the call.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(u32::try_from(size_of::<RawFd>()).unwrap_or(4)) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd.as_raw_fd());
    }

    // SAFETY: `msg` is fully initialised above and outlives the call.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), std::ptr::addr_of!(msg), 0) };
    if sent < 0 {
        return Err(Error::unsupported(format!(
            "sendmsg(SCM_RIGHTS): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Receive one descriptor sent with [`send_fd`].
///
/// # Errors
///
/// The `recvmsg` errno, or a message that carried no descriptor — which is a
/// refusal and not a zero: a caller that read "no fd" as fd 0 would answer
/// notifications on its own stdin.
pub fn recv_fd(socket: BorrowedFd<'_>) -> aisme_core::error::Result<OwnedFd> {
    use aisme_core::error::Error;

    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: 1,
    };
    // SAFETY: a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(size_of::<RawFd>()).unwrap_or(4)) };
    let mut control = vec![0u8; space as usize];

    // SAFETY: a zeroed `msghdr`, with every field used below set before the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len() as _;

    // SAFETY: `msg` is initialised and the kernel writes only into the buffers
    // it points at, both of which outlive the call.
    let got = unsafe { libc::recvmsg(socket.as_raw_fd(), std::ptr::addr_of_mut!(msg), 0) };
    if got < 0 {
        return Err(Error::unsupported(format!(
            "recvmsg(SCM_RIGHTS): {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: reading back the control message the kernel just wrote, from the
    // buffer we supplied.
    let fd = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(Error::unsupported(
                "the message carried no descriptor; a listener is not optional",
            ));
        }
        std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>())
    };
    if fd < 0 {
        return Err(Error::unsupported("the descriptor received is not one"));
    }
    // SAFETY: the kernel installed this descriptor in our table and nothing
    // else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
// A panic is the failure report in a test; the adapter's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        id_valid, install_openat_filter, probe, recv, recv_fd, respond_deny, send_fd, wexit_status,
        wif_exited,
    };

    /// The plan's done-condition for `F2.WS.05`: **a denied `openat` returns
    /// `-EACCES` to the caller**.
    ///
    /// The whole mechanism, end to end, with no mock anywhere: a child installs
    /// the real filter, hands the real listener to its supervisor over a real
    /// `SCM_RIGHTS` message, and makes a real `open`. The supervisor receives
    /// the notification the kernel raised and answers it. What the child's
    /// `open` returns is the kernel's answer to our decision.
    #[test]
    fn a_denied_openat_returns_eacces_to_the_caller() {
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};

        let mut sv: [libc::c_int; 2] = [0; 2];
        // SAFETY: a socketpair into storage we own.
        let made =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(made, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: the kernel just created both descriptors and nothing else owns them.
        let (parent_end, child_end) =
            unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

        // SAFETY: `fork`; the child below reaches `_exit` on every path and
        // calls only syscalls between here and there.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());

        if pid == 0 {
            // The child: the supervised process.
            drop(parent_end);
            // A hung supervisor must not hang the suite; SIGALRM ends this
            // child and the parent's assertion then reports a signal rather
            // than waiting for ever.
            // SAFETY: `alarm` takes no pointers.
            unsafe { libc::alarm(20) };
            let Ok(listener) = install_openat_filter() else {
                // SAFETY: `_exit` in a forked child.
                unsafe { libc::_exit(101) }
            };
            if send_fd(child_end.as_fd(), listener.as_fd()).is_err() {
                // SAFETY: as above.
                unsafe { libc::_exit(102) }
            }
            // Close our copy: the supervisor holds the only one that matters,
            // and a listener the target still holds would keep the notification
            // alive after the target died.
            drop(listener);

            // The trapped call. What comes back is the kernel's rendering of
            // the supervisor's answer.
            // SAFETY: `open` with a NUL-terminated literal and no mode.
            let rc = unsafe { libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) };
            let code = if rc >= 0 {
                // It was permitted. That is a failure of the test's premise and
                // is reported as one rather than as a passing deny.
                0
            } else {
                // SAFETY: reading errno immediately after a failed call.
                unsafe { *libc::__errno_location() }
            };
            // SAFETY: `_exit` in a forked child.
            unsafe { libc::_exit(code) }
        }

        // The parent: the supervisor.
        drop(child_end);
        let listener = recv_fd(parent_end.as_fd()).expect("the listener did not arrive");
        let notification = recv(listener.as_fd()).expect("no notification arrived");
        assert_eq!(
            notification.nr,
            i32::try_from(libc::SYS_openat).unwrap_or(-1),
            "the filter trapped something other than openat"
        );
        assert_eq!(notification.pid, u32::try_from(pid).unwrap_or(0));
        assert!(
            id_valid(listener.as_fd(), notification.id),
            "the notification was stale before it was answered"
        );
        respond_deny(listener.as_fd(), notification.id, libc::EACCES).expect("the deny");

        let mut status = 0;
        // SAFETY: waiting on the child we forked, with storage we own.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            wif_exited(status),
            "the child did not exit normally (status {status:#x}); a hung supervisor alarms out"
        );
        assert_eq!(
            wexit_status(status),
            libc::EACCES,
            "the denied openat returned {} and not EACCES",
            wexit_status(status)
        );
    }

    /// A stale notification is not answered into.
    ///
    /// The target dies while the supervisor holds its notification; `ID_VALID`
    /// is what stops the answer landing in a reused id and deciding somebody
    /// else's syscall.
    #[test]
    fn a_notification_whose_target_died_is_not_answered_into() {
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};

        let mut sv: [libc::c_int; 2] = [0; 2];
        // SAFETY: a socketpair into storage we own.
        let made =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(made, 0);
        // SAFETY: freshly created descriptors, unowned elsewhere.
        let (parent_end, child_end) =
            unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

        // SAFETY: `fork`; the child reaches `_exit` on every path.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(parent_end);
            // SAFETY: `alarm` takes no pointers.
            unsafe { libc::alarm(20) };
            let Ok(listener) = install_openat_filter() else {
                // SAFETY: `_exit` in a forked child.
                unsafe { libc::_exit(101) }
            };
            let _ = send_fd(child_end.as_fd(), listener.as_fd());
            drop(listener);
            // SAFETY: the trapped call; the supervisor will never answer it.
            unsafe { libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) };
            // SAFETY: `_exit` in a forked child.
            unsafe { libc::_exit(0) }
        }

        drop(child_end);
        let listener = recv_fd(parent_end.as_fd()).expect("the listener");
        let notification = recv(listener.as_fd()).expect("the notification");
        assert!(id_valid(listener.as_fd(), notification.id));

        // Kill the target while its syscall is held, and reap it.
        // SAFETY: signalling the child we forked.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        // SAFETY: waiting on that child.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };

        assert!(
            !id_valid(listener.as_fd(), notification.id),
            "a dead target's notification still reads as live"
        );
        // Answering it is a no-op rather than an error: the syscall it named is
        // already gone, which is the outcome, so the supervisor is not asked to
        // handle a failure that is not one.
        respond_deny(listener.as_fd(), notification.id, libc::EACCES)
            .expect("answering a stale id must not be an error");
    }

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
