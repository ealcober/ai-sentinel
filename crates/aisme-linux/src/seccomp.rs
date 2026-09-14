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

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

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

impl Notification {
    /// The directory descriptor argument of an `openat`, read as the kernel
    /// stored it.
    ///
    /// **Truncate and reinterpret; never range-check.** A descriptor is a
    /// 32-bit value and the kernel leaves it in a 64-bit argument slot without
    /// sign-extending, so `AT_FDCWD` — which is `-100` — arrives as
    /// `0x0000_0000_ffff_ff9c`. `i32::try_from` on that is an **error**, and a
    /// caller that wrote `.unwrap_or(0)` would turn the commonest `openat` in
    /// the system into one relative to file descriptor **0**: an absence read
    /// as a value, in the conversion written to avoid one. Measured, not
    /// reasoned: the first version of this code did exactly that and refused
    /// every plain `open` as "relative to a descriptor".
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "the argument slot holds a 32-bit descriptor; truncating is the correct read"
    )]
    pub const fn dirfd(&self) -> i32 {
        self.args[0] as i64 as i32
    }

    /// The flags argument of an `openat`, read the same way and for the same
    /// reason.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "the argument slot holds a 32-bit flag set; truncating is the correct read"
    )]
    pub const fn open_flags(&self) -> i32 {
        self.args[2] as i64 as i32
    }

    /// The path argument: a **pointer** into the target's memory, never a path.
    #[must_use]
    pub const fn path_addr(&self) -> u64 {
        self.args[1]
    }
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
pub fn send_fd(
    socket: BorrowedFd<'_>,
    fd: BorrowedFd<'_>,
    payload: &[u8],
) -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;

    // The descriptor travels **with its own request**, not beside it. SCM_RIGHTS
    // needs at least one byte of ordinary data, and a filler byte would land in
    // the reader's stream ahead of the line it belongs to — measured: the
    // daemon received `\0{"jsonrpc"…}` and the request did not parse, while the
    // filtered session died with ENOSYS because nobody answered it.
    if payload.is_empty() {
        return Err(Error::unsupported(
            "a descriptor must travel with its request; SCM_RIGHTS needs a byte of data",
        ));
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: payload.len(),
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

// ---------------------------------------------------------------------------
// The allow path: a descriptor the supervisor opened (`I-28`, `F2.WS.05`)
// ---------------------------------------------------------------------------

/// `RESOLVE_NO_MAGICLINKS` — refuse to traverse `/proc/*/fd/*` and friends,
/// which are links whose target changes under the resolver.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

/// `SECCOMP_ADDFD_FLAG_SEND` — install the descriptor **and** return it as the
/// syscall's value, in one step. Kernel ≥ 5.14.
const ADDFD_FLAG_SEND: u32 = 0x02;

/// Why an `openat` cannot be permitted as asked.
///
/// Every variant names the thing that stopped it, because "unsupported" tells
/// an operator nothing they can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreproducible {
    /// A flag outside the F2 subset, by the name the caller used.
    Flag(&'static str),
    /// The call named a directory descriptor rather than the cwd.
    RelativeToDescriptor,
}

impl Unreproducible {
    /// The operator's words.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Unreproducible::Flag(name) => name,
            Unreproducible::RelativeToDescriptor => {
                "openat relative to a directory descriptor (F2 reproduces AT_FDCWD only)"
            }
        }
    }
}

/// Whether F2 can reproduce this `openat` exactly.
///
/// **Limit one of `Q-13`.** F2 opens for reading, with `O_CLOEXEC`. Anything
/// whose effect this subset cannot reproduce — a create, a truncate, an append,
/// a directory open, a write mode — is **denied with the flag named**, never
/// permitted: a descriptor that does not mean what the caller asked for is
/// worse than a refusal, because the caller will use it believing it does.
///
/// # Errors
///
/// The first flag that puts the call outside the subset.
pub fn reproducible(dirfd: i32, flags: i32) -> Result<(), Unreproducible> {
    if dirfd != libc::AT_FDCWD {
        return Err(Unreproducible::RelativeToDescriptor);
    }
    for (bit, name) in [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_PATH, "O_PATH"),
        (libc::O_TMPFILE, "O_TMPFILE"),
    ] {
        // `O_TMPFILE` carries `O_DIRECTORY` in its own bit pattern, so it is
        // tested as a whole mask rather than as a single bit.
        if flags & bit == bit {
            return Err(Unreproducible::Flag(name));
        }
    }
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => Ok(()),
        libc::O_WRONLY => Err(Unreproducible::Flag("O_WRONLY")),
        _ => Err(Unreproducible::Flag("O_RDWR")),
    }
}

/// Read the target's path argument out of its memory.
///
/// **Nothing decided from this may be delivered to the target as permission to
/// re-resolve it.** The string is read to learn what to open; what the target
/// receives is the descriptor this supervisor opened from it. If the target
/// rewrites the buffer after this read, it changes nothing: the file was
/// already chosen, opened and validated, and an fd names an inode rather than
/// a name (`I-28`).
///
/// # Errors
///
/// `process_vm_readv`'s errno, or a path with no terminator inside the window
/// read — which is refused rather than truncated into a shorter path that
/// names a different file.
pub fn read_target_path(pid: u32, addr: u64) -> aisme_core::error::Result<std::ffi::CString> {
    use aisme_core::error::Error;

    let mut buf = [0u8; libc::PATH_MAX as usize];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: usize::try_from(addr).unwrap_or(0) as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: both iovecs point at storage that outlives the call; the remote
    // one is the target's and the kernel validates it, returning EFAULT rather
    // than faulting us.
    let got = unsafe {
        libc::process_vm_readv(
            libc::pid_t::try_from(pid).unwrap_or(-1),
            std::ptr::addr_of!(local),
            1,
            std::ptr::addr_of!(remote),
            1,
            0,
        )
    };
    if got < 0 {
        // A short read at the end of a mapping is ordinary; retry the tail in
        // one page so a path near a boundary is not lost. F2 keeps it simple
        // and refuses, naming it, rather than reading a partial path.
        return Err(Error::unsupported(format!(
            "process_vm_readv from {pid}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let len = usize::try_from(got).unwrap_or(0);
    let end = buf[..len]
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::unsupported("the path argument has no terminator"))?;
    std::ffi::CString::new(&buf[..end])
        .map_err(|e| Error::unsupported(format!("the path argument: {e}")))
}

/// Open `path` the way the target asked, from the target's own directory.
///
/// Resolved relative to `/proc/<pid>/cwd`, so a relative path means what it
/// meant to the caller, and with `RESOLVE_NO_MAGICLINKS`, so the resolution
/// cannot be steered through a link whose target moves.
///
/// # Errors
///
/// `openat2`'s errno — including the target's own `ENOENT`, which is the
/// answer the caller would have got and is passed back unchanged.
pub fn open_as_target(pid: u32, path: &std::ffi::CStr) -> aisme_core::error::Result<OwnedFd> {
    use aisme_core::error::Error;

    let cwd = std::ffi::CString::new(format!("/proc/{pid}/cwd"))
        .map_err(|e| Error::unsupported(format!("cwd path: {e}")))?;
    // SAFETY: `O_PATH|O_DIRECTORY` on a NUL-terminated path; the descriptor is
    // owned below.
    let dirfd = unsafe { libc::open(cwd.as_ptr(), libc::O_PATH | libc::O_DIRECTORY) };
    if dirfd < 0 {
        return Err(Error::unsupported(format!(
            "/proc/{pid}/cwd: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: freshly opened, unowned elsewhere.
    let dir = unsafe { OwnedFd::from_raw_fd(dirfd) };

    // `open_how` is `#[non_exhaustive]` in libc, so it is zeroed and filled —
    // which is also the kernel's own contract: unknown fields must be zero, and
    // starting from zero is how that stays true when the struct grows.
    // SAFETY: an all-zero `open_how` is the documented starting point.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    // The flags this subset reproduces, and only these: `reproducible` has
    // already refused anything else (limit one of `Q-13`).
    how.flags = u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC).unwrap_or(0);
    how.resolve = RESOLVE_NO_MAGICLINKS;
    // SAFETY: `openat2` with a directory descriptor we own, a NUL-terminated
    // path, and an `open_how` that outlives the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            std::ptr::addr_of!(how),
            size_of::<libc::open_how>(),
        )
    };
    let fd = RawFd::try_from(fd)
        .map_err(|_| Error::unsupported("openat2 returned something that is not a descriptor"))?;
    if fd < 0 {
        return Err(Error::unsupported(format!(
            "openat2 {}: {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the kernel just gave us this descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Permit the held syscall by handing the target **our** descriptor.
///
/// This is the whole of `I-28` in one call. `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
/// would let the kernel re-run the syscall, re-resolving the path string after
/// the decision — and a rename of any directory component, by any process on
/// the machine, changes what that string names. The freezer does not close it
/// either: the attack does not need the bytes to change. Only a descriptor the
/// supervisor opened and validated survives, because a descriptor names an
/// inode and not a name.
///
/// `SECCOMP_ADDFD_FLAG_SEND` installs the descriptor and returns it as the
/// syscall's value in one step; it needs kernel ≥ 5.14.
///
/// # Errors
///
/// The ioctl's errno. A stale id is success: the syscall it named is gone.
pub fn respond_with_fd(
    listener: BorrowedFd<'_>,
    id: u64,
    fd: BorrowedFd<'_>,
) -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;

    if !id_valid(listener, id) {
        return Ok(());
    }
    // SAFETY: a zeroed `seccomp_notif_addfd`, every field set below.
    let mut addfd: libc::seccomp_notif_addfd = unsafe { std::mem::zeroed() };
    addfd.id = id;
    addfd.flags = ADDFD_FLAG_SEND;
    addfd.srcfd = u32::try_from(fd.as_raw_fd()).unwrap_or(0);
    addfd.newfd = 0;
    addfd.newfd_flags = u32::try_from(libc::O_CLOEXEC).unwrap_or(0);

    // SAFETY: the ioctl reads `addfd`, which we own and which outlives it.
    let rc = unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ADDFD,
            std::ptr::addr_of!(addfd),
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(Error::unsupported(format!("NOTIF_ADDFD: {e}")));
    }
    Ok(())
}

/// Answer every syscall this listener holds, until it closes.
///
/// **What F2 can and cannot do here, stated because it constrains the caller.**
/// A classic BPF filter sees syscall numbers and register values, never paths,
/// so the filter traps *every* `openat` and the supervisor decides each one.
/// The only "permit unchanged" the kernel offers is
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, which `I-28` forbids for a path-bearing
/// syscall — so an open this supervisor cannot reproduce cannot be permitted
/// either, and is denied.
///
/// That makes this loop **correct and narrow at the same time**: a session
/// running under it may read and may not write, because limit one of `Q-13`
/// reproduces `O_RDONLY` only. It is why `aisme run` does not install the
/// filter by default — `F3.PT.02`'s kernel-side trie is what will let the
/// filter trap the escalate class alone, and until then a session-wide filter
/// would deny every write in the session.
///
/// Each answer is reported through `record`, so the caller can put it in the
/// WAL: the tuple is the syscall's pid, whether a validated descriptor was
/// delivered, and the reason when it was not.
///
/// # Errors
///
/// Only a listener that failed for a reason other than closing. A closed
/// listener — the session ended — is the ordinary exit and returns `Ok`.
pub fn serve_notifications(
    listener: BorrowedFd<'_>,
    mut record: impl FnMut(u32, bool, Option<&str>),
) -> aisme_core::error::Result<()> {
    loop {
        let Ok(n) = recv(listener) else {
            // The listener closed: the session is over. Every syscall still
            // held gets ENOSYS from the kernel, which is fail-closed and is
            // the kernel's answer rather than one of ours.
            return Ok(());
        };
        if n.nr != i32::try_from(libc::SYS_openat).unwrap_or(-1) {
            // The filter traps nothing else, so this is a kernel we do not
            // understand. Denying is the safe direction and it is named.
            respond_deny(listener, n.id, libc::EACCES)?;
            record(n.pid, false, Some("a syscall the filter does not trap"));
            continue;
        }
        if let Err(why) = reproducible(n.dirfd(), n.open_flags()) {
            respond_deny(listener, n.id, libc::EACCES)?;
            record(n.pid, false, Some(why.reason()));
            continue;
        }
        let Ok(path) = read_target_path(n.pid, n.path_addr()) else {
            respond_deny(listener, n.id, libc::EACCES)?;
            record(n.pid, false, Some("the path argument could not be read"));
            continue;
        };
        if let Ok(fd) = open_as_target(n.pid, &path) {
            respond_with_fd(listener, n.id, fd.as_fd())?;
            record(n.pid, true, None);
        } else {
            // The supervisor's own open failed — most often the target's own
            // ENOENT. Answering EACCES rather than passing the errno through is
            // the conservative choice and is visible in the record; widening it
            // is `F3.EN.12`'s.
            respond_deny(listener, n.id, libc::EACCES)?;
            record(n.pid, false, Some("the supervisor could not open it"));
        }
    }
}

/// Let `pid` read this process's memory, and nothing else.
///
/// **Measured, not anticipated.** `process_vm_readv` needs
/// `PTRACE_MODE_ATTACH_REALCREDS`, and Yama's default `ptrace_scope = 1` grants
/// that only to a **descendant's ancestor**. `agentd` is the session's sibling,
/// not its parent, so without this every path argument read fails and every
/// trapped `openat` is denied — which is what the first end-to-end run did,
/// fourteen times, with `cat` reporting *"libc.so.6: Permission denied"*.
///
/// `PR_SET_PTRACER` is the narrow grant that fits: **one** named process, set by
/// the session on itself, before it is supervised. It is not `CAP_SYS_PTRACE`
/// for the daemon and it is not `ptrace_scope = 0` for the machine.
///
/// # Errors
///
/// `prctl`'s errno. On a kernel without Yama the call is refused as unknown and
/// that is **not** a failure: nothing was blocking the read there.
pub fn allow_ptrace_by(pid: i32) -> aisme_core::error::Result<()> {
    use aisme_core::error::Error;

    // SAFETY: `PR_SET_PTRACER` takes an integer, no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::c_long::from(pid), 0, 0, 0) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        // No Yama: the option does not exist and nothing needed granting.
        if e.raw_os_error() == Some(libc::EINVAL) {
            return Ok(());
        }
        return Err(Error::unsupported(format!("PR_SET_PTRACER({pid}): {e}")));
    }
    Ok(())
}

/// The pid on the other end of a connected Unix socket.
///
/// The kernel's answer, which neither side can forge — the same fact the
/// daemon's own authorization rests on, read from the client's side.
///
/// # Errors
///
/// `getsockopt`'s errno.
pub fn peer_pid(socket: BorrowedFd<'_>) -> aisme_core::error::Result<i32> {
    use aisme_core::error::Error;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = u32::try_from(size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: `cred` is a live, correctly sized `ucred` and `len` is its size;
    // the descriptor is borrowed for the call.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(Error::unsupported(format!(
            "SO_PEERCRED: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(cred.pid)
}

#[cfg(test)]
// A panic is the failure report in a test; the adapter's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        id_valid, install_openat_filter, open_as_target, probe, read_target_path, recv, recv_fd,
        reproducible, respond_deny, respond_with_fd, send_fd, wexit_status, wif_exited,
        Unreproducible,
    };
    use std::os::fd::OwnedFd;

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
            if send_fd(child_end.as_fd(), listener.as_fd(), b"listener\n").is_err() {
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

    /// Set up a socketpair and fork; the child installs the filter and hands
    /// the listener back. Returns `(pid, parent_end)` in the parent and runs
    /// `child` in the child, which never returns.
    ///
    /// Written once because four tests need the same dance, and a dance
    /// repeated four times drifts in one of them.
    fn supervised(
        child: impl FnOnce(std::os::fd::BorrowedFd<'_>) -> i32,
    ) -> (i32, OwnedFd, OwnedFd) {
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};

        let mut sv: [libc::c_int; 2] = [0; 2];
        // SAFETY: a socketpair into storage we own.
        let made =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(made, 0, "socketpair: {}", std::io::Error::last_os_error());
        // SAFETY: freshly created descriptors, unowned elsewhere.
        let (parent_end, child_end) =
            unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

        // SAFETY: `fork`; the child reaches `_exit` on every path below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            drop(parent_end);
            // A supervisor that never answers must not hang the suite.
            // SAFETY: `alarm` takes no pointers.
            unsafe { libc::alarm(20) };
            let Ok(listener) = install_openat_filter() else {
                // SAFETY: `_exit` in a forked child.
                unsafe { libc::_exit(101) }
            };
            if send_fd(child_end.as_fd(), listener.as_fd(), b"listener\n").is_err() {
                // SAFETY: as above.
                unsafe { libc::_exit(102) }
            }
            drop(listener);
            let code = child(child_end.as_fd());
            // SAFETY: `_exit` in a forked child.
            unsafe { libc::_exit(code) }
        }
        (pid, parent_end, child_end)
    }

    /// Reap the child and return its exit code, failing loudly on a signal.
    fn reap(pid: i32) -> i32 {
        let mut status = 0;
        // SAFETY: waiting on the child we forked, with storage we own.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid);
        assert!(
            wif_exited(status),
            "the child did not exit normally (status {status:#x}); a hung supervisor alarms out"
        );
        wexit_status(status)
    }

    /// Open a path and return its first byte, or a marker. Runs in the child.
    fn open_and_read_first_byte(path: &std::ffi::CStr) -> i32 {
        // SAFETY: `open` with a NUL-terminated path and no mode.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            // SAFETY: errno immediately after a failed call.
            return 200 + unsafe { *libc::__errno_location() }.min(50);
        }
        let mut byte = [0u8; 1];
        // SAFETY: reading one byte into storage we own, from a descriptor the
        // kernel just installed.
        let got = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
        // SAFETY: closing a descriptor we own.
        unsafe { libc::close(fd) };
        if got == 1 {
            i32::from(byte[0])
        } else {
            199
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aisme-seccomp-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cstr(path: &std::path::Path) -> std::ffi::CString {
        std::ffi::CString::new(path.to_str().unwrap()).unwrap()
    }

    /// The allow path: the target receives **the supervisor's** descriptor, and
    /// reads through it.
    #[test]
    fn an_allowed_openat_delivers_a_descriptor_the_supervisor_opened() {
        use std::os::fd::AsFd;

        let dir = scratch("allow");
        let file = dir.join("secret");
        std::fs::write(&file, b"A").unwrap();
        let path = cstr(&file);

        let (pid, parent_end, child_end) =
            supervised(move |_| open_and_read_first_byte(&path.clone()));
        drop(child_end);

        let listener = recv_fd(parent_end.as_fd()).expect("the listener");
        let n = recv(listener.as_fd()).expect("the notification");
        // Limit one: only what F2 reproduces exactly.
        reproducible(n.dirfd(), n.open_flags()).unwrap_or_else(|e| {
            panic!(
                "dirfd {} flags {:#o} refused: {}",
                n.dirfd(),
                n.open_flags(),
                e.reason()
            )
        });
        let asked = read_target_path(n.pid, n.path_addr()).expect("the path argument");
        let opened = open_as_target(n.pid, &asked).expect("the supervisor's own open");
        respond_with_fd(listener.as_fd(), n.id, opened.as_fd()).expect("ADDFD");

        assert_eq!(
            reap(pid),
            i32::from(b'A'),
            "the target did not read through the descriptor we handed it"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// TOCTOU, form (i): the path buffer changes **after** the syscall, and the
    /// target still receives the file the supervisor validated.
    ///
    /// The supervisor plays the attacker so the race is deterministic: it reads
    /// the argument, rewrites the target's own buffer to name a different file,
    /// then opens what it read and answers. Under
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` the kernel would re-resolve that
    /// buffer and the target would receive the *other* file — which is exactly
    /// why `CONTINUE` may never permit a path-bearing syscall (`I-28`).
    #[test]
    fn rewriting_the_path_after_the_syscall_does_not_change_what_arrives() {
        use std::os::fd::AsFd;

        let dir = scratch("toctou-i");
        let good = dir.join("authorized");
        let evil = dir.join("swapped-in");
        std::fs::write(&good, b"A").unwrap();
        std::fs::write(&evil, b"B").unwrap();
        assert_eq!(
            good.to_str().unwrap().len(),
            evil.to_str().unwrap().len(),
            "the two paths must be the same length so the rewrite fits the buffer"
        );
        let asked_for = cstr(&good);
        let swapped = cstr(&evil);

        let (pid, parent_end, child_end) =
            supervised(move |_| open_and_read_first_byte(&asked_for.clone()));
        drop(child_end);

        let listener = recv_fd(parent_end.as_fd()).expect("the listener");
        let n = recv(listener.as_fd()).expect("the notification");
        let read_back = read_target_path(n.pid, n.path_addr()).expect("the path argument");

        // The attack: the target's buffer now names the other file.
        let bytes = swapped.as_bytes_with_nul();
        let local = libc::iovec {
            iov_base: bytes.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: bytes.len(),
        };
        let remote = libc::iovec {
            iov_base: usize::try_from(n.args[1]).unwrap_or(0) as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        // SAFETY: both iovecs point at storage that outlives the call; the
        // kernel validates the remote one and returns EFAULT rather than
        // faulting us.
        let wrote = unsafe {
            libc::process_vm_writev(
                libc::pid_t::try_from(n.pid).unwrap_or(-1),
                std::ptr::addr_of!(local),
                1,
                std::ptr::addr_of!(remote),
                1,
                0,
            )
        };
        assert!(
            wrote > 0,
            "the rewrite did not happen, so nothing was raced"
        );
        assert_eq!(
            read_target_path(n.pid, n.args[1]).unwrap(),
            swapped,
            "the target's buffer was not actually changed"
        );

        // We open what we READ, not what the buffer says now.
        let opened = open_as_target(n.pid, &read_back).expect("the supervisor's own open");
        respond_with_fd(listener.as_fd(), n.id, opened.as_fd()).expect("ADDFD");

        assert_eq!(
            reap(pid),
            i32::from(b'A'),
            "the target received the swapped-in file: the decision and the object came apart"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// TOCTOU, form (ii): a directory component is **renamed** between the
    /// decision and the response.
    ///
    /// This is the one the cgroup freezer would not have caught. The attack
    /// needs no access to the target and does not change a single byte of the
    /// path: any process on the machine can rename a directory, and the same
    /// string then names a different file. Only a descriptor survives it,
    /// because a descriptor names an inode and a path names a name.
    #[test]
    fn renaming_a_directory_after_the_decision_does_not_change_what_arrives() {
        use std::os::fd::AsFd;

        let dir = scratch("toctou-ii");
        let live = dir.join("workspace");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("data"), b"A").unwrap();
        let path = cstr(&live.join("data"));

        let (pid, parent_end, child_end) =
            supervised(move |_| open_and_read_first_byte(&path.clone()));
        drop(child_end);

        let listener = recv_fd(parent_end.as_fd()).expect("the listener");
        let n = recv(listener.as_fd()).expect("the notification");
        let asked = read_target_path(n.pid, n.path_addr()).expect("the path argument");

        // Decided and opened: from here the object is fixed.
        let opened = open_as_target(n.pid, &asked).expect("the supervisor's own open");

        // The attack, by a third party with no access to the target: the
        // directory moves aside and a different tree takes its name.
        let moved = dir.join("moved-aside");
        std::fs::rename(&live, &moved).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("data"), b"B").unwrap();

        respond_with_fd(listener.as_fd(), n.id, opened.as_fd()).expect("ADDFD");

        assert_eq!(
            reap(pid),
            i32::from(b'A'),
            "the rename changed what the target received: the string was resolved twice"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `AT_FDCWD` survives the trip through a 64-bit argument slot.
    ///
    /// The regression this pins: `i32::try_from(args[0] as i64)` **fails** for
    /// `AT_FDCWD`, because the kernel leaves the 32-bit descriptor
    /// zero-extended as `0x0000_0000_ffff_ff9c`. A caller that wrote
    /// `.unwrap_or(0)` would read the commonest `openat` in the system as one
    /// relative to descriptor 0.
    #[test]
    fn a_descriptor_argument_is_truncated_and_not_range_checked() {
        let mut n = super::Notification {
            id: 0,
            pid: 0,
            nr: 0,
            args: [0; 6],
        };
        // As the kernel presents it.
        n.args[0] = 0x0000_0000_ffff_ff9c;
        assert_eq!(n.dirfd(), libc::AT_FDCWD);
        assert!(
            i32::try_from(n.args[0]).is_err(),
            "the value does fit i32, so this test no longer pins anything"
        );

        n.args[2] = u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC).unwrap_or(0);
        assert_eq!(n.open_flags(), libc::O_RDONLY | libc::O_CLOEXEC);
        assert!(reproducible(n.dirfd(), n.open_flags()).is_ok());
    }

    /// Limit one of `Q-13`: anything F2 cannot reproduce exactly is denied
    /// **with the flag named**, never permitted.
    #[test]
    fn a_flag_outside_the_subset_is_denied_by_name() {
        assert!(reproducible(libc::AT_FDCWD, libc::O_RDONLY).is_ok());
        assert!(reproducible(libc::AT_FDCWD, libc::O_RDONLY | libc::O_CLOEXEC).is_ok());

        for (flags, name) in [
            (libc::O_RDONLY | libc::O_CREAT, "O_CREAT"),
            (libc::O_RDONLY | libc::O_TRUNC, "O_TRUNC"),
            (libc::O_RDONLY | libc::O_APPEND, "O_APPEND"),
            (libc::O_RDONLY | libc::O_DIRECTORY, "O_DIRECTORY"),
            (libc::O_WRONLY, "O_WRONLY"),
            (libc::O_RDWR, "O_RDWR"),
        ] {
            let refused = reproducible(libc::AT_FDCWD, flags).unwrap_err();
            assert_eq!(
                refused.reason(),
                name,
                "the refusal did not name the flag that caused it"
            );
        }

        // Limit one also covers where the path is resolved from: F2 reproduces
        // AT_FDCWD only, and a real directory descriptor is refused rather than
        // resolved from the wrong directory.
        let refused = reproducible(3, libc::O_RDONLY).unwrap_err();
        assert_eq!(refused, Unreproducible::RelativeToDescriptor);
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
            let _ = send_fd(child_end.as_fd(), listener.as_fd(), b"listener\n");
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
