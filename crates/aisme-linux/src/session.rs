// SPDX-License-Identifier: Apache-2.0
//! Starting a supervised session: fork, confine the child, keep the parent.
//!
//! **`aisme run` is the session's ancestor, and that is the whole point.** There
//! are exactly two ways to observe a process tree's actions on Linux — own the
//! tree, or hold a capability — and the kernel is built to refuse a third.
//! Measured: an unprivileged `fanotify` listener is told an event happened and
//! is given `pid=0` for every process but itself; Yama grants a sibling the
//! memory of the process that named it and **not** that process's children,
//! while it grants an **ancestor** everything at any depth with no grant at all
//! (`docs/12`, M4, M8, M9). Every real agent forks, so a supervisor that is not
//! an ancestor supervises only the first process of a session.
//!
//! **Why it lives here and not in `aisme-cli`.** `fork` and `pre_exec` are
//! `unsafe`, and `unsafe` is forbidden in L4's product edges (`CLAUDE.md`).
//! Putting the whole sequence in one L2 function is what the adapter layer is
//! for, and it means there is exactly one place to audit rather than a hazard
//! spread across a command-line crate.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::PathBuf;
use std::process::{Child, Command};

use aisme_core::error::{Error, Result};

/// A session that is running, and what the parent needs to supervise it.
pub struct Supervised {
    /// The supervised command.
    pub child: Child,
    /// Its seccomp listener, when the session asked to be trapped.
    pub listener: Option<OwnedFd>,
    /// The Landlock ABI the write scope was applied at, or `None` where this
    /// kernel has no Landlock — a named degradation and never a refusal.
    pub landlock_abi: Option<u8>,
}

/// How many threads this process has, from `/proc/self/status`.
///
/// **Load-bearing rather than defensive.** Between `fork` and `execve` only
/// async-signal-safe calls are legal in a process that has threads, because a
/// lock another thread held is frozen in the child and never released — and the
/// child below allocates, opens files and builds a Landlock ruleset. In a
/// single-threaded process none of that can deadlock. So the count is checked
/// rather than assumed, and a threaded caller is refused with the reason
/// instead of deadlocking one run in a thousand.
fn threads() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
}

/// Fork, confine the child, `exec` the command, and keep the parent alive as
/// its supervisor.
///
/// The child, in order, and nothing that can fail is placed after the filter:
///
/// 1. `PR_SET_PDEATHSIG(SIGKILL)` — killing the supervisor kills the session.
///    `F2.WS.08` justified `exec` by saying *"nothing in the chain can be
///    skipped by killing an intermediary"*, and this is what keeps that true
///    now that there is an intermediary. Measured: it survives `execve` and
///    fires (`docs/12`, M5).
/// 2. The Landlock write scope, which the child then cannot widen.
/// 3. The seccomp filter, when the session asked for one, and its listener is
///    handed to the parent over a socketpair — `SECCOMP_FILTER_FLAG_NEW_LISTENER`
///    gives the descriptor to whoever installed the filter, and that has to be
///    the process the filter applies to.
/// 4. `execve`.
///
/// **No acknowledgement travels back**, and none is needed: a trapped syscall
/// blocks in the kernel until somebody answers it, so a child that runs ahead of
/// the parent's loop simply waits. If the parent dies first the listener closes
/// and every held syscall gets `ENOSYS`, which is fail-closed.
///
/// # Errors
///
/// A threaded caller, a command that cannot be spawned, or a confinement the
/// kernel refused. The caller must not run the command unsupervised on any of
/// them: a command somebody asked to have watched must not run unwatched
/// without being told.
pub fn spawn_supervised(
    program: &str,
    args: &[String],
    scopes: &[PathBuf],
    trap_openat: bool,
) -> Result<Supervised> {
    use std::os::unix::process::CommandExt as _;

    match threads() {
        Some(1) => {}
        Some(n) => {
            return Err(Error::unsupported(format!(
                "aisme run has {n} threads; the child's setup between fork and exec allocates, \
                 which is only safe in a single-threaded process"
            )));
        }
        None => {
            return Err(Error::unsupported(
                "/proc/self/status is unreadable, so the thread count cannot be checked".to_owned(),
            ));
        }
    }

    // Probed in the parent so the caller can report the degradation before the
    // fork, and applied in the child so only the child is confined.
    let support = crate::landlock::probe();

    let (ours, theirs) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| Error::unsupported(format!("socketpair: {e}")))?;

    let scopes: Vec<PathBuf> = scopes.to_vec();
    let mut command = Command::new(program);
    command.args(args);

    // SAFETY: the closure runs in the child between `fork` and `execve`. The
    // thread count above is 1, so no lock can be held by another thread and the
    // allocations inside `restrict_writes_to` cannot deadlock. Nothing here
    // touches the parent's memory: `scopes` and `theirs` are moved in, and the
    // child either `exec`s or returns an error std reports through its own pipe.
    unsafe {
        command.pre_exec(move || {
            // 1. Die with the supervisor. `prctl` here takes no pointers; the
            //    enclosing `unsafe` on `pre_exec` is what covers this block.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 2. The write scope. A kernel without Landlock is a named
            //    degradation the parent already reported, not a refusal here.
            if crate::landlock::probe().available() {
                crate::landlock::restrict_writes_to(&scopes)
                    .map_err(|e| std::io::Error::other(e.detail))?;
            }
            // 3. The filter, and its listener to the parent. From here the
            //    child is trapped whatever happens next.
            if trap_openat {
                let listener = crate::seccomp::install_openat_filter()
                    .map_err(|e| std::io::Error::other(e.detail))?;
                crate::seccomp::send_fd(theirs.as_fd(), listener.as_fd(), b"L\n")
                    .map_err(|e| std::io::Error::other(e.detail))?;
            }
            Ok(())
        });
    }

    // `Invalid` and not `Unsupported`: the caller named a program that is not
    // there, which is a different thing from a platform that cannot do this —
    // and the difference is what lets `aisme run` keep exiting **127** for a
    // command that could not be run, which is the shell's convention and what
    // anything scripted around it reads.
    let child = command.spawn().map_err(|e| {
        Error::new(
            aisme_core::error::ErrorKind::Invalid,
            format!("cannot exec {program}: {e}"),
        )
    })?;

    let listener = if trap_openat {
        Some(crate::seccomp::recv_fd(ours.as_fd())?)
    } else {
        None
    };

    Ok(Supervised {
        child,
        listener,
        landlock_abi: support.available().then_some(support.abi),
    })
}

/// Leave this process wearing the status the supervised command left.
///
/// **A death by signal must look like a death by signal.** Exiting with
/// `128 + n` is what a shell *prints*, not what it sees: a caller that inspects
/// the wait status would read a normal exit where there was none, and anything
/// scripted around `aisme run` would stop being able to tell a crash from a
/// program that chose to return 137. The signal is re-raised on this process
/// with the default handler restored, so the parent of `aisme run` observes
/// exactly what it would have observed without it.
///
/// Never returns.
pub fn exit_like(status: std::process::ExitStatus) -> ! {
    use std::os::unix::process::ExitStatusExt as _;

    if let Some(signal) = status.signal() {
        // SAFETY: restoring the default disposition and raising a signal on
        // this process; neither takes a pointer and neither can fail in a way
        // the fallback below does not cover.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
        // Only reached if the signal was somehow blocked or ignored, which
        // would make the status unreproducible. The shell's spelling is then
        // the honest second best, and it is reached only here.
        std::process::exit(128 + signal);
    }
    std::process::exit(status.code().unwrap_or(1));
}
