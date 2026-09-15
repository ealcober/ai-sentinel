// SPDX-License-Identifier: Apache-2.0
//! `aisme run`'s composition root (plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in this crate that names a concrete adapter or uses
//! `cfg(target_os)`.** `aisme run` forks a confined child and then supervises
//! it, and a choice like that belongs in one auditable place — the same reason
//! `A-05` puts a composition root on every L3 engine.
//!
//! Every function here is a thin naming of an `aisme-linux` seam. The `unsafe`
//! that a fork and a signal re-raise require lives there, in L2, because §3.1
//! forbids it in L4's product edges.

/// Fork, confine the child, `exec` the command, and return what the parent
/// needs to supervise it.
///
/// # Errors
///
/// The adapter's own refusal, named: a threaded caller, a command that cannot
/// be spawned, or a confinement the kernel rejected.
#[cfg(target_os = "linux")]
pub fn spawn_supervised(
    program: &str,
    args: &[String],
    scopes: &[std::path::PathBuf],
    trap_openat: bool,
) -> Result<aisme_linux::Supervised, (u8, String)> {
    aisme_linux::spawn_supervised(program, args, scopes, trap_openat).map_err(|e| {
        // 127 is the shell's convention for "command not found", and a caller
        // that scripts around `aisme run` reads it the same way. Everything
        // else is this guard failing, which is an ordinary 1.
        let code = if e.kind == aisme_core::error::ErrorKind::Invalid {
            127
        } else {
            1
        };
        (code, e.detail)
    })
}

/// Answer this session's held opens until its last process is gone.
///
/// `allow` decides one open and `record` is told what became of it. The adapter
/// owns the `I-28` machinery — `openat2` with `RESOLVE_NO_MAGICLINKS`, the
/// reproducible subset, `ADDFD` — and this crate owns neither.
///
/// # Errors
///
/// The adapter's own refusal, named.
#[cfg(target_os = "linux")]
pub fn serve_notifications(
    listener: std::os::fd::BorrowedFd<'_>,
    allow: impl FnMut(&str) -> bool,
    record: impl FnMut(u32, bool, Option<&str>),
) -> Result<(), String> {
    aisme_linux::serve_notifications_with(listener, allow, record).map_err(|e| e.detail)
}

/// Leave this process wearing the status the supervised command left, so a
/// death by signal looks like one.
#[cfg(target_os = "linux")]
pub fn exit_like(status: std::process::ExitStatus) -> ! {
    aisme_linux::exit_like(status)
}

/// Off Linux there is no seccomp, no Landlock and no session to supervise.
#[cfg(not(target_os = "linux"))]
pub fn spawn_supervised(
    _program: &str,
    _args: &[String],
    _scopes: &[std::path::PathBuf],
    _trap_openat: bool,
) -> Result<std::convert::Infallible, (u8, String)> {
    Err((1, "a supervised session needs a Linux kernel".to_owned()))
}

/// Off Linux there are no notifications to answer.
#[cfg(not(target_os = "linux"))]
pub fn serve_notifications(
    _listener: std::os::fd::BorrowedFd<'_>,
    _allow: impl FnMut(&str) -> bool,
    _record: impl FnMut(u32, bool, Option<&str>),
) -> Result<(), String> {
    Err("seccomp needs a Linux kernel".to_owned())
}

/// Off Linux the status is propagated without a signal to re-raise.
#[cfg(not(target_os = "linux"))]
pub fn exit_like(status: std::process::ExitStatus) -> ! {
    std::process::exit(status.code().unwrap_or(1));
}
