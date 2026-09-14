// SPDX-License-Identifier: Apache-2.0
//! `aisme run`'s composition root (plan §3.1 rules `A-01`, `A-05`).
//!
//! **The only module in this crate that names a concrete adapter or uses
//! `cfg(target_os)`.** `aisme run` installs a kernel filter on itself, and a
//! choice like that belongs in one auditable place — the same reason `A-05`
//! puts a composition root on every L3 engine.

/// Install the escalate-class seccomp filter on this process and return its
/// listener.
///
/// # Errors
///
/// The kernel's own refusal, named.
#[cfg(target_os = "linux")]
pub fn install_filter() -> Result<std::os::fd::OwnedFd, String> {
    aisme_linux::install_openat_filter().map_err(|e| e.detail)
}

/// Off Linux there is no seccomp.
#[cfg(not(target_os = "linux"))]
pub fn install_filter() -> Result<std::os::fd::OwnedFd, String> {
    Err("seccomp needs a Linux kernel".to_owned())
}

/// Let the process on the other end of `socket` read this one's memory.
///
/// The supervisor must read the path argument of a trapped `openat`, and that
/// needs ptrace permission which Yama's default scope grants only to an
/// ancestor. The session grants it to **one** named process, itself, before it
/// is supervised.
///
/// # Errors
///
/// The peer's identity or the grant, named.
#[cfg(target_os = "linux")]
pub fn allow_supervision_by(socket: std::os::fd::BorrowedFd<'_>) -> Result<i32, String> {
    let pid = aisme_linux::peer_pid(socket).map_err(|e| e.detail)?;
    aisme_linux::allow_ptrace_by(pid).map_err(|e| e.detail)?;
    Ok(pid)
}

/// Off Linux there is no ptrace scope to satisfy.
#[cfg(not(target_os = "linux"))]
pub fn allow_supervision_by(_socket: std::os::fd::BorrowedFd<'_>) -> Result<i32, String> {
    Err("PR_SET_PTRACER needs a Linux kernel".to_owned())
}

/// Hand a descriptor to the daemon over an open control socket.
///
/// # Errors
///
/// The `sendmsg` errno.
#[cfg(target_os = "linux")]
pub fn send_listener(
    socket: std::os::fd::BorrowedFd<'_>,
    listener: std::os::fd::BorrowedFd<'_>,
    request: &[u8],
) -> Result<(), String> {
    aisme_linux::send_fd(socket, listener, request).map_err(|e| e.detail)
}

/// Off Linux there is nothing to hand over.
#[cfg(not(target_os = "linux"))]
pub fn send_listener(
    _socket: std::os::fd::BorrowedFd<'_>,
    _listener: std::os::fd::BorrowedFd<'_>,
    _request: &[u8],
) -> Result<(), String> {
    Err("SCM_RIGHTS needs a Unix socket".to_owned())
}
