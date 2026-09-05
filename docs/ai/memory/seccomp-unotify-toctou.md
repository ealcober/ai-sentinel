---
name: seccomp-unotify-toctou
description: Never decide from user memory read in a seccomp notification — resolve the path, or hand back an fd
type: domain
---

Never decide from user memory read in a notification. At L3 the LSM-resolved `struct file` is the path of record; at L2 the supervisor resolves the path itself and hands the target the descriptor with `SECCOMP_IOCTL_NOTIF_ADDFD`.

**Why it matters:** It is the difference between an enforcement point and a race. The kernel documentation says outright that `seccomp_unotify` must not be used to make security policy decisions, because the caller can rewrite the argument after the supervisor reads it.

**How to apply:** For open-class syscalls, resolve and `ADDFD` (`F3.EN.12`). Never `read` the pointer argument out of the target and then allow. A blocked syscall fails with `ENOSYS` when the listener fd closes, so listener death must be a defined path, not an assumption.

**Source:** H-01, `F3.EN.12`

Related: [[cgroup-connect-l2-net-deny]], [[landlock-l2-file-deny]]
