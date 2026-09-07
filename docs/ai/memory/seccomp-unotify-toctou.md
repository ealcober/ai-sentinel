---
name: seccomp-unotify-toctou
description: Never decide from user memory read in a seccomp notification — resolve the path, or hand back an fd
type: domain
---

Never decide from user memory read in a notification. At L3 the LSM-resolved `struct file` is the path of record; at L2 the supervisor resolves the path itself and hands the target the descriptor with `SECCOMP_IOCTL_NOTIF_ADDFD`.

**Why it matters:** It is the difference between an enforcement point and a race. The kernel documentation says outright that `seccomp_unotify` must not be used to make security policy decisions, because the caller can rewrite the argument after the supervisor reads it.

**How to apply:** For open-class syscalls, resolve and `ADDFD` (`F3.EN.12`). Never `read` the pointer argument out of the target and then allow. A blocked syscall fails with `ENOSYS` when the listener fd closes, so listener death must be a defined path, not an assumption.

**`ADDFD` is a capability of its own, and it is probed by feature test.** The notifier arrived in 5.0, `CONTINUE` in 5.5, `SECCOMP_IOCTL_NOTIF_ADDFD` in **5.9** and `ADDFD_FLAG_SEND` in 5.14, so "has `seccomp_unotify`" does not mean "can answer a decision". `CapabilitySet` carries both flags and `tier_of` reads `seccomp_addfd`, because a kernel that can only ever answer *deny* does not keep L2-'s promise (`I-28`).

**The probe's discriminator is `EFAULT`, not `ENOTTY`** — measured on the matrix 2026-09-07, after the first version got it backwards. Attempt the ioctl with a `NULL` argument on a live listener and read `errno`:

| errno | Means |
|---|---|
| `EFAULT` (14) | The command exists; it reached `copy_from_user` and rejected the `NULL`. **Present.** |
| `EINVAL` (22) | The command does not exist. **Absent.** |
| `ENOTTY` (25) | Never appears. |

The notify fd is an anon inode with its own `ioctl` handler, so an unknown command falls to that handler's `default:` arm and returns `EINVAL`; the VFS's `ENOTTY`, which is what a file with no handler at all would give, is unreachable. A rule written as `absent if ENOTTY` therefore answers "present" on **every** kernel — an absence read as a value, in the check written to avoid one. Measured: 5.4 `EINVAL`, and 5.10 / 5.15 / 6.1 / 6.8 / 7.0 all `EFAULT`. **Ubuntu 20.04's 5.4 is `L1`**, not L2-.

**Source:** H-01, `F3.EN.12`, `F0.VM.02` (measured 2026-09-07), `docs/05_challenge_ampliacion_f2.md` point 13

Related: [[cgroup-connect-l2-net-deny]], [[landlock-l2-file-deny]]
