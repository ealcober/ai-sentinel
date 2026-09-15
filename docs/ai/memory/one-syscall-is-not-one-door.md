---
name: one-syscall-is-not-one-door
description: Three syscalls open a path — open, openat, openat2 — and a filter that names one of them enforces nothing
type: domain
---

A seccomp filter that traps `openat` alone is bypassed by calling `open` or `openat2` directly. Measured on 2026-09-15 against a policy that **denied** a file, in a session running under `--trap-openat`:

| syscall | result |
|---|---|
| `open` | **opened** — the supervisor never saw it |
| `openat` | denied |
| `openat2` | **opened** — the supervisor never saw it |

**Why it matters:** it is not the *retry by indirection* `DT-05` describes, where a denial is followed by a second attempt through another route. It succeeds **first time**, so nothing is denied, nothing is recorded, and the deny and escalate classes are decoration for any program that does not go through glibc. glibc's `open()` issues `openat`, which is exactly what makes the gap invisible: every ordinary program is trapped and only a deliberate one is not.

**How to apply:** enumerate the syscalls that perform the operation, not the one the libraries happen to use. For opening a path on x86-64 that is `open` (2), `openat` (257) and `openat2` (437). The same question is owed for every other class before it is claimed: a write is `write`, `pwrite64`, `writev`, `pwritev`, `pwritev2` and `sendfile`; an exec is `execve` and `execveat`; a deletion is `unlink`, `unlinkat` and `rename*`.

**And the three do not agree on their arguments**, so trapping them is not enough on its own. `openat(dirfd, path, flags)` is the shape most code assumes. `open(path, flags, mode)` has **no descriptor argument**, so reading `args[0]` as one takes a pointer for a file descriptor. `openat2(dirfd, path, how, size)` keeps its flags inside a `struct open_how` in the target's memory, with a `resolve` field that changes what the path means — so a supervisor that opened it with its own resolution and handed back the descriptor would be answering a question the caller did not ask. `I-28` decides that case: an open the supervisor cannot reproduce is **denied with the reason**, never permitted.

**Source:** `F2.WS.05`, measured 2026-09-15

Related: [[seccomp-args-are-32-bit]], [[seccomp-unotify-toctou]]
