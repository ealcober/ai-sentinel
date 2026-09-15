---
name: landlock-l2-file-deny
description: Landlock gives in-kernel path deny with no reboot and no BPF-LSM — it is what makes tier L2 real
type: domain
---

Landlock gives in-kernel, inherited, monotonic path deny with no reboot and no BPF-LSM. Measured on stock WSL2 by `F0.WSL.01`: **ABI 7, and enforcing** — under a real ruleset handling `WRITE_FILE|MAKE_REG` with one `PATH_BENEATH` rule, a write inside the allowed directory succeeded and a write outside returned `EACCES`.

**Why it matters:** It is what makes L2 a real tier instead of a seccomp trap storm under `npm ci`. Most users will not reboot to add `lsm=...,bpf`, and WSL2 — the Windows strategy — is L2 by default.

**How to apply:** A Landlock domain is **monotonic**: it can only ever narrow, and a running process's domain cannot be widened. So a grant issued after a process starts binds only processes started after it, and the prompt must say so. Probe with the `landlock_create_ruleset` syscall, never by reading `/sys/kernel/security/lsm`, which does not exist when securityfs is unmounted.

**F2 is where the measured capability becomes enforcement** (`F2.WS.11`). `aisme run` builds one ruleset from the session's declared scope and applies it before `exec`, so the supervised command inherits a domain it cannot widen. Measured on ABI 9: a write outside the scope returns `EACCES` and the file is not created; a write inside succeeds. The handled rights are every write-shaped one the running ABI knows — not `WRITE_FILE|MAKE_REG` alone, because a scope that stopped `touch` and allowed `ln -s`, `mkfifo` or `mkdir` outside it would have a hole that only shows when somebody uses it — plus `TRUNCATE` from ABI 3, since truncating a file is a write and asking for the right below that ABI is `EINVAL` rather than a degradation.

**Apply it before the seccomp filter, not after.** `landlock_add_rule` needs an `O_PATH` descriptor per allowed directory, so a ruleset built under a filter that traps `openat` sends the session's own setup to the supervisor — which `I-28` then requires it to refuse. The filter is irreversible; everything that can still fail belongs above it.

**Source:** §2.2.1, and `F2.WS.11` measured 2026-09-15

Related: [[cgroup-connect-l2-net-deny]], [[wsl2-capabilities]]
