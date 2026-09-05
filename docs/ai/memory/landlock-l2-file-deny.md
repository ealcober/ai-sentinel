---
name: landlock-l2-file-deny
description: Landlock gives in-kernel path deny with no reboot and no BPF-LSM — it is what makes tier L2 real
type: domain
---

Landlock gives in-kernel, inherited, monotonic path deny with no reboot and no BPF-LSM. Measured on stock WSL2 by `F0.WSL.01`: **ABI 7, and enforcing** — under a real ruleset handling `WRITE_FILE|MAKE_REG` with one `PATH_BENEATH` rule, a write inside the allowed directory succeeded and a write outside returned `EACCES`.

**Why it matters:** It is what makes L2 a real tier instead of a seccomp trap storm under `npm ci`. Most users will not reboot to add `lsm=...,bpf`, and WSL2 — the Windows strategy — is L2 by default.

**How to apply:** A Landlock domain is **monotonic**: it can only ever narrow, and a running process's domain cannot be widened. So a grant issued after a process starts binds only processes started after it, and the prompt must say so. Probe with the `landlock_create_ruleset` syscall, never by reading `/sys/kernel/security/lsm`, which does not exist when securityfs is unmounted.

**Source:** §2.2.1

Related: [[cgroup-connect-l2-net-deny]], [[wsl2-capabilities]]
