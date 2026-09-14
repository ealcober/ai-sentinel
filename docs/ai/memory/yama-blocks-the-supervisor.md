---
name: yama-blocks-the-supervisor
description: A seccomp supervisor cannot read its target's path argument under Yama's default ptrace scope — the session must name it with PR_SET_PTRACER
type: domain
---

`process_vm_readv` needs `PTRACE_MODE_ATTACH_REALCREDS`, and Yama's default `kernel.yama.ptrace_scope = 1` grants that only to an **ancestor** of the target. `aisme-agentd` is the session's *sibling*, not its parent — `aisme run` `exec`s the supervised command, and the daemon was already running.

So the supervisor reads nothing, every trapped `openat` is denied, and the session cannot start. Measured on 2026-09-15, before the grant existed: `cat: error while loading shared libraries: libc.so.6: cannot open shared object file: Permission denied`, with fourteen denials recorded as *"the path argument could not be read"*.

**Why it matters:** the failure is silent in the direction that looks correct. A supervisor that denies everything **looks fail-closed**, so it passes a casual review; what it actually is, is a guard that has stopped being able to make decisions.

**How to apply:** the session grants it to **one** named process, on itself, before it is supervised — `prctl(PR_SET_PTRACER, <supervisor pid>)`. The pid comes from `SO_PEERCRED` on the control socket the session has just opened, which is the kernel's answer and neither side can forge. This is not `CAP_SYS_PTRACE` for the daemon and not `ptrace_scope = 0` for the machine: it is one process, named by the process it will supervise.

Order matters: grant **before** installing the filter. A seccomp filter is irreversible and inherited across `exec`, so a run that installs one and then fails to arrange supervision leaves a command whose every `openat` returns `ENOSYS`.

On a kernel with no Yama, `PR_SET_PTRACER` fails with `EINVAL` and that is **not** an error: nothing was blocking the read there.

**Source:** `F2.WS.05`, measured 2026-09-15

Related: [[seccomp-unotify-toctou]], [[seccomp-args-are-32-bit]]
