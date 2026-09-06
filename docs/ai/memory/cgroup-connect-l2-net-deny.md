---
name: cgroup-connect-l2-net-deny
description: BPF_CGROUP_INET4/6_CONNECT denies egress in kernel with cgroup v2 and no lsm= change
type: domain
---

`BPF_CGROUP_INET4/6_CONNECT` denies egress in the kernel with cgroup v2 and no `lsm=` change, and it sees the destination address in the kernel.

**Why it matters:** Network Slam at L2 is T0 and TOCTOU-free; seccomp would be neither. A seccomp filter cannot read the `sockaddr` the caller passed without reading user memory, which is a race by construction.

**How to apply:** Attach per session cgroup so only session flows are judged — and find the v2 hierarchy in `/proc/mounts` (`$3 == "cgroup2"`): a hybrid host such as Ubuntu 20.04 keeps it at `/sys/fs/cgroup/unified`, and `mkdir` under the v1 tmpfs at `/sys/fs/cgroup` yields a directory `bpftool` cannot attach to (measured, `F0.VM.02`). The attach itself holds on every matrix kernel from 5.4 to 7.0: `EPERM` inside the session cgroup, `ECONNREFUSED` outside. `F0.WSL.01` confirmed every kernel prerequisite on WSL2 — `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, cgroup v2 unified, BTF present — and the attach was then measured on WSL2's 6.18 and on all seven matrix kernels (`F0.VER.16` holds).

**Source:** §2.2.1, `F3.EN.10`

Related: [[landlock-l2-file-deny]], [[seccomp-unotify-toctou]]
