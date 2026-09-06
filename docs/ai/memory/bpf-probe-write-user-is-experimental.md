---
name: bpf-probe-write-user-is-experimental
description: bpf_probe_write_user is experimental, gpl_only and refused under kernel lockdown; mainline neither warns nor taints — using it would make AISME a rootkit
type: platform-limit
---

`bpf_probe_write_user` is documented as *"meant for experiments"* and for *"debug, divert, and manipulate execution of semi-cooperative processes"* (`include/uapi/linux/bpf.h`). Measured at mainline `master` by `F0.VER.08`: the source has **no warning and no taint** — the UAPI text still promises a logged warning that the code no longer emits. What the kernel actually does is stronger: the helper's proto is `.gpl_only = true`, and it is dispatched as `security_locked_down(LOCKDOWN_BPF_WRITE_USER) < 0 ? NULL : &bpf_probe_write_user_proto` — under kernel lockdown it does not exist.

**Why it matters:** Using it to hide from a monitored process is what would make the product a rootkit and end the compliance story. `I-01` and `I-02` exist because of this: AISME never modifies an observed process and never hides from it.

**How to apply:** Forbidden outside a `research` feature, and `cargo xtask verify-layering` fails on a mention anywhere else. When a process probes for instrumentation, record that as a signal — do not defeat it.

**Source:** H-05

Related: [[seccomp-unotify-toctou]]
