---
name: bpf-probe-write-user-is-experimental
description: bpf_probe_write_user is experimental, taints the kernel log, and using it would make AISME a rootkit
type: platform-limit
---

`bpf_probe_write_user` is documented as experimental and warns in the kernel log when used.

**Why it matters:** Using it to hide from a monitored process is what would make the product a rootkit and end the compliance story. `I-01` and `I-02` exist because of this: AISME never modifies an observed process and never hides from it.

**How to apply:** Forbidden outside a `research` feature, and `cargo xtask verify-layering` fails on a mention anywhere else. When a process probes for instrumentation, record that as a signal — do not defeat it.

**Source:** H-05

Related: [[seccomp-unotify-toctou]]
