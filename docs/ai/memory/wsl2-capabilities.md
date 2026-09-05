---
name: wsl2-capabilities
description: What the stock WSL2 kernel gives AISME — measured, not assumed: Landlock ABI 7 enforcing, BPF-LSM compiled but inactive, cgroup v2, BTF, systemd, no TPM
type: platform-limit
---

Measured by `F0.WSL.01` on 2026-09-05 against kernel `6.18.33.1-microsoft-standard-WSL2`. Full outcome table in `docs/reports/01_f0-verification.md`.

| Capability | Measured |
|---|---|
| **Landlock** | **ABI 7**, `CONFIG_SECURITY_LANDLOCK=y`, first entry in `CONFIG_LSM`. **Enforcement proven**: under a real ruleset handling `WRITE_FILE\|MAKE_REG` with one `PATH_BENEATH` rule, a write inside the allowed directory succeeded and a write outside returned `EACCES` |
| **BPF-LSM** | `CONFIG_BPF_LSM=y` is **compiled in**, but `bpf` is **absent** from the active `CONFIG_LSM` list (`landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo`) |
| BPF and cgroup hooks | `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y` |
| cgroup | **v2 only**, unified, no v1 controllers mounted. Root controllers: `cpuset cpu io memory hugetlb pids rdma` |
| BTF | `/sys/kernel/btf/vmlinux` present, `CONFIG_DEBUG_INFO_BTF=y` — CO-RE works |
| systemd | PID 1 is `systemd` on this install (`systemd=true` in `/etc/wsl.conf`); it stays **opt-in** on WSL2 generally |
| **TPM** | **None.** `CONFIG_TPM` is not set, so there is no driver, and `/dev/` has no `tpm*` node |
| securityfs | **Not mounted.** `/sys/kernel/security/lsm` does not exist |
| KVM | `/dev/kvm` present, group `kvm`, CPU reports `vmx`. The owner's user is not yet in that group |

**Why it matters:** WSL2 is the Windows strategy (`ADR-02`), so these values decide what Windows developers actually get. Three consequences are load-bearing:

1. **Tier L2 is real here.** Landlock denies in kernel, without a reboot and without BPF-LSM, which is what makes `L2` a usable tier rather than a euphemism for "observe only" (`F3.3`, `F2.WS.11`). Risk `R-15` — Landlock absent, falling back to `L2-` — does not apply to WSL2.
2. **L3 is a configuration change away, not a kernel rebuild.** Because `CONFIG_BPF_LSM=y` is already compiled in, reaching L3 needs `kernelCommandLine=lsm=...,bpf` in `.wslconfig` and `wsl --shutdown`. Plan §2.16.1 held a custom-bzImage fallback in reserve for the case where it was not compiled in; on this kernel that fallback is unnecessary.
3. **Forensics on WSL2 are software-signed by construction.** No TPM driver exists, so `key_hw` is a software value there and non-repudiation rests on external anchoring, enabled by default (`I-18`, risk `R-18`).

**How to apply:** probe with the **Landlock syscall and `/proc/config.gz`**, never with `cat /sys/kernel/security/lsm` — securityfs is unmounted on stock WSL2, so that read returns `ENOENT` and a literal reading reports "no LSM list", which is an absence read as a value (general rule 9) and would misreport the tier as `L1`. When the installer offers the L3 upgrade on WSL2, it edits `.wslconfig` on the Windows side, which the Linux daemon cannot do for the user: it prints the exact line and the `wsl --shutdown` that applies it.

Related: [[wsl2-has-no-tpm]], [[landlock-l2-file-deny]], [[cgroup-connect-l2-net-deny]]
