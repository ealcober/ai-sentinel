---
name: distro-default-lsm-lists
description: Which distributions ship BPF-LSM active out of the box — Debian 12 and Fedora 40 do, Ubuntu does not — measured across the kernel matrix; it decides the tier a fresh install lands on and what the L3 offer has to say
type: platform-limit
---

Measured by `F0.VM.02` on 2026-09-06, inside each distribution's own cloud image under `cargo xtask vm probe`, reading the **active** list from `/sys/kernel/security/lsm` rather than `CONFIG_LSM`:

| Image | Kernel | Active LSM list | Landlock ABI | Tier |
|---|---|---|---|---|
| Ubuntu 20.04 | 5.4.0-216 | `lockdown,capability,yama,apparmor` | — (pre-5.13) | **L1** (no `ADDFD`) |
| Debian 11 | 5.10.0-46 | `lockdown,capability,yama,apparmor,tomoyo` | — (pre-5.13) | **L2-** |
| Ubuntu 22.04 | 5.15.0-190 | `lockdown,capability,landlock,yama,apparmor` | 1 | **L2** |
| Debian 12 | 6.1.0-52 | `lockdown,capability,landlock,yama,apparmor,tomoyo,**bpf**` | 2 | **L3** |
| Ubuntu 24.04 | 6.8.0-138 | `lockdown,capability,landlock,yama,apparmor` | 4 | **L2** |
| Fedora 40 | 6.8.5-301 | `lockdown,capability,yama,selinux,**bpf**,landlock` | 4 | **L3** |
| Ubuntu 26.04 | 7.0.0-30 | `lockdown,capability,landlock,yama,apparmor,ima,evm` | 8 | **L2** |

The tier column is Annex D.1's rule as `aisme-core::tier::tier_of` implements it — L2- needs `SECCOMP_IOCTL_NOTIF_ADDFD` (kernel ≥ 5.9, measured by feature test, not by version) **and** the cgroup v2 freezer, L2 adds Landlock and the cgroup connect hook, L3 adds `bpf` in the active list. All seven guests have the freezer and the seccomp notifier; **only 20.04's 5.4 lacks `ADDFD`**, which is why it is L1 while every other row can answer a trapped decision. Every one of them compiles `CONFIG_BPF_LSM=y`; what differs is whether `bpf` is in the **active** list, which is set by the kernel command line (`lsm=`) and defaults to `CONFIG_LSM`. Debian and Fedora put it there. Ubuntu does not, on any release measured. BTF is present on all seven, including the 5.4 of Ubuntu 20.04 — so BTF is present everywhere. **L1 is not "no BTF"**: it is a kernel that cannot *answer* a trapped decision or cannot *hold* one. 20.04's 5.4 is the case that shows it — BTF present, notifier present, freezer present, `ADDFD` absent, so the only verdict it could ever deliver on an escalate-class open is *deny*, and L2- promises more than that.

**Why it matters:** the plan's §2.17 tier ladder is right, but the *distribution* a user runs decides where they land without touching anything. A Debian 12 or Fedora user gets full L3 enforcement from the first `aisme run`. An Ubuntu user gets L2 — a real tier, Landlock and cgroup hooks in kernel — and reaching L3 is a `lsm=…,bpf` on the kernel command line plus a reboot. Two of the plan's own expectations were wrong in opposite directions: it expected 5.4 to be L1 and Debian 12 to be L2 or worse.

**How to apply:** the installer's L3 offer (`DEP.INS.03`) is only relevant on Ubuntu and on WSL2; on Debian 12 and Fedora it must detect L3 and say so, not offer a reboot for nothing. `F1.PA.05`'s degradation state machine and `I-16`'s honesty banner read the active list, never `CONFIG_LSM`. And R-15 is about kernels older than 5.13, not about any distribution's policy.

**Source:** `docs/reports/01_f0-verification.md` (`F0.VM.02`), the `vm/images/*.probe.log` files on the owner's host, plan §2.17 and §4.12

Related: [[wsl2-capabilities]], [[landlock-l2-file-deny]], [[cloud-images-are-the-kernel-matrix]]
