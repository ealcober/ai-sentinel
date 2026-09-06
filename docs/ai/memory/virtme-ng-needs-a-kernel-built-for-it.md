---
name: virtme-ng-needs-a-kernel-built-for-it
description: Under WSL2 there is no /boot/vmlinuz to reuse, and a distro kernel panics under virtme-ng because 9p and virtiofs are modules — the matrix needs kernels built for it
type: toolchain
---

Measured while implementing `F0.VM.01` on 2026-09-06:

1. **WSL2 has no `/boot/vmlinuz`.** Its kernel is supplied by the Windows side, so `virtme-ng` cannot reuse the running kernel the way it does on an ordinary distribution. `/lib/modules/` holds module trees for the WSL2 kernels but no image to boot.
2. **A distro kernel is not enough.** `apt-get download linux-image-unsigned-<ver>-generic` followed by `dpkg-deb -x` yields a working `vmlinuz` — and both commands run **without `sudo`**, which matters because `cargo xtask doctor` never installs. Booting it under `virtme-ng` panics at `mount_root_generic`: Ubuntu ships 9p and virtiofs as **modules**, and `virtme-ng` needs them built in to mount the host root filesystem read-only.
3. So the kernel matrix wants kernels **built for it** — `vng --build` per version — rather than fetched.

**Why it matters:** `I-12` forbids any kernel-touching test on a host OS, so the VM is not a convenience, it is the only legal place for `F0.VER.16`, `F0.VER.19` and every L2/L3 test from F3 onward. A plan that assumes `virtme-ng` will "just boot the CI kernel matrix" (§4.2) is assuming a step that costs a kernel build per matrix entry.

**How to apply:** budget `F0.VM.02` as a build task, not a download task. Fetching images is still the right move for `F0.VM.01`'s full distro VMs (Ubuntu, Debian, Fedora cloud images boot their own kernels under plain `qemu`); it is the *matrix* that needs building. And on WSL2 expect TCG rather than KVM until the owner's session picks up the `kvm` group.

**Source:** `F0.VM.01` implementation notes in `docs/reports/01_f0-verification.md`; plan §4.2, `I-12`

Related: [[wsl2-capabilities]], [[cgroup-connect-l2-net-deny]]
