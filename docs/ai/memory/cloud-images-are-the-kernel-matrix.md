---
name: cloud-images-are-the-kernel-matrix
description: Under WSL2 virtme-ng has no host kernel to reuse and a distro kernel panics on it; distribution cloud images boot their own kernels under plain qemu and ARE the matrix — no build needed
type: toolchain
---

Measured while implementing `F0.VM.01` on 2026-09-06:

1. **WSL2 has no `/boot/vmlinuz`.** Its kernel is supplied by the Windows side, so `virtme-ng` cannot reuse the running kernel the way it does on an ordinary distribution. `/lib/modules/` holds module trees for the WSL2 kernels but no image to boot.
2. **A distro kernel is not enough.** `apt-get download linux-image-unsigned-<ver>-generic` followed by `dpkg-deb -x` yields a working `vmlinuz` — and both commands run **without `sudo`**, which matters because `cargo xtask doctor` never installs. Booting it under `virtme-ng` panics at `mount_root_generic`: Ubuntu ships 9p and virtiofs as **modules**, and `virtme-ng` needs them built in to mount the host root filesystem read-only.
3. **The conclusion I first drew from this — that the matrix needs kernels built per version — was wrong**, and fell the same day. A distribution *cloud image* boots its own kernel and initramfs under plain `qemu` with no host rootfs, no `sudo`, no build; the distro kernels are the matrix (20.04→5.4, Debian 11→5.10, 22.04→5.15, Debian 12→6.1, 24.04→6.8, 26.04→7.0). `cargo xtask vm up/run/probe` do exactly that. `virtme-ng` remains the tool for a kernel no distribution ships.

**Why it matters:** `I-12` forbids any kernel-touching test on a host OS, so the VM is not a convenience, it is the only legal place for `F0.VER.16`, `F0.VER.19` and every L2/L3 test from F3 onward. A plan that assumes `virtme-ng` will "just boot the CI kernel matrix" (§4.2) is assuming a step that costs a kernel build per matrix entry.

**How to apply:** reach for a cloud image first and `virtme-ng` only for a kernel no distribution ships. Keep the base image pristine and boot a fresh qcow2 overlay every run — that is the restore-from-snapshot `I-12` asks for. On WSL2 expect TCG rather than KVM until a login session picks up the `kvm` group.

**Source:** `F0.VM.01` implementation notes in `docs/reports/01_f0-verification.md`; plan §4.2, `I-12`

Related: [[wsl2-capabilities]], [[cgroup-connect-l2-net-deny]]
