---
name: wsl2-import-mechanics
description: What `wsl.exe --import` from inside WSL2 requires — NTFS for the VHDX and every shared file, a script file instead of an inline `bash -c`, sequential imports, no `linux-tools-$(uname -r)` for the Microsoft kernel
type: platform-limit
---

Measured by `F0.WSL.02` on 2026-09-06 while `cargo xtask vm up wsl2-ubuntu-24.04` imported `aisme-wsl2-ubuntu-24.04` from this distribution through interop.

| Fact | How it showed |
|---|---|
| The VHDX must be on **NTFS** | `--import` into a directory under `\\wsl.localhost\…` fails with `ERROR_UNHANDLED_EXCEPTION`; `%LOCALAPPDATA%\aisme\vm` works. `%LOCALAPPDATA%` is resolved with `cmd.exe /c echo %LOCALAPPDATA%` and `wslpath -u` |
| Two distributions share **only `/mnt/c`** | `cp` from this distribution's `vm/images/probe.o` inside the new one: `cannot stat`. Anything the guest needs is staged on NTFS and read back at the same `/mnt/c/...` path |
| An inline script does not survive `wsl.exe -- bash -c …` | Windows argument re-quoting: awk saw literal backslashes (`backslash not last character`) and `2>&1` arrived as a bare `2`. Write the script to NTFS and run `bash /mnt/c/.../run.sh` |
| Imports are **sequential** | Two `--import` calls at once: the second fails with `ERROR_SHARING_VIOLATION` on the tarball |
| No `linux-tools-$(uname -r)` for the Microsoft kernel | `apt` has no such package, so Ubuntu's `bpftool` wrapper refuses to run; the versioned binary under `/usr/lib/linux-tools/*/` from `linux-tools-generic` runs, and so does libbpf's static release binary — which `vm probe` stages on NTFS so the guest installs nothing |
| **Another guest clears every distribution's `WSLInterop`** in two measured ways | (1) A freshly imported guest's **first boot with its `wsl.conf` applied**: a trivial session, no script, and the entry is gone three seconds later; every later boot of that guest is harmless, as are its idle and explicit terminations and a full `apt` purge-and-reinstall inside it. (2) A **systemd** guest: `systemd-binfmt.service` has `ExecStop=systemd-binfmt --unregister`, which flushes the shared table — fired by a dpkg trigger on `/usr/lib/binfmt.d` (`python3.12-minimal`, pulled by `linux-tools`) or by the guest's termination ([rancher-desktop#10049](https://github.com/rancher-sandbox/rancher-desktop/issues/10049); masking does not help). `exec format error` on every `.exe` here until a new session is opened from Windows or root re-registers `:WSLInterop:M::MZ::/init:PF`. `vm up` takes the first boot and re-registers (`sudo -n`) or prints the line; `vm probe` holds a systemd guest open |
| A cwd on the WSL filesystem makes `wsl.exe` warn | `Failed to translate '\\wsl.localhost\…'`; run it from `/mnt/c` |
| cgroup v1 is a **per-distribution** opt-in | `[automount] cgroups=v1` in `wsl.conf`, [microsoft/WSL#13546](https://github.com/microsoft/WSL/pull/13546) (merged 2025-10-03), falling back to v2 under `cgroup_no_v1=all`; not a `.wslconfig` host setting. WSL 2.7.8.0 honours it: hybrid hierarchy, v2 at `/sys/fs/cgroup/unified`, v1 controllers mounted; tier L2, `connect4` attaches on the unified mount |
| securityfs is unmounted in the guest too | Same as the host (`F0.WSL.01`): mount it, or read `CONFIG_LSM` |

**Why it matters:** WSL2 is the Windows strategy (`ADR-02`), and the installer will ship AISME into a user's distribution through this same interop. Every fact above is a constraint on `DEP.INS.*`: files handed to another distribution go through NTFS, scripts go as files, and nothing assumes the distribution can install a kernel-matched tools package.

**How to apply:** `xtask/src/vm.rs` (`wsl2_import`, `wsl2_exec`, `hold_open`) encodes each row. Terminate a systemd guest only after the last interop call of the session.

**Source:** `docs/reports/01_f0-verification.md`, section *WSL2 images*.

Related: [[wsl2-capabilities]], [[cloud-images-are-the-kernel-matrix]]
