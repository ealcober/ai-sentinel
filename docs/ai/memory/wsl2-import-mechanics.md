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
| No `linux-tools-$(uname -r)` for the Microsoft kernel | `apt` has no such package, so Ubuntu's `bpftool` wrapper refuses to run; the versioned binary under `/usr/lib/linux-tools/*/` from `linux-tools-generic` runs |
| **Terminating a systemd guest clears every distribution's `WSLInterop`** | Three times, each within a second of the guest stopping: `exec format error` on every `.exe` here until a new session is opened from Windows or root re-registers `:WSLInterop:M::MZ::/init:PF`. binfmt_misc is one kernel-wide table; a non-systemd guest's termination leaves it intact, and masking `systemd-binfmt.service` does not help — [rancher-desktop#10049](https://github.com/rancher-sandbox/rancher-desktop/issues/10049) measured both. `vm probe` holds the guest open |
| A cwd on the WSL filesystem makes `wsl.exe` warn | `Failed to translate '\\wsl.localhost\…'`; run it from `/mnt/c` |
| securityfs is unmounted in the guest too | Same as the host (`F0.WSL.01`): mount it, or read `CONFIG_LSM` |

**Why it matters:** WSL2 is the Windows strategy (`ADR-02`), and the installer will ship AISME into a user's distribution through this same interop. Every fact above is a constraint on `DEP.INS.*`: files handed to another distribution go through NTFS, scripts go as files, and nothing assumes the distribution can install a kernel-matched tools package.

**How to apply:** `xtask/src/vm.rs` (`wsl2_import`, `wsl2_exec`, `hold_open`) encodes each row. Terminate a systemd guest only after the last interop call of the session.

**Source:** `docs/reports/01_f0-verification.md`, section *WSL2 images*.

Related: [[wsl2-capabilities]], [[cloud-images-are-the-kernel-matrix]]
