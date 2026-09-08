---
name: llvm-config-is-suffixed
description: bpf-linker looks for an unsuffixed `llvm-config`, Debian-family LLVM installs are suffixed, and two different environment variables are needed
type: domain
---

`cargo install bpf-linker` fails with *"could not find llvm-config in directories specified by environment variable `PATH`"* on a host where the required LLVM **is** installed and working. Measured twice on this host, at `bpf-linker` 0.11.1 and 0.11.0, with `/usr/lib/llvm-21/bin/llvm-config --version` reporting **21.1.8** — exactly the version `crates/aisme-ebpf/rust-toolchain.toml` requires.

The cause is in `bpf-linker`'s own `build.rs` (`:584`–`:625`): when `LLVM_PREFIX` is unset it searches `PATH` for a file named **exactly** `llvm-config`. Debian, Ubuntu and Pop!_OS install `/usr/bin/llvm-config-21`, with the suffix. Nothing matches, and the error names `PATH` rather than the real problem.

**Why it matters:** the error text sends the reader looking for a missing LLVM that is not missing. It cost two failed installs here before the build script was read instead of the message.

**How to apply:** set **both** variables, because two different crates read two different names — `LLVM_PREFIX` by `bpf-linker`'s build script, and `LLVM_SYS_211_PREFIX` by `llvm-sys 211.0.0`, which `--features llvm-21` pulls in. Setting one is a coin flip on which crate fails first:

```
LLVM_PREFIX=/usr/lib/llvm-21 LLVM_SYS_211_PREFIX=/usr/lib/llvm-21 \
  cargo +nightly-2026-01-01 install bpf-linker --version 0.11.0 \
  --no-default-features --features llvm-21
```

`cargo xtask doctor` composes this line from the pin, so it does not have to be remembered — this file exists for the day the pin moves and the `LLVM_SYS_<major>1_PREFIX` name has to be checked against the `llvm-sys` version the new feature selects, rather than assumed from the formula.

**Source:** `F0.REPO.02`, `F0.REPO.06`

Related: [[cloud-images-are-the-kernel-matrix]]
