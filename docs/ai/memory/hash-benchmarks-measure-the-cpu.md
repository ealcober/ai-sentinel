---
name: hash-benchmarks-measure-the-cpu
description: A hash benchmark that does not name the target's crypto extensions measures the machine, not the algorithm — BLAKE3 vs SHA-256 swings 4.4x to 6.4x on SHA-NI alone
type: performance
---

Measured by `F0.VER.13` on a 320-byte `RawEvent` leaf, 2 M iterations each: BLAKE3 **6.41×** faster than SHA-256 on a stock `--release` build, **4.40×** with `-C target-cpu=native`. The test CPU has **no SHA-NI** (`sha_ni` absent from `/proc/cpuinfo`), so `sha2` runs a software SHA-256 at 160 MB/s. On a CPU with the extension, hardware SHA-256 is several times faster and most of the gap closes.

**Why it matters:** the ratio is not a property of the two algorithms at that size. It is a property of whether the target has SHA-NI. A benchmark quoted without that fact will be reproduced on different hardware, come out differently, and look like a regression in AISME rather than a difference in the machine.

**How to apply:** quote hash throughput with the target's crypto extensions named, exactly as a CPU or latency figure is meaningless without its tier (§2.22). BLAKE3 stays the default for `F5.FO.01`'s Merkle leaves not because of the multiple but because it is fast **everywhere** — a fixed cost that does not depend on an extension being present, which matters when the same code runs on a developer's laptop, a CI host, an Android phone and inside WSL2.

**Source:** `F0.VER.13` in `docs/reports/01_f0-verification.md`; H-17 and plan §2.18

Related: [[hardware-keys-are-p256]], [[wsl2-capabilities]]
