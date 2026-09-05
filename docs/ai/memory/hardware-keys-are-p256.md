---
name: hardware-keys-are-p256
description: Commodity hardware offers non-exportable P-256, not Ed25519, and Noise DH is X25519
type: platform-limit
---

Commodity TPM 2.0, Secure Enclave and StrongBox offer non-exportable **P-256**, not Ed25519. Noise's DH is X25519.

**Why it matters:** A hardware key cannot be a Noise static. The hardware key signs the **verdict**; a software key protects the **channel**. Conflating the two produces a design that cannot be built on any shipping device.

**How to apply:** Sign remote `ALLOW` verdicts with the hardware P-256 key (`I-06`); use software X25519 for the Noise static. Record `key_hw` per forensic block and show it in the UI. Ed25519 only where no hardware key exists.

**Source:** H-17, §2.20.6

Related: [[wsl2-has-no-tpm]]
