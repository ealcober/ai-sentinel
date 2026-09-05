---
name: wsl2-has-no-tpm
description: WSL2 exposes no TPM device, so forensics there are software-signed
type: platform-limit
---

No TPM device under WSL2. Measured by `F0.WSL.01` on kernel `6.18.33.1`: `CONFIG_TPM` is **not set**, so there is no driver at all, and `/dev/` contains no `tpm*` node. The absence is structural, not a missing device.

**Why it matters:** The forensic chain is software-signed for Windows users, and external anchoring is what carries non-repudiation there rather than hardware attestation.

**How to apply:** On WSL2 record `key_hw` as a software value and enable external root anchoring by default (`I-18`). Never let the UI imply hardware attestation on that platform. A `key_hw` claim in a block must match its signer.

**Source:** R-18, `F0.VER.18`

Related: [[wsl2-capabilities]], [[hardware-keys-are-p256]]
