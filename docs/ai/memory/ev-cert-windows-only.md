---
name: ev-cert-windows-only
description: Azure Trusted Signing cannot substitute for an EV certificate on a Windows kernel driver
type: process
---

Azure Trusted Signing cannot substitute for an EV certificate on kernel drivers. Partner Center requires an EV certificate associated with the account **before** any binary can be attestation-signed, and hardware-token storage is mandatory for OV certificates too, so there is no cheaper tier.

**Why it matters:** It is the whole reason Windows is served by WSL2 rather than by a driver. Every other platform is trivial by comparison: Apple $99/yr, Android $25 once, Linux free with GPG. The entire signing burden sat on one component, which was also the longest phase and the highest-blast-radius code in the project.

**How to apply:** Do not reopen the Windows driver on the assumption that the ~$10/month Trusted Signing path applies. It works for ordinary executables and not for `aisme-flt.sys`. The retained specification is plan Annex F, marked `[POST]`.

**Source:** `ADR-02`

Related: [[wsl2-capabilities]], [[wsl2-has-no-tpm]]
