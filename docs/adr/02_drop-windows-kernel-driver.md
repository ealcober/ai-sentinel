# ADR-02 — Defer the Windows kernel driver; cover Windows via WSL2

**Status**: **Accepted** 2026-08-17 · **Date raised**: 2026-08-17
**Raised by**: project owner · **Supersedes in part**: the Windows phase, finding `H-15`

> **Editor's note (2026-08-17, after ADR-03 and the challenge review).** Identifiers
> below predate two later changes. Read "phase `F3`" as *the Windows phase, now plan
> Annex F*; "the F2 Linux engine" as *F3*; and the traits `KernelSource` /
> `PolicyPublisher` / `Enforcer` as their current names `Sensor` / `Enforcer` /
> `Adjudicator` (plan §3.2). "Removed" below means excluded from the workspace and
> the gate matrix; the code stays in the tree as the Annex F specification. Read the
> tier L2 definition as plan §2.17 today (Landlock + cgroup connect hooks + seccomp);
> the seccomp-only shape is `L2-`. The body is otherwise unchanged.

## Context

Finding `H-15` in the implementation plan already flagged Windows code-signing as a `[RISK]` on the critical path. Investigation on 2026-08-17 confirmed the situation is **worse than the plan assumed**:

- **Azure Trusted Signing does not replace an EV certificate for kernel drivers.** Microsoft requires that a Hardware Dev Center / Partner Center account have at least one EV certificate associated with it before any binary can be submitted for attestation signing. Only EV certificates satisfy the driver-distribution signing requirements. The cheap modern path (~$10/month, no hardware token) exists for ordinary executables but **not** for what AISME needs.
- Since 2023, hardware-token/HSM storage is mandated for **OV** certificates too, not only EV — so there is no cheaper commercial tier to drop to.
- PPL/ELAM additionally requires MVI membership, a months-long corporate process that can be denied.

By contrast, no other target platform imposes anything comparable:

| Platform | Signing gate | Cost | Nature |
|---|---|---|---|
| **Windows (kernel driver)** | **EV cert + Partner Center + attestation/WHQL; MVI for PPL** | **$300–900/yr + months** | **Commercial + corporate vetting** |
| macOS | Apple Developer Program; Endpoint Security entitlement requires manual Apple approval | $99/yr | Digital, but with an approval gate |
| iOS | Apple Developer Program; `packet-tunnel-provider` entitlement is standard | $99/yr | Fully digital |
| Android | Self-signed keystore; Play account | $25 once | Free, self-service |
| Linux | GPG; **no Secure Boot issue because we chose eBPF over a kernel module** | Free | Self-service |

The entire burden is concentrated in **one component**: `aisme-flt.sys`, phase `F3`. It is also the longest single phase (4 weeks), the only one requiring C and the WDK, and the highest-blast-radius code in the project — a kernel defect is a bugcheck on a user's machine.

## Decision

**Defer the Windows kernel driver. Cover Windows through WSL2.**

Phase `F3` is marked `[POST]`, EV certificate procurement (`F0.WIN.01`) and the MVI application (`F0.WIN.02`) are cancelled for the MVP, and the Windows driver test rig (Driver Verifier, HLK, `T4.3.*`) leaves the CI matrix. **Windows remains a supported platform** through WSL2 running the F2 Linux engine.

### Why WSL2 rather than dropping Windows outright

**Windows developers overwhelmingly run AI coding agents inside WSL2, which is a real Linux kernel.** Verified: WSL2 supports eBPF and the stock Microsoft kernel ships with BTF, so `aisme-ebpf` and the Linux engine run unmodified. BPF-LSM requires activation at boot, so WSL2 lands at **service tier L2** as defined in `H-16` — full observability plus `seccomp_unotify` enforcement and cgroup freezing. No driver, no C, no EV certificate, no MVI, no additional engineering.

| Option | Engineering cost | Signing gate | Windows coverage |
|---|---|---|---|
| Remove Windows entirely | 0 | none | none |
| **Remove driver, support via WSL2** | **0** | **none** | **WSL2 developers, tier L2** |
| Add Windows user-space tier (ETW only, no driver) | ~1 week | ordinary cert (~$10/mo Trusted Signing) | native Windows, observe-only |
| Original plan with driver | 4 weeks + months of procurement | EV + Partner Center + MVI | native Windows, full enforce |

Both the first and second rows remove exactly the same cost and risk; the second retains coverage for Windows-based developers at no additional effort, because the Linux engine is already being built.

## Consequences

**Accepted consequences:**
- MVP critical path drops from ~14–15 weeks to ~11–12.
- The project becomes single-language (Rust) with no WDK, no C, no kernel-driver risk.
- The highest-severity failure mode in the project — a kernel bugcheck on a user's machine — is eliminated.
- **Coverage boundary**: agents running as native Windows processes (Claude Desktop, native VSCode, any `.exe` agent) are outside the WSL2 VM and therefore invisible. Agents running inside WSL2 are fully covered. This boundary must be surfaced in the UI per invariant `I-16`.
- `aisme-windows`, `driver/aisme-flt`, `T4.3.*` and the Windows CI matrix are removed. The `aisme-uiagent` design (permission-model note §7.2) loses its Windows implementation but keeps the architecture, which was driven by the session-0 constraint — worth preserving, since macOS will need the same split.
- **WSL2 exposes no TPM** (`R1-18`). The forensic chain for Windows-via-WSL2 users is therefore signed with a software key (`key_hw = SoftwareEd25519`), and its non-repudiation rests on external root anchoring, which is enabled by default for such installs (`I-18`). This consequence of the platform choice surfaced in the challenge review, not when the decision was taken; it is stated in the README and shown in the UI.

**Reversal cost.** Moderate but not prohibitive. The plan's architecture deliberately keeps all intelligence in the Rust daemon behind the `KernelSource` / `PolicyPublisher` / `Enforcer` traits (`F1.PA.01`), precisely so a platform backend can be added later. Re-adding Windows means writing the driver and starting the procurement — the core engine does not change. **Keep the trait boundaries even with Windows removed**, or this reversal becomes expensive.

## Follow-up actions

- [x] Confirm scope — **WSL2 path chosen** by the project owner, 2026-08-17.
- [x] Update plan §2.16 (`H-15` rewritten, §2.16.1 added), Part III (`F3` → `[POST]`, F0 tasks deprecated, effort table), Part IV (`§4.3` → `[POST]`, platform matrix).
- [x] Update `README.md` platform claims and `docs/ai/invariants.md` (`I-11`, `I-13` marked inactive).
- [x] Retain the `Sensor`/`Enforcer`/`Adjudicator` trait boundaries (§3.2).
- [x] **`F0.WSL.01`** (2026-09-05) — the stock WSL2 kernel **does** ship `CONFIG_BPF_LSM=y`, with `bpf` absent from the active LSM list. WSL2 is **L2** by default and reaches **L3** through `kernelCommandLine=` in `.wslconfig`; no custom kernel is needed. Landlock is ABI 7 and enforcing, so the L2 tier is real there.
- [ ] **`F0.WSL.02`** — WSL2 test images: with/without systemd, cgroup v1 and v2.
- [ ] Add `/mnt/*` (9p/virtiofs) path canonicalization coverage to `T4.6.07`.
- [ ] Handle NAT vs. mirrored WSL2 networking in the flow model.

## Sources

- [Driver Code Signing Requirements — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Azure Trusted Signing and Hardware Program verification — Microsoft Q&A](https://learn.microsoft.com/en-au/answers/questions/5866910/hardware-program-verification-using-azures-trusted)
- [Attestation signing with Azure Trusted Signing — Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/2110207/azure-trusted-signing-certificate-attestation-sign)
- [FAQ: Kernel-Mode Code Signing Certificates — SSL.com](https://www.ssl.com/faqs/faq-kernel-mode-code-signing-certificates/)
- [Build a Custom WSL 2 Kernel in 2026 — Box of Cables](https://www.boxofcables.dev/build-a-custom-wsl-2-kernel-in-2026/)
- [Enable eBPF on WSL2 — gist](https://gist.github.com/MarioHewardt/5759641727aae880b29c8f715ba4d30f)
