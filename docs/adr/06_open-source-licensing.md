# ADR-06 — Open-source licensing: Apache-2.0, with GPL where the kernel requires it

**Status**: **Accepted** 2026-09-03 · **Raised by**: project owner

## Context

The project is released as open source. The owner's stated goal has two parts: give the work away, and be recognised for it. Those are not in tension, but they are served by different instruments, and one part of the choice is not a choice at all.

**The constraint that decides the kernel side.** Loading a BPF program follows the same licence rules as loading a kernel module. The verifier inspects which helpers a program calls, and a helper marked `gpl_only` — `bpf_probe_read` among them, roughly a quarter of the helper set — requires the program to declare a GPL-compatible licence, enforced at load time. AISME's probes use several. The eBPF programs are GPL-2.0-only under any policy this project could adopt.

**Where the boundary stops.** The kernel documentation is explicit that a user-space program interacting with eBPF through the syscall interface is not a derivative work of the BPF program. The user-space engine is free.

**The component that decides the rest.** The AI Sentinel SDK exists to be embedded in third-party AI applications. `ADR-05` and plan F9 treat it as the strategic component: the thing that makes AISME an instrumentation standard instead of a permanent reverse-engineering effort. A copyleft SDK cannot be embedded in a proprietary application, so a copyleft SDK is not adopted, so the strategy does not work.

## Decision

| Path | Licence |
|---|---|
| `crates/aisme-ebpf/**` | **GPL-2.0-only** — required by the kernel |
| `crates/aisme-ebpf-common/**` | **GPL-2.0-only OR BSD-2-Clause** — the same structs compile into both sides; this is `libbpf`'s arrangement for the same reason |
| All other code | **Apache-2.0** |
| `docs/**` | **CC-BY-4.0** |

**Apache-2.0 rather than MIT**, for two properties this project uses: an express **patent grant** with a termination clause for anyone who initiates patent litigation over the work, and the **`NOTICE` file** (§4d), whose attribution survives into derivative works as a licence obligation.

**Not AGPL.** AGPL protects against software being run as a hosted service by someone who returns nothing. AISME is a workstation agent and an on-device mobile engine; its only server component is a relay designed to hold no plaintext and to be self-hosted. That door is barely open. Against a marginal benefit, copyleft would break the SDK's entire purpose and would meet enterprise legal review — the audience — as a blocker.

**Recognition is three mechanisms, and only one is the licence**: `NOTICE` (enforceable attribution), `CITATION.cff` (citable design work), and **trademark** on the names, which Apache-2.0 §6 deliberately does not grant, leaving them available to register.

**Contributions under the DCO**, not a CLA. Contributors keep copyright; there is no assignment.

## Consequences

**Good.** The licence map matches the architecture's own boundary, so it needs no special pleading. Anyone may adopt, embed and ship the SDK. The patent grant protects contributors and users symmetrically. Attribution is a licence term rather than a courtesy.

**Costs.** Apache-2.0 is incompatible with GPL-2.0-only, so `aisme-ebpf-common` must stay dual-licensed and must not acquire an Apache-2.0-only dependency — it is `no_std` with zero dependencies (`A-03`), which already forbids that, so the licence constraint and the architectural constraint agree. A permissive licence also means a competitor may build a product on this work; that is the accepted price of the gift.

**The DCO's real consequence.** The project **cannot be relicensed without the agreement of every contributor**. Today the owner is the sole copyright holder, so the option remains open until the first external contribution is merged. Anyone contemplating a commercially licensed edition must decide before that point, not after.

**Reversal cost.** Moving *to* a more restrictive licence later requires every contributor's consent (see above) and would break downstream users who relied on the terms. Moving to a *more permissive* one is always possible for the copyright holders. The asymmetry is why the permissive choice is made deliberately rather than by default.

## Follow-up actions

- [ ] Register the trademarks **AISME** and **AI Sentinel**, since the licence explicitly does not cover them.
- [ ] `F0.GATE.08` (`verify-docs`) checks the SPDX header of every source file against the map in `LICENSE.md`, and fails on a missing or contradicting header.
- [ ] `F0.GATE.03` configures `cargo-deny` for licence policy; its allow-list must reflect the map, and must reject an Apache-2.0-only dependency inside `aisme-ebpf-common`.
- [ ] Decide the commercial question before merging the first external contribution.
