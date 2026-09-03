# ADR-04 — Tauri v2 for the mobile client, with a `uniffi` fallback built from the start

**Status**: **Accepted** 2026-08-17 · **Raised by**: architecture · **Formalizes**: plan §2.20.7

## Context

The control plane's UI is React/TypeScript by an earlier decision. `H-19` adds Android and iOS, and the naive extension of that decision — a second UI in Kotlin and a third in Swift — triples the UI work and, worse, duplicates the Noise handshake, the protocol types and the secure-key bindings in a language where re-implementing them is a security downgrade.

Two hard constraints bound the choice. The iOS Network Extension runs in a **separate process with a ceiling near 50 MB** (`budgets.toml`: 45 MB hard), so the client cannot be memory-careless. And Tauri v2's mobile targets are **younger than its desktop targets**, which is a schedule risk on a component the MVP needs.

## Decision

**Tauri v2 for the client shell on desktop, Android and iOS.** One React/TS UI. The logic layer — `aisme-core` plus `aisme-clientcore`, carrying the ontology, correlation, taint, policy, flow classifier and crypto — compiles to `aarch64-linux-android` and `aarch64-apple-ios` and is bound through **`uniffi`**. The sensor layer stays native, thin and logic-free: Kotlin `VpnService`, Swift `NEPacketTunnelProvider`.

**The `uniffi` boundary is built from the start, while Tauri works.** That is the substance of this decision, not an afterthought: it is what turns the fallback from a rewrite into a shell swap.

Rejected: React Native plus a separate desktop app (duplicates crypto and protocol in TypeScript); Flutter (a third language for no benefit here); native Kotlin and Swift UIs (3× the UI work — reconsider `[POST]`).

## Consequences

**Good.** One UI, one crypto and protocol implementation, one classifier tested once on CI on x86_64. The mobile client inherits every correction made to the shared core rather than drifting from it.

**Costs.** A `uniffi` boundary that would not be needed if Tauri mobile were certain. Its cost is real and it is the premium paid for the fallback.

**Risks.** Tauri v2 mobile blocks the release (risk R-05, Med/Med).

**Reversal cost — low, by construction.** If Tauri mobile blocks, the fallback is a native shell hosting the same web UI over the same `uniffi` core. **The shared-core investment survives either way**, which is only true because the boundary exists before it is needed. Building `uniffi` "later, if we need it" would make this reversal a rewrite.

## Follow-up actions

- [ ] `F11.CC.03` **builds** the `uniffi` fallback path, not merely plans it — a fallback that has never been compiled is not a fallback.
- [ ] `F11.CC.01`/`F11.CC.02` keep the key split from ADR-02's correction: software X25519 for the Noise channel, hardware P-256 for verdict signing.
- [ ] The iOS extension holds only the classifier and flow table, never the forensic store (`budgets.toml`, `mobile.ios_extension`).
