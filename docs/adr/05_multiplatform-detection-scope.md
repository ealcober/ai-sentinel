# ADR-05 — Detection is multiplatform: AI Sentinel detects and contains on-device

**Status**: **Accepted** 2026-08-17 · **Raised by**: project owner · **Formalizes**: `H-19`

## Context

"The app must also work on Android and iOS" has two readings, and only one of them was obviously buildable:

- **A** — the *control plane* runs on mobile: monitor sessions, answer Circuit Breaker prompts from a phone while the workstation engine runs.
- **B** — AISME *detects and contains AI agents running on the phone*.

The naive objection to B is "no eBPF, no minifilter, therefore no detection". That confuses a **mechanism** with a **capability**. What the system needs is: that an agent is active, what it intends, what it physically does, and the causal link between the last two. On mobile, three of those four come from supported, first-class platform frameworks — and one of them arrives in **higher fidelity than on desktop**.

## Decision

**Both readings ship.** A is F11; B is F10, the **AI Sentinel** product surface.

The ontology, correlation engine, taint model, policy language and forensic format are **shared and identical** with the workstation engine. Only the sensor and enforcement adapters differ. Four sensors: the network tunnel (`VpnService` / `NEPacketTunnelProvider`), the AI Sentinel SDK, device posture, and platform telemetry. A fifth — eBPF on rooted or AOSP builds — is `[POST]`.

Explicitly **`[CUT]`**: Android `AccessibilityService` screen-scraping. It would give broad cross-app text visibility and it is a Play policy minefield, an enormous privacy liability, and redundant given the tunnel and the SDK. The same reasoning as `H-05`: do not build a surveillance capability a security review will reject.

## Consequences

**Good.**
- **Network Slam has genuine parity.** The highest-value enforcement action in the system — dropping an exfiltration flow before the packet leaves the device — works on both platforms **without root, without MDM, and without violating a store policy**. Exfiltration is the primary threat in this model, and mobile is not a weaker platform for it.
- **Semantic capture is *better* on mobile.** On desktop, extracting chain-of-thought means the F4 reverse-engineering ladder, the most fragile part of the system. The SDK gives the same data structurally, losslessly, with no reverse engineering. For the semantic layer, mobile is the easy platform.
- One engine, tested once, on CI, on x86_64.

**Costs.** File and process visibility are bounded by the app sandbox. That boundary is real, it is enumerated in the capability parity matrix (§2.20.2, Annex D), and it is **surfaced in-app** (`I-16`): the product shows its actual coverage on the device it is running on.

**Risks.** Store review (R-04): the app must be positioned as a security console for the user's own devices, never as a tool to monitor third parties. SDK adoption (R-14): if it is zero, the network layer still detects, and `aisme.sentinel.uncooperative` makes non-adoption visible rather than invisible.

**Reversal cost.** Adding S5 (eBPF on rooted/AOSP) is additive and needs no change above the adapter layer — the trait boundaries carry it.

## Follow-up actions

- [ ] The in-app coverage disclosure (`F10.FO.05`) is a product invariant, not a nice-to-have: `T4.11.13` asserts the displayed tier matches the runtime probe on six device configurations.
- [ ] The flow corpus is synthetic-first (§4.14.1) — this decision must not become a reason to collect real users' traffic.
