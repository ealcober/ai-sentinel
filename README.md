# AISME — AI Sessions Manager & Security Engine

Kernel-level observability and containment for autonomous AI coding agents.

AISME watches what an AI agent *says it is going to do* and what it *actually does to your machine*, links the two causally, and stops the operations that do not match. It runs on Linux workstations from Ring-0 — including **Windows via WSL2** — and on Android and iOS through the **AI Sentinel** app.

> **Status: pre-implementation.** The architecture and implementation plan are complete (Parts 0–VIII, Annexes A–I), reviewed twice — for correctness and for executability — with every finding applied; no product code exists yet. Start at [the plan](docs/01_phase5_implementation_plan.md); the live position is in [STATE](docs/ai/STATE.md); every change is in the [changelog](docs/CHANGELOG.md).

---

## The problem

An AI agent with tool access is an execution engine driven by natural language. When it hallucinates, gets prompt-injected by a file it reads, or simply misunderstands, the result is not a wrong answer — it is a modified filesystem, a spawned process, or an outbound connection. The operating system cannot tell the difference between a legitimate refactor touching 100 files and ransomware touching the same 100 files, because it has no representation of *why*.

AISME adds that representation.

## What it does

| | |
|---|---|
| **Semantic capture** | Extracts prompts, chain-of-thought and tool calls before TLS encryption — no MITM proxy, no certificate installation, no modification of the observed process |
| **Kernel telemetry** | eBPF records every file, process and network operation the agent's process tree performs. On Windows this runs inside WSL2, which is a real Linux kernel |
| **Causal correlation** | Binds declared intent to physical mutation with measurable precision, producing a provenance DAG |
| **Containment that stays liveable** | Blocks at the kernel boundary before hardware is touched. Outside the workspace it **asks** rather than silently denying; inside it, it **warns and learns** — suppression rules absorb known-benign patterns so the guardrail stays quiet on legitimate work, and a suppressed event is still recorded and still enforced |
| **Tamper-evident forensics** | Merkle-chained audit log, signed by a hardware key where one exists and by a software key otherwise — the record says which — with externally anchored roots |
| **Mobile detection** | AI Sentinel detects and blocks AI-agent exfiltration on Android and iOS at the network layer, with no root and no MDM required |

## Design commitments

These are enforced by gates that run locally, not aspirations:

- **< 50 MB RAM** for the hot daemon, **< 3% CPU** under a defined reference workload, **< 15 µs** p99 added syscall latency.
- **Strictly read-only observation.** AISME never modifies the memory, control flow or cryptographic state of a monitored process. It does not defeat certificate pinning, and it does not hide itself from the system.
- **Deterministic enforcement.** The Observer LLM scores and advises; it can never authorize. Blocking decisions are made by compiled policy in the kernel.
- **Honest coverage.** The product shows the user what it can and cannot see on their specific device. It never implies protection it does not have.

## Architecture at a glance

```
Control plane   aisme-ui (desktop) · AI Sentinel (Android/iOS) · aisme-cli
                             │
User space      aisme-agentd (hot path, ≤50 MB)  →  aisme-forensicd (cold path)
                             │                            └─ DuckDB · Merkle · OTLP
Ring 0          Linux:   eBPF · BPF-LSM · seccomp_unotify · cgroup freezer
                Windows: the same, inside WSL2
                Mobile:  VpnService / NEPacketTunnelProvider · AI Sentinel SDK
```

Full topology and the reasoning behind every choice: [implementation plan, Part II](docs/01_phase5_implementation_plan.md).

## Repository layout

```
crates/        Rust workspace — engine, daemons, correlation, compression, CLI
driver/        aisme-flt — Windows minifilter (C11 / WDK)  [POST — ADR-02]
mobile/        AI Sentinel — Android (Kotlin) and iOS (Swift) sensor shims
sdk/           AI Sentinel SDK bindings for third-party AI applications
ui/            React/TypeScript control-plane UI (Tauri v2 shell)
xtask/         Build, test and certification orchestration
docs/          Plan, reviews, ADRs, design notes, threat model, research, LLM working docs, changelog
LICENSE*       Apache-2.0, GPL-2.0 (eBPF only), BSD-2-Clause; map in LICENSE.md
tests/         Fixtures, labelled corpora, adversarial scenarios
```

## Documentation map

| Document | Purpose |
|---|---|
| [docs/01_phase5_implementation_plan.md](docs/01_phase5_implementation_plan.md) | The definitive plan. Start here |
| [docs/02_challenge_ampliacion_sistema.md](docs/02_challenge_ampliacion_sistema.md) | Correctness review: 209 findings with their patches, all applied; the owner's ten decisions |
| [docs/03_challenge_accionabilidad.md](docs/03_challenge_accionabilidad.md) | Executability review: 35 findings with their patches, all applied |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Every change, by commit and task |
| [LICENSE.md](LICENSE.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) | Licence map, contribution rules, vulnerability reporting |
| [docs/security/01_threat-model.md](docs/security/01_threat-model.md) | Assets, ranked adversaries, trust boundaries, non-goals |
| [docs/ai/AGENTS.md](docs/ai/AGENTS.md) | Working contract for development LLMs |
| [docs/ai/STATE.md](docs/ai/STATE.md) | Live project state — what is done, what is next |
| [docs/ai/invariants.md](docs/ai/invariants.md) | Non-negotiable constraints |
| [docs/design/](docs/design/) | `01_permission-model.md` (the permission and suppression model), `02_aisme-run.md` (the session launcher) |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [docs/research/](docs/research/) | Original research documents (Spanish) and extracted text |

## Naming

- **AISME** — the system as a whole, and the workstation engine (Linux, including Windows through WSL2).
- **AI Sentinel** — the Android and iOS application.
- **AI Sentinel SDK** — the embeddable library for third-party AI applications.

## Scope and honesty

AISME's workstation engine enforces from Ring-0 on Linux, and on Windows through WSL2 — a real Linux kernel, so the engine runs unmodified. **Agents running as native Windows processes are outside the WSL2 VM and are not covered.** Native Windows kernel enforcement is deferred; the reasoning and the retained specification are in [ADR-02](docs/adr/02_drop-windows-kernel-driver.md) and plan Annex F.

WSL2 exposes no TPM, so on that platform the forensic chain is signed with a software key and its non-repudiation rests on external root anchoring, which is enabled by default there. Every record states which key signed it.

On mobile, AISME enforces at the network and tool-call layers, which is what the platforms permit — synchronous, pre-egress, and sufficient for the exfiltration threat, but not equivalent to kernel enforcement for file and process activity.

All coverage differences are enumerated in the capability parity matrix (plan §2.20.2) and surfaced in the product itself. AISME never claims a capability it does not have on the device it is running on.

What AISME does **not** defend against is stated as plainly as what it does: see the non-goals in the [threat model](docs/security/01_threat-model.md).

## Licence

**Apache-2.0**, except where the kernel requires otherwise: the eBPF programs are **GPL-2.0-only**, because a BPF program that calls a `gpl_only` helper must declare a GPL licence and the kernel verifier enforces it at load time. User-space code is not a derivative work of a BPF program, so the engine, the SDK and everything else are Apache-2.0. Documentation is CC-BY-4.0.

The full map and the reasoning are in [LICENSE.md](LICENSE.md); the decision is [ADR-06](docs/adr/06_open-source-licensing.md). Attribution obligations are in [NOTICE](NOTICE). The names *AISME* and *AI Sentinel* are not licensed (Apache-2.0 §6).

Contributions are welcome under the [DCO](CONTRIBUTING.md) — no CLA, contributors keep their copyright. To report a vulnerability, read [SECURITY.md](SECURITY.md) first; two adversary classes are documented non-goals.

If this work is useful in research, [CITATION.cff](CITATION.cff) has the citation.
