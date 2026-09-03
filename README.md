# AISME — AI Sessions Manager & Security Engine

Kernel-level observability and containment for autonomous AI coding agents.

AISME watches what an AI agent *says it is going to do* and what it *actually does to your machine*, links the two causally, and stops the operations that do not match. It runs on Linux workstations from Ring-0 — including **Windows via WSL2** — and on Android and iOS through the **AI Sentinel** app.

> **Status: pre-implementation.** Architecture and implementation plan are complete (Parts 0–VIII, Annexes A–G) and have been through a full challenge review; no product code has been written yet. See [the plan](docs/01_phase5_implementation_plan.md) and [the review](docs/02_challenge_ampliacion_sistema.md).

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

These are enforced by CI gates, not aspirations:

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
driver/        aisme-flt — Windows minifilter (C11 / WDK)  [DEFERRED — ADR-02]
mobile/        AI Sentinel — Android (Kotlin) and iOS (Swift) sensor shims
sdk/           AI Sentinel SDK bindings for third-party AI applications
ui/            React/TypeScript control-plane UI (Tauri v2 shell)
xtask/         Build, test and certification orchestration
docs/          Plan, ADRs, design notes, research sources, LLM working docs
tests/         Fixtures, labelled corpora, adversarial scenarios
```

## Documentation map

| Document | Purpose |
|---|---|
| [docs/01_phase5_implementation_plan.md](docs/01_phase5_implementation_plan.md) | The definitive plan. Start here |
| [docs/02_challenge_ampliacion_sistema.md](docs/02_challenge_ampliacion_sistema.md) | Challenge review of the whole system: 209 findings, unapplied patches, owner decisions |
| [docs/ai/AGENTS.md](docs/ai/AGENTS.md) | Working contract for development LLMs |
| [docs/ai/STATE.md](docs/ai/STATE.md) | Live project state — what is done, what is next |
| [docs/ai/invariants.md](docs/ai/invariants.md) | Non-negotiable constraints |
| [docs/design/](docs/design/) | Design notes under active development |
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

## Licence

TBD.
