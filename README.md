# AISME — AI Sessions Manager & Security Engine

Kernel-level runtime security and provenance for autonomous AI coding agents — eBPF, Landlock and seccomp on Linux, including WSL2.

AISME watches what an AI agent *says it is going to do* and what it *actually does to your machine*, links the two causally, and stops the operations that do not match. It supervises **off-the-shelf agents** through their own hook interface — Claude Code, Cursor, Codex CLI, Copilot CLI, Gemini CLI, OpenCode, Amp — so the agent needs no modification and no cooperation beyond starting under `aisme run`. It runs on Linux workstations from Ring-0, including **Windows via WSL2**, and on Android and iOS through the **AI Sentinel** app.

## Status

A working **walking skeleton**, phase F2 of eleven. What follows is what runs today, with the command that proves each line — not a roadmap.

| Capability | State | Evidence |
|---|---|---|
| Policy compiler (AISME-PL → compiled rules, per-session `${workspace}` / `${home}` bindings) | **works** | `cargo test --workspace` · `deploy/policy/skeleton.aisme` |
| Kernel enforcement, file opens (seccomp user-notification; the decision is taken on what the descriptor *names*, never on the path a caller typed) | **works** | `cargo xtask test-skeleton` |
| Kernel enforcement, write scope (one Landlock ruleset applied before `exec`, inherited by the whole tree) | **works** | measured: a write outside the scope is denied in kernel with **no supervisor woken** |
| Session supervision (`aisme run` is the session's own ancestor, so every descendant is supervised; no component holds a capability) | **works** | `ADR-09` · `crates/aisme-cli/tests/session.rs` |
| Intent plane (`aisme declare` as a pre/post-tool hook; start and end of each tool call) | **works** | 1 ms per call, measured |
| Tool-call attribution (actions joined to the declaration that explains them; **ambiguity is marked, never guessed**) | **works** | `crates/aisme-agentsim/src/record.rs` |
| Append-only WAL and forensic tail (`aisme-forensicd --tail`, resumes with zero loss) | **works** | `tests/tail.rs` |
| Terminal adjudicator (the escalate class asks a human, in raw mode, with a real budget) | **works** | `crates/aisme-agentd/src/terminal.rs` |
| eBPF sensor (one `openat` tracepoint, real ring buffer) | **loads and runs** | `ACCEPTED · ringbuf: true` on kernel 7.1.5 |
| Correlation engine, detectors, taint propagation | specified, **not built** | plan phase `F5` |
| Semantic capture before TLS | specified, **not built** | plan phase `F4` |
| Control-plane UI, mobile apps, SDK | specified, **not built** | phases `F8`, `F10`, `F11` |
| Native Windows kernel driver | **`[POST]`, deferred** | [ADR-02](docs/adr/02_drop-windows-kernel-driver.md) |

**Measured latency**, over 100 000 samples: an unsupervised `openat` at **1.80 µs** p99; a held
syscall answered by the supervisor with a validated descriptor at **46.6 µs** p99 against a budget of
400 µs; a write denied in kernel by Landlock at **2.42 µs** p99 against a budget of 12 µs. The
in-kernel deny costs **19× less** than the supervised round trip — which is the whole architectural
argument, in figures. Reproduce with `cargo xtask bench-t0 --syscalls 100000`.

**387 tests pass and the local gate is green** — `cargo test --workspace` and
`cargo xtask gate --level commit`. There is **no hosted CI**: every gate runs on your machine
(`I-27`), which is a deliberate constraint and not an omission.

Start at [the plan](docs/01_phase5_implementation_plan.md); the live position is in
[STATE](docs/ai/STATE.md); every change is in the [changelog](docs/CHANGELOG.md).

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
Ring 0          Linux:   eBPF · Landlock · cgroup connect hooks · seccomp_unotify · cgroup freezer · BPF-LSM (tier L3)
                Windows: the same, inside WSL2, at tier L2 by default
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
docs/          Plan, reviews, phase amplifications, ADRs, design notes, threat model, field research, LLM working docs, changelog
LICENSE*       Apache-2.0, GPL-2.0 (eBPF only), BSD-2-Clause; map in LICENSE.md
tests/         Fixtures, labelled corpora, adversarial scenarios
```

## Documentation map

| Document | Purpose |
|---|---|
| [docs/01_phase5_implementation_plan.md](docs/01_phase5_implementation_plan.md) | The definitive plan. Start here |
| [docs/02_challenge_ampliacion_sistema.md](docs/02_challenge_ampliacion_sistema.md) | Correctness review: 209 findings with their patches, all applied; the owner's ten decisions |
| [docs/03_challenge_accionabilidad.md](docs/03_challenge_accionabilidad.md) | Executability review: 35 findings with their patches, all applied |
| [docs/04_final_coherence_seal.md](docs/04_final_coherence_seal.md) | The seal: final coherence pass — 134 findings, host probe, unverified register |
| [docs/05](docs/05_challenge_ampliacion_f2.md) … [docs/11](docs/11_challenge_ampliacion_recomendaciones.md) | Phase amplifications: each point taken to Challenge / Verification / Implementation / Tests / Documentation before any code is written |
| [docs/12](docs/12_investigacion_guardarrailes_sesiones_ia.md) · [docs/14](docs/14_plan_de_cierre_f2_y_campo.md) … [docs/18](docs/18_preparacion_para_publicacion.md) | Host measurements, the F2 closing plan, and the release preparation. [docs/17](docs/17_plan_de_cierre_de_f2.md) is the live one |
| [docs/research/](docs/research/) | Field studies: [01](docs/research/01_incidentes_y_defensas_de_agentes_ia.md) incidents and defences with 32 dated cases · [02](docs/research/02_hooks_de_agentes_como_fuente_de_intencion.md) agent hooks as a source of intent, eleven vendors compared · [03](docs/research/03_atribucion_de_procedencia_y_tracepoints.md) provenance attribution, verified against kernel source |
| [docs/README.md](docs/README.md) | **The full index** — every document, what it is for, and where to start |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Every change, by commit and task |
| [LICENSE.md](LICENSE.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) | Licence map, contribution rules, vulnerability reporting |
| [docs/security/01_threat-model.md](docs/security/01_threat-model.md) | Assets, ranked adversaries, trust boundaries, non-goals |
| [docs/ai/AGENTS.md](docs/ai/AGENTS.md) | Working contract for development LLMs |
| [docs/ai/STATE.md](docs/ai/STATE.md) | Live project state — what is done, what is next |
| [docs/ai/invariants.md](docs/ai/invariants.md) | Non-negotiable constraints |
| [docs/design/](docs/design/) | `01_permission-model.md` (the permission and suppression model), `02_aisme-run.md` (the session launcher) |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [docs/ai/memory/](docs/ai/memory/) | Durable facts that were expensive to discover, one per file |

## Naming

The **repository** is `ai-sentinel`, after the idea the whole project is about. The **components**
keep their own names, and they are not interchangeable — the plan, the ADRs and the capability
parity matrix all say which component does what:

- **AISME** — the system as a whole, and the workstation engine (Linux, including Windows through WSL2).
- **AI Sentinel** — the Android and iOS application.
- **AI Sentinel SDK** — the embeddable library for third-party AI applications.

So "AI Sentinel" is the mobile app, not the repository and not the engine. Never *"AISME
Sentinel"*.

## Scope and honesty

AISME's workstation engine enforces from Ring-0 on Linux, and on Windows through WSL2 — a real Linux kernel, so the engine runs unmodified. **Agents running as native Windows processes are outside the WSL2 VM and are not covered.** Native Windows kernel enforcement is deferred; the reasoning and the retained specification are in [ADR-02](docs/adr/02_drop-windows-kernel-driver.md) and plan Annex F.

WSL2 exposes no TPM, so on that platform the forensic chain is signed with a software key and its non-repudiation rests on external root anchoring, which is enabled by default there. Every record states which key signed it.

On mobile, AISME enforces at the network and tool-call layers, which is what the platforms permit — synchronous, pre-egress, and sufficient for the exfiltration threat, but not equivalent to kernel enforcement for file and process activity.

All coverage differences are enumerated in the capability parity matrix (plan §2.20.2) and surfaced in the product itself. AISME never claims a capability it does not have on the device it is running on.

What AISME does **not** defend against is stated as plainly as what it does: see the non-goals in the [threat model](docs/security/01_threat-model.md).

## Contributing

### Run it in five minutes

```bash
cargo xtask doctor                     # the host, measured — names every missing prerequisite
cargo test --workspace                 # 387 tests, no kernel touched
cargo xtask gate --level commit        # what the pre-commit hook runs, under 10 minutes

# And see it enforce something. The daemon holds the policy; the session asks it.
cargo build --workspace
mkdir -p /tmp/aisme/{wal,ws}
./target/debug/aisme-agentd --run /tmp/aisme/wal --ticks 2000000 \
    --serve-ipc /tmp/aisme/a.sock --policy deploy/policy/skeleton.aisme &
AISME_AGENTD_SOCKET=/tmp/aisme/a.sock \
    ./target/debug/aisme run --scope /tmp/aisme/ws --trap-openat -- /bin/cat /etc/shadow
#   → "denied an openat … refused by the session's adjudicator", and 0 asked.
#     A compiled deny asks nobody, which is what makes it stronger than a prompt.
```

`cargo xtask doctor` is the one to run first. It measures fifteen prerequisites and says what each
unblocks: documentation and host-only Rust work proceed on a `FAIL`, anything that builds the eBPF
objects or boots a VM does not.

### How this project decides things

Six rules, and reading them will save you an afternoon:

- **Nothing enters unverified.** A claim about a kernel, a library or a platform cites a command, a
  figure or a file. What could not be verified goes in an explicit register, not into prose.
- **Every defect is a numbered point**, never "noted as debt", and every point says what would
  falsify it. A point with no falsification criterion is an opinion with a number.
- **A `FAIL` is fixed before committing** — never worked around, never declared in the commit body.
  If a guard exists, its property matters.
- **An absence is never read as a value.** A missing key is not zero, an unreadable field is not
  "fine", and a default where there was an unknown leaves a written reason.
- **There is no hosted CI, and that is deliberate** (`I-27`). Every gate runs on your machine, and
  the repository contains **no** workflow file — not one with safe triggers, not a manually
  dispatched one. `verify-docs` fails if one appears. Please do not send a pull request adding one.
- **No kernel-touching test runs on a host** (`I-12`). Snapshot VMs only, through
  `cargo xtask vm up <image>`. This is the rule most often broken in good faith.

### Good first tasks

Each is specified, open as of this writing, and needs none of the owner's hardware. Check it is still
open in [docs/ai/STATE.md](docs/ai/STATE.md) before you start.

| Task | Why it is a good first one |
|---|---|
| **The degradation banner asserts absences it never measured.** On a host where the sensor loads with `ringbuf: true`, the banner still prints `degraded: no BPF ring buffer`. `probe()` is right to claim nothing it did not measure; the banner turns that silence into an assertion. It needs a third state — *not measured* — rather than a reworded second one | self-contained, no kernel, one enum and its printer. `STATE.md` → *Open, not blocking* |
| **`crates/aisme-ebpf-policy` has 52 lines and no test.** It is the second BPF object; `aisme-loaderd` depends on its map names, key sizes and the order of the two slots in `Array<u64,2>`, and nothing checks them | a renamed map currently fails at publication time in a guest instead of at `cargo test` on a laptop |
| **Edge cases in `crates/aisme-proto`.** A codec with 961 lines and 8 tests. The interesting inputs are the ones that would be *accepted* wrongly: an `id` that is a float, a duplicate key, an unterminated escape, a lone surrogate, a number past `i64` | pure functions, no setup, and the project's rule 4 says a defect biasing toward acceptance is the urgent kind |
| **The exit tracepoint** (`docs/17` point 5) — `sys_exit_openat`, so a denial the filter never trapped is *recorded* and not only enforced | for somebody who wants kernel work and has a VM. Needs `cargo xtask vm up` |

### The deep end

Three phases are fully specified and unbuilt: the **correlation engine and detector runtime** (`F5`),
the **mobile sensors** for Android and iOS (`F10`, `F11`), and the **control-plane UI** (`F8`). Each
has a task table in [the plan](docs/01_phase5_implementation_plan.md) stating what it owes and what
its done-condition is. You do not need to read the plan to start — doctor, tests, gate, a first task
— but it is where you go to understand why anything is the way it is.

Contributions are under the [DCO](CONTRIBUTING.md): no CLA, and you keep your copyright.

## Licence

**Apache-2.0**, except where the kernel requires otherwise: the eBPF programs are **GPL-2.0-only**, because a BPF program that calls a `gpl_only` helper must declare a GPL licence and the kernel verifier enforces it at load time. User-space code is not a derivative work of a BPF program, so the engine, the SDK and everything else are Apache-2.0. Documentation is CC-BY-4.0.

The full map and the reasoning are in [LICENSE.md](LICENSE.md); the decision is [ADR-06](docs/adr/06_open-source-licensing.md). Attribution obligations are in [NOTICE](NOTICE). The names *AISME* and *AI Sentinel* are not licensed (Apache-2.0 §6).

Contributions are welcome under the [DCO](CONTRIBUTING.md) — no CLA, contributors keep their copyright. To report a vulnerability, read [SECURITY.md](SECURITY.md) first; two adversary classes are documented non-goals.

If this work is useful in research, [CITATION.cff](CITATION.cff) has the citation.
