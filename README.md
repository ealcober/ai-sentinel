# AISME — AI Sessions Manager & Security Engine

Kernel-level runtime security and provenance for autonomous AI coding agents — eBPF, Landlock and seccomp on Linux, including WSL2.

AISME watches what an AI agent *says it is going to do* and what it *actually does to your machine*, links the two causally, and stops the operations that do not match. It supervises **off-the-shelf agents** through their own hook interface — Claude Code, Cursor, Codex CLI, Copilot CLI, Gemini CLI, OpenCode, Amp — so the agent needs no modification and no cooperation beyond starting under `aisme run`. It runs on Linux workstations from Ring-0, including **Windows via WSL2**, and on Android and iOS through the **AI Sentinel** app.

**[See it in action](#see-it-in-action)** · **[What it stops today](#what-it-stops-today)** · **[Install](#install)** · **[Monitor an agent](#monitor-an-agent)** · **[Contributing](#contributing)** · **[Support the project](#support-the-project)**

## See it in action

A real transcript, not a mock-up. The daemon holds a three-rule policy; the agent runs under
`aisme run`, which is the session's own parent and supervises every process it spawns.

```console
$ aisme run --scope ~/project --trap-openat -- cat /etc/shadow
session 4a337b739a88dd55: denied an openat from pid 518764: refused by the session's adjudicator
/bin/cat: /etc/shadow: Permission denied
session 4a337b739a88dd55 ended: 2 delivered, 1 denied, 0 asked

$ aisme run --scope ~/project -- sh -c "rm -f /tmp/outside.txt"
rm: cannot remove '/tmp/outside.txt': Permission denied
```

Two different mechanisms, and the difference is the architecture. The first is a **compiled deny**:
the open is held by a seccomp supervisor, judged against the policy, and refused — with **`0 asked`**,
because a rule that never prompts cannot be answered away. The second is the **write scope**: one
Landlock ruleset, applied before the agent starts, refuses a deletion outside the project **in the
kernel**, without waking any supervisor at all.

> **The architectural argument, in figures** — over 100 000 samples: a write denied in kernel by
> Landlock costs **2.42 µs** p99; a held syscall answered by the supervisor costs **46.6 µs** p99.
> The in-kernel deny is **19× cheaper**, which is why AISME puts every decision it can in the kernel.
> Reproduce with `cargo xtask bench-t0 --syscalls 100000`.

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

**394 tests pass and the local gate is green** at the time of writing — `cargo test --workspace` and
`cargo xtask gate --level commit`. There is **no hosted CI**: every gate runs on your machine
(`I-27`), which is a deliberate constraint and not an omission.

Start at [the plan](docs/01_phase5_implementation_plan.md); the live position is in
[STATE](docs/ai/STATE.md); every change is in the [changelog](docs/CHANGELOG.md).

---

## What it stops today

Each line below is measured, with a test that fails if it stops being true. What is **not** in this
list is not claimed. The rows about **reading** files need `--trap-openat`, which today also refuses
writes — so they hold for scripted runs, and an interactive agent gets the write-scope rows (see
[Monitor an agent](#monitor-an-agent)).

| An agent tries to… | What happens | Mechanism |
|---|---|---|
| read a file the policy denies (`/etc/shadow`) | refused, **nobody is asked** | compiled deny, seccomp supervisor |
| read credentials (`~/.aws/credentials`) | the call is **held** and a human answers in the terminal; the answer is obeyed both ways | escalation, terminal adjudicator |
| write or delete outside the project | refused **in the kernel**, no supervisor woken | Landlock write scope |
| reach a denied file **through a symlink** | refused — the decision is taken on what the descriptor *names*, never on the path typed | locate with `O_PATH`, then decide |
| use `open` or `openat2` instead of `openat` | trapped too; `openat2` is refused outright | all three path-opening syscalls are filtered |
| escape through a child, a grandchild, a shell three deep | supervised all the way down | `aisme run` is the session's ancestor |
| switch off its own approvals (`--dangerously-skip-permissions` and similar) | **no verdict changes** | the policy never consults the agent |

**Not yet, and said plainly:** blocking network egress (the cgroup connect hook is phase `F3`);
catching an action that contradicts what the agent *declared* it would do (the correlation engine is
`F5`); seeing prompts and tool results before TLS (`F4`). The intent plane already records every
declaration beside every action — what is unbuilt is the engine that judges the pair.

## Install

**There is no packaged release yet.** AISME installs from source, and today it is a tool for people
who want to run it, test it and help build it — not yet a service to leave running unattended.

**You need:** Linux **5.14 or newer** (seccomp's descriptor injection arrived in 5.14 and Landlock in
5.13; WSL2's kernel qualifies), a systemd user session (each agent session gets its own cgroup), and
Rust — `rustup` picks up the pinned toolchain from `rust-toolchain.toml` on its own.

```bash
git clone https://github.com/ealcober/ai-sentinel && cd ai-sentinel
cargo xtask doctor                      # measures your host and names anything missing
cargo build --release
install -Dm755 target/release/aisme target/release/aisme-agentd target/release/aisme-forensicd \
    -t ~/.local/bin                     # `aisme` must be on PATH for the hook below
```

**The eBPF sensor is optional.** Enforcement — the seccomp supervisor and the Landlock scope — needs
no BPF and no privilege at all. The sensor adds kernel-wide observation; building it needs the pinned
nightly and `bpf-linker` (`cargo xtask build-ebpf`), and loading it needs `CAP_BPF`.

**About `deploy/systemd/`:** those units are the **target** deployment — an unprivileged daemon with
an empty capability set, and a separate loader holding `CAP_BPF`. They are **not yet a working
install**: the daemon runs until `systemctl stop` (it exits cleanly on `SIGTERM`), but the unit
starts it without a policy, and nothing yet creates the `aisme` user or installs to `/usr/lib/aisme`.

## Monitor an agent

Three pieces: the daemon holds the policy and the log, `aisme run` supervises the agent, and a hook
tells AISME what the agent *says* it is about to do.

**1. Start the daemon** with a policy. [`deploy/policy/skeleton.aisme`](deploy/policy/skeleton.aisme)
is a working three-rule example — deny `/etc/shadow`, escalate `${home}/.aws/**`, allow the rest —
and the place to start writing your own.

```bash
mkdir -p ~/.local/state/aisme/wal
aisme-agentd --run ~/.local/state/aisme/wal \
    --serve-ipc "$XDG_RUNTIME_DIR/aisme.sock" --policy deploy/policy/skeleton.aisme &
export AISME_AGENTD_SOCKET="$XDG_RUNTIME_DIR/aisme.sock"
```

It runs until `SIGTERM` or `SIGINT` (`kill %1`, or Ctrl-C in the foreground), and stops between
ticks, so every event it drained is already fsynced to the WAL. `--ticks N` bounds the run instead,
which is what the tests and gates use.

**2. Run the agent under it.** Any agent, unmodified — but give it the directories it keeps its own
state in, or it cannot save anything:

```bash
aisme run --scope ~/my-project --scope ~/.claude --scope ~/.claude.json --scope /tmp -- claude
```

Every `--scope` is a place the agent may **write**; everything else is refused in the kernel. A real
agent writes more than its project — Claude Code keeps sessions and history in `~/.claude/` and
`~/.claude.json`, and scratch files under `/tmp`; other agents have their own places — and measured,
without those scopes those writes are simply refused. **The trade-off is real:** granting
`~/.claude` also lets the agent rewrite its own hook configuration, which the narrower scope forbids.

**`--trap-openat` is not for interactive agents yet.** It puts every file open in front of the
policy, which is what makes the deny and escalate rules work — and today it refuses **every open for
writing, even inside the scope**, because the supervisor only reproduces read-mode opens faithfully.
Use it for scripted runs and testing. Widening the supervisor to the write class is one of the
routes costed for `F3.EN.11`/`F3.EN.12`, and the choice among them is still open.

**3. Install the intent hook** — optional, and it is what lets AISME attribute each action to the
tool call that caused it. Merge the `hooks` key of
[`deploy/hooks/aisme-hooks.json`](deploy/hooks/aisme-hooks.json) into **`~/.claude/settings.json`**,
your *user* file — **never** a project's `.claude/settings.json`, which is attacker-writable content
and the exact surface of CVE-2025-59536 and CVE-2026-48124. Several other agents read Claude Code's
settings format as well; which ones, and how, is in [`docs/research/02`](docs/research/02_hooks_de_agentes_como_fuente_de_intencion.md).
On a shared machine, put the hook in managed settings with `allowManagedHooksOnly: true`, so an agent
cannot switch it off mid-session.

**4. Watch it.** Every open, every denial and every declared tool call goes to an append-only log:

```bash
aisme-forensicd --tail ~/.local/state/aisme/wal         # follows the log; resumes with zero loss
```

When a rule escalates, the question appears **in the agent's own terminal** with four answers —
deny, allow once, allow for this session, always — and the held system call waits for it.

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
cargo test --workspace                 # the whole suite, no kernel touched
cargo xtask gate --level commit        # what the pre-commit hook runs, under 10 minutes

# And see it enforce something. The daemon holds the policy; the session asks it.
cargo build --workspace
mkdir -p /tmp/aisme/{wal,ws}
./target/debug/aisme-agentd --run /tmp/aisme/wal \
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
| **Write-mode opens under `--trap-openat`.** The supervisor reproduces only read-mode opens, so trap mode refuses every write, even inside the scope — which is why an interactive agent runs scope-only today (see [Monitor an agent](#monitor-an-agent)) | larger than the others, user space only, and the most useful single change for real sessions. The routes are costed in `docs/14` point 4; agree one in an issue first |
| **The exit tracepoint** (`docs/17` point 5) — `sys_exit_openat`, so a denial the filter never trapped is *recorded* and not only enforced | for somebody who wants kernel work and has a VM. Needs `cargo xtask vm up` |

### The deep end

Three phases are fully specified and unbuilt: the **correlation engine and detector runtime** (`F5`),
the **mobile sensors** for Android and iOS (`F10`, `F11`), and the **control-plane UI** (`F8`). Each
has a task table in [the plan](docs/01_phase5_implementation_plan.md) stating what it owes and what
its done-condition is. You do not need to read the plan to start — doctor, tests, gate, a first task
— but it is where you go to understand why anything is the way it is.

Contributions are under the [DCO](CONTRIBUTING.md): no CLA, and you keep your copyright.

## Support the project

AISME is built by a small team, and donations pay for the work. Send **only** on the networks named
here — anything else is lost.

| Currency | Network | Address |
|---|---|---|
| Bitcoin | Bitcoin (native SegWit) | `bc1q0j72u04dr560p29072ckgqqmggc5xnfk6c6hm4` |
| ETH and EVM tokens | Ethereum, BNB Smart Chain and other EVM-compatible networks | `0xDac59b7A1A212d7AaD1a8456bD2b6618456EF109` |
| Solana | Solana | `ASrFjfFNwKLCURqZE7WgFMudacyJMt87HxGLTW3zFCHC` |

**This README is the only place these addresses are published.** An address in an issue, a pull
request, a message or anywhere else that claims to be ours is not — check it against this file in
the official repository, [`github.com/ealcober/ai-sentinel`](https://github.com/ealcober/ai-sentinel),
before sending anything. Each address passes its network's checksum (bech32, EIP-55, base58 to a
32-byte key).

## Licence

**Apache-2.0**, except where the kernel requires otherwise: the eBPF programs are **GPL-2.0-only**, because a BPF program that calls a `gpl_only` helper must declare a GPL licence and the kernel verifier enforces it at load time. User-space code is not a derivative work of a BPF program, so the engine, the SDK and everything else are Apache-2.0. Documentation is CC-BY-4.0.

The full map and the reasoning are in [LICENSE.md](LICENSE.md); the decision is [ADR-06](docs/adr/06_open-source-licensing.md). Attribution obligations are in [NOTICE](NOTICE). The names *AISME* and *AI Sentinel* are not licensed (Apache-2.0 §6).

Contributions are welcome under the [DCO](CONTRIBUTING.md) — no CLA, contributors keep their copyright. To report a vulnerability, read [SECURITY.md](SECURITY.md) first; two adversary classes are documented non-goals.

If this work is useful in research, [CITATION.cff](CITATION.cff) has the citation.
