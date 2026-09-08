# CLAUDE.md — working instructions for this repository

You are working on **AISME**, a Ring-0 security engine for AI agents. This file is the entry point. Read it fully before doing anything.

## Read order (every session, in this order)

This list is canonical. `docs/ai/AGENTS.md` §1 repeats it verbatim and plan Part 0 rule 5 points to it; a gate checks the two path lists agree.

1. **This file** — rules and forbidden patterns.
2. `docs/ai/AGENTS.md` — session protocol and the **definition of done**.
3. `docs/ai/STATE.md` — what is actually done and what is next. Trust this over your assumptions.
4. `docs/ai/invariants.md` — constraints you may not violate.
5. `docs/01_phase5_implementation_plan.md` — the plan. Find your task by its `F<phase>.<block>.<task>` ID.
6. The relevant ADR in `docs/adr/` if your task touches an architectural decision.
7. Skim `docs/ai/memory/` — durable facts that were expensive to discover.

## Write order (end of every session, non-optional)

1. Update `docs/ai/STATE.md` — task statuses, what you learned, what is blocked.
2. Add a line to `docs/CHANGELOG.md` under `[Unreleased]` for every task you closed.
3. Append to `docs/ai/memory/` if you discovered something durable and non-obvious.
4. Write an ADR if you made or changed an architectural decision.
5. If the plan is now wrong, **fix the plan** — it is a living document.
6. Leave a handoff note in `docs/ai/handoff/` if the task is mid-flight.

## How to execute the plan

The plan is the roadmap. Execute it in this order and this way; nothing here is optional.

1. **Pick the next task from `docs/ai/STATE.md` → "Next up".** It names the phase and the task IDs in order. Within a phase, work the task table top to bottom unless a task's Notes column says otherwise. Check the phase's **Entry** row in plan §3.7.1 before starting; if an Entry condition is only available as a mock, say so in `STATE.md` under `## Mocked entries`.
2. **One task ID per unit of work.** Announce it. Do not start a second task before the first is done by the definition in `docs/ai/AGENTS.md` §2.
3. **Edit surgically. Never regenerate a file.** Change only what the task requires; keep every existing comment and its reasoning; if your change makes a comment false, rewrite that comment and say so in the commit. A rewrite silently loses what nobody is looking at. If you believe a rewrite is genuinely needed, ask the owner and explain why.
4. **One commit per task**, subject `<area>(<task-id>): <what changed>`, body stating what was verified and how. Commit only when the task's own checks pass. **Push every commit immediately** — the owner has asked for this as a standing rule, and a commit that never leaves this machine is an outage waiting for a disk (`docs/ai/AGENTS.md` §2-bis).
5. **Predict before you measure.** Any command that produces a number (`bench-*`, `verify-budgets`, the §F0.4 backlog) gets its expected outcome written down first — in the commit body or in `STATE.md` — and then the measurement.
6. **A phase closes only on its gate.** Run the phase's `GATE F<n>` block and paste its output. `PASS` and `PENDING <phase>` are acceptable; `FAIL` is not; `SKIP` needs a reason. Exit code 3 means *not implemented in any phase yet* and names the task that will implement it — that is a map, not an error.
7. **Nothing enters the plan or the docs unverified.** A claim about a kernel, a platform or a library that you cannot show with a command or a citation goes into §F0.4 as a verification row, not into prose.
8. **When the plan is wrong, fix the plan** — surgically, in the same commit, citing the task. When an `H-xx` finding or an invariant is wrong, write an ADR; do not implement around it.
9. **When blocked**, write the blocker into `STATE.md` with what would unblock it, then stop. Do not mark a task done that is not.
10. **Report what happened, not a summary of it.** Gate output, test output, the number you measured. A failed step is reported as failed.

## The single most important rule

> **The implementation plan contains 19 findings `H-01` … `H-19` in Part II. Eighteen record a design from the original research that was analysed and rejected, cut, corrected or deferred, with the reasoning; `H-19` adds a requirement the research did not cover.**
>
> If you are about to implement something that appears in `docs/research/` but contradicts an `H-xx` finding, **the finding wins.** Do not "restore" the original design believing you are fixing an omission. If you genuinely think a finding is wrong, write an ADR arguing it — do not silently implement around it.

The most commonly re-introduced mistakes, all forbidden:

| Do not | Because | Finding |
|---|---|---|
| Make an eBPF program block waiting for user space (FUSE-RPC, sleepable RPC tricks) | Deadlocks the kernel, no timeout, misses the SLA | `H-01` |
| Put DuckDB in `aisme-agentd` | Breaks the 50 MB invariant on its own | `H-03` |
| Use JSON anywhere on the hot path | Allocation and CPU cost incompatible with both budgets | `H-04` |
| Use `bpf_probe_write_user` to hide from the monitored process | Makes the product a rootkit; kills the compliance story | `H-05` |
| Patch, hook or otherwise modify the observed process, including defeating certificate pinning | Introduces a real vulnerability; also redundant | `H-06` |
| Put the Observer LLM in a blocking decision path, or let it authorize anything | Non-deterministic, network-dependent, prompt-injectable | `H-11`, `H-12` |
| Send high-volume telemetry through `FltSendMessage` | Thread-pool exhaustion; freezes the machine under build load | `H-08` |
| Map a whole session to one OTel `trace_id` | Unbounded traces; backends drop them | `H-09` |
| Write kernel-mode Rust for the Windows driver | Not viable for MVP certification | `H-14` |

## Architecture rules (Plan §3.1–3.2)

Five layers, **strictly downward dependencies**. This is what lets one engine serve Linux, WSL2, Android, iOS and the SDK.

```
L4 EDGES     cli · otel · relay · ui · mobile shells
L3 ENGINES   agentd (hot, 50 MB) · forensicd (cold)
L2 ADAPTERS  aisme-linux · sentinel-core · aisme-sdkhost   ← platform cfg lives here (plus the L3 composition root)
L1 CORE      aisme-core (ontology, traits, policy IR, taint) · aisme-correlate (causal graph)
L0 WIRE      aisme-ebpf-common — no_std, zero deps, layout-stable
```

| Rule | |
|---|---|
| **`aisme-core` has no I/O, no async runtime, no `cfg(target_os)`, no platform crate.** | The moment it learns about a platform, mobile reuse dies. Enforced by `cargo xtask verify-layering`. |
| No layer depends upward; no sibling dependency inside L2. | |
| No platform-specific type in `aisme-core`'s public API. | This is what keeps `ADR-02` reversible. |
| `agentd` depends on adapters **only through L1 traits**. | Enables `MockSensor` for the whole test suite. |
| The composition root is `aisme-agentd::platform` — the **only** module that names concrete adapters or uses `cfg(target_os)`. | A rule with no legal home is not a rule. |
| `unsafe` is forbidden in `aisme-core` and in the **product** edges of L4 (`cli`, `otel`, `relay`, `clientcore`, the mobile shells); permitted in L0 (layout), L2 (platform FFI) and the L3 runtimes (`mmap` for ring buffer and WAL), always with a safety comment. `xtask` is L4 and is build tooling, not shipped: its one `unsafe impl GlobalAlloc` **is** how the zero-allocation invariant is measured (`F1.RT.03`), and there is no safe way to write a global allocator. | `agentd` cannot map its own ring buffer without it. |

**The system has three interfaces, not fifteen subsystems:** `Sensor`, `Enforcer`, `Adjudicator`. Five sensing mechanisms and five prompt-delivery mechanisms are *implementations*, not subsystems. If you find yourself writing a parallel code path for a platform, you are probably missing a trait implementation.

**After GATE F1 the L1 traits are frozen.** Changing one requires an ADR — five tracks code against them in parallel.

**F2 is a walking skeleton.** Its out-of-scope list is as binding as its task list. Do not add features to it.

## Invariants you must not break

Full list in `docs/ai/invariants.md`. The ones that fail the gate:

- `aisme-agentd` RSS **< 50 MB**; aggregate CPU **< 3%**; T0 p99 **< 15 µs** — canonical values in `budgets.toml`, checked by a gate.
- AISME **never modifies an observed process**. There is a test (`T4.5.06`) that proves this; it must keep passing.
- **No kernel-touching test runs on a host OS.** Ever. Snapshot VMs only.
- The Observer LLM's output can only **raise** severity, never authorize.
- A false positive is as serious as a missed detection. The benign corpus gate tolerates **zero** blocks.
- **Suppression silences notification, never recording or enforcement** (`I-26`).
- **Zero hosted-CI cost** (`I-27`), the project's hardest rule: every gate runs locally and **the repository contains no GitHub workflow or action whatsoever**. Not one with safe triggers, not a manually dispatched one. Additional consumption is zero. A hosted run, if ever needed, is announced first, one-off, verified, and its file removed again.

## Conventions

- **All code, comments, identifiers and documentation in English.** Conversation with the project owner is in Spanish.
- Product names, exactly: `AISME` (system / workstation engine), `AI Sentinel` (Android + iOS app), `AI Sentinel SDK` (embeddable library). Never "AISME Sentinel".
- Task IDs are stable and append-only. A dead task becomes `DEPRECATED`; it is never deleted or renumbered.
- Markers: `[MVP]` required · `[POST]` deferred, do not implement · `[CUT]` rejected, forbidden · `[RISK]` external blocker.

## Working style

- **Finish tasks, including their gate.** A phase is not done because the code runs; it is done when its `GATE F<n>` commands pass. Report gate output, not a summary of it.
- **Prefer the boring, testable mechanism.** This is a security product; cleverness that cannot be tested is a liability. The plan repeatedly chooses supported OS primitives over impressive hacks — follow that instinct.
- **When you hit a platform limit, document it and degrade explicitly.** Never leave undefined behaviour, and never let the product imply a capability it does not have on the current device.
- If a decision is genuinely ambiguous and the answer changes the work materially, ask. Otherwise pick the sensible default, state it, and continue.

## Build and verify

Phase `F0` populates the workspace. The gates, all local:

```bash
cargo xtask gate --level commit     # what the pre-commit hook runs, < 10 min
cargo xtask gate --level pr         # run before merging a branch
cargo xtask verify-budgets          # resource invariants
cargo xtask verify-layering         # §3.1 dependency direction
cargo xtask verify-docs             # cross-document consistency
cargo xtask test-kernels            # eBPF verifier across the kernel matrix
cargo xtask test-benign             # false-positive gate
```

**Every gate runs locally.** There is no hosted CI and no workflow file at all (`I-27`); `verify-docs` fails if one appears, whatever its triggers. Never run kernel tests outside a disposable VM (`cargo xtask vm up <name>`).

Every `cargo xtask` command in plan Annex H exists from F0. One whose phase has not arrived exits **3** and names the task that implements it; `gate --level` reports that as `PENDING`, not as a failure.
