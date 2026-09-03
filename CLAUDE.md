# CLAUDE.md — working instructions for this repository

You are working on **AISME**, a Ring-0 security engine for AI agents. This file is the entry point. Read it fully before doing anything.

## Read order (every session, in this order)

1. **This file.**
2. `docs/ai/STATE.md` — what is actually done and what is next. Trust this over your assumptions.
3. `docs/ai/invariants.md` — constraints you may not violate.
4. `docs/PHASE5_IMPLEMENTATION_PLAN.md` — the plan. Find your task by its `F<phase>.<block>.<task>` ID.
5. The relevant ADR in `docs/adr/` if your task touches an architectural decision.

## Write order (end of every session, non-optional)

1. Update `docs/ai/STATE.md` — task statuses, what you learned, what is blocked.
2. Append to `docs/ai/memory/` if you discovered something durable and non-obvious.
3. Write an ADR if you made or changed an architectural decision.
4. If the plan is now wrong, **fix the plan** — it is a living document.

## The single most important rule

> **The implementation plan contains 19 findings `H-01` … `H-19` in Part II. Each one records a design from the original research that was analysed and rejected or corrected, with the reasoning.**
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
L2 ADAPTERS  aisme-linux · sentinel-core · aisme-sdkhost   ← all cfg(target_os) lives here
L1 CORE      aisme-core — ontology, traits, policy IR, taint, correlation
L0 WIRE      aisme-ebpf-common — no_std, zero deps, layout-stable
```

| Rule | |
|---|---|
| **`aisme-core` has no I/O, no async runtime, no `cfg(target_os)`, no platform crate.** | The moment it learns about a platform, mobile reuse dies. Enforced by `cargo xtask verify-layering`. |
| No layer depends upward; no sibling dependency inside L2. | |
| No platform-specific type in `aisme-core`'s public API. | This is what made removing Windows cost an afternoon instead of a refactor. |
| `agentd` depends on adapters **only through L1 traits**. | Enables `MockSensor` for the whole test suite. |

**The system has three interfaces, not fifteen subsystems:** `Sensor`, `Enforcer`, `Adjudicator`. Five sensing mechanisms and five prompt-delivery mechanisms are *implementations*, not subsystems. If you find yourself writing a parallel code path for a platform, you are probably missing a trait implementation.

**After GATE F1 the L1 traits are frozen.** Changing one requires an ADR — four tracks code against them in parallel.

**F2 is a walking skeleton.** Its out-of-scope list is as binding as its task list. Do not add features to it.

## Invariants you must not break

Full list in `docs/ai/invariants.md`. The ones that fail CI:

- `aisme-agentd` RSS **< 50 MB**; aggregate CPU **< 3%**; T0 p99 **< 15 µs**.
- AISME **never modifies an observed process**. There is a test (`T4.5.06`) that proves this; it must keep passing.
- **No kernel-touching test runs on a host OS.** Ever. Snapshot VMs only.
- The Observer LLM's output can only **raise** severity, never authorize.
- A false positive is as serious as a missed detection. The benign corpus gate tolerates **zero** blocks.

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

The workspace is not yet populated — phase `F0` creates it. Once it exists:

```bash
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo xtask verify-budgets          # resource invariants
cargo xtask test-kernels            # eBPF verifier across the kernel matrix
cargo xtask test-benign             # false-positive gate
```

Never run kernel tests outside a disposable VM (`cargo xtask vm up <name>`).
