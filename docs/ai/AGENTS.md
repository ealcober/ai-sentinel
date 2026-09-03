# AGENTS.md — working contract for development LLMs

This is the operational protocol. `CLAUDE.md` at the repository root is the short version and is loaded automatically; this file is the detail.

## 1. Session protocol

### On start
```
1. CLAUDE.md                    ← rules and forbidden patterns
2. docs/ai/STATE.md             ← what is actually done; trust it over assumptions
3. docs/ai/invariants.md        ← what you may not break
4. docs/PHASE5_IMPLEMENTATION_PLAN.md  ← find your task by ID
5. docs/adr/ (relevant only)    ← why things are the way they are
6. docs/ai/memory/ (skim)       ← durable non-obvious facts
```

### During
- Work one task ID at a time. Announce which one.
- If you discover the plan is wrong, say so and fix the plan. It is a living document, not scripture — except for Part II findings, which need an ADR.
- If you are blocked, write the blocker into `STATE.md` before stopping, with enough detail that someone else could unblock it.

### On finish (non-optional)
```
1. Update docs/ai/STATE.md      ← statuses, learnings, blockers
2. Append docs/ai/memory/*.md   ← only durable, non-obvious discoveries
3. Write an ADR if you decided something architectural
4. Update the plan if reality diverged from it
5. Leave a handoff note in docs/ai/handoff/ if the task is mid-flight
```

## 2. Definition of done

A task is done when **all** of these hold. Not four out of five.

- [ ] Code compiles clean with `clippy -D warnings`.
- [ ] Tests exist and pass, including at least one negative/adversarial case.
- [ ] Relevant invariants (`docs/ai/invariants.md`) verified, not assumed.
- [ ] Budget gate passes if the task touches `agentd`, the driver, or a mobile sensor.
- [ ] The phase gate command output is **shown**, not summarized.
- [ ] `STATE.md` updated.

A phase is done when its `GATE F<n>` block passes in full. Code that works but whose gate has not been run is **not done**.

## 3. Reporting rules

- **Show gate output.** "Tests pass" is not a report; the command and its output is.
- **If something failed, say so with the output.** A skipped step is reported as skipped.
- **Never claim a measurement you did not take.** Budget numbers come from `cargo xtask verify-budgets`, not from estimation.
- **Do not report completion for partial work.** Report what is done, what is not, and why.

## 4. Forbidden actions

| Never | Why |
|---|---|
| Run a kernel test outside a disposable VM | Bricking a machine is expensive and demoralizing (`I-12`) |
| Implement something contradicting an `H-xx` finding without an ADR | That is how rejected designs get resurrected (`I-25`) |
| Add `serde_json` to `aisme-agentd` | Hot path (`I-21`) |
| Use `bpf_probe_write_user`, Frida, Detours, or any process-modifying technique | `I-01`, `I-02` |
| Loosen a budget to make a test pass | The budget is the product |
| Delete or renumber a task ID | `I-23` |
| Weaken the benign corpus gate to ship | `I-15` |
| Commit or push without being asked | Standard |

## 5. Memory discipline

`docs/ai/memory/` holds **durable, non-obvious facts** — one file per fact, with a short frontmatter block. Write there when you learn something that:
- was expensive to discover (a platform limitation, a kernel behaviour, a toolchain quirk), **and**
- is not already recorded in the plan, the code, or an ADR, **and**
- will still be true and relevant in a month.

Do **not** write there: task status (that is `STATE.md`), architectural decisions (those are ADRs), or anything the code already says.

## 6. When to ask the human

Ask when the answer materially changes the work and you cannot resolve it from the plan, the code, or a sensible default:
- A trade-off between two invariants.
- A product decision with user-visible consequences.
- Anything involving money, legal exposure, or an external account (certificates, store submissions).

Do not ask for permission to do the work you were asked to do. Pick the sensible default, state it, continue.

## 7. Domain context you will need

**Latency tiers.** T0 = in-kernel, deterministic, <15 µs p99. T1 = user-space round trip, <1 ms. T2 = frozen process + human/LLM, seconds. Know which tier you are working in; the wrong assumption produces the wrong design.

**The two-process split.** `agentd` is the hot path with the 50 MB budget; `forensicd` is the cold path with DuckDB, compression and the Observer. Never put cold-path work in `agentd`.

**Platform tiers.** Linux L3 (full enforce, needs BPF-LSM and a reboot), L2 (enforce via `seccomp_unotify`, no reboot), L1 (observe only). The MVP quality target is that **L2 is genuinely useful**, because most users will not reboot.

**The mobile asymmetry.** Desktop can ask before the fact; mobile denies first and grants retroactively. That is a platform constraint, not a bug — see `docs/design/permission-model.md` §7.
