# AGENTS.md — working contract for development LLMs

This is the operational protocol. `CLAUDE.md` at the repository root is the short version and is loaded automatically; this file is the detail.

## 1. Session protocol

### On start

The canonical list lives in `CLAUDE.md`; it is repeated here verbatim and a gate checks the two agree.

```
0. cargo xtask doctor           ← the host, measured rather than read
1. CLAUDE.md                    ← rules and forbidden patterns
2. docs/ai/AGENTS.md            ← you are here; the definition of done is §2 below
3. docs/ai/STATE.md             ← what is actually done; trust it over assumptions
4. docs/ai/invariants.md        ← what you may not break
5. docs/01_phase5_implementation_plan.md  ← find your task by ID
6. docs/adr/ (relevant only)    ← why things are the way they are
7. docs/ai/memory/ (skim)       ← durable non-obvious facts
```

Step 0 is a measurement, not a gate. A `FAIL` names every missing prerequisite and what it
unblocks: documentation and host-only Rust work may proceed on one; anything that builds the eBPF
objects, benchmarks, or boots a VM may not.

### During
- Work one task ID at a time. Announce which one.
- If you discover the plan is wrong, say so and fix the plan. It is a living document, not scripture — except for Part II findings, which need an ADR.
- If you are blocked, write the blocker into `STATE.md` before stopping, with enough detail that someone else could unblock it.

### On finish (non-optional)
```
1. Update docs/ai/STATE.md      ← statuses, learnings, blockers, and the header's own date
2. Add a line to docs/CHANGELOG.md for every task closed
3. Append docs/ai/memory/*.md   ← only durable, non-obvious discoveries
4. Write an ADR if you decided something architectural
5. Update the plan if reality diverged from it
6. Leave a handoff note in docs/ai/handoff/ if the task is mid-flight
```

The execution directives — how to pick a task, edit, commit, measure and close a phase — are in `CLAUDE.md` §"How to execute the plan". They are not repeated here.

## 2. Definition of done

A task is done when **all** of these hold. Not seven out of eight.

- [ ] Code compiles clean with `clippy -D warnings`.
- [ ] Tests exist and pass, including at least one negative/adversarial case.
- [ ] Relevant invariants (`docs/ai/invariants.md`) verified, not assumed.
- [ ] Budget gate passes if the task touches `agentd`, `forensicd`, the BPF programs, or a mobile sensor (`sentinel-core` or a platform shim).
- [ ] **If the task touches an architectural boundary** (ADR-01 decision 3): the relevant ADR was re-read and is still true, or a superseding ADR was written.
- [ ] **If the phase started against a mocked entry condition** (§3.7.1), the gate output says which.
- [ ] The phase gate command output is **shown**, not summarized.
- [ ] `STATE.md` updated.

A phase is done when its `GATE F<n>` block passes in full. Code that works but whose gate has not been run is **not done**.

## 3. Reporting rules

- **Show gate output.** "Tests pass" is not a report; the command and its output is.
- **If something failed, say so with the output.** A skipped step is reported as skipped.
- **Never claim a measurement you did not take.** Budget numbers come from `cargo xtask verify-budgets`, not from estimation.
- **Do not report completion for partial work.** Report what is done, what is not, and why.

## 2-bis. Push every commit

**A commit that is not pushed does not exist.** Push immediately after
committing, every time, without being asked. The owner's machine is the only
place this work lives until it reaches `origin`, and a local-only commit is an
outage waiting for a disk.

This is not a preference about workflow: `CLAUDE.md` §"How to execute the plan"
says "do not push unless asked", and the owner has asked, standing, for every
commit. Where the two disagree, this line wins.

## 3-bis. Verification rules

Each of these was paid for by a defect that reached a commit or a VM. They are
here rather than in a habit, because a habit is not a rule.

- **Verify the effect of an edit, never the report of the edit.** A script that
  prints `ok` has proved that it ran, not that it changed anything: an edit
  whose anchor drifted matches nothing and reports success. Confirm with
  `grep`, a compile, or a test — and read the count, not the exit code.
- **Measure exit codes with no pipe in the way.** `cmd | tail` makes `$?` the
  status of `tail`, so a gate that failed reports 0, and a truncating pipe
  silently discards the number being reported. Use `cmd > file 2>&1; echo $?`
  or `PIPESTATUS`.
- **A check that produces no result must say so.** An empty answer reads as a
  clean one. A probe that parses nothing prints `NONE FOUND`; a comparison the
  script can make, the script makes — never leave the reader to compare by eye.
- **See a guard fail before trusting it.** Break the thing it guards on purpose
  and watch it name the failure. A guard only ever exercised by the happy path
  is a guard nobody has seen work, and three in this repository were reporting
  compliance they had never checked.
- **Run it, do not read it.** The defects that reading missed and running found:
  a guard that announced a refusal and then ran the command, a loop that spun a
  core flat out, a `cp` glob that skipped two binaries, an error message that
  blamed a cause it had not measured. Reading confirms intent; running confirms
  behaviour.
- **Never state a cause you did not establish.** An error that reports the
  likely reason instead of the observed one sends the next reader to the wrong
  place. Report what the failing component said, and add a cause only where the
  evidence names it.
- **Scope a search before concluding an absence.** A `grep` over the wrong
  subtree prints "does not exist" for something that does. An absence is a
  finding only when the search covered where the thing would be.
- **Never rewrite a file by line range.** Splicing by index deleted 716 lines
  of a working file in this repository. Edit by anchor, and confirm the anchor
  matched exactly once.
- **A counter nobody reads may as well not exist.** Wire every measurement to
  something that reports it — a health state, a gate line, a summary — in the
  same change that adds it.

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
| Add a GitHub workflow or action — any file, any trigger, including `workflow_dispatch` | `I-27` — this project incurs zero hosted-CI cost, permanently; `verify-docs` fails on existence, not on triggers |
| Let a suppression rule remove evidence or weaken enforcement | `I-26` — suppression is notification-only |
| Regenerate a file instead of editing it | A rewrite silently loses the reasoning nobody is looking at; ask the owner if one is genuinely needed |
| **Leave a commit unpushed** | §2-bis — a commit that is not pushed does not exist. This row said the opposite of §2-bis for two phases, and a session that read the table instead of the section asked for permission it already had |

## 5. Memory discipline

`docs/ai/memory/` holds **durable, non-obvious facts** — one file per fact, with the frontmatter defined in plan §7.4 (`name`, `description`, `type`). Write there when you learn something that:
- was expensive to discover (a platform limitation, a kernel behaviour, a toolchain quirk), **and**
- is not already recorded in the plan, the code, or an ADR, **and**
- will still be true and relevant in a month.

Do **not** write there: task status (that is `STATE.md`), architectural decisions (those are ADRs), or anything the code already says.

Files in `docs/ai/` are instruction files, referenced by fixed name from `CLAUDE.md`, and are **exempt** from the `NN_` numbering that applies to the rest of `docs/`. A challenge report (`docs/NN_*.md`) is a further kind: it holds *what is wrong and what the patch is*, its points are append-only, and it is a proposal until its patches are applied.

## 6. When to ask the human

Ask when the answer materially changes the work and you cannot resolve it from the plan, the code, or a sensible default:
- A trade-off between two invariants.
- A product decision with user-visible consequences.
- Anything involving money, legal exposure, or an external account (certificates, store submissions).

Do not ask for permission to do the work you were asked to do. Pick the sensible default, state it, continue.

## 7. Domain context you will need

**Latency tiers.** T0 = in-kernel, deterministic, <15 µs p99 (L3) / <20 µs (L2). T1 = user-space round trip, <1 ms. T2 = frozen process + human/LLM, seconds. Canonical values in `budgets.toml`. Know which tier you are working in; the wrong assumption produces the wrong design.

**The two-process split.** `agentd` is the hot path with the 50 MB budget; `forensicd` is the cold path with DuckDB, compression and the Observer. Never put cold-path work in `agentd`.

**Platform tiers.** Linux L3 (full enforce, needs BPF-LSM and a reboot), **L2** (no reboot: in-kernel file deny via Landlock, in-kernel network deny via cgroup connect hooks, escalation via `seccomp_unotify`), L2- (seccomp only, no Landlock), L1 (observe only). The MVP quality target is that **L2 is genuinely useful**, because most users will not reboot — and WSL2, the Windows strategy, is L2 by default.

**The mobile asymmetry.** Desktop can ask before the fact; mobile denies first and grants retroactively. That is a platform constraint, not a bug — see `docs/design/01_permission-model.md` §7.
