# 03 — Challenge-expansion: is the plan executable?

> **Method**: skill `challenge-ampliar`, second pass. Points are closed **one at a time, in order**, each with Challenge · Verification · Implementation · Tests · Documentation. After every point, a coherence pass over all previous points and over the repository. **Surgical edits only, never a rewrite.**
>
> **The question is different from report 02.** That one asked *is this correct?* and produced 209 findings. This one asks **is this executable?** — if an implementer opens F0 tomorrow and works straight through, where do they stop because something they need does not exist?
>
> **One continuous numbering across both reports**, so nothing collides and every cross-reference is unambiguous: points continue at **`P-35`** (report 02 closed `P-01`…`P-34`), defects at **`D-210`** (report 02 reached `D-209`), the unverified register at **`R1-19`**, the fallen register at **`R2-14`**. Created 2026-08-17.

## Baseline measurement (run before any point was written)

Read-only script over `docs/01_phase5_implementation_plan.md`. **Prediction written before running** → result:

| # | Check | Predicted | Measured | Verdict |
|---|---|---|---|---|
| A1 | Distinct `cargo xtask` subcommands cited | >20 | **77** | ✓, and far worse than predicted |
| A2 | Task rows with a thin column set | >0 | 43 (mostly 2-column tables by design) | ✓ but largely a false positive |
| A3 | Gate commands no task creates | >15 | **72 of 77** | ✓ |
| A4 | Named artefacts never created by a task | >5 | 11 named; 4 uncreated | ✓ |
| A5 | Placeholders (`TBD`/`TODO`) left in the plan | >0 | **1** | ✓, and the plan is cleaner than expected |
| A6 | Phases with a thin task list | 0 | 0 (299 task rows across 14 blocks) | ✓ |
| A7 | Fixtures and corpora named with no schema | >3 | 7 fixtures, 5 corpora; **1 of 5 corpora has a format** | ✓ |
| A8 | Protocol methods named but not specified | 6 | **6** | ✓ |
| A9 | `EventKind` variants enumerated | — | **0** | the most important type in the system has no value list |
| A10 | AISME-PL grammar present (BNF/EBNF) | — | **absent** — Annex B is examples | |

**What the numbers say.** The plan is correct, coherent and well-reasoned, and it is **not yet executable**. Its gates are 77 commands, of which 5 are assigned to anyone. Its central type has no variants. Its policy language has examples but no grammar. Its protocol has method names but no shapes. An implementer would stop at the first gate.

## Skeleton

| Point | Object | Status |
|---|---|---|
| P-35 | **The `xtask` surface** — 77 commands, 5 tasked | **closed** |
| P-36 | `EventKind`, `EventPayload`, `Verdict` — the wire enumeration | pending |
| P-37 | AISME-PL — a grammar, not examples | pending |
| P-38 | Control-plane protocol — method shapes and error model | pending |
| P-39 | Fixtures and corpora — formats, provenance, size | pending |
| P-40 | `F0.VER.01…18` — the R1 register needs its commands in the plan | pending |
| P-41 | ADR-04 and ADR-05 — owed by the plan, never written | pending |
| P-42 | The threat model (`F0.SEC.01`) — a named deliverable that does not exist | pending |
| P-43 | The ten seed memories — listed, never written | pending |
| P-44 | The reference workload — the CPU budget rests on a trace nobody recorded | pending |
| P-45 | Phase entry and exit artefacts — what each phase hands the next | pending |
| P-46 | Final sweep: is every gate command now creatable, and by whom? | pending |

Report 02's owner questions `Q-01`…`Q-10` are answered and closed; where this report cites one it writes `02:Q-nn`. Any new owner question here starts at **`Q-11`**.

---

## R1 — Unverified claims (continues from report 02)

| # | Claim | Where | Why unverified | What would verify it |
|---|---|---|---|---|

## R2 — Claims that fell (continues from report 02)

| # | Claim | Who | What toppled it | Lesson |
|---|---|---|---|---|

---

## Closed points

### P-35 — The `xtask` surface: 77 commands, 5 tasked

**1. Challenge.** Every gate in the plan is a `cargo xtask` invocation. That was a deliberate and good choice: it makes gates runnable on a laptop, which is what `I-27` requires now that there is no hosted CI. But the plan treats `xtask` as if it existed. Measured: **77 distinct subcommands cited across the gates, and one task creates five of them** (`F0.REPO.03`: `build-ebpf`, `dist`, `verify-budgets`, plus `verify-layering` and `vm up` added in review). The other 72 appear only inside gate blocks.

The consequence is not subtle. An implementer finishes F1, runs `GATE F1`, and the second line — `cargo xtask verify-layering` — either does not exist or, worse, exists as a stub that exits 0. **A gate that cannot run is indistinguishable from a gate that passes**, and the plan's entire quality argument rests on gates.

Could it be simpler? No — the commands are the right granularity. What is missing is an inventory and an owner per command.

**2. Verification.**

- **D-210** 72 of 77 subcommands have no creating task. Measured by extracting every `cargo xtask <cmd>` from the plan and diffing against the task rows that create one. *Damage today*: none, no code. *Open path*: every phase gate from F1 onward is unrunnable on arrival, and the phase either stalls or — the likely outcome — someone marks it done without running it, which `AGENTS.md` §2 forbids and no mechanism catches. *Bias*: **optimistic** — the plan presents 77 verifications it has not arranged to be able to perform → **urgent, and it blocks F1**. *Falsified by*: an inventory in which every cited command maps to a task.
- **D-211** No command taxonomy. The 77 split into families that behave differently — `verify-*` (fast, hermetic, no VM), `test-*` (needs fixtures, sometimes a VM), `bench-*` (needs quiet hardware and produces a number), `vm *` (provisioning), `gate --level` (a composite that runs the others), plus the `sdk`/`sentinel`/`win` sub-namespaces. Without the taxonomy, `gate --level commit` cannot know which commands are safe to run in ten minutes on a laptop. *Bias*: neutral; structural.
- **D-212** **A missing subcommand fails as "unknown command", which reads like a tooling problem rather than an unimplemented phase.** There is no mechanism making an un-built gate say so. *Bias*: **optimistic** — the failure is ambiguous exactly where clarity matters. *Falsified by*: running a future phase's gate and getting a message that names the phase which will implement it.
- **D-213** `cargo xtask verify-docs fails` appears in a release-blocker list (§4.12) and was counted as a subcommand by the extractor — it is prose, not a command. Harmless, but it shows the list has never been machine-read. The inventory below is machine-checkable precisely so this cannot recur.
- Verified sound: the choice of `xtask` over a shell script or a Makefile (one language, one toolchain, cross-platform, and it participates in the workspace's own lints); the `sdk`/`sentinel`/`win` sub-namespacing; `gate --level` as the composite the pre-commit hook calls (`F0.GATE.01`).

No question for the owner: this is an omission with one obvious shape.

**3. Implementation.**

A new **Annex H — the `xtask` command surface** will be added to the plan, after Annex G. It is a table of every command with four columns: **command · contract · created by · level**. "Contract" is one sentence stating what it does and what its exit code means. "Created by" is the task ID that must implement it. "Level" is which `gate --level` sets include it.

The command families and their rules:

| Family | Rule |
|---|---|
| `verify-*` | Hermetic: no VM, no network, no fixtures beyond the repository. Must run in seconds. Always in `commit`. Exit 0 = the property holds |
| `test-*` | May need fixtures, corpora or a VM. Declares its needs and **skips loudly** — never silently — when they are absent |
| `bench-*` | Produces a number, writes it to `docs/reports/`, and compares against `budgets.toml`. Never in `commit`: benchmarks on a busy laptop are noise |
| `vm *` | Provisioning and execution inside disposable VMs (`I-12`). Never touches the host kernel |
| `gate --level` | A composite. Runs the members of one level and reports each member's result, not a summary (`AGENTS.md` §3) |
| `sdk *`, `sentinel *`, `win *` | Sub-namespaces owned by F9, F10 and Annex F respectively |

**The mechanism that fixes D-212**, and the reason this is cheap: `F0.REPO.03` will create **every one of the 77 subcommands from the start**, each with its real argument parsing and a body that is exactly:

```
error: `cargo xtask test-taint` is not implemented yet.
       It is created by task F5.DT.01 (phase F5 — Correlation, taint and forensics).
       Annex H lists every command and the task that implements it.
exit 3
```

Exit code 3 means **"not yet implemented"**, distinct from 1 (the property does not hold) and 2 (the command could not run: missing VM, missing fixture). `gate --level` reports exit 3 as `PENDING <phase>` rather than as a failure, so a phase gate run early tells the implementer exactly which phases are still owed — instead of a shell error that looks like a broken toolchain.

This turns the 77 commands from a liability into a map: **the command surface becomes the plan's own progress report.** Running `cargo xtask gate --level pr` in week 5 prints, line by line, what is done and what phase owes the rest.

Concretely:
- `F0.REPO.03` is rewritten to: *"`xtask` orchestrator: the argument surface of **every** command in Annex H, each unimplemented body exiting 3 with its owning task; plus working implementations of `build-ebpf`, `dist`, `vm up`, `vm run`, `vm probe`, `verify-layering`, `verify-budgets`, `verify-docs` and `gate --level`."*
- Each of the other 68 commands gains its owning task in Annex H, drawn from the phase whose gate first uses it.
- `F0.GATE.08` (`verify-docs`) gains one check: **every `cargo xtask` string in the plan resolves to a row in Annex H, and every Annex H row names a task that exists.** That is what would have caught D-210 and what makes D-213 impossible.
- GATE F0 gains `cargo xtask gate --level commit` — which at F0 must pass with every member either green or `PENDING`.

**4. Tests.**
- **New** — `verify-docs`: plan ↔ Annex H ↔ task IDs, three-way. Fails on a cited command with no row, a row with no task, and a task ID that does not exist.
- **New** — `xtask` self-test: every subcommand in Annex H is reachable through argument parsing (`--help` lists it), and every unimplemented one exits 3 with a message naming its task. This is a table-driven test over the same inventory, so the inventory cannot drift from the binary.
- **New** — `gate --level commit` completes under ten minutes on the reference laptop with every member green or `PENDING`; a member exiting 1 fails the gate, a member exiting 3 does not.
- **Changed** — every phase gate in the plan is now a set of commands that provably exist from F0 onward.

**5. Documentation.** New Annex H in the plan; Part I index gains it; `F0.REPO.03` and `F0.GATE.08` rewritten; GATE F0 gains the composite line; `CLAUDE.md` "Build and verify" gains one sentence on exit code 3 so a session that hits it knows what it means.

**Closure.** Verified by extracting all 77 command strings and diffing against the tasks that create one: five matched. The finding is the largest actionability defect in the plan and it blocks F1, not some distant phase. The fix costs one F0 task and turns the gap into a progress map — running any gate early now names the phases still owed instead of failing as a broken toolchain. Nothing fell. Open: none.

