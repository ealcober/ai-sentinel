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
| P-36 | `EventKind`, `EventPayload`, `Verdict` — the wire enumeration | **closed** |
| P-37 | AISME-PL — a grammar, not examples | **closed** |
| P-38 | Control-plane protocol — method shapes and error model | **closed** |
| P-39 | Fixtures and corpora — formats, provenance, size | **closed** |
| P-40 | `F0.VER.01…18` — the R1 register needs its commands in the plan | **closed** |
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
| R1-19 | A BPF program can range-check `EventKind` in one comparison, and the verifier accepts it | P-36 D-215 | Not compiled | Load a program doing `kind >= 0x4000 && kind < 0x5000` on the matrix kernels (`F0.VM.02`) |
| R1-20 | Landlock ABI 4 can express `port_in` for TCP bind/connect, and nothing else network-related | P-37 §B.9 | Read from the ABI summary, not tested | `landlock_create_ruleset` with a net rule on a 6.7+ kernel |

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

---

### P-36 — `EventKind`: the most important type has no values

**1. Challenge.** F1 calls `RawEvent` "the single most important type in the system" and specifies its layout to the byte. Its `kind` field is `EventKind`, described as "u16, exhaustive enum, append-only and versioned". Measured: **zero variants are enumerated anywhere in the plan.** F1 cannot begin; F3's ten probes have nothing to emit; F4's four capture tiers have nothing to tag; F5's detectors have nothing to match on. Every downstream phase would invent its own values and they would not agree.

The layout rule is right and the append-only rule is right. What is missing is the list — and, more importantly, a *structure* for the list that survives ten phases of additions without renumbering.

**2. Verification.**

- **D-214** `EventKind` has no variants. *Damage today*: none. *Open path*: F1 blocks, or four phases each invent a numbering and the wire format forks. *Bias*: neutral, but **it is on F1's critical path** → urgent. *Falsified by*: a normative enumeration.
- **D-215** Append-only without reserved ranges is a trap. If variants are numbered sequentially as they are thought of, the first file-related addition after a network variant sits between two network variants forever, and any grouping logic in the kernel (`kind >= X && kind < Y`) becomes impossible. BPF programs *want* range checks: they are one comparison instead of a lookup. *Bias*: neutral; a design defect that only shows up in phase F5. *Falsified by*: the enumeration reserving a block per category.
- **D-216** `EventPayload` is "a union, fixed size 256 B" with no variants either, and no rule tying a payload variant to its `kind`. A union whose discriminant lives in a different field is exactly the shape that produces a misread when the two disagree across a version skew. *Bias*: **optimistic** — the wire-version check catches a *different* driver version, not a payload/kind mismatch within one version. *Falsified by*: a compile-time assertion pairing each `kind` with its payload variant.
- Verified sound: 320-byte fixed layout, `u16` discriminant (65 536 values is ample; a `u8` would not have been), the append-only rule and its wire-version gate (`F1.EV.02`).

No question for the owner.

**3. Implementation.** A new **§F1.1.1 Event taxonomy (normative)** in the plan, and the same table as Annex A's companion, stating:

**Ranges are reserved per category and never reordered.** A new variant takes the next free value *inside its range*. A category that fills its range gets a second range, never a renumbering.

```rust
#[repr(u16)]
#[non_exhaustive]
pub enum EventKind {
    // 0x0000–0x0FFF  META — lifecycle and self-observability
    SessionStart = 0x0001, SessionEnd = 0x0002, CapabilityChange = 0x0003,
    CoverageGap  = 0x0004,      // I-17: observation lapsed, recorded as a gap
    DropNotice   = 0x0005,      // ring buffer overflow, with the count
    PolicyGeneration = 0x0006,  // a new compiled policy became active
    DegradedEnter = 0x0007, DegradedLeave = 0x0008,

    // 0x1000–0x1FFF  PROCESS
    ProcFork = 0x1001, ProcExec = 0x1002, ProcExit = 0x1003,
    ProcSetuid = 0x1004, ProcCgroupMove = 0x1005,

    // 0x2000–0x2FFF  FILE
    FileOpen = 0x2001, FileWrite = 0x2002, FileUnlink = 0x2003,
    FileRename = 0x2004, FileTruncate = 0x2005, FileChmod = 0x2006,
    FileLink = 0x2007, FileMount = 0x2008,

    // 0x3000–0x3FFF  NETWORK
    SockConnect = 0x3001, SockAccept = 0x3002, SockSend = 0x3003,
    SockClose = 0x3004, DnsQuery = 0x3005,
    FlowOpen = 0x3006, FlowClose = 0x3007,   // mobile tunnel (F10)

    // 0x4000–0x4FFF  EXECUTION HAZARD — the never-promptable classes
    MemfdCreate = 0x4001, ExecveAt = 0x4002, PreloadEnv = 0x4003,

    // 0x5000–0x5FFF  INTROSPECTION — anti-analysis signals (H-05)
    PtraceAttach = 0x5001, ProcessVmRw = 0x5002, MapsRead = 0x5003,
    BpfCall = 0x5004, PerfEventOpen = 0x5005, SelfObservation = 0x5006,

    // 0x6000–0x6FFF  SEMANTIC — the intent plane (F4, F9)
    Prompt = 0x6001, ChainOfThought = 0x6002, ToolCall = 0x6003,
    ToolResult = 0x6004, ToolManifest = 0x6005, InferenceTurn = 0x6006,

    // 0x7000–0x7FFF  DECISION — enforcement and the permission model
    VerdictIssued = 0x7001, EscalationRaised = 0x7002, EscalationResolved = 0x7003,
    GrantCreated = 0x7004, GrantExpired = 0x7005, GrantRevoked = 0x7006,
    SuppressionHit = 0x7007, ScopeWidenAttempt = 0x7008,

    // 0x8000–0x8FFF  DETECTION — Annex G
    FindingRaised = 0x8001, SessionRiskChanged = 0x8002,

    // 0x9000–0x9FFF  FORENSIC
    MerkleBlockClosed = 0x9001, RootAnchored = 0x9002,
}
```

Three rules travel with it:

1. **Range checks are the kernel's grouping primitive.** A BPF program asking "is this an execution hazard?" is `kind >= 0x4000 && kind < 0x5000`, one comparison. This is why the ranges exist and why they may never be reordered.
2. **`EventPayload` is a union whose variant is determined by `kind`'s range**, one payload struct per range, each ≤ 256 B: `MetaPayload`, `ProcPayload`, `FilePayload`, `NetPayload`, `HazardPayload`, `IntrospectPayload`, `SemanticPayload`, `DecisionPayload`, `DetectionPayload`, `ForensicPayload`. A compile-time table maps range → payload type, and `F1.EV.03` asserts every variant's range has a payload and every payload fits (D-216).
3. **`#[non_exhaustive]`** so a consumer compiled against an older wire version cannot pattern-match exhaustively and silently miss a new kind — it must have a `_ => ` arm, which becomes the honest "unknown kind, recorded, not interpreted" path.

Task changes: `F1.EV.01` gains "the §F1.1.1 taxonomy in full"; `F1.EV.03` gains the range↔payload assertion and a test that every declared variant is reachable from at least one producer (a probe, a capture tier, the SDK or the engine) — an unproduced variant is dead weight or a missing producer, and either is worth knowing.

**4. Tests.** **New** — `F1.EV.03` extended: `size_of::<RawEvent>() == 320`; every variant's discriminant inside its declared range; range→payload mapping total; every variant produced by at least one producer in the test suite. **New** — wire-skew test: an event with a `kind` from an unknown range is recorded with its bytes and marked `uninterpreted`, never dropped and never guessed (`I-17`).

**5. Documentation.** Plan §F1.1.1 (new); Annex A gains a pointer from each node type to the `EventKind` values that create it; Annex E gains "Event range".

**Closure.** Verified by grep: zero variants existed. The enumeration is now normative and structured so that ten phases of additions cannot force a renumbering — which is what "append-only" needs in order to mean anything. The range design also buys the kernel a one-comparison category test it would otherwise do with a map lookup. Nothing fell. Open: none.

---

### P-37 — AISME-PL: a grammar, not examples

**1. Challenge.** `F1.PL.01` says "AISME-PL grammar and parser per **Annex B**". Annex B contains four TOML examples and eight compiler requirements. Measured: **no grammar** — no BNF, no EBNF, no field inventory. The examples are good and they are not a specification: they show `match = { path_under = … }` and `match = { taint_any = …, dest_not_in = …, not_declassified = true }` without ever saying what the complete set of match keys is, which combine, or what a compiler must reject.

This matters more than it looks. The policy language is compiled to **five backends** (`F1.PL.03`), two of which — Landlock and cgroup hooks — cannot express most verdicts. Without a grammar, `F1.PL.08` ("a backend rejects what it cannot express") has nothing to check a rule against.

**2. Verification.**

- **D-217** No grammar. *Damage today*: none. *Open path*: F1.PL blocks; or a parser is written from four examples and the first policy that uses an unanticipated combination either silently misparses or is rejected for the wrong reason. *Bias*: neutral, **on F1's critical path** → urgent. *Falsified by*: an EBNF and a match-key inventory.
- **D-218** No match-key inventory, so **no way to know which keys a backend supports**. Landlock matches paths and access rights and nothing else — it cannot see taint, cannot see a destination, cannot escalate. `F1.PL.08` requires a compile-time rejection with a tier-specific message, and that requires a per-backend capability table. *Bias*: **optimistic** — the plan asserts a check it gives no basis to perform. *Falsified by*: the table below.
- **D-219** Conflict resolution is unspecified. `B.1` forbids "allow/deny conflicts on the same match", but two rules rarely match *identically* — they overlap. Which wins when `workspace-free` (allow, `path_under ${workspace}`) and `credentials-ask` (escalate, `path_glob **/.env`) both match `${workspace}/.env`? Without a stated rule this is undefined behaviour in the security core. *Bias*: **optimistic** → urgent. *Falsified by*: a precedence rule and a test that the example set resolves deterministically.
- Verified sound: TOML as the surface syntax (no new parser, diffable, familiar); the eight compiler requirements `B.1`–`B.8`; determinism (`B.3`) and atomic publication (`B.4`).

**Question for the owner (Q-11)** — it changes the language's shape and a user's mental model: on `D-219`, should rule precedence be **most-specific-wins** (longest matching path prefix, like a routing table — familiar, but "specific" is ill-defined across different key types) or **strictest-verdict-wins** (deny > escalate > warn > allow, order-independent, trivially explainable, and it fails safe)? The implementation below assumes **strictest-wins**, because in a security product the surprising outcome should be the safe one, and because it makes rule files order-independent and therefore mergeable.

**3. Implementation.** Annex B gains **§B.0 Grammar** and **§B.9 Backend capability matrix**, before the existing examples.

```ebnf
policy        = { session_defaults | rule | suppression | profile } ;
rule          = "[[rule]]" , id , group , match , verdict ,
                { taint | severity_floor | promptable | suppressible
                | audit | event | escalate_if } ;
suppression   = "[[suppression]]" , match , scope , ttl_days , origin , [ report ] ;

id            = "id" , "=" , string ;                  (* unique; the diff key *)
group         = "group" , "=" , GROUP ;
verdict       = "verdict" , "=" , ( "allow" | "warn" | "escalate" | "deny" ) ;
match         = "match" , "=" , "{" , match_key , { "," , match_key } , "}" ;
match_key     = path_under | path_glob | path_class | exec_class | exec_path
              | dest_in | dest_not_in | port_in | proto
              | taint_any | taint_all | not_declassified
              | tool_name | origin | instruction_bearing
              | scope_rel | age_lt | first_of_kind ;
GROUP         = "FILES_OUTSIDE_WORKSPACE" | "SYSTEM_CONFIG" | "CREDENTIALS"
              | "NETWORK_EGRESS" | "EXECUTE" | "FILELESS_EXECUTE"
              | "PERSISTENCE" | "PERSISTENCE_CONFIG" | "PACKAGE_INSTALL"
              | "SELF_PROTECTION" | "DEVICE" ;
```

Keys inside one `match` are **AND**; a list value is **OR** within that key. There is no `not`, no nesting and no arithmetic: the language is deliberately not Turing-complete, because it compiles into a BPF program with a verifier loop budget.

**§B.9 Backend capability matrix** — which keys and verdicts each backend can express. This is the table `F1.PL.08` checks against:

| | BPF trie (L3) | Landlock (L2 file) | cgroup connect (L2 net) | Sentinel (mobile) | Windows `[POST]` |
|---|---|---|---|---|---|
| `path_under`, `path_glob`, `path_class` | ✅ | ✅ | ❌ | ⚠️ SDK-reported | ✅ |
| `dest_in`, `dest_not_in`, `port_in`, `proto` | ✅ | ⚠️ ports only, ABI ≥ 4 | ✅ | ✅ | ✅ |
| `exec_class`, `exec_path` | ✅ | ✅ (exec right) | ❌ | ❌ | ✅ |
| `taint_*`, `not_declassified` | ✅ | ❌ | ✅ via the session map | ✅ | ✅ |
| `tool_name`, `origin`, `instruction_bearing` | ❌ user-space only | ❌ | ❌ | ✅ SDK | ❌ |
| verdict `allow` / `deny` | ✅ | ✅ | ✅ | ✅ | ✅ |
| verdict `escalate` | ✅ | **❌** | **❌** | ✅ | ✅ |
| verdict `warn` | ✅ | ⚠️ allow + notify from user space | ⚠️ same | ✅ | ✅ |

**A rule a backend cannot express is a compile-time error naming the backend, the key or verdict at fault, and the tier the rule will therefore not cover** — never a silent drop (`B.8`, general rule 9). The common case is benign and must read clearly: an `escalate` rule is compiled into the BPF trie at L3 and, at L2, into a Landlock *deny* plus a user-space escalation path — the compiler states that substitution rather than performing it silently.

**§B.10 Precedence** (assuming the owner confirms Q-11): **strictest verdict wins**, `deny > escalate > warn > allow`, evaluated over every rule whose match succeeds. Order in the file is irrelevant, so policy files merge without conflict. Two rules with the same verdict and overlapping matches are not a conflict. `B.1`'s "no allow/deny conflict" is restated as: **a rule that can never be the strictest for any input is unreachable and fails to compile** — that is the real defect the requirement was reaching for.

Task changes: `F1.PL.01` gains "per Annex B §B.0"; `F1.PL.02` gains the unreachability check as defined by §B.10; `F1.PL.08` gains "against the §B.9 matrix".

**4. Tests.** **New** — grammar conformance: a corpus of accepted and rejected policy files, one rejection per grammar rule, each asserting the *message*, not only the failure. **New** — precedence: the four Annex B examples plus a deliberately overlapping pair resolve to the documented verdict, and the resolution is invariant under file order (shuffle the rules, same result). **New** — backend rejection: an `escalate` rule targeting a Landlock-only tier produces the substitution notice; a `taint_any` rule targeting Landlock is a compile error naming the key. **Changed** — `test-policy-compiler` covers all three.

**5. Documentation.** Annex B §B.0, §B.9, §B.10; `B.1` restated; `01_permission-model.md` §4.1 gains a pointer to §B.9 (why `warn` behaves differently at L2); Annex E gains "Backend capability".

**Closure.** Verified by searching the plan for any grammar production: none. The three findings compound — no grammar means no key inventory, no key inventory means the backend-rejection rule has nothing to check, and no precedence rule means the security core has undefined behaviour on overlapping rules, which the four examples already exhibit (`${workspace}/.env` matches both `workspace-free` and `credentials-ask`). One owner question is open (Q-11); the implementation proceeds on strictest-wins.

---

### P-38 — The control-plane protocol: six method names, no shapes

**1. Challenge.** `F8.API.01` names six methods — `subscribe`, `getSession`, `getGraph`, `respondEscalation`, `setPolicy`, `pairDevice` — and says "**this is the same protocol F11 consumes remotely**, defined once". That sentence is the load-bearing one: the desktop UI, the CLI, the mobile app and the relay all speak it. `F8.API.02` says the schema lives in `aisme-proto` with TS codegen. Measured: **no method signature, no error model, no versioning behaviour, no authorization rule per method.**

Two phases (F8a, F11) and two languages (Rust, TypeScript) are supposed to code against it in parallel. They cannot.

**2. Verification.**

- **D-220** No method shapes. *Damage today*: none. *Open path*: F8a and F11 run in parallel by design (§3.7) and would each invent the protocol. *Bias*: neutral; **it blocks the parallelism the schedule depends on** → urgent. *Falsified by*: signatures in `aisme-proto`.
- **D-221** **No per-method authorization.** The protocol carries `respondEscalation` and `setPolicy`, and `F7.PS.08` requires that policy mutation be accepted **only from a human principal**, never from a session lineage. The transport authenticates by peer identity (`F1.IPC.01`, `SO_PEERCRED`), but nothing says which methods require what. A remote caller over the relay is not a local peer, and `I-06` caps what it may do. *Bias*: **optimistic** — the authorization rule exists in F7 and has no expression in the protocol that carries the call → urgent.
- **D-222** No error model. JSON-RPC has an error object; nothing says which failures are protocol errors, which are domain results, and which must never be distinguishable. That last class matters: **a failed `pairDevice` must not reveal whether the pairing secret was wrong or expired**, or the protocol leaks an oracle. *Bias*: **optimistic** (a security-relevant omission). *Falsified by*: an error table with a stated indistinguishability rule.
- **D-223** `subscribe` is the only streaming method and its backpressure is unspecified. The UI subscribing to a session under `npm ci` receives events faster than it can render. Unbounded buffering in `agentd` violates §3.4's "bounded everything"; dropping silently violates `I-17`. *Bias*: **optimistic** → the rule must be stated: **the server coalesces and reports the coalescing**, never silently drops.
- Verified sound: JSON-RPC 2.0 over UDS (not on the hot path, so `I-21` is satisfied); one schema with TS codegen (`F8.API.02`); the same protocol local and remote, which is what makes the relay blind (`I-07`) — it forwards opaque frames.

No question for the owner.

**3. Implementation.** A new **Annex I — control-plane protocol (normative)** with four sections.

**I.1 Methods.** Each row: name · direction · params · result · authorization · idempotent.

| Method | Params | Result | Auth | Idempotent |
|---|---|---|---|---|
| `getCapabilities` | — | tier, `key_hw`, coverage boundary, versions | any authenticated peer | yes |
| `listSessions` | `{ active_only }` | session summaries | any | yes |
| `getSession` | `{ session_id }` | session detail, risk, taint, tier | any | yes |
| `getGraph` | `{ session_id, since_seq, limit }` | graph delta, `next_seq` | any | yes |
| `subscribe` | `{ session_id?, kinds[], min_severity }` | stream of events, coalesced | any | n/a |
| `respondEscalation` | `{ escalation_id, verdict, nonce, sig? }` | accepted \| expired \| superseded | **local peer, or remote with a hardware signature (`I-06`)** | **yes** — first valid verdict wins, later ones return `superseded` |
| `setPolicy` | `{ source, generation_expected }` | new generation \| conflict | **human principal only (`F7.PS.08`)** | no — compare-and-swap on generation |
| `manageGrant` | `{ op: create\|revoke, … }` | grant state | **human principal only** | yes |
| `manageSuppression` | `{ op: create\|revoke, … }` | rule state | **human principal only** | yes |
| `pairDevice` | `{ qr_payload, device_pubkey, hw_pubkey }` | paired \| rejected | **local peer only** | no |
| `revokeDevice` | `{ device_id }` | revoked | local peer, or the device revoking itself | yes |
| `verifySession` | `{ session_id }` | inclusion proofs, `key_hw`, anchor status | any | yes |

Three authorization classes, checked by the server on every call, never by the client: **any authenticated peer** (read-only), **local peer** (`SO_PEERCRED`, UID matches the installing user), **human principal** (a local peer whose process is *not* inside any session cgroup — this is what mechanically distinguishes the user from the agent, and it is what `F7.PS.08` needs).

**I.2 Errors.** Protocol errors use JSON-RPC codes; domain outcomes are *results*, not errors — `expired`, `superseded` and `conflict` are successful calls with a negative answer, so a client cannot conflate "the network broke" with "you were too late".

| Condition | Shape | Note |
|---|---|---|
| Malformed / unknown method | JSON-RPC `-32600`/`-32601` | |
| Unauthorized for this method | `-32001`, message names the class required | Never names *why* the caller failed |
| Version incompatible | `-32002` with both versions | §3.6 |
| Escalation expired or already answered | **result**, not error | |
| Policy generation conflict | **result** with the current generation | |
| **Pairing failure of any kind** | `-32003`, **one message, constant time** | Wrong secret, expired secret and unknown device are **indistinguishable** — anything else is an oracle |

**I.3 Streaming and backpressure.** `subscribe` is server-push with a bounded per-subscriber queue. On pressure the server **coalesces by intent** (the same rule as the permission model's prompts) and emits a `Coalesced { kind_range, count, window }` marker. It never drops silently: a subscriber that cannot keep up receives fewer, larger, honest events (`I-17`). A subscriber that stops reading is disconnected after a bounded timeout, and the disconnection is an event.

**I.4 Versioning.** Semver in `aisme-proto`. Minor is additive and forward-compatible; a client ignores unknown fields. Major means the server refuses with `-32002` naming both versions — never a partial conversation. TS types are generated from the Rust definitions (`F8.API.02`), so the two cannot drift; `test-protocol-contract` proves it.

Task changes: `F8.API.01` gains "per Annex I"; new `F8.API.03 | Authorization classes enforced server-side on every method, including the human-principal test by session-cgroup membership | F7.PS.08 has its expression in the protocol`; `F11.PA.01` gains "pairing failures are constant-time and indistinguishable (Annex I.2)".

**4. Tests.** **New** — `test-protocol-authz`: every method called from each of the three principal classes, asserting the matrix; specifically, a caller inside a session cgroup is refused `setPolicy`, `manageGrant` and `manageSuppression` (this is `RF-24`'s protocol half). **New** — `test-pairing-oracle`: wrong, expired and unknown-device pairings are indistinguishable in message and in timing. **New** — `test-subscribe-backpressure`: a slow subscriber under the reference workload receives coalescing markers and zero silent drops. **Changed** — `test-protocol-contract` also asserts every Annex I method exists in both languages with matching shapes.

**5. Documentation.** New Annex I; Part I index; `F8.API.01`/`F11.PA.01` task text; Annex E gains "human principal".

**Closure.** Verified by searching for any signature or error definition: none existed. D-221 is the one that matters — `F7.PS.08` states a security rule about who may change policy, and the protocol that carries every policy change had no way to express it. The human-principal test (a local peer outside any session cgroup) is the mechanical distinction the rule needs. Nothing fell. Open: none.

---

### P-39 — Fixtures and corpora: named everywhere, specified once

**1. Challenge.** The test plan rests on seven fixtures and five corpora. Measured: the red-team corpus has a TOML format (Annex C) — and **the other four corpora have no format at all**, the fixtures have build notes but no interface, and nothing says who produces them, how large they are, or how they are versioned. The flow corpus is "10,000 labelled network flows captured from real devices" (§4.11), which is a data-collection project with privacy implications, described in one line.

These are not test details. `T4.11.01`'s classifier gate, `T4.7.02`'s IRR gate and `T4.6.01`'s correlation gate are all *release blockers* whose inputs do not exist.

**2. Verification.**

- **D-224** Four of five corpora have no schema: `benign`, `flows`, `mobile-apps`, `annex-g`. *Damage today*: none. *Open path*: F5, F6 and F10 each land on a gate whose corpus has to be invented at the moment it is needed, by whoever is unlucky. *Bias*: neutral → but three release blockers depend on it.
- **D-225** **The flow corpus has a privacy problem the plan does not name.** "Captured from real devices" means real traffic metadata — destinations, SNI, timing — from real people. Even metadata-only, that is personal data under GDPR, and this is an EU-targeted product that elsewhere refuses to let a relay see plaintext (`I-07`). *Bias*: **optimistic** — the plan asks for a dataset it has not thought about collecting lawfully → **urgent, and it is a legal exposure, not only an engineering one**. *Falsified by*: a stated provenance and consent basis.
- **D-226** No fixture interface. `fx-sse-server` is "a local TLS server streaming SSE with known token content" — used as ground truth by `T4.5.01`, `T4.5.02`, `T4.5.08` and `T4.5.13`. Four tests compare against "known content" that is nowhere defined. *Bias*: neutral. *Falsified by*: a fixture contract.
- **D-227** No corpus versioning. A corpus is an input to a *gate*, so a change to it changes what passes. The plan versions policy generations, wire formats and offset manifests, and not the data its release blockers read. *Bias*: **optimistic** — a silent corpus edit can turn a red build green. *Falsified by*: a manifest with a hash and a changelog.
- Verified sound: building the TLS fixtures rather than testing against moving third-party binaries (§4.5, one of the plan's better instincts); the Annex C scenario TOML; benign twins (P-33); the hard-negative emphasis for video (`T4.11.02`).

No question for the owner: the privacy answer below is the conservative one and does not need a decision to proceed.

**3. Implementation.** A new **§4.14 Test assets: fixtures and corpora (normative)**.

**Every corpus is a directory with a `manifest.toml`** carrying: `schema`, `version`, `entry_count`, `sha256` of the content, `produced_by`, `licence`, and for anything derived from real observation, `provenance` and `consent_basis`. `verify-docs` asserts the manifest hash matches the content; a gate records the corpus version in its report, so a result is always attributable to an input.

| Corpus | Format | Entries | Produced by | Provenance |
|---|---|---|---|---|
| `redteam` | Annex C TOML, one file per scenario | 24 classes × ≥ 3 instances | Written by hand with the detector (`F5.DT.*`) | Synthetic |
| `benign` | Same TOML with `expect.verdict = "allow"` or `"warn"` and `max_prompts` | 16 workflows + one twin per detector | Recorded from real developer workflows **on the team's own machines** | Synthetic or self-recorded |
| `annex-g` | A view, not a corpus: `redteam ∪ benign` filtered by `detector` | — | Generated | — |
| `flows` | Parquet: one row per flow, **metadata only** — see below | ≥ 10 000 | `F10.CORE.*` capture tool | **See D-225 resolution** |
| `mobile-apps` | Flow corpus subset, labelled by app category | ≥ 2 000 | Same | Same |

**Resolution of D-225 — the flow corpus is synthetic-first.** Three tiers, in this order, and the gate states which tier it ran against:

1. **Generated (primary, and the only one a gate may require).** A traffic generator drives real client SDKs (Anthropic, OpenAI, Google, Mistral, Ollama) and real negative sources (a video player, a messaging client, a package manager) against **local or first-party endpoints**, recording only the metadata the classifier consumes. No third party's traffic, no consent question, reproducible, and regenerable when a protocol changes — which matters, because QUIC adoption will invalidate a captured corpus.
2. **Self-recorded (supplementary).** Team members' own devices, opt-in, metadata only, with a documented retention window.
3. **Third-party capture: `[CUT]`.** Not collected. It is personal data, the product's own invariants refuse far less than this, and tier 1 is better science anyway because it is reproducible.

The corpus row schema is **metadata only, and enumerated** — `ts`, `direction`, `bytes`, `packets`, `proto`, `dst_ip_class` (not the address), `dst_port`, `sni_hash`, `dns_name_hash`, `ja4`, `ja4h`, `inter_arrival_us[]`, `frame_sizes[]`, `label`, `app_category`. **No payload field exists in the schema**, so `T4.11.05` ("zero payload inspection") is enforced by the *shape of the data*, not only by the code. That is the strongest form the invariant can take.

**Fixture contract.** Each fixture ships a `fixture.toml` declaring `provides` (what a test may assume), `ground_truth` (the file a test compares against) and `build` (the reproducible command). `fx-sse-server` declares its token stream in `ground_truth/sse-tokens.json`, so the four tests that compare against "known content" compare against a file.

Task changes: `F0.VM.01` gains "fixture build harness"; new `F0.ASSET.01 | Corpus manifest format, verify-docs hash check, and the empty directory structure with its licences | Gates can name the corpus version they certified`; `F10.CORE.13 | Flow-corpus generator driving real SDKs against local endpoints, metadata-only schema | The corpus is regenerable, which a captured one is not`; `F5.DT.08 | Benign-twin authoring: one twin per detector, written with the detector | I-15 weights them equally`.

**4. Tests.** **New** — `verify-docs` checks every corpus manifest hash and fails on drift. **New** — a schema test asserting the flow row type has **no** payload field, which is `T4.11.05` enforced structurally. **New** — corpus regeneration: the generator reproduces a corpus with the same label distribution, so a regenerated corpus is comparable. **Changed** — `T4.11.01` and `T4.7.02` record the corpus version in their report.

**5. Documentation.** Plan §4.14 (new); Part I index; `docs/ops/` gains nothing (this is build-time); Part VI tree gains `manifest.toml` and `fixture.toml`; Annex E gains "corpus manifest".

**Closure.** Verified by listing every corpus and fixture reference and looking for a format: one of five had one. D-225 is the finding with consequences outside engineering — the plan casually asked for 10 000 real network flows from real devices, in a product whose own invariants forbid a relay from seeing plaintext. Making the corpus synthetic-first is not only the lawful answer, it is the better one: it regenerates when QUIC or a provider's TLS stack changes, and a captured corpus does not. Nothing fell. Open: none.

---

### P-40 — `F0.VER.01…18`: the register needs its commands in the plan

**1. Challenge.** Report 02 turned its R1 register into `F0.VER.01…18` and made "the register is empty" a condition of GATE F0. That was right, and it is currently a promise: **the plan's F0 table has one row covering all eighteen**, pointing at a register in a different document. An implementer would have to read report 02, extract eighteen verification commands from a table, and hope none was ambiguous.

Worse, four of the eighteen are not equal to the others: `R1-04` (Landlock present), `R1-16` (cgroup hook attaches), `R1-18` (no TPM in WSL2) and `R1-12` (hardware curves) **change what a plan row says**. The other fourteen confirm or withdraw a claim. That difference should be visible.

**2. Verification.**

- **D-228** The eighteen verifications live in another document. *Damage today*: none. *Open path*: F0 does thirteen of them and nobody notices the other five, because there is no per-item row to leave unchecked. *Bias*: neutral. *Falsified by*: eighteen rows in the plan.
- **D-229** **Four verifications are blocking and fourteen are not, and the plan does not distinguish them.** `R1-04` decides whether the L2 row in H-16 and Annex D reads as written; `R1-16` decides whether `F3.EN.10` exists at all; `R1-18` decides a risk rated High/High and a README sentence; `R1-12` decides the signing curve across F5, F10 and F11. If those four are deferred, four phases build on an assumption. *Bias*: **optimistic** → they belong in week 1, not "before GATE F0".
- **D-230** No stated outcome per verification. Report 02's register says what *would* verify a claim, not what happens to the plan if it fails. `R1-04` failing means the L2 row becomes L2- and the CPU budget expectation changes; that consequence is written nowhere. **Predict before you measure** (general rule 5): each verification should state, now, what each possible result will mean. *Bias*: neutral, and it is the rule the whole method rests on.
- Verified sound: the decision to make the register a gate condition; the numbering; the "empty at GATE F0" bar.

No question for the owner.

**3. Implementation.** The F0 table's single `F0.VER.01…18` row is replaced by a new **§F0.4 Verification backlog** with eighteen rows: **id · claim · command · if it holds · if it does not**. The last two columns are the prediction, written before the measurement.

The four blocking ones are marked `[BLOCKING]` and move to week 1, ahead of `F0.REPO.01`:

| ID | Claim | Command | If it holds | If it does not |
|---|---|---|---|---|
| `F0.VER.04` `[BLOCKING]` | Landlock is active on the matrix kernels and in stock WSL2 (`R1-04`) | `cat /sys/kernel/security/lsm`; `landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)` per VM | §2.2.1, H-16's L2 row and Annex D stand as written; `F3.EN.09` proceeds | The affected platform is **L2-**; the installer, Annex D and the CPU expectation say so; `F2.WS.11` is dropped from the skeleton and `F3.EN.09` becomes conditional |
| `F0.VER.16` `[BLOCKING]` | `BPF_CGROUP_INET4/6_CONNECT` attaches without BPF-LSM and denies only session flows (`R1-16`) | `bpftool cgroup attach` on a VM with `bpf` absent from the LSM list; `connect` from inside and outside the session cgroup | `F3.EN.10` proceeds; Network Slam is T0 at L2 | Network Slam at L2 falls back to `seccomp_unotify` with its TOCTOU caveat stated; `H-13`'s slam condition gains an L2 note; the L2 CPU budget is re-examined |
| `F0.VER.18` `[BLOCKING]` | WSL2 exposes no TPM (`R1-18`) | `ls /dev/tpm* /dev/tpmrm*` inside the WSL2 image | Risk R-18 stands; software signing and default anchoring for WSL2 confirmed in README, ADR-02 and the UI | R-18 is downgraded; the WSL2 row in Annex D gains a hardware-key line; the README sentence is removed |
| `F0.VER.12` `[BLOCKING]` | Commodity TPM, Secure Enclave and StrongBox offer non-exportable P-256 and not Ed25519 (`R1-12`) | `tpm2_getcap algorithms`; the Apple and Android key-generation docs; a key-generation attempt on each | H-17 and `F5.FO.02`/`F10.FO.01`/`F11.CC.02` stand | The curve choice is revisited in an ADR; `key_hw` gains the value the hardware actually offers |

The remaining fourteen (`F0.VER.01`…`03`, `05`…`11`, `13`…`15`, `17`, `19`, `20`) keep the same four columns and run any time before GATE F0. Two of them are new from this report: `R1-19` (BPF range check on `EventKind`) and `R1-20` (Landlock ABI 4 port rules), so the backlog is **twenty**, not eighteen, and GATE F0's count changes with it.

GATE F0 gains `cargo xtask verify-backlog` — a command that reads §F0.4, checks that every row has a recorded outcome in `docs/reports/f0-verification.md`, and fails if any is unrecorded. "The register is empty" becomes a machine check rather than a habit.

**4. Tests.** **New** — `verify-backlog` as above, and a `verify-docs` check that every `R1-nn` in reports 02 and 03 has a matching `F0.VER.nn` row (so a future report's register entry cannot be forgotten). **Changed** — GATE F0's memory-file count and its new backlog line.

**5. Documentation.** Plan §F0.4 (new, replacing one row); GATE F0; `STATE.md` "Next up" item 8 points at §F0.4 and marks the four blocking ones as week 1; report 02's R1 register gains a line noting that its entries are now plan rows.

**Closure.** Verified by comparing the F0 table against report 02's register: one row stood for eighteen items. The substantive finding is D-229 — four of the verifications are not confirmations but decisions in disguise, and three phases plus a High/High risk rest on them. Writing each one's two possible outcomes *before* measuring is the project's own rule 5, applied to itself. The backlog grew to twenty as this report added two. Nothing fell. Open: none.

