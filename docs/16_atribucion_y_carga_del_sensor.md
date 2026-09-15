# Challenge-amplification — the attribution rule and the sensor load, against the source

Two decisions, both verified line by line against the tree rather than against what the plan says
about it. The first decides what the product can **trace and detect**; the second decides what it
does to **this kernel**.

## The headline, before the detail

**The rule I proposed to you last message is wrong, and the source says so.** I proposed that a
declaration should bind to an action when the declaring process's *parent* is an ancestor of the
action — the "sibling rule". Reading `crates/aisme-agentsim/src/record.rs:414-455` shows it
reintroduces, for **14.4 %** of model turns, exactly the defect that module's central test exists to
prevent. The recommendation below is different and narrower, and it is better for detection.

| | Verdict |
|---|---|
| Sibling rule, as I proposed it | **Rejected.** It mis-attributes concurrent tool calls and widens who may explain an action |
| Attribute where unambiguous, **mark ambiguity**, count it | **Recommended** |
| Load the sensor once, as `ADR-10` says | **Recommended, with one cheaper check first** |

---

## Point 1 — What a declaration binds to

**Done when:** a trace recorded from a real session attributes every action it can, marks the rest,
and the manifest says how many of each.

### 1. Challenge

*Is this the best solution?* The proposal I made was not, and the refutation is in the module's own
test.

`attribute` (`record.rs:205`) walks the action's ancestry, and at each ancestor looks for *"the
latest declaration from this process that was already made when the action happened"*
(`record.rs:211-216`). The design assumes **the declaring process is an ancestor of the actions it
explains.** `actions_are_attributed_by_ancestry_and_not_by_arrival_order` (`record.rs:425`) is built
on exactly that: declarations come from pids `100` and `200`, and the actions come from `101`, `201`
and `102` — children and a grandchild **of the declarers**. Its own comment says why it is written
that way: *"at the moment the first tool call's action happens, the most recent declaration is the
second one — so 'attribute to the latest declaration' hands half of each tool call's work to the
other, and every summary count still comes out right."*

**A pre-tool hook is not an ancestor.** In the topology a real agent has, the hook and the tool's
subprocess are two **children** of the agent. Measured on this tree: with both planes finally
reaching one WAL, the trace reported **55 of 55 actions unattributed**, and the declarations carry
`ppid = 0` because `declaration_event` stamps only `tgid` (`crates/aisme-agentd/src/declare.rs:56`).

So the two mechanisms were designed against **different topologies**, and neither is wrong on its
own. `F2.WS.03`'s declaration is a hook's; `record.rs`'s attribution is `agentsim`'s, where a process
declares and then forks.

*Why the sibling rule fails.* Under `d.tgid == current || d.ppid == current`, an action's walk
reaches the agent `A`, and **every** hook of that session has `ppid == A`. All of them match, and
"the latest at or before" picks the most recent — which is the precise defect the test above was
built to fail. It is not a rare case: `docs/12` M3 measured **14.4 %** of 11,182 model turns issuing
parallel tool calls, so roughly one turn in seven would have its actions handed to the wrong
declaration. And the counts would still come out right, which is what makes it dangerous.

*Can it be simplified?* Yes, and the simplification is the recommendation: **stop trying to
manufacture a link the kernel does not provide.** Attribute where the evidence is unambiguous, and
where it is not, say so and count it.

### 2. Verification

**For traceability and detection, this is the half that matters, and it is where the sibling rule is
worst.**

- **It widens who may explain an action.** Under the ancestry rule only an **ancestor** can explain
  what its descendants did. Under the sibling rule, *any child of any ancestor* can — and in an agent
  session the agent spawns everything, so any tool subprocess could declare intent covering its
  siblings' actions. `DT-04` exists because *a declaration may be a lie*; a rule that lets a
  compromised subprocess emit a benign `Read` declaration that then explains another process's
  exfiltration is a rule that helps the attacker write the alibi. The ancestry rule at least requires
  being in the action's own lineage.
- **A wrong attribution is invisible; a missing one is not.** `record.rs:34-40` already states this
  as the module's principle, about the ancestry bound: *"Beyond it the action is attributed to
  nothing, which is the conservative direction — an unattributed action is visible, while a wrongly
  attributed one is not."* The recommendation below is that principle applied to the same question
  one level up. Choosing the sibling rule would contradict a rule this module already follows.
- **The fixture is ground truth for a measurement.** `§4.6` measures correlation precision and
  recall against these tokens. A fixture whose tokens are wrong for one turn in seven does not
  measure a correlator; it measures the recorder's guess, and it does so with a number that looks
  fine.

**Not verified, and it is the one thing I will not resolve alone:** whether a fixture with a marked
ambiguous fraction is acceptable to you as `F0.ASSET.02`. It changes the asset from *"every action
explained"* to *"every action explained or explicitly marked unexplainable, with the proportion
stated"*. My view is that it is strictly better, because the alternative is the same fixture with the
ambiguity hidden inside wrong tokens. But it is your asset and it is the input to a gate.

### 3. Implementation

**Nothing is manufactured. Three changes, and the third is the one that matters.**

- **The declaration will carry its parent.** `declaration_event` will stamp `event.ppid` with the
  declaring peer's parent, read by the **daemon** from `/proc/<peer>/stat` while the peer is still
  connected — derived from the kernel's own `SO_PEERCRED` pid, never claimed by the caller, and read
  at the only moment a 1 ms process is certainly still there. This records a fact that is currently
  lost; it decides nothing on its own.
- **`attribute` will return a verdict, not a token.** It will yield one of *attributed to token T*,
  *unexplained* (no candidate), or **ambiguous** (more than one candidate declaration in flight under
  the same ancestor at the action's time). Ambiguity will be detected before a winner is picked, so
  the "latest" tie-break is never reached where it would be a guess.
- **A candidate is a declaration whose `tgid` is the ancestor, or whose `ppid` is the ancestor.** The
  second clause is what lets a hook explain anything at all — and because a tie is reported rather
  than broken, it adds no false explanation. Where one tool call is in flight, which `docs/12` M3
  measures at **85.6 %** of turns, the attribution is exact.
- `Recorded` will carry `ambiguous` beside `unattributed`, and `--to-trace` will print both. A trace
  entry that is ambiguous will carry token `0` like an unexplained one, because the format has one
  way to say *no ground truth* and inventing a second would change `F1.SIM.02`.

**What will not be done, and why:** no time window, no "nearest declaration", no heuristic that turns
an absence into a value. `I-19` and the module's own comment both point the same way.

### 4. Tests

**Existing, kept and not weakened:**

- `actions_are_attributed_by_ancestry_and_not_by_arrival_order` (`record.rs:425`) stays exactly as it
  is. Under the new rule its declarers are still ancestors, so it must keep passing unchanged — and if
  it needs changing, the rule has grown beyond what is written here.
- `the_ground_truth_token_is_not_a_value_the_engine_can_see` stays: ambiguity must not invent a token.

**New:**

- **A hook's declaration explains its sibling's actions.** One agent, one hook declaring, one tool
  acting; the action is attributed. This is the case that produces zero today.
- **Two hooks in flight make their siblings' actions ambiguous, not wrong.** Two declarations under
  one agent and an action in a subtree of neither — the action is counted `ambiguous`, its token is
  `0`, and **no** token from either declaration appears. Written so that the sibling rule I proposed
  fails it, because that rule would attribute to the later one.
- **Ambiguity is counted and visible in the summary.** A recording with ambiguous actions reports
  them; a caller cannot mistake it for a complete one.
- **A declaration carries its parent.** Through the real socket, driven by `serve_line`, asserting
  `ppid` is the connecting process's parent and not a value the caller sent.

### 5. Documentation

- Plan `F2.WS.03`'s row: a declaration is attributed to the process that made it **or to its
  parent**, and a tie is reported rather than broken. The row currently says *"a process in the
  action's own ancestry"*, which a hook is not, and that sentence is the one that has to change.
- Plan `F0.ASSET.02`'s row and `§4.6`: the fixture's manifest carries `attributed`, `ambiguous` and
  `unattributed`, and the correlation gate scores against the attributed set with the other two
  stated. A gate that scored against a guessed set would measure the recorder.
- `docs/ai/memory/`: a new memory — *the declarer is not an ancestor*. The durable fact is that two
  correct mechanisms specified against different process topologies compose into one that explains
  nothing, and that the join a hook can provide is weaker than the one `agentsim` provides.
- `docs/research/01` Part V: `D-4`'s neighbour gains this, since `DT-04`'s "a declaration may be a
  lie" now has a second edge — *and a declaration may be about somebody else's work*.

### Closing

Verified against `record.rs:205-229` (the walk), `:34-40` (the module's own conservative principle),
`:414-455` (the test built to fail the arrival-order rule), `declare.rs:56` (`ppid` never stamped),
and `docs/12` M3 (**14.4 %** of turns with parallel tool calls). **The skeleton's own recommendation
fell**: the sibling rule I proposed to you would mis-attribute roughly one turn in seven while
reporting correct totals, and would let any subprocess write an alibi for its siblings. What replaces
it attributes the 85.6 % exactly and marks the rest. Open, and yours: whether a fixture with a stated
ambiguous fraction is acceptable as `F0.ASSET.02`.

---

## Point 2 — Loading the sensor on this kernel

**Done when:** the tracepoint's argument offsets are confirmed on this kernel, and `--load-sensor`
has answered.

### 1. Challenge

*Is this the best solution?* `ADR-10` is the right instrument and its scope is right. What the source
review adds is that **one check should come before the load, and it is cheaper and more informative
than the load itself.**

The program is one tracepoint, `sys_enter_openat` (`crates/aisme-ebpf/src/main.rs:107`), and it
*always returns 0* with the comment *"a tracepoint's return value cannot deny anything, and this
program observes"*. It reads three fixed offsets out of the trace record and copies a path with
`bpf_probe_read_user_str_bytes`. `bpf_probe_write_user` appears **nowhere** in the tree except in
`xtask/src/rules.rs:185`, which is the gate that forbids it.

**The risk that is real is not a crash, it is garbage.** `OPENAT_FILENAME_OFFSET = 24` and its two
neighbours are *"an ABI detail of a **format file**, not of the kernel headers, so it is **verified in
the guest**"* (`main.rs:87-95`) — by `cargo xtask vm probe`, against
`/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format` (`xtask/src/vm.rs:692`). The VM
matrix tops out at **7.0**; this host runs **7.1.5**. The offsets have never been checked here. A
wrong offset does not fault — `ctx.read_at` returns a `Result` and the helper fails safely — it
yields a *pointer that is not the filename*, and the recording fills with nonsense that looks like
data.

*Is it coherent with the specs?* Yes, and one property makes the blast radius small in a way worth
stating: the program's **first** act is to look the calling tgid up in `AISME_SESSIONS` and return if
it is absent (`main.rs:122`). A loaded program with no session registered observes **nothing** and
reserves nothing from its ring buffer.

*Can it be simplified?* Yes: read the format file first. It needs the same privilege and answers the
only question that can silently corrupt the asset.

### 2. Verification

**Safe, on the evidence, with the three things that could go wrong each named:**

- **Kernel stability.** An observe-only tracepoint that returns 0 and touches no kernel state is what
  every `bpftrace` one-liner is. It passes the verifier or it does not load at all. `EbpfLoader::load`
  reports a refusal with the kernel's own words (`crates/aisme-linux/src/sensor.rs:180-198`), and
  `--load-sensor` detaches immediately — *"this is a question, not a session"*.
- **Data integrity, which is the real exposure.** Covered by reading the format file first. If the
  offsets differ on 7.1, the recording is not attempted and the finding goes into `F0.VER`'s register
  as a measured fact about a kernel the matrix does not cover — which is worth more than the
  recording.
- **Scope creep.** `ADR-10` already names `nothing_measured_means_no_bpf_load_is_attempted_on_the_host`
  as the tripwire. That stands.

**Nothing here is unclear enough to ask about.** The one input still needed is operational: the
`sudo`, which both steps share, and which I will ask for once rather than twice.

### 3. Implementation

In this order, and stopping at the first that disagrees:

1. `sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format` — read-only, loads nothing.
   Compare `filename`, `flags` and `mode` against 24, 32 and 40. **This host refuses the file
   unprivileged**, which is why it shares the `sudo` rather than preceding it.
2. If they match: `sudo aisme-agentd --load-sensor`, output pasted verbatim into `docs/ai/STATE.md`
   whatever it says.
3. If they do not match: **stop.** The offsets become a `F0.VER` row measured on 7.1, `F3.PT.*` gains
   a note that the format is not stable above 7.0, and the recording waits for a kernel the matrix
   covers.

### 4. Tests

None, and deliberately: a one-off manual act is not a test, and giving it one is how an exception
becomes a habit. `ADR-10` already says this.

What the source review adds as **owed regardless of this ADR** is a numbered point rather than a fix
here: the offsets are checked in the guest by a shell script inside `vm probe`, and nothing checks
them at run time. A sensor that started against a format it had not verified would produce a
recording nobody could tell from a good one. That is `F3.PT.*`'s, it is not this phase's, and it is
the kind of gap that survives three phases unless it is written down.

### 5. Documentation

- `ADR-10` gains step 1 above in its follow-up list, before the load.
- `docs/ai/STATE.md`: both outputs verbatim, whatever they say.
- `docs/01`'s `F0.4` verification backlog: a row for the 7.1 offsets, with its prediction written
  before the measurement — *if they match, the matrix's range extends and the recording proceeds; if
  they do not, `F3.PT.*` owns a run-time check and the fixture waits.*

### Closing

Verified against `aisme-ebpf/src/main.rs:87-95` (the offsets and where they are checked), `:107-124`
(observe-only, and the session filter that makes an idle load silent), `sensor.rs:168-198` (a refusal
carries the kernel's words), `xtask/src/vm.rs:692` (the guest's format check), `xtask/src/rules.rs:185`
(the gate forbidding the write helper), and this host's `uname -r` — **7.1.5**, above the matrix's
7.0. **One claim of the skeleton fell:** that the load is the first thing to do. Reading the format
file is cheaper, shares the same privilege, and is the only check that catches the failure that would
silently corrupt the asset. Open: nothing but the `sudo`.

---

## Whole-document coherence

1. **The two points share one failure mode and it is the project's own signature defect.** A wrong
   attribution and a wrong tracepoint offset both produce **plausible data**: totals that add up,
   paths that parse. Neither announces itself. Both are answered the same way here — by refusing to
   produce a value where the evidence does not support one, which is `I-19` and is the rule
   `record.rs:34-40` already states in its own words.
2. **Point 1 makes point 2 more valuable, not less.** A fixture that marks its ambiguous fraction is
   only worth recording if the actions in it are real; a fixture recorded against wrong offsets would
   have neither. Doing point 2's step 1 first protects point 1's output.
3. **Corrected while reading:** my previous message told you the sibling rule's risk was
   "over-attribution when one agent has two hooks in flight, the same ambiguity the current rule
   already has". That understated it twice. The current rule does **not** have this ambiguity — its
   declarers are ancestors, so two of them are in different subtrees — and the frequency is measured
   at 14.4 % of turns rather than unknown.

**Against the specs**, nothing here contradicts an invariant or an `H-xx` finding. Point 1 corrects a
plan sentence (`F2.WS.03`'s *"a process in the action's own ancestry"*) that a hook cannot satisfy,
and it does so by narrowing what the recorder claims rather than by widening what it asserts. Point 2
narrows `I-12` through the ADR that already exists for it.

**One thing is yours and it is small:** whether `F0.ASSET.02` may be a fixture with a stated
ambiguous fraction. Everything else here is executable.
