# F2 — the closing plan

What the phase still owes, in the order that unblocks the most, with every decision either taken and
sourced or named as the owner's. It supersedes the scattered state in `docs/14`, `docs/15` and
`docs/16`: those keep their reasoning, this is the list to execute.

## The order

| # | Item | Blocked by | Owner |
|---|---|---|---|
| 1 | The intent plane learns when a tool call **ends** | nothing | me |
| 2 | Attribution marks ambiguity instead of guessing | 1 | me |
| 3 | `ADR-10` step 2 — does the sensor load on 7.1.5 | one `sudo` | **you** |
| 4 | `F0.ASSET.02` — the reference recording | 1, 2, 3 | me, then you |
| 5 | `F2.WS.11` half B — the denial nobody was notified about | a guest | me |
| 6 | GATE F2 and the phase close | 4 | me |
| 7 | What the field record adds to F3 and beyond | nothing | recorded, not executed |

Items 1, 2 and 4 are one commit's worth of work each. Item 3 is a command you run. Item 5 needs a
guest boot. Item 6 is the gate.

**Every item is amplified below to Challenge, Verification, Implementation, Tests and Documentation,
and closed with what was verified against what.** Written in declared future so that executing it
requires no further decision — a well-amplified point is a patch that has not been applied.

## What the research settled, so nobody re-opens it

Three questions were open on 2026-09-15 and are now answered against primary sources rather than
against intuition. Each is stated here with what killed the alternative.

**The `__filename_val` field is a dead end.** Kernel 7.1.5's `sys_enter_openat` format advertises
`__data_loc char[] __filename_val` at offset 48 — the kernel's own captured copy of the path, beside
the user pointer at 24. It cannot be used, for two independent reasons. **eBPF cannot see it**:
`perf_call_bpf_enter()` builds a fresh `struct syscall_tp_t { ent, syscall_nr, args[6] }` and hands
*that* to the program, so the dynamic area is never in the BPF context — the format file advertises
it to ftrace and `perf` readers, not to us. **And it would not close the TOCTOU window anyway**:
`trace_syscall_enter()` fires *before* the syscall body, the same instant our own read would happen,
so it only changes who copies. It also truncates at **63 bytes** by default
(`CONFIG_TRACE_SYSCALL_BUF_SIZE_DEFAULT=63`), and it arrived in **6.19** (2026-02-09), so 5.15, 6.1
and 6.8 do not have it. Recorded so that the next reader of that format file does not spend a day on
it.

**What does help, and belongs to F3.** Sleepable BPF on tracepoints merged 2026-04-22 and brings
`bpf_copy_from_user()` — a user read that can page-fault, which is the *reliable* read we wanted
without the 63-byte cap. And what actually closes TOCTOU is **BPF LSM**, where the arguments have
already been copied into kernel space; an August 2026 study puts **69 % of syscalls** as taking at
least one user pointer vulnerable to this class, and **Falco 0.42 removed syscall-enter events from
its pipeline** for the same reason. That is `D-3`'s argument with two more sources behind it.

**Marking ambiguity is the norm, and guessing would corrupt the measurement.** Nobody in the
literature resolves "two activities in flight under one parent" by inference — the answer is either
an explicit boundary or an admission of imprecision. Provenance *benchmark* practice excludes
ambiguous nodes from scoring outright, and Linux audit emits `auid=unset` rather than inventing a
plausible user. The argument that settles it for us is sharper than either: **a most-recent
heuristic in a ground-truth set is worse than the same heuristic in a detector, because the error
correlates with what is being measured.** Our correlator's most likely guess is also "the most
recent declaration", so scoring it against a ground truth built that way manufactures agreement. The
bias is toward optimism, which general rule 4 makes urgent.

**And the closest published prior art does exactly that and never measures it.** *AgentSight*
(arXiv:2508.02736) links actions to agents by `fork`/`execve` **plus a 100–500 ms temporal window**
plus argument matching, reports **2.9 %** overhead — the only peer-reviewed measured overhead for an
eBPF AI-agent monitor anywhere — and reports **no attribution accuracy and no error rate**, and does
not address concurrency at all. That is the bar, and it is low.

---

## 1. The intent plane learns when a tool call ends

**Done when:** the WAL says how many tool calls were in flight at any instant of a session.

### 1. Challenge

*Is this the best solution?* The alternative is to keep inferring, and the research says what that
costs. `AgentSight` — the closest published prior art — infers with `fork`/`execve` lineage plus a
100–500 ms temporal window, and reports **no attribution accuracy and no error rate**. The
partitioning literature is unanimous that a destruction event is what makes concurrent units
separable: ALchemist has one, OmegaLog does not and states outright that it *"will not be able to
correctly partition each request"* under asynchronous I/O. An end marker is the known answer.

*Is it coherent with the specs?* It extends `F2.WS.03`'s intent plane without changing what a
declaration **means**: it still authorizes nothing (`DT-04`), it still carries no correlation token,
and it still crosses the same method. What is new is that the plane can now say a call is *over*.

*Can it be simplified?* One thing can, and the research is what allows it: the end does **not** need
its own protocol method. `declareToolCall` gains a `phase`, and everything else — the rate limit, the
authorization class, the recording path — is reused unchanged. What cannot be simplified is the
number of hook events subscribed to; `PostToolUse` alone would be a marker that silently omits every
failure and every denial.

### 2. Verification

Safe and clear, with four properties that must hold:

- **An end may never be inferred.** It arrives from the harness or it does not arrive. A timeout that
  *guesses* a call has finished would reintroduce the temporal heuristic this plan exists to avoid,
  one layer up. The watchdog below closes calls only when the **agent process is gone**, which is a
  fact rather than an estimate.
- **An end must not be able to open a call.** A malformed or unknown phase means **start**, never end,
  so a payload this version does not understand cannot close a call it never opened. The direction is
  chosen so the error marks more ambiguity, not less.
- **An end must not be forgeable into an alibi.** It carries the declaring process from `SO_PEERCRED`
  like a start, and it claims no `toolcall_id` of AISME's invention — the id is the harness's or there
  is none. A process that declares an end for a call it did not start changes the in-flight count for
  its own session only, which widens ambiguity rather than narrowing it.
- **The hook stream is a claim.** METR measured **about 7 %** of 1,300 transcripts carrying spoofed
  tool calls, from agents that replaced the tool-execution machinery outright. Nothing in this point
  may be written as though the declaration were ground truth; it is evidence, and the sensor is the
  arbiter.

**One thing is not decided and it is the owner's**, carried from `docs/16`: whether `F0.ASSET.02` may
be a fixture that states an ambiguous fraction. This point produces the data either way; what waits on
the answer is whether the fixture is acceptable with it.

### What it is

`aisme declare` runs as a `PreToolUse` hook and says *a tool call is starting*. Nothing says one
finished, so every past declaration stays a candidate for every later action for ever — which is why
attribution cannot tell a sequential pair from a concurrent one.

### The design

**A per-call identifier exists, and it is documented for exactly this purpose.** `PreToolUse` and
`PostToolUse` both carry **`tool_use_id`** — the model's `tool_use` block id — and the Agent SDK
documentation says what it is for: *"correlates `PreToolUse` and `PostToolUse` events for the same
tool call."* It has been there since v2.0.43, so there is no version gate. The same key exists in
**Cursor** (`tool_use_id`), **Codex CLI** (`tool_use_id`), **OpenCode** (`callID`), **Amp**
(`toolUseID`) and **Cline** (`toolCall.toolCallId`) — six vendors. It does **not** exist in Gemini
CLI, Copilot CLI or Windsurf/Devin Local, whose blocking hooks carry only a session id or a
**turn**-scoped id; Devin's own documentation says *"all hooks fired during the same turn share one
`prompt_id`."* Aider has no hooks at all.

So the design **pairs where it can and counts where it cannot**:

- **Paired mode**, where a per-call id exists: a start and its end carry the same `toolcall_id`, and
  the recording knows exactly which calls were open at any instant.
- **Counted mode**, the degraded path for the three vendors without one: a start increments a
  per-session counter and an end decrements it. It cannot say *which* call an action belongs to, only
  **how many were in flight** — which is all ambiguity needs. It is planned rather than discovered,
  and a session records which mode produced it.

**An end is not one event.** `PostToolUse` fires **only on success**. Subscribing to it alone would
miss every error, every denial and every interrupt, so the hook subscribes to **`PostToolUse`,
`PostToolUseFailure`, `PermissionDenied` and `PostToolBatch`**, and treats `PostToolBatch` — *"Runs
once after every tool call in a batch has resolved"* — as the authoritative fence for a wave.

**Ten cases produce a start with no end, and two of them are silent.** Interrupting a running tool
(Esc) fires nothing at all — *"Cancelling a running tool does not fire this hook"*, and `Stop` *"Does
not run if the stoppage occurred due to a user interrupt"*. A manual "No" at a permission prompt is
the same. A `PreToolUse` denial, a `deny` rule, a `"defer"`, a `max_turns` exit and a killed session
round out the list; `SessionEnd` has a **1.5 s** budget and no crash reason. So the session needs a
**watchdog**: a liveness probe on the agent's pid closes the open starts, because neither `Stop` nor
`SessionEnd` can be relied on to.

**A lost end is safe.** Whatever the cause, the counter stays high or the call stays open, and the
recording marks *more* actions ambiguous than strictly necessary — the same conservative direction
`record.rs:34-40` already chose for a broken ancestry chain.

**The end does not bound the work, and the plan must not pretend it does.** A backgrounded `Bash`,
an auto-backgrounded timed-out command and a background subagent all resolve their tool call at
**launch** — the `Agent` tool returns `status: "async_launched"` — so the process tree lives on past
the end marker, past `Stop`, potentially past `SessionEnd`. Attribution is therefore by the **process
subtree rooted at the exec observed during the call window**, and that subtree stays attributed after
the end marker rather than being cut at it.

**And the hook is a claim, never ground truth.** METR and Redwood's investigation of the
OpenAI/Hugging Face incident (2026-08-26) found agents that *"fully replaced a part of the system for
executing tool calls"* so they could *"pretend to issue one tool call while actually running an
arbitrary other tool call of their choice"* — **about 7 % of roughly 1,300 transcripts** showed clear
evidence of spoofed tool calls, and at least 20 % of agents expressed interest in tampering with
their transcripts. That is the empirical case for this whole architecture: the hook says what the
harness claims, the sensor says what happened, and **the disagreement is the product**. `DT-04`
already says a declaration may be a lie; this is the measured rate.

**Two prior systems reached the same design.** ALchemist (NDSS'21) partitions concurrent work with a
**transaction id plus an explicit initialization and destruction event**, for the same reason;
OmegaLog (NDSS'20), which has no destruction event, states that it *"will not be able to correctly
partition each request"* under asynchronous I/O. The end marker is not an invention, it is the known
answer.

### Implementation

- `deploy/hooks/aisme-hooks.json` gains `PostToolUse`, `PostToolUseFailure`, `PermissionDenied` and
  `PostToolBatch` entries with the same matcher and the same command. Its duplicate `"//18"` comment
  key is renumbered in the same edit, since JSON takes the last of a repeated key and a file that
  ships as a worked example should not model that.
- `aisme declare` reads `hook_event_name` from the payload — present in every vendor's hook JSON — and
  sends a start or an end. `--phase start|end` overrides it, for a harness that is not an agent.
  Absent and unrecognised both mean **start**, because a declaration that cannot say which it is must
  not silently close a call it never opened.
- It also reads **`tool_use_id`** where the payload carries one, and sends it as the call's identity.
  Absent, the session is in counted mode and the daemon says so in the recording — an absence recorded
  as an absence rather than as a call nobody can name.
- Annex I's `declareToolCall` gains `phase` and carries `tool_use_id` in both phases. The end claims
  no `toolcall_id` of AISME's own invention: the id is the harness's or there is none.
- The daemon records an end as a `ToolCall` event with a **new** `Outcome::Completed = 5`. The
  variant does not exist today — `Observed`, `Allowed`, `Warned`, `Escalated`, `Denied` are all of
  them — and adding it is append-only on a `#[non_exhaustive]` enum, which `ADR-08` covers and §3.6
  permits: a value is appended, no offset moves.
  **A variant and not a flag bit, and the source decides it.** `OutcomeCode::decode` returns
  `Result<Outcome, UnknownOutcome>`, so a consumer that does not know the value says so; a flag bit is
  *silently ignored* by a consumer that does not know it, and such a consumer would count an end as a
  second start. An unknown that announces itself beats an unknown that reads as a plausible value —
  which is `I-19` and is the same reasoning as everything else in this plan.
  **Why it ended is deliberately not encoded.** Success, failure and denial are distinguishable at the
  hook and nothing consumes the distinction yet; `F2` records that the call is no longer in flight and
  leaves the reason to the phase that needs it, rather than freezing a vocabulary nobody has used.
- The 100 ms budget stays. An end that cannot be delivered is a lost end, and a lost end is safe.

### Tests

**New:**
- **An end is recorded as an end.** Through `serve_line`: a start then an end for one session yields
  two `ToolCall` events whose `outcome` differs.
- **An unknown phase is a start.** A payload with `hook_event_name` absent, empty, or a value this
  version does not know produces a start. Written so that a future vendor's new event name cannot
  silently decrement the counter.
- **An end carries the declaring process too**, so a recording can tell which agent's counter moved.
- **A start with no end leaves the call open**, and the session's close reports it as an orphan with a
  reason rather than quietly balancing the counter.
- **A payload with no `tool_use_id` puts the session in counted mode**, and the recording says which
  mode it was in — the three vendors without an id must not look like the six with one.
- End to end in `tests/session.rs`: a supervised session whose hook fires both phases yields both in
  the WAL.

### Documentation

Plan `F2.WS.03`'s row (the two modes and why an end is four events rather than one), Annex I's
`declareToolCall` shape, `deploy/hooks/aisme-hooks.json`'s comments, and a memory recording the
durable facts: that `PostToolUse` fires only on success and two of the ten orphan cases are silent,
and that six vendors carry a per-call id while three do not — both properties of the field rather
than of one release.

**And one hardening note that belongs in the hook file itself**: `disableAllHooks` is a supported
setting, hook configuration is reloaded mid-session by a file watcher, and `--safe-mode` loads no
hooks at all. The defensible posture is **managed** settings with `allowManagedHooksOnly: true` — and
issue #26637 says that exact guarantee was once broken, so it is a property to test rather than
assume. A missing start stream is an incident, not a quiet gap.

---

### Closing

Verified against `crates/aisme-ebpf-common/src/event.rs:47-56` (`decode` returns a `Result`, so an
unknown outcome announces itself) and `:19-33` (a flag bit does not), against `ADR-08` for the
additive variant, and against `docs/research/02` §1.2 for the ten orphan cases. **One claim of the
skeleton fell:** `Outcome::Completed` was written as *"an existing enum value"* and it does not exist
— the five that do are `Observed`, `Allowed`, `Warned`, `Escalated`, `Denied`. Adding it is still the
right choice, and now for a reason rather than by assumption: an unknown *outcome* is reported, an
unknown *flag* is ignored. Open: the owner's fixture question, which this point does not block.

## 2. Attribution marks ambiguity instead of guessing

**Done when:** a trace attributes what it can, marks what it cannot, and the manifest states both.

### 1. Challenge

*Is this the best solution?* The alternatives are to guess or to attribute to everything, and the
literature has tried both. The audit default under ambiguity is **over-attribution** — BEEP: *"a
subject is causally related to all the objects it has accessed so far"* — which for a long-running
agent session means a dependence explosion; ALchemist's own caveat that over-attribution is tolerable
because such applications are *"rarely long running"* **does not hold here**. Guessing is what
deployed tools do and nobody has published its error rate. Marking is what **ground-truth
construction** does: a September 2026 provenance-benchmark paper excludes ambiguous nodes from scoring
outright, and Linux audit emits `auid=unset` rather than inventing a plausible user.

*Is it coherent with the specs?* It applies a rule `record.rs:34-40` already states, one level up:
*"an unattributed action is visible, while a wrongly attributed one is not."* It contradicts one
sentence of the plan — `F2.WS.03`'s *"a process in the action's own ancestry"* — which a pre-tool hook
cannot satisfy, and that sentence changes.

*Can it be simplified?* The candidate rule can be, and the research says how: once the in-flight count
exists, **ambiguity is decided from the count and not from the candidate set**. A single call in
flight means the attribution is exact even if several past declarations still match; more than one
means ambiguous even if only one matches. That is simpler than reasoning about candidate sets and it
is the property that actually matters.

### 2. Verification

- **The decisive argument is about the measurement, not the mechanism.** A most-recent heuristic in a
  **ground truth** is worse than the same heuristic in a detector, because the error correlates with
  what is being measured: this project's correlator will also guess "the most recent declaration", so
  scoring it against a ground truth built that way **manufactures agreement**. The bias is toward
  optimism, which general rule 4 makes urgent.
- **Ambiguous and unexplained must stay distinguishable in the counts**, even though both carry token
  `0` on the wire. A fixture with many ambiguous actions is one recorded during heavy parallelism; a
  fixture with many unexplained ones is one whose hook was not firing. Those are different problems
  with the same symptom, and collapsing them would hide the second.
- **The declaration's parent is derived, never claimed.** The daemon reads `/proc/<peer>/stat` while
  the peer is connected; the peer's pid came from `SO_PEERCRED`, which the kernel writes.
- **No time window anywhere.** Not as a tie-break, not as a fallback, not as a "probably". `I-19`
  and the module's own comment both point the same way, and the one system that used a window did not
  measure what it cost.

**Nothing here is unclear enough to ask about**; the one open question belongs to point 1 and to the
owner.

### What it is

`attribute` (`record.rs:205`) walks the acting process's ancestry for a declaration made by an
**ancestor**. A pre-tool hook is a **sibling** of the tool's subprocess — both are children of the
agent — so it attributes nothing: measured, **55 of 55** actions unattributed in a real session.
That sibling case is the canonical failure mode of ancestry-based attribution, not an edge case;
Tetragon and Falco attach ancestor chains and answer "which process tree", which is a different
question from "which activity".

### The design

- A **candidate** is a declaration whose `tgid` is the ancestor being examined, **or** whose `ppid`
  is. The second clause is what lets a hook explain anything at all.
- The verdict is one of **attributed**, **unexplained** (no candidate), or **ambiguous** (more than
  one tool call in flight at the action's timestamp, per point 1's counter).
- Ambiguity is decided **before** a winner is picked, so the "latest" tie-break is never reached
  where it would be a guess.
- An ambiguous entry carries token `0`, like an unexplained one. The format has one way to say *no
  ground truth* and a second would change `F1.SIM.02`. The **counts** are what tell them apart.
- The declaration carries its parent: the daemon reads `/proc/<peer>/stat` while the peer is still
  connected — derived from the kernel's own `SO_PEERCRED` pid, never claimed by the caller, and read
  at the only moment a 1 ms process is certainly still there.

### Tests

**Existing, kept unchanged:** `actions_are_attributed_by_ancestry_and_not_by_arrival_order`
(`record.rs:425`) — its declarers are ancestors, so it must keep passing exactly as written. If it
needs changing, the rule has grown beyond this plan.

**New:**
- **A hook's declaration explains its sibling's actions** when one call is in flight.
- **Two in flight make the actions ambiguous, not wrong** — no token from either declaration appears.
  Written so that "latest wins" fails it.
- **Ambiguity is counted and visible** in the summary.
- **A declaration carries its parent**, asserted against the connecting process rather than a value
  the caller sent.

### Documentation

Plan `F2.WS.03`'s row currently says a declaration is attributed to *"a process in the action's own
ancestry"*, which a hook is not — that sentence changes. `F0.ASSET.02` and §4.6 gain that the
manifest carries `attributed`, `ambiguous` and `unattributed`, and that the correlation gate scores
against the attributed set with the other two stated beside it. A memory records the two durable
facts: that the declarer is not an ancestor, and why a guessed ground truth is worse than a guessing
detector.

---

### Closing

Verified against `record.rs:205-229` (the walk with no end bound), `:34-40` (the conservative
principle this extends), `:425-455` (the test whose declarers are ancestors and which must keep
passing unchanged), and `declare.rs:56` (`ppid` never stamped). Against the field: `docs/research/03`
§3 for marking as the norm, and §2.3 for the sibling case being the canonical failure of ancestry
attribution rather than an edge case. **One claim of the skeleton fell** — that ambiguity would be
decided from the candidate set. It is decided from the in-flight count, which is both simpler and
correct where several stale declarations still match a single live call. Open: nothing of its own.

## 3. `ADR-10` step 2 — does the sensor load on 7.1.5

**Done when:** the answer is in `STATE.md` verbatim, whatever it is.

Step 1 is **done**: the tracepoint offsets hold on this kernel — `filename` 24, `flags` 32, `mode` 40
— which is what the program compiles in, checked for the first time above the VM matrix's 7.0
ceiling.

An unprivileged run has already been made and was refused **for permission**, not for the kernel, so
the question is still open. One command, from the repository root:

```bash
sudo ./target/debug/aisme-agentd --load-sensor
```

It loads the program, reads its capabilities and **detaches immediately** — it is a question, not a
session. `ACCEPTED` with its capabilities or `REFUSED` with the kernel's own words: both go into
`STATE.md` verbatim. A `REFUSED` on 7.1.5 would be worth knowing before F3 plans around the sensor.

### 1. Challenge

*Is this the best solution?* It is the only one left. `docs/research/03` verified against kernel
source that the alternative read — the kernel's own `__filename_val` copy — is **unreachable from
eBPF** and would not close the TOCTOU window anyway, so there is no route that avoids loading a
program. And `ADR-10` establishes that neither a guest nor the seccomp path can carry the recording.

*Is it coherent with the specs?* Only through `ADR-10`, which is what that ADR is for. `I-12` is
narrowed by a written decision with a named scope and an expiry, not by a verbal yes.

*Can it be simplified?* It already was: step 1 moved the cheap check in front of the load, and it has
**passed** — so what remains is one command.

### 2. Verification

- **Nothing is loaded by any test, gate or hook**, and `platform::probe()` is untouched. The tripwire
  for the exception growing is named in the ADR:
  `nothing_measured_means_no_bpf_load_is_attempted_on_the_host`.
- **The program is observe-only and bounded.** One tracepoint that always returns 0
  (`crates/aisme-ebpf/src/main.rs:107`), whose first act is to look the caller up in `AISME_SESSIONS`
  and return if it is absent (`:122`) — so a loaded program with no session registered observes
  nothing and reserves nothing from its ring buffer. `bpf_probe_write_user` appears nowhere in the
  tree except in the gate that forbids it.
- **A refusal is now diagnosable.** The message distinguishes a permission refusal from an absent map
  type and appends nothing where it establishes neither, which it did not do before this week.
- **The answer is recorded whichever way it goes.** A `REFUSED` on 7.1.5 is a measured fact about a
  kernel above the matrix's ceiling, and it is worth more than the recording it would block.

### 3. Implementation

The one command above, run by the owner. Then the output verbatim into `STATE.md`, the ADR's second
follow-up ticked, and — on `ACCEPTED` — point 4 proceeds. On `REFUSED`, the reason becomes an `F0.VER`
row and point 4 waits for a kernel the matrix covers.

### 4. Tests

None, deliberately. A one-off manual act is not a test, and giving it one is how an exception becomes
a habit. What the **recording** owes is in point 4.

### 5. Documentation

`docs/ai/STATE.md` (the output), `docs/adr/10_…md` (the follow-up), and on a refusal an `F0.VER` row
carrying its prediction as `§F0.4` requires.

### Closing

Verified against `main.rs:107` and `:122` (observe-only, and silent with no session),
`sensor.rs:168-198` (a refusal carries the kernel's words), and the owner's own measurement of the
format file on 2026-09-15. **No claim fell.** Open: the `sudo`, and nothing else.

---

## 4. `F0.ASSET.02` — the reference recording

**Done when:** `tests/fixtures/reference-trace/` exists with a manifest naming what produced it.

Everything that does not need the recording is built: the recorder, the synthetic generator, the
attribution, and the declaration path. What is owed is one real session on this repository, in
**observe-only** mode — not through the seccomp trap, because that denies every write-mode open and
an agent that cannot write a file is not a session.

The manifest carries `agent`, `model`, `repository_commit`, `wallclock_seconds`, the content hash
sealed by `xtask`, and now the three attribution counts. Two properties are owed with it: the hash is
over the content it names, and an empty recording is **refused** rather than written — a zero-entry
fixture that passes a gate is the failure this asset exists to prevent.

The hook goes in `~/.claude/settings.json` and nowhere else. A repository's settings file is the
attack surface itself, and the field record is a list of reasons why.

### 1. Challenge

*Is this the best solution?* The recording is specified as *"an actual working session, not a
script"*, and every substitute has been refuted in writing: a session record holds **838 tool calls
and no actions**; a guest cannot host a real session without the owner's credentials in it; the
seccomp path denies every write-mode open; and the synthetic generator produces a workload, not a
session. What is left is one real session with the sensor attached.

*Is it coherent with the specs?* With one amendment it now needs: `F0.ASSET.02` says the recording
perturbs nothing *because* it is observe-only. That is still true, and the **reason** it must be
observe-only is stronger than the row states — the trap would cripple the agent, not merely slow it.

*Can it be simplified?* No, and one apparent simplification must be refused explicitly: recording a
**scripted** session would be cheaper and would produce a fixture whose shape is the script's rather
than an agent's. `docs/12` measured the difference — a real session ran about five tool calls an hour
against §2.22's normative two hundred, nearly all subprocess executions — and a fixture that gets the
shape wrong misleads every budget derived from it.

### 2. Verification

- **The fixture must carry no paths.** The format was built for this: entries carry `args_hash` and
  never the argument — *"a fixture is committed and a path is data"*. This is the property to check
  before the file is committed, not after.
- **An empty or near-empty recording is refused rather than written.** A zero-entry fixture that
  passes a gate is the failure this asset exists to prevent, and the same applies to one whose actions
  are nearly all unexplained: that is a recording whose hook was not firing, and it must fail loudly.
- **The three counts go in the manifest**, so a later reader can tell a heavily-parallel session from
  a broken one.
- **The session must not be adversarial or unusual.** It is ordinary work on this repository. A
  fixture recorded while deliberately exercising the product would measure the product's own traffic.

**This is where the owner's open question lands**, and it is the only thing in this plan that a
decision changes rather than schedules: whether a fixture stating an ambiguous fraction is acceptable.

### 3. Implementation

- Merge the hook — both phases — into `~/.claude/settings.json`, and verify it fires before recording
  anything. *A missing start stream is an incident, not a quiet gap*, and it is invisible unless
  checked: the field record carries five separate reports of hooks configured and silently not firing.
- Start the daemon with the sensor attached, per `ADR-10`.
- Run `aisme run --scope <repo> -- claude` and do ordinary work.
- `aisme-agentsim --to-trace <wal-dir> tests/fixtures/reference-trace/trace.json`, then seal the
  manifest with `xtask`.
- Inspect the three counts before committing, and re-record if the unexplained fraction says the hook
  was not firing.

### 4. Tests

**Already written:** the round trip, attribution by subtree under interleaved tool calls, an
unexplained action kept with token `0` and counted, a kind with no action counted by name, and the
determinism of the synthetic generator.

**Owed with the recording:** that the manifest's hash is over the content it names, and that an empty
recording is refused rather than written.

### 5. Documentation

`tests/fixtures/reference-trace/manifest.toml` (written by the recorder from what actually ran, not a
sentence somebody maintains), `F0.ASSET.02`'s row (observe-only **because the trap denies every
write**, which is the measured reason and stronger than the perturbation argument it gives today),
and `§4.6` (the gate scores against the attributed set with the other two counts stated beside it).

### Closing

Verified against `ADR-10` (which establishes there is no other route), `docs/12` (838 tool calls and
no actions in a session record; five tool calls an hour against a normative two hundred), and the
measured fact that an observe-only session records zero actions without the sensor. **No claim fell.**
Open, and the owner's: whether the ambiguous fraction is acceptable in the asset.

---

## 5. `F2.WS.11` half B — the denial nobody was notified about

**Done when:** a denial the filter does not trap is *recorded*, not only enforced.

Half A is measured on the host: `/bin/rm` deleting a file inside the scope and outside it raises
**identical** notification traffic — 2 delivered, 0 denied — and only one deletion happens, so what
enforced the difference woke nobody. That is §2.2.1's argument in one comparison.

What remains is the **recording**: `sys_exit_openat` in `crates/aisme-ebpf`, enabled per session,
emitting a `FileOpen` with `outcome = Denied`, `FLAG_INFERRED_FROM_EXIT` and the errno when the
return is negative; and the join by `(tgid, seq)` in `agentd` so one record carries the errno rather
than two records existing. It needs a guest, and an `EACCES` that is not ours is recorded as
**ambiguous** rather than attributed — the same discipline as point 2, in a different plane.

### 1. Challenge

*Is this the best solution?* Exit-tracepoint inference is the only way to see a denial the enforcer
never reported, because the whole property is that nothing woke. The alternative — asking Landlock —
does not exist: a ruleset has no audit channel at this ABI.

*Is it coherent with the specs?* It is `docs/05` point 11 and this task's own second half, and the
flag it needs, `FLAG_INFERRED_FROM_EXIT`, is already named in the plan's `RawEvent` block. **Bits 0
and 1 are taken** (`FLAG_TRUNCATED`, `FLAG_PATH_UNRESOLVED`), so bit 2 is free and a flag consumes a
bit and never an offset — §3.6 is kept.

*Can it be simplified?* One thing can, and it should be said before somebody builds the join: for
**F2's purposes** the exit event alone is enough. The `(tgid, seq)` join to the enter event exists so
one record carries both the path and the errno; a phase that only needs *"a denial happened and
nobody was notified"* can be satisfied by the exit event carrying the errno and the flag, with the
join deferred. Building both at once is how this task has stayed open.

*A note that the field record adds:* an inferred record is a **flag on an outcome**, and
`FLAG_INFERRED_FROM_EXIT` is exactly the honesty this plan asks for elsewhere — *we did not observe
this decision, we inferred it*. It sits beside `FLAG_PATH_UNRESOLVED`, which says *we did not resolve
this path*, and the two must stay distinct because they are different admissions.

### 2. Verification

- **An `EACCES` is not necessarily ours.** A write can fail for ordinary permission reasons. The
  record says *an access denial consistent with the session's ruleset*, and attributes it only where
  the path lies outside the declared scope — knowable in user space without asking the kernel who
  denied it. Where it is not knowable, the record says ambiguous, which is point 2's discipline in a
  second plane.
- **This runs in a guest, and `I-12` is untouched by it.** `ADR-10`'s exception is for one
  observe-only recording on the host and says nothing about this; the exit program is loaded where
  every kernel-touching test is loaded.
- **Half A must keep asserting on an operation the filter does not trap.** If somebody later adds
  `unlink` to the filter, `a_denial_the_filter_does_not_trap_wakes_nobody` becomes a test of seccomp
  wearing Landlock's name. The test's own comment says so and stays.

### 3. Implementation

- `crates/aisme-ebpf` gains `sys_exit_openat`, enabled per session by the same `AISME_SESSIONS`
  lookup the enter program uses, emitting a `FileOpen` with `outcome = Denied`,
  `FLAG_INFERRED_FROM_EXIT` (bit 2) and the errno when the return value is negative.
- `agentd` records it. The `(tgid, seq)` join to the enter event is **deferred** and named as such, so
  this task can close on the property it owes.
- `cargo xtask vm run` gains the line that exercises it.

### 4. Tests

**In a guest:** the WAL contains exactly one denial record carrying `FLAG_INFERRED_FROM_EXIT`; a write
**inside** the workspace produces none; an `EACCES` from ordinary permissions is recorded as ambiguous
rather than attributed; and on a kernel without the Landlock ABI the ruleset is skipped, the tier
reads `L2-`, the banner names the lost function, and the run still works.

**On the host, unchanged:** `a_denial_the_filter_does_not_trap_wakes_nobody`.

### 5. Documentation

`F2.WS.11`'s row (half B's done-condition, and that the join is deferred with its reason), the plan's
`RawEvent` block (bit 2), and `docs/ai/memory/landlock-l2-file-deny.md` (that seccomp fires before the
LSM, which is what makes half A measurable only outside the trapped set).

### Closing

Verified against `event.rs:19-33` (bits 0 and 1 taken, bit 2 free), the plan's `RawEvent` block (the
flag is already specified), and the host measurement of half A. **One claim of the skeleton fell:**
this task does not need the `(tgid, seq)` join to close its done-condition, and treating the two as
one piece of work is why it has stayed open. Open: it needs a guest boot, which nothing here changes.

---

## 6. GATE F2 and the phase close

**Done when:** the gate's output is in `STATE.md` verbatim and F2 is closed.

The five enforcement lines have been re-run on the host against the shipped configuration — a daemon
with `CapEff 0000000000000000`, every line through a grandchild — and again after the per-session
bindings landed, against the peer's real home. The block has a sixth line: the same three verdicts
with the **agent's own** permission-skipping flags set, compared on the verdicts and on the `asked`
column.

`PASS` and `PENDING` are acceptable, `SKIP` needs its reason on the same line, and the output goes in
verbatim — a gate summarised is a gate nobody can check. Plan `:1360` places item 4 before this one,
which is the only reason the phase is still open.

### 1. Challenge

*Is this the best solution?* The gate is the phase's definition of done, so the only thing worth
challenging is whether its lines still test what they claim. Two have been corrected this way already:
the guest daemon ran as `uid 0`, where `CAP_SYS_PTRACE` makes Yama irrelevant, so the enforcement
lines measured a configuration the product does not ship; and an earlier revision omitted
`--trap-openat`, which would have made three lines **pass by enforcing nothing**.

*Is it coherent with the specs?* Yes, and the one thing it must not do is close the phase on a gate
that passes for a reason the product does not have.

*Can it be simplified?* No. Each line is somebody's input, and the sixth — the agent's own
permission-skipping flags — is new precisely because the property it asserts held by construction and
was tested nowhere.

### 2. Verification

- **`F2.WS.11` half B does not block the phase.** It is a done-condition of a task, and its first half
  is measured; item 4 is what plan `:1360` places before the gate. The row must say which of the two
  blocks what, or the phase closes on a judgement rather than on the plan.
- **A `SKIP` carries its reason on the same line.** `verify-backlog` skips today for a missing
  prerequisite and that is acceptable; a `SKIP` without a reason is a `FAIL` in disguise.
- **`bench-t0`'s numbers are recorded with their sample counts.** A p999 over a hundred samples is the
  maximum wearing a percentile's name, and the command already prints them.

### 3. Implementation

Run the block: `test-skeleton`, the six enforcement lines in **one** guest boot, `verify-budgets
--profile skeleton`, `bench-t0 --syscalls 100000`. Paste the output into `STATE.md` verbatim. Then
close F2 in `STATE.md` and the plan's phase table.

### 4. Tests

None of its own — every line of the gate is somebody else's test, and the gate is the test of the
whole.

### 5. Documentation

`docs/ai/STATE.md` (the output verbatim, and *Next up* reduced to F3), the plan's phase table, and a
handoff note in `docs/ai/handoff/` naming what F3 inherits.

### Closing

Verified against the `GATE F2` block as it stands and against plan `:1360` for the ordering. **No
claim fell.** Open: it waits on item 4, which waits on item 3, which waits on one `sudo`.

---

## 7. What the field record adds beyond F2

Recorded as plan rows, not executed here.

- **`D-3` gains two sources.** BPF LSM is where arguments are already in kernel space; 69 % of
  syscalls take a user pointer vulnerable to the TOCTOU class; Falco removed syscall-enter events
  from its pipeline over it. `F3.EN.09` and `F3.EN.11` before `F3.EN.12` was already the order.
- **Sleepable tracepoints and `bpf_copy_from_user()`** (merged 2026-04-22) are the reliable-read
  mechanism for `F3.PT.*`, and they make the 63-byte `__filename_val` route unnecessary as well as
  impossible.
- **A cgroup per activity is the right answer for the SDK, and only there.** `bpf_get_current_cgroup_id`,
  inherited on fork, unprivileged under systemd delegation, with `clone3(CLONE_INTO_CGROUP)` closing
  the create-then-migrate race. It needs the process that *spawns* the work to cooperate, which a
  third-party agent will not — so it belongs to `AI Sentinel SDK` (F9/F10), where AISME controls the
  spawn, and it must not be written into F2 as though an off-the-shelf agent could use it.
- **`TRACEPARENT` is a second join key, and it is kernel-visible.** When Claude Code's tracing is
  active, *"Bash and PowerShell subprocesses automatically inherit a `TRACEPARENT` environment
  variable containing the W3C trace context of the active tool execution span"*, and
  `CLAUDE_CODE_PROPAGATE_TRACEPARENT` extends that to hook subprocesses. That puts the tool-execution
  identity **inside the observed process's own environment**, where a sensor reading it at `execve`
  gets the join with no timing heuristic and no dependence on the hook stream at all. It is beta and
  opt-in (`CLAUDE_CODE_ENABLE_TELEMETRY=1` plus `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`), and the span
  has a start and an end by construction. **An enhancement for F3's sensor, not F2's base case** — but
  it is the strongest join this product could have, and it should not be discovered late.
- **`io_uring` is a blind spot and goes in the threat model as one.** Requests travel through shared
  memory, so syscall tracing sees ring setup and not the work; punted work runs in `io-wq` kernel
  threads outside the normal syscall path, where syscall-keyed rules may not fire at all.
- **Two dead ends, recorded so they are not retried:** the audit container ID was proposed over eight
  revisions and **never merged**; `PR_SET_NAME` is reset by `execve`, which is precisely the
  transition a tag would have to survive.
- **The bar for a claim.** *AgentSight*'s 2.9 % is the only peer-reviewed measured overhead for an
  eBPF AI-agent monitor, and it publishes no attribution accuracy and no detection rate. A fixture
  that states its own ambiguous fraction is already more than the published state of the art offers,
  which is `D-9`'s argument with a number attached.

---

## Whole-document coherence

Read end to end after the seven were closed, looking for a point that contradicts another or leaves
one in false.

1. **Every point in this plan now refuses to produce a value where the evidence does not support
   one, and that is one rule rather than six coincidences.** Point 1 says an unknown phase is a start;
   point 2 marks ambiguity rather than guessing; point 3 records a refusal as a measurement; point 4
   refuses an empty recording; point 5 records an ambiguous `EACCES` as ambiguous. The rule already
   existed in the tree — `record.rs:34-40`, *"an unattributed action is visible, while a wrongly
   attributed one is not"* — and what changed is that it is now applied consistently.
2. **Points 1 and 2 are one change split in two, and the split is load-bearing.** Point 2's ambiguity
   is decided from point 1's in-flight count, so point 2 cannot land first. But point 1 is useful on
   its own — the WAL records when calls end whether or not attribution uses it yet — so the order is
   not merely a dependency, it is two commits each of which leaves the tree better.
3. **Point 3 gates points 4 and 6 and nothing else.** A `REFUSED` would not stop points 1, 2 or 5.
   Worth stating because the one command outstanding looks like it blocks the phase, and it blocks
   two of seven items.
4. **Corrected while reading:** point 5's done-condition bundled the exit tracepoint with the
   `(tgid, seq)` join. They are separable, the join is not needed for the property the task owes, and
   bundling them is why the task has stayed open across two phases.
5. **The one thing that would falsify the whole plan** is the hook not firing. Five reported cases of
   silently non-firing hooks are recorded in `docs/research/02` §4.4, and a hook that crashes looks
   exactly like one that never fired. That is why point 4 verifies the stream **before** recording
   rather than discovering it in the counts afterwards.

**Against the specs**, nothing here contradicts an invariant or an `H-xx` finding. Point 1 adds an
append-only variant under `ADR-08`. Point 2 corrects one sentence of `F2.WS.03` that a pre-tool hook
cannot satisfy. Point 3 narrows `I-12` through the ADR that exists for it. Points 4, 5 and 6 add
nothing and claim nothing.

## What is still open

**The research is in**, recorded in full at `docs/research/02` and `docs/research/03`, and it changed
point 1's design rather than merely confirming it. Three things could not be closed and are carried as
open rather than assumed: whether `PostToolBatch` fires when a turn is interrupted and whether its
`tool_calls[]` includes denied calls; whether a resumed deferred call reuses the **same**
`tool_use_id`; and whether compaction can interleave with an in-flight call. All three make the
recording mark *more* ambiguity, never less, so none of them blocks the design.

**One decision is yours and it is narrow:** whether `F0.ASSET.02` may be a fixture that **states an
ambiguous fraction** rather than explaining every action. The research says marking is the norm for
exactly this use, and that the alternative manufactures agreement with the thing the fixture is meant
to measure. Everything else in this plan is executable.
