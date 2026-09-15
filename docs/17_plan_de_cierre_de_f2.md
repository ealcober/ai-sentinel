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
- The daemon records an end as a `ToolCall` event with `Outcome::Completed` rather than `Observed`.
  That is an existing enum value on an existing field, so §3.6's append-only rule is untouched — no
  new flag, no new offset.
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

## 2. Attribution marks ambiguity instead of guessing

**Done when:** a trace attributes what it can, marks what it cannot, and the manifest states both.

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
