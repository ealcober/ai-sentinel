# Challenge-amplification — the two recommendations F2 leaves to the owner

`docs/10` closed F2's plan and left two decisions that are not a step inside a plan. This document
amplifies the **recommendation** made for each, so that taking it is execution rather than design.

Two points, in the order the work would happen. Point 1 unblocks four things and point 2 unblocks
one, so point 1 is first.

## How to read this

Each point is five sections. **Challenge** asks whether the recommendation is the best answer and
whether the project's own specifications agree. **Verification** is a second pass asking whether it
is safe, clear and compliant, and says so plainly when it is not. **Implementation** is what will be
done, already sieved by the two above. **Tests** names what changes and what is new.
**Documentation** names every file and what changes in it.

Nothing here touches the repository. The measurements below were taken with read-only scripts
before any point was written, and each is named where it is used.

## The measurements, taken before anything was written

Five, all on this host, `kernel.yama.ptrace_scope = 1`, 2026-09-15. What each result would mean was
written down before it existed.

| # | Question | Answer |
|---|---|---|
| M1 | Does **ancestry alone** let a process read a descendant's memory, with no `PR_SET_PTRACER`? | **Yes**, at depth 1, 2 and 3 |
| M2 | What does a supervised process get when its supervisor is `SIGKILL`ed **mid-session**? | Every later `openat` **refused**: 102 639 ok, then 297 361 denied, and it ran to completion rather than hanging |
| M3 | What exit semantics does today's `exec` give? | `exit 42` → 42; `SIGTERM` → death **by signal**, not exit 143 |
| M4 | What does a real session record contain? | 4 879 records over seven days, 838 tool calls — **830 of them `Bash`** — carrying intents and **no actions** |
| M5 | Does `PR_SET_PDEATHSIG` survive `execve` and fire? | **Yes**: the command died when the intermediary was `SIGKILL`ed |

M1 and M5 are the two that decide point 1. M4 is the one that **refutes** point 2's recommendation.

---

## Point 1 — `aisme run` stops `exec`-ing and becomes the session's ancestor

**Done when:** `aisme run --trap-openat -- sh -c '<anything that forks>'` is supervised to any
depth, with no daemon holding any capability, and the five GATE F2 enforcement lines pass against
the configuration `deploy/systemd/aisme-agentd.service` describes.

### 1. Challenge

*Is this the best of the three?* The three were: give `agentd` `CAP_SYS_PTRACE`; split a privileged
supervisor out as `aisme-loaderd` already is for `CAP_BPF`; or make `aisme run` the ancestor.

**The first is refused by the project's own precedent, not by preference.** `docs/06` point 3
refused `agentd` a writable policy-map descriptor on the grounds that it would leave
`CapabilityBoundingSet=` decorative — *"the capability gone and the authority kept"*.
`CAP_SYS_PTRACE` is **broader** than what was refused there: it reads any process's memory on the
machine, not one map. Granting it would make that refusal incoherent.

**The second works and costs more than the third.** A privileged supervisor is a new binary, a new
unit, a new socket and a new thing to audit, and it still puts `CAP_SYS_PTRACE` somewhere.

**The third costs no privilege anywhere, and M1 is why it works.** Yama grants an ancestor
unconditionally. Measured at depth 3 with no `PR_SET_PTRACER` present at all: a process reads its
child after `execve`, and its grandchild, and its great-grandchild. Every real agent forks, and
depth is the case that breaks today.

*Is it coherent with the specs?* **It is what two of them already ask for.**
`docs/design/02_aisme-run.md` step 8 is *"serve terminal adjudication on the controlling TTY **for
the life of the session**"* and step 9 is *"**on exit**: close the session, release the cgroup,
flush the WAL, print a one-line summary"*. Both assume `aisme run` outlives the command. F2 chose
`exec`, and has since had to move the summary before `exec` (`docs/09` point 2), move the
adjudicator into `agentd` (`F2.WS.06`), and move the cgroup release into `agentd` (`docs/10`
point 2). **The Yama finding is the fourth thing that one choice has cost.**

*Can it be simplified?* One decision inside it can, and section 3 takes it: whether `aisme run`
evaluates the policy itself or asks the daemon. It asks the daemon.

**The objection on record, and it falls to M2 and M5.** `F2.WS.08`'s row says *"`exec`, not
`fork`+`wait`, so the exit status is the child's with nothing between, and nothing in the chain can
be skipped by killing an intermediary."* Both halves are answerable:

* **Killing the intermediary does not free the child.** M2: with the supervisor `SIGKILL`ed
  mid-session, the supervised process had every subsequent `openat` refused — 297 361 of them — and
  ran to completion rather than hanging. The kernel provides the property; `exec` was not what was
  providing it.
* **And the child can be made to die with it.** M5: `PR_SET_PDEATHSIG` survives `execve` and fired,
  killing the command when the intermediary was `SIGKILL`ed. So "nothing can be skipped by killing
  an intermediary" is preserved exactly, by one `prctl`.
* **The exit status is reproducible.** M3 fixes the target: `exit 42` must give 42, and a death by
  signal must be observable **as a death by signal** and not as exit 143. That is `waitpid` plus
  re-raising the signal on self, and section 4 pins both.

### 2. Verification

Safe, clear and compliant, with five properties that must be explicit because each is a way the
change could be wrong.

- **The supervisor must be the ancestor, and it must be the one that reads.** `aisme run` will read
  the trapped path and perform the validated open, because it is the only process in the design
  that Yama permits without a capability. `agentd` will not read the target's memory at all after
  this, and `PR_SET_PTRACER` and `peer_pid` leave the session path entirely. **Deleting them is part
  of the change**, not a tidy-up: a grant left in place is a grant someone will rely on.
- **The policy stays the daemon's, and so does the decision.** `aisme run` will ask `agentd` for a
  verdict per trapped open and will not hold a `CompiledPolicy`. This is `docs/10` step 1's
  property and it is not weakened here: a session that evaluated its own policy would be choosing
  whether to be enforced. The cost is one control-plane round trip per open, and **T1's budget has
  the room**: 46.6 µs measured against 400 µs target and 1000 µs hard.
- **`I-28` is unchanged.** The allow path is still `openat2` with `RESOLVE_NO_MAGICLINKS` performed
  by the supervisor and delivered with `ADDFD`; only *which process* performs it changes. The
  `reproducible` subset and its refusals move with it, untouched.
- **The child must be confined before it runs, and the parent must not be.** Landlock and the
  seccomp filter will be applied in the **child**, after `fork` and before `exec`. Applying either
  in the parent would confine the supervisor: a Landlocked `aisme run` could not open the files it
  must open on the child's behalf, and a filtered one would trap its own opens.
- **A session that cannot be supervised must not run.** The child will wait for the parent to
  confirm it holds the listener before `exec`, over the same socketpair that carried it. Without
  that, a child could `exec` and start issuing traps before the parent's loop exists, and the
  kernel would answer them with `ENOSYS`.

**Nothing here is ambiguous enough to ask about.** The one judgement — daemon-decides versus
session-evaluates — is settled by `docs/10` step 1 and by a measured budget, not by taste.

### 3. Implementation

**`crates/aisme-cli/src/run.rs`** — `run()` becomes fork-and-supervise:

1. Parse, derive the session id, create and **join** the session cgroup. The parent joins, so the
   child inherits it; this is unchanged except that the joiner is no longer the command.
2. Print the session line. It stays before the fork, so its position does not depend on scheduling.
3. Connect to `agentd` and register the session, carrying `session_id`, `tty`, `cgroup`,
   `trapping`, `unattended` and `escalate` as it does today. **No listener travels on this
   message any more** — the daemon no longer answers notifications — so `Registered.listener`
   becomes dead weight and is removed with it.
4. `socketpair`, then `fork`.
5. **Child:** `PR_SET_PDEATHSIG(SIGKILL)`; `apply_write_scope`; `install_openat_filter` when
   `--trap-openat`; send the listener to the parent over the socketpair; wait for the parent's
   one-byte acknowledgement; `exec`. Nothing that can fail is placed after the filter.
6. **Parent:** receive the listener; run the notification loop; `waitpid`; then exit with the
   child's status — `std::process::exit(code)` for a normal exit, and for a signal, restore the
   default handler and `raise` the same signal on itself so the caller sees a death by signal.
7. On exit, close the control socket. The daemon's `cgroup.events` poll then releases the cgroup
   exactly as `docs/10` point 2 built it; nothing about the release changes.

**`crates/aisme-cli/src/platform.rs`** gains one function, `serve_session_notifications`, which is
the composition root naming `aisme_linux`'s loop — the same shape `aisme-agentd::platform` has
today, in the crate that now runs it. `allow_supervision_by` is **deleted**.

**`crates/aisme-linux/src/seccomp.rs`** is unchanged. `serve_notifications_with` already takes the
listener, a decision callback and a recording callback; the caller changes and the adapter does
not. `allow_ptrace_by` and `peer_pid` lose their last caller and are **removed** from the crate's
public surface.

**`crates/aisme-proto/src/rpc.rs`** gains `decideOpen`, class `LocalPeer`: params
`{ session_id, path }`, result `{ verdict }`, not idempotent-sensitive because it changes nothing.
Its Annex I row says what it is for and what it is not: it carries no descriptor, grants nothing,
and a session that stops calling it is a session that has stopped enforcing — which the daemon sees
as silence, not as permission.

**`crates/aisme-agentd`** loses the session thread and keeps everything else. `ipc.rs` answers
`decideOpen` by evaluating the compiled policy it already holds, and by asking its
`TerminalAdjudicator` when the verdict is `Escalate` — so the prompt still comes from the daemon,
on the tty the session named, and `F2.WS.06`'s property that the unattended answer is never read
from the daemon's environment is untouched. `platform::serve_session_notifications` and
`answer_notifications` are **deleted**; `release_session_cgroup` stays and keeps its own thread.

**What is deliberately not in this point:** moving the adjudicator or the terminal into
`aisme run`. Design step 8 asks for it and `F8.UA.01` owns it, and doing it here would mix a
privilege correction with a UI relocation.

### 4. Tests

**Existing, changed:**

- `crates/aisme-cli/tests/session.rs::the_exit_status_is_the_childs` gains the case M3 measured:
  a command killed by a signal must make `aisme run` die by the **same signal**, not exit 143. The
  test asserts on the wait status, not on a shell's rendering of it.
- `crates/aisme-agentd/src/ipc.rs`'s registration tests drop the listener entirely and keep the
  cgroup validation, which is where their value now is.
- `trapping_without_a_daemon_refuses_before_installing_the_filter` keeps its property and moves to
  the parent side of the fork.

**New:**

- **The one this point exists for**, in `tests/session.rs`: `aisme run --trap-openat -- sh -c 'cat
  /etc/hostname'` succeeds, and the daemon reports the opens of the **grandchild** as delivered.
  Today it reports 13 denials. It runs on the host, because it loads no BPF program.
- Depth, in the same file: a command nested three levels — `sh -c 'sh -c "sh -c ..."'` — is
  supervised throughout. M1 says the kernel allows it; this says the product does.
- **Killing the intermediary kills the session**: `SIGKILL` the `aisme run` process and assert the
  command is gone within a bounded wait. This is M5 as a product test, and it is the one that keeps
  `F2.WS.08`'s stated property from being quietly lost.
- **Killing the intermediary before that, refusal not escape**: with `PDEATHSIG` removed in a test
  build the orphan must find every `openat` refused. This is M2 as a product test and it fails
  closed by construction; it exists so that a future change that drops the filter is caught.
- **The parent is not confined**: after the fork the parent can open a file outside the session's
  scope, and the child cannot. A ruleset applied on the wrong side of the fork passes every other
  test in this list.
- **`decideOpen` is refused for a peer that is not local**, beside the existing
  `a_session_registration_from_a_stranger_is_refused`.
- **A session whose daemon refuses `decideOpen` denies the open**, rather than defaulting to allow.

### 5. Documentation

- **`docs/design/02_aisme-run.md`**: §3's step 7 stops saying *"`exec` the command"* and says fork,
  confine, `exec`, supervise, wait. Steps 8 and 9 stop being marked as owed elsewhere, because the
  process that must perform them exists again. The note that steps 4 and 5 run in the opposite
  order to their numbers stays, and gains that both now happen in the child.
- **Plan `F2.WS.08`'s row**: the `exec` sentence is rewritten rather than deleted, and it records
  why it changed — M2 and M5, named, with the figures. A comment that mentions a decision that has
  been reversed is worse than none.
- **Plan `F2.WS.05`'s row**: the supervisor is `aisme run`; the decision is the daemon's; the
  listener no longer travels on `registerSession`.
- **Plan Annex I**: the `registerSession` row loses its descriptor; a `decideOpen` row is added.
- **Plan `GATE F2`**: the block's five enforcement lines are unchanged, and the sentence added
  after them says they now measure the shipped configuration, naming the commit that made it true.
- **`docs/ai/invariants.md`**: no invariant changes. `I-28` is untouched and `I-19` still holds.
  A line is added to the `I-12` discussion recording that the supervision path loads no BPF program
  and therefore runs on a host.
- **`docs/adr/`**: **one ADR**, because this reverses a recorded decision and `CLAUDE.md` requires
  it. It argues from M1, M2, M3 and M5, states the three options and their costs, and records that
  `CAP_SYS_PTRACE` was refused for the same reason `docs/06` point 3 refused a policy-map
  descriptor.
- **`docs/ai/memory/yama-blocks-the-supervisor.md`**: its "how to apply" line already says the
  choice is architectural; it gains the answer taken and the measurement behind it.
- **`docs/ai/STATE.md`**: *Blocked* empties, and the Done row carries the grandchild figures before
  and after.

**Closing.** Verified against `crates/aisme-cli/src/run.rs` as it stands, `docs/06` point 3's
refusal, `docs/design/02_aisme-run.md` steps 7 to 9, plan `F2.WS.08`'s row, and five measurements
taken before the point was written. **The recommendation survives, and the objection on record
falls**: `F2.WS.08` justified `exec` by saying nothing in the chain can be skipped by killing an
intermediary, and M2 shows the kernel already provides that while M5 shows one `prctl` restores the
rest. Two things the skeleton did not say are now fixed rather than left to whoever implements it:
the filter and the ruleset go in the **child**, and the child must not `exec` until the parent has
the listener. Open: nothing that blocks; the adjudicator's move to `aisme run` is named as
`F8.UA.01`'s and deliberately excluded.

---

## Point 2 — the reference-trace recording

**Done when:** `tests/fixtures/reference-trace/` holds a recording whose `manifest.toml` names what
produced it, and both gates it exists for — the CPU gate and the correlation gate — can read it.

### 1. Challenge

**The recommendation this point was written to amplify does not survive its own first
measurement.** `docs/10`'s step 6 recommended *"deriving the trace from the agent's own session
record"*, on the grounds that only the agent knows which actions each of its tool calls caused.
M4 says that is half true and the half that is false is the half that matters.

*What a session record actually contains.* Measured on this session: 4 879 records over seven days,
**838 tool calls**, of which **830 are `Bash`**. Every record carries a timestamp, a uuid, a parent
uuid and, for results, the id of the tool call that produced them. So the record holds **intents,
linked to each other, and no actions at all**: it knows a shell command was run and it does not know
which files that command opened.

*What the format needs.* `Entry` is `{ t_offset_us, action, args_hash, correlation_token,
declared_intent }`, and `action` is one of five: `toolcall`, `file_read`, `file_write`, `exec`,
`https_request`. Four of the five are **actions a kernel sees and a transcript does not**.

So the two sources fail in opposite directions, and neither is the answer alone:

| source | intents | actions |
|---|---|---|
| a kernel sensor | no | yes |
| a session record | yes | **no** |

*And the shape is wrong as well as the content.* §2.22's normative reference workload for
component (c) is *"200 tool calls/hour, 4 000 file reads, 600 writes, 40 subprocess executions,
120 HTTPS requests"*. This session ran about **five tool calls an hour**, nearly all of them
subprocess executions, with no file reads or HTTPS requests in its tool surface at all. A trace
derived from it would be a workload no gate should be calibrated against, and §2.22 is explicit
that *"the trace's hash appears in every certification report; a CPU figure certified against a
different trace is not comparable"*.

*What does work, and it is already designed.* `declareToolCall` exists for exactly this join
(`F2.WS.03`): the agent volunteers the intent over the control socket **while** the sensor records
the actions, and the recorder attributes each action to the tool call whose process subtree produced
it. For a subprocess tool call that attribution is exact rather than heuristic — the command's
descendants are that tool call and nothing else — which is what makes it ground truth and not a
guess. The plan's own sentence about the token confirms the split: *"the correlation token never
travels on it — if it did, the engine could join on it and §4.6's precision and recall would measure
the join rather than the correlator"*. The recorder writes the token; the socket never carries it.

*Can it be simplified?* The **recorder** can be built and tested now against a synthetic agent, and
that is section 3. What cannot be simplified is that a real recording needs a real agent on a kernel
where the sensor loads, and section 2 is about that.

### 2. Verification

**This is not 100 % clear and it is not mine to settle. Two questions, and each changes the work.**

**Question A — where may the recording be made?** The sensor must be loaded for actions to exist.
`I-12` says no kernel-touching test runs on a host, and the project's operative reading of it is in
its own code: `platform::probe()` reports nothing present *"so no BPF load is attempted on a host
running the test suite"*. A one-off recording is not the test suite, and a VM cannot host a real
Claude Code session. So either:

- **A1.** The recording is made **on the owner's host**, once, with the sensor deliberately loaded
  and `I-12`'s discussion amended to say that a recording is not a test. This is the only route
  that produces a *real* session.
- **A2.** The recording is made **in a guest**, against an agent that is not Claude Code — the
  simulator driving a real workload, or another tool. `manifest.toml`'s `provenance` field then
  stops saying *"a real Claude Code session"* and says what it is.

**Question B — what declares the tool calls?** Claude Code does not call `declareToolCall`. A
pre-tool hook invoking a one-line client would, and the session is the owner's to configure. Without
it there are no intents, every `correlation_token` is `0`, and the correlation gate gets nothing —
which is the state `docs/10` step 6 already recorded.

**What is not in question, and it is worth stating because it removes the objection I raised
before.** A committed fixture carries **no paths**: `args_hash` is *"a hash of the arguments; the
arguments themselves are not in the trace, because a fixture is committed and a path is data"*. The
only field carrying free text is `declared_intent`, and the format already allows `-` for "said
nothing". So publishing a recording of a real session publishes timings, action kinds, hashes and —
at the owner's choice — nothing else.

### 3. Implementation

**Everything that does not depend on the two answers is built first, and it is most of it.**

- **`aisme-agentsim` gains `--to-trace <wal-dir> <trace-file>`**: it reads the WAL through
  `aisme_core::wal`'s replayer and joins each action to the declaration whose process subtree
  contains its `tgid`.

  *(Corrected while implementing it, and the correction is a layer. This first said `aisme-forensicd`
  "because `forensicd` is the cold path and already owns reading the WAL". **`forensicd` is `L3` and
  `aisme-agentsim` is `L4`**, so `forensicd` cannot name the trace format and `verify-layering`
  would refuse it. The stated reason was also false: the replayer is `aisme_core::wal`, which is
  `L1` and available to both. Writing and recovering the format in one crate puts the round trip
  inside one crate's tests, which is where it belongs.)*
- **The attribution rule is stated in the code and not inferred by a reader**: an action belongs to
  the most recent declaration from a process in its own ancestry, and to `0` when there is none.
  `0` is written, never omitted, because an absent token and an unattributed action must not look
  alike.
- **`aisme-agentsim` gains `--emit-trace <file>`**, which writes a synthetic session in the same
  format with known tokens. It is what lets the recorder be tested without any agent at all, and it
  is how the summary counts and the round trip are pinned.
- **`cargo xtask record-trace`** wraps the three steps an operator would otherwise get wrong in
  order: start the daemon, run the session, convert, and verify the hash the manifest claims.
- **`manifest.toml` is written by the sealing step and not by the recorder**, so that the `sha256`
  has one implementation. `xtask` already computes that hash and `verify-docs` already checks it;
  a second implementation in a product binary is a second answer to the same question. The recorder
  writes `trace.txt` and prints what it recovered; `cargo xtask record-trace` writes the manifest,
  fills `produced_by` from what actually ran, and seals the hash. A provenance line a human
  maintains is a provenance line that will one day be wrong.
- **The correlation token is not the `toolcall_id`**, and this is the subtlety the implementation
  surfaced. The id travels on the control socket, so an engine reading the replayed stream sees it —
  and the plan is explicit that a token the engine can see makes §4.6 measure a join rather than a
  correlator. The recorder derives the token from *who declared, when, and which call*, which is
  stable, unique in practice, and appears nowhere the engine reads. A test asserts the declared id
  never reaches the ground truth.

**Only after Question A and B are answered:** the recording itself, the `agent`, `model`,
`repository_commit` and `wallclock_seconds` fields, and the `sha256` over the content.

### 4. Tests

**New:**

- **Round trip, and it is the one that matters**: `agentsim --emit-trace` writes a synthetic
  session, `agentsim` replays it, `forensicd --to-trace` recovers it, and the recovered summary
  counts and tokens equal the originals. A recorder that loses the attribution passes every test
  that only checks the file parses.
- **Attribution by subtree**: two declarations interleaved in time, with actions from both process
  subtrees arriving mixed, are attributed by ancestry and not by arrival order. The obvious
  implementation — "the most recent declaration" — passes a single-threaded test and fails this one.
- **An unattributed action is `0` and is counted**: an action with no declaration in its ancestry
  reaches the trace with token `0`, and the manifest's `entry_count` includes it. Dropping it would
  make a partial recording look complete.
- **The manifest's hash is over the content it names**: recompute it and compare, which is the
  check `verify-docs` already performs for the fixture directory and which this must not diverge
  from.
- **An empty recording is refused, not written**: a run that produced no actions writes no fixture
  and says why. A zero-entry trace that passes a gate is the failure this asset exists to prevent.

### 5. Documentation

- **`tests/fixtures/reference-trace/manifest.toml`**: the `produced_by` line becomes whatever
  actually produced it, and the comment explaining that F0 left it empty is replaced by the
  recorder's own account.
- **Plan `F0.ASSET.02`'s row**: it gains that the recording needs **both** a sensor and
  declarations, with the measurement that shows why neither source alone suffices, and it names the
  two open questions rather than implying the mechanism is settled.
- **Plan §2.22**: the normative workload paragraph gains a sentence saying the shipped fixture must
  be compared against those counts, because a trace that does not resemble them is not the
  workload the CPU budget was written for.
- **Plan Annex H**: a `record-trace` row.
- **`docs/ai/STATE.md`**: *Next up* item 2 is rewritten from "blocked, and it is the owner's" to
  the two questions and the work that proceeds regardless.

**Closing.** Verified against `crates/aisme-agentsim/src/trace.rs`'s `Entry` and `Summary`, plan
§2.22's normative workload, plan `:3904`'s sentence about the token never travelling on the socket,
`tests/fixtures/reference-trace/manifest.toml` as it stands, and M4. **The recommendation fell.**
Deriving the trace from the agent's own record cannot work: the record carries intents and no
actions, and four of the format's five action kinds are things only a kernel sees. It fell a second
time on shape — this session ran about five tool calls an hour against a normative workload of two
hundred, nearly all of them subprocess executions. What replaces it is the mechanism the project
already designed and has not yet used: declarations joined to sensed actions by process subtree.
One objection I raised earlier also falls, and in the owner's favour: a committed fixture carries
hashes and not paths, so the privacy question narrows to one optional free-text field. **Open, and
genuinely the owner's**: where the recording may be made, and what declares the tool calls.

---

## Coherence between the two points

Three things the two points do to each other, found by reading them against one another after both
were closed.

**1. Point 1 appears to give point 2 a route with no sensor, and it does not.** Under point 1
`aisme run` sees every trapped `openat` of every process in the session, with its pid, and it is the
ancestor — so attribution by subtree is free and no BPF program need load anywhere. It is worth
naming because somebody will propose it, and it fails on the sentence `F0.ASSET.02` already carries:
*"recorded in observe-only mode before any enforcement rule is loaded, **so recording it perturbs
nothing**"*. A trapped open costs **46.6 µs against 1.8 µs unsupervised** — twenty-six times — and
§2.22 replays the fixture *"at 1× with its recorded inter-arrival timing"* because *"totals are not
a workload"*. A recording made through the trap would preserve the counts and destroy the timings
the fixture exists for. It also sees only opens: `file_write`, `exec` and `https_request` are not
`openat`, so three of the five action kinds would be missing anyway.

**2. Point 1 does give point 2 the action stream, at the daemon, for free.** `decideOpen` carries
`{ session_id, path }` to `agentd` for every trapped open, so the daemon learns each action without
reading anybody's memory and can record it beside the declaration it already receives. That is a
real simplification of point 2's recorder — it needs no new transport — and it inherits the
perturbation above, so it applies to a recording made **with** enforcement and not to
`F0.ASSET.02`'s.

**3. Point 1 does not disturb the authorization classes, and it was worth checking.** `aisme run`
joins the session cgroup, so `in_session_cgroup` now classifies it as the agent rather than the
human — which is correct and deliberate, and would matter if `decideOpen` were a `HumanPrincipal`
method. It is `LocalPeer`, which asks only that the uid match, so the supervisor can call it and a
future `setPolicy` still cannot be called from inside a session.

## What this document changed

| Point | What it settled |
|---|---|
| 1 | The recommendation **holds**, and the objection on record falls. Ancestry alone permits reading at depth 3 with no `PR_SET_PTRACER` (M1); killing the supervisor leaves the child refused rather than free (M2); `PR_SET_PDEATHSIG` survives `exec` and restores the rest (M5). Two things the recommendation had not said are now fixed: the filter and the ruleset go in the **child**, and the child must not `exec` until the parent holds the listener. `CAP_SYS_PTRACE` is refused for the same reason `docs/06` point 3 refused a policy-map descriptor |
| 2 | The recommendation **falls** (M4). A session record carries intents and no actions; four of the format's five action kinds are things only a kernel sees; and this session's shape is forty times sparser than §2.22's normative workload and almost entirely one action kind. The mechanism is the one already designed — declarations joined to sensed actions by process subtree — and most of it can be built and tested before either open question is answered |

**One question survives for the owner, and it is point 2's**: where the recording may be made, and
what declares the tool calls. Point 1 needs an ADR because it reverses a recorded decision, and the
ADR's argument is written above rather than owed.
