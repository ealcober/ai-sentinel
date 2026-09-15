# Challenge-amplification — closing F2

> **Status**: complete — three points
> **Scope**: what F2 still owes, and how it closes. The request that produced this document asked
> for `F2.WS.09`, `.10` and `.11` to be amplified; **point 1 found they already are**, in
> `docs/05` points 9 to 11, so this document verifies those against the tree as it is now rather
> than writing a second specification of them.
> **Method**: `/challenge-ampliar` — five sections per point, written in the declared future so
> whoever implements it decides nothing and only executes.

## How to read this

The coherence review runs first, as it did in `docs/09`, and it paid again: five findings, one of
which means **the gate as written would deny nothing**.

**The points:**

1. The coherence review. **Closed** — five findings, and the discovery that three of the four
   things this document was asked to amplify already are.
2. `docs/09` point 6 — releasing the session cgroup. The one thing here that genuinely lacked an
   amplification.
3. The closing plan: the order, what each remaining task owes, and the four corrections GATE F2
   needs before it can be run.

---

## Point 1 — The coherence review

**Done when:** what F2 still owes is what the tree says it owes, not what the plan said before the
enforcement thread landed.

### 1. Challenge

*Is this the best solution?* The alternative was to amplify the four named items directly. That is
what was asked, and it would have produced a second specification of three of them — which is
exactly the defect `docs/09` point 6 exists to prevent, and which `CLAUDE.md` general rule 13
treats as a defect in its own right. One review costs a point; four duplicate points cost every
reader who then has to work out which one is current.

*Is it coherent with the specs?* It is the specs' own instruction. `CLAUDE.md` general rule 1
admits no claim that has not been verified against the code, and "this task needs amplifying" is a
claim.

*Can it be simplified?* It is already one point. What follows is what the reading found.

### 2. Verification

**Finding 1 — three of the four are already amplified, and the fourth is GATE F2 itself.**

`docs/05_challenge_ampliacion_f2.md` carries thirteen points, and `grep "^## Point"` lists them:
point 9 is `F2.WS.09`, point 10 is `F2.WS.10`, point 11 is `F2.WS.11` and **point 12 is GATE F2**.
Each has its five sections, written in the declared future. They were written on 2026-09-07,
before the enforcement thread landed, so what they need is **verification against today's tree**,
not replacement. Points 2 and 3 of this document do that and specify only what is missing.

**Finding 2 — the gate would deny nothing, because trapping became opt-in after it was written.**

Plan `:1643`'s GATE F2 block runs, among others:

```bash
cargo xtask vm run <image> --with-dist -- aisme run -- sh -c 'cat /etc/shadow'   # denied -EACCES
```

`aisme run` **installs no filter** without `--trap-openat`, and that flag exists for a measured
reason (`docs/09` point 3's closing): a classic BPF filter sees syscall numbers and never paths,
so it traps every `openat`; `CONTINUE` is forbidden for a path-bearing syscall (`I-28`); and limit
one of `Q-13` reproduces `O_RDONLY` only — so a filtered session **cannot write**, and filtering by
default would break every session. The gate was written before that was known and has not caught
up. **As it stands, those three lines would exit 0 with the file printed**, and a gate that passes
by not enforcing is worse than one that fails.

**Finding 3 — the gate asks for two verdicts the daemon has no way to reach.**

The same block expects `/etc/shadow` **denied** and `~/.aws/credentials` **escalated** — the two
halves of F2's one hardcoded policy (`deny /etc/shadow`, `escalate ~/.aws/**`, default allow, plan
`:1609`). What F2 built is a **session-declared escalate list**: `aisme run --escalate <prefix>`
carries prefixes in `registerSession`, and the notify loop asks about those and delivers a
validated descriptor for everything else. There is no deny rule and no compiled policy in the
daemon, because the loader owns the policy and the daemon holds no map (`docs/06` point 3).

So the gate needs one of two things, and point 3 chooses: either the compiled policy reaches the
enforcer, or the gate's lines say what F2 actually delivers. **Neither is a small edit made in
passing**, which is why it is a numbered decision rather than a note.

**Finding 4 — the reference-trace recording is due and nothing says so.**

Plan `:1360` (`F0.ASSET.02`): *"The recording itself runs **after `F2.WS.08` and before GATE F2**,
because `aisme run` is an F2 deliverable"*. `F2.WS.08` closed at `df183b6`. The recording is
therefore **owed now**, and neither `STATE.md`'s "Next up" nor `docs/09` mentions it. It is not a
task ID of its own, which is precisely how it would be missed: it belongs to an F0 row whose other
halves are long done.

**Finding 5 — `F2.WS.11` is genuinely not started, and that is worth confirming rather than
assuming.** `grep -rn "landlock_create_ruleset\|LANDLOCK_" crates/ --include=*.rs` returns two
hits, both in `crates/aisme-core/src/policy/backend.rs`, and both are the *names of policy keys* a
Landlock backend would accept — not a syscall. Every other mention is a capability field or a
degradation sentence. So there is no half-built ruleset to reconcile with, which is the good case.

**What was checked and holds:**

* The plan's GATE F2 block now reads `vm run <image> --with-dist --` on every guest line. `docs/05`
  point 12's blocker — *"the guest has no AISME binaries"* — is **closed**, and `--with-dist`
  stages `aisme` among the six.
* `cargo xtask test-skeleton` and `cargo xtask bench-t0` both exit **3**, owned by `F2.WS.10` and
  `F2.WS.09` in `xtask/src/annex_h.rs:380` and `:74`. That is the map, not an error.
* `budgets.toml:119` carries `[profiles.skeleton]`, so `verify-budgets --profile skeleton` has a
  target to compare against and needs only an artefact.
* `F0.VER.04`, which `F2.WS.11` is conditional on, holds — `STATE.md` records the backlog as 21 of
  21 with only `.12`'s hardware half open.

### 3. Implementation

Nothing in the repository. This point produces the shape of the other two, and one correction:

- **`docs/05` points 9 to 12 are the specifications for `F2.WS.09`, `.10`, `.11` and GATE F2.**
  This document does not restate them. Point 3 records, per task, only what has changed under them
  since 2026-09-07 — and for two of them, nothing has.
- Plan `:1643`'s GATE F2 block gains the flags its own lines need, in the commit that implements
  `F2.WS.10`; the choice between "policy in the enforcer" and "the gate says what F2 delivers" is
  taken in point 3 and its reasoning goes in the plan beside the block.
- `docs/ai/STATE.md` gains the reference-trace recording under *Next up*, with its plan row, so an
  obligation that belongs to no F2 task ID stops being invisible.

### 4. Tests

None. A coherence review is not a property of the product. What it does owe, and what points 2 and
3 inherit, is that every claim about what exists cites `file:line` or a command's exit code.

### 5. Documentation

- `docs/01_phase5_implementation_plan.md` `:1643`: the gate block, per point 3.
- `docs/ai/STATE.md`: the reference-trace recording, named as owed.
- `docs/05_challenge_ampliacion_f2.md`: **unchanged**. Its points 9 to 12 stand; this document
  cites them rather than copying them, which is the whole reason it exists.

**Closing.** Verified against `docs/05_challenge_ampliacion_f2.md` (thirteen points, 9–12 covering
exactly what this document was asked to amplify), plan `:1643` (the gate block, now with
`--with-dist` and still without `--trap-openat`), plan `:1609` (F2's one policy), plan `:1360`
(`F0.ASSET.02`'s recording, due after `F2.WS.08`), `xtask/src/annex_h.rs:74,380` with both commands
measured at **exit 3**, `budgets.toml:119`, and a grep for Landlock syscalls returning only policy
key names. **One claim of the request fell**: three of the four items were already amplified, so
this document verifies rather than duplicates. Open: nothing in this point — finding 3's choice is
taken in point 3.

---

## Point 2 — Releasing the session cgroup

**Done when:** a machine that has run a thousand sessions has no session cgroups left.

### 1. Challenge

*Is this the best solution?* Every `aisme run` creates `aisme-<id>` under the delegated subtree and
**nothing removes it**. Measured on 2026-09-15: the directory survived the run, empty. The design
note's step 9 says *"On exit: close the session, release the cgroup, flush the WAL"* — and
`docs/09` point 2 moved the summary before `exec` because **`exec` has no after**. The same
argument takes the release with it: the process that created the cgroup *is* the supervised command
from that moment, so it cannot clean up after itself.

Four shapes were weighed:

1. **`aisme run` forks and waits.** It could then release on exit — at the cost of the pid, the
   terminal, the exit status and an unskippable chain, which is what `docs/09` point 2 refused.
2. **systemd.** A transient scope would be released by systemd. F2 has no unit per session and
   inventing one is `F8.CLI.01`'s.
3. **A sweeper in `agentd`** that periodically removes empty `aisme-*` directories. Simple, and
   wrong in the way sweepers usually are: it either runs too often or leaves a window, and it
   cannot tell an empty new session from a finished one.
4. **`agentd` owns the lifecycle of the sessions it is told about**, and removes the cgroup when it
   becomes unpopulated.

(4) is the one that fits what already exists: `registerSession` already tells the daemon a session
started, and cgroup v2 already publishes when one empties.

*Is it coherent with the specs?* Yes, and it closes a gap in the same seam: the daemon already
holds the session's listener, its tty and its escalate class. The cgroup path is the fourth thing
about a session, and the registration is where a session's facts belong.

*Can it be simplified?* Yes, and the simplification is the mechanism. cgroup v2 publishes
`cgroup.events` with a `populated` line, and **that file is pollable**: `poll(2)` returns
`POLLPRI` when it changes. So there is no sweeper and no interval — the daemon waits for the
kernel to say the session is empty, and then removes the directory.

### 2. Verification

- **A session that does not trap must still be released.** Today `aisme run` registers only with
  `--trap-openat`, because the listener is the message. So **the listener becomes optional and the
  registration does not**: `aisme run` registers every session, and `registerSession` refuses a
  *trapping* session with no listener rather than refusing every session without one. The refusal
  keeps its meaning — a filtered process with nobody to answer it fails every `openat` — and stops
  being the reason unfiltered sessions are invisible to the daemon.
- **Removing a cgroup is removing a directory, and only ever an empty one.** `rmdir` on a cgroup
  with processes in it fails with `EBUSY`, which the kernel enforces and this code does not have to.
  It is `rmdir`, never recursive: a session subtree with children is not F2's and deleting one
  would be deleting something nobody asked about.
- **The path is checked before it is used.** The daemon removes a directory a client named, so the
  name is constrained: it must be under the daemon's own delegated subtree and its last component
  must match `aisme-<16 hex>`. A registration naming anything else is refused with the reason. This
  is the one place in the session protocol where a client's string becomes a filesystem operation,
  and it is worth the check even though the peer is uid-matched.
- **A daemon that dies leaves the directory.** That is the honest state and not worth a
  crash-recovery mechanism in F2: an empty cgroup costs a directory entry. `F8.CLI.01`'s session
  registry is where a restart learns what it was watching, and this point says so rather than
  building half of it.
- **The watch must not cost a thread per session that never ends.** It ends: `poll` on
  `cgroup.events` returns when the last process leaves, and the loop that answers notifications is
  already one thread per session. The release joins that thread rather than adding another.

### 3. Implementation

- `registerSession`'s params gain `cgroup` (a path). `Registered` gains `cgroup: Option<String>`;
  `crates/aisme-agentd/src/ipc.rs`'s `register_session` validates it — under the daemon's own
  cgroup subtree, last component matching `aisme-` plus sixteen hexadecimal digits — and refuses
  with the reason otherwise.
- The listener becomes **optional**: `Registered.listener` becomes `Option<OwnedFd>`, and the
  refusal moves to *"a session that declares an escalate class must carry its listener"*.
- `crates/aisme-cli/src/run.rs` registers **every** session, not only trapping ones, sending the
  cgroup path it just created. Failure to register a non-trapping session is a **warning**, not a
  refusal: the session is supervised by nothing in that case, and refusing to run it would be a new
  reason for `aisme run` to fail that F2 never had.
- `crates/aisme-agentd/src/platform/mod.rs`'s session thread gains a final step: after the
  notification loop ends — or immediately, when there is no listener — it polls
  `<cgroup>/cgroup.events` until `populated 0`, then `rmdir`s the directory and says so on the
  summary line.
- The poll is bounded by nothing: a session may run for days. It ends when the cgroup empties,
  which is the event it is waiting for.

### 4. Tests

**Existing to change:** `a_session_registration_without_its_listener_is_refused` becomes
`a_trapping_session_without_its_listener_is_refused`, and gains a case: a registration with no
listener and **no escalate class** is accepted, because that is a session the daemon only watches.

**New:**

- A path test, and it is the one that matters: a registration naming `/etc`, `..`-traversal, a
  sibling outside the daemon's subtree, or `aisme-nothex` is refused **with the reason**, and the
  daemon removes nothing. Driven through `register_session`, so the production validator is what
  runs.
- A release test on the host, skipped **with its reason** where the subtree is not delegated: run
  `aisme run -- true`, then assert the session cgroup is gone within a bounded wait. The cgroup
  directory is read back rather than the daemon's log, because the log says what it believes.
- A still-running test: a session whose command is `sleep`, asserted **present** while it runs and
  gone after — so the release is not simply "remove it at once", which would pass the test above.

### 5. Documentation

- `docs/design/02_aisme-run.md` step 9: the release named as `agentd`'s, with the reason `exec` has
  no after.
- Plan `F2.WS.08`'s row and Annex I.1's `registerSession` row: the `cgroup` parameter and the
  listener becoming optional.
- `docs/09` point 6: marked closed by reference, so the same fix is not specified twice.

**Closing.** Verified against `crates/aisme-cli/src/run.rs`'s `enter_session_cgroup` (which creates
and never removes), `docs/design/02_aisme-run.md` step 9 (which asks for a release), `docs/09`
point 2's `exec` argument (which is why the creator cannot do it), and
`crates/aisme-agentd/src/ipc.rs`'s `register_session` (where the listener is currently mandatory).
**One claim of the skeleton fell**: `docs/09` point 6 called this *"owed alongside `F8.CLI.01`"* —
it is not, because `registerSession` and the session thread both already exist, and what remains is
one parameter and one `poll`. Open: nothing.

---

## Point 3 — The closing plan

**Done when:** GATE F2 has been run and its output is in `STATE.md`.

### 1. Challenge

*Is this the best order?* Three tasks remain, plus point 2, plus a recording, plus the gate. The
order is decided by what unblocks what and by what would otherwise be measured twice:

1. **`F2.WS.11` — Landlock.** First, because it is the last thing that changes what the gate
   observes, and because its seam already exists: `pre_exec` in `crates/aisme-cli/src/run.rs` runs
   after the cgroup and before `exec`, which is the only place a ruleset is inherited from.
   `docs/05` point 11 specifies it and nothing under it has changed.
2. **`docs/09` point 6 / this document's point 2 — the cgroup release.** Second, because it
   touches `registerSession`, and doing it after `F2.WS.10` would mean writing the skeleton's
   fixture twice.
3. **`F2.WS.10` — the whole slice on `MockSensor`.** Third. It is the gate's first line and the
   thing that makes every later phase testable in milliseconds, so it should see the finished
   shape, not an interim one. `docs/05` point 10 specifies it.
4. **`F2.WS.09` — latency.** Fourth, because a baseline is only worth recording once the code it
   measures has stopped changing. `docs/05` point 9 specifies it, and Annex H already assigns it
   `bench-t0`.
5. **The reference-trace recording** (`F0.ASSET.02`, finding 4). Fifth, and it must be **before**
   the gate: plan `:1360` says so, and it is recorded in observe-only mode so that making it
   perturbs nothing.
6. **GATE F2.**

*Is it coherent with the specs?* Yes, with one correction the gate itself needs, which is
finding 2 and finding 3.

*Can it be simplified?* The sequence cannot — each step is somebody's input. The **gate** can, and
that is the decision below.

### 2. Verification

**The decision finding 3 asked for: the gate's lines gain the flags, and F2's policy stays where
F2 put it.**

The alternative — making the compiled policy reach the enforcer so `aisme run` needs no flags —
is a real design and it is **F3's**: `F3.PT.02` puts the trie in the kernel and the enforcer reads
it there. Building a user-space copy of that in F2, so a gate line can be shorter, would be
building the thing `docs/06` point 3 refused: a policy the daemon holds. F2's escalate class is
declared by the session, and the gate should say so.

So GATE F2's guest lines become, with the reasons written beside them in the plan:

```bash
cargo xtask vm run <image> --with-dist -- \
    aisme run --trap-openat -- sh -c 'cat /etc/hostname'      # allowed: a validated descriptor
cargo xtask vm run <image> --with-dist -- \
    aisme run --trap-openat --escalate /etc/shadow -- sh -c 'cat /etc/shadow'   # no answer -> deny
AISME_TERMINAL_ANSWER=d cargo xtask vm run <image> --with-dist -- \
    aisme run --trap-openat --escalate "$HOME/.aws" -- sh -c 'cat ~/.aws/credentials'
```

**Three properties this keeps, and they are why it is not a weakening:**

- The **exit criterion is unchanged**: an engineer types `aisme run`, the terminal asks, they
  answer, the syscall obeys. Line three is that, and it already passes on the host.
- The denial in line two is a **real** denial: the supervisor is asked, has no answer within the
  budget, and the kernel returns `-EACCES` to the caller. It is not a filter that happens to be
  off.
- A line that passes because nothing was enforced is impossible to write this way, because the
  flags that enable enforcement are on the line.

**What is deliberately not done**: the gate is not made to pass by lowering it. Line two asks for
the same observable outcome the plan asked for — `cat /etc/shadow` returns `-EACCES` — and gets it
by the mechanism F2 actually has.

**One thing to ask the owner rather than decide**, because it changes what F2 claims: plan `:1609`
lists F2's policy as `deny /etc/shadow`, `escalate ~/.aws/**`, default allow. After this, F2
demonstrates **escalate and its two answers**, and `deny` is what an unanswered escalation
produces. The compiled `deny` verdict — a rule that is refused without anybody being asked —
reaches the kernel in `F3.PT.02`. **Is F2's scope row rewritten to say that, or is a user-space
deny added to the enforcer?** This point does not choose: the first is honest about what F2 is, the
second is the copy of F3 that `docs/06` refused.

### 3. Implementation

- Plan `:1643`: the gate block gains the flags above and a sentence for each, plus a line for the
  reference-trace recording before it.
- Plan `:1609`'s scope row: whichever of the two the owner answers.
- `docs/ai/STATE.md` *Next up*: the six steps in the order above, each naming the document that
  specifies it — `docs/05` points 9, 10, 11 for the tasks, this document's point 2 for the cgroup,
  plan `:1360` for the recording.
- Nothing else. The three remaining tasks are implemented from `docs/05`, unchanged.

### 4. Tests

None of its own. Every step in the order carries the tests its own specification names, and the
gate is the test of the whole.

What this point does add is one rule for running the gate: **its output goes into `STATE.md`
verbatim**, as plan §3.7.1's F2 row requires (*"the GATE F2 output recorded in `STATE.md`"*), and a
`SKIP` in it needs its reason beside it. A gate summarised is a gate nobody can check.

### 5. Documentation

- Plan `:1643` and `:1609`, as above.
- `docs/ai/STATE.md`: the order, and afterwards the gate's output.
- `docs/CHANGELOG.md`: one line per task as each closes.

**Closing.** Verified against plan `:1643` (the gate block as it stands), `:1609` (F2's policy
row), `:1360` (the recording's timing), `docs/05` points 9–11 (the three remaining
specifications, unchanged since 2026-09-07), `crates/aisme-cli/src/run.rs`'s `pre_exec` (the seam
`F2.WS.11` needs, already present), and both gate commands measured at **exit 3**. **Nothing of
the skeleton fell.** **Open, and the owner's**: whether F2's scope row is rewritten to say that F2
demonstrates escalate and its answers, with compiled `deny` arriving in `F3.PT.02` — or whether a
user-space deny is added to the enforcer, which is the copy of F3 `docs/06` point 3 refused.

---

## What this document changed

| Point | What it settled |
|---|---|
| 1 | Three of the four things it was asked to amplify **already are**, in `docs/05` points 9–11; the gate would **deny nothing** as written, because trapping became opt-in after it; the gate asks for two verdicts the daemon cannot reach; and `F0.ASSET.02`'s recording is due now and invisible |
| 2 | The cgroup is released by **`agentd`**, on `poll` of `cgroup.events` — not by a sweeper and not by the process `exec` replaced. The listener becomes optional so an unsupervised session is still watched, and the client's path is validated because it becomes a filesystem operation |
| 3 | The order: `.11`, the cgroup, `.10`, `.09`, the recording, the gate. The gate's lines gain the flags F2's design requires rather than F2 gaining a policy copy `docs/06` refused |

**Still open for the owner:** whether F2's scope row says that F2 demonstrates *escalate* and its
answers — with compiled `deny` arriving in `F3.PT.02` — or whether a user-space deny goes into the
enforcer now.
