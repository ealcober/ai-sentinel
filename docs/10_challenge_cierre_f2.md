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

1. **`F2.WS.05`'s missing half — the compiled policy reaches the supervisor.** First, because every
   later measurement is taken against whatever the enforcer decides, and because it is the
   difference between a gate that demonstrates enforcement and one that demonstrates a flag.

   **`aisme-agentd --policy <file>`** parses and compiles at startup with
   `aisme_core::policy::{parse, compile}` — the same F1 compiler `aisme-loaderd --publish` uses, so
   a policy that compiles for one compiles for the other — and holds the `CompiledPolicy`. The
   supervisor builds an `EventFacts` for each trapped open and calls
   `aisme_core::policy::evaluate` (`crates/aisme-core/src/policy/evaluate.rs:80`), which already
   exists and is L1's. `Verdict::Deny` refuses with `-EACCES` and **asks nobody**;
   `Verdict::Escalate` asks the adjudicator; `Allow` and `Warn` are answered with a validated
   descriptor.

   **Two things this point's first draft got wrong, both toward the insecure, and both measured
   rather than argued:**

   * It said `aisme run --policy <file>`. That would let **the supervised party choose what governs
     it**, and a policy the agent can pick is not enforcement — it is opt-in. The design note is
     already right: step 3 has the session *"register with `agentd` … **receiving** the compiled
     policy generation"* (`docs/design/02_aisme-run.md:34`). The policy is the daemon's, and the
     session learns which one is in force.
   * It said to carry the lowered `(prefix, verdict)` table. **The lowering is not the policy.**
     `BpfTrieBackend::lower` emits only `Term::PathUnder` prefixes and says so
     (`crates/aisme-linux/src/policy.rs:157`: *"Only prefixes become trie keys. A glob is accepted
     by the plan and matched elsewhere"*) — and the skeleton's escalate rule is
     `path_glob = "~/.aws/**"`. Carrying that table would have shipped the deny and the write scope
     and **dropped the escalate rule GATE F2's third line depends on**. Measured: the shipped
     policy's three rules lower to **two** trie entries, which is what the guest reported as
     `A: 2  B: 2` on 2026-09-09.

   `--escalate <prefix>` stays as the shorthand it is, for tests and for a session with no daemon
   policy, and is documented as such.
2. **`F2.WS.11` — Landlock.** Because it is the last thing that changes what the gate observes, and
   because its seam already exists: `pre_exec` in `crates/aisme-cli/src/run.rs` runs after the
   cgroup and before `exec`, which is the only place a ruleset is inherited from. `docs/05`
   point 11 specifies it and nothing under it has changed.
3. **`docs/09` point 6 / this document's point 2 — the cgroup release.** Because it
   touches `registerSession`, and doing it after `F2.WS.10` would mean writing the skeleton's
   fixture twice.
4. **`F2.WS.10` — the whole slice on `MockSensor`.** It is the gate's first line and the
   thing that makes every later phase testable in milliseconds, so it should see the finished
   shape, not an interim one. `docs/05` point 10 specifies it.
5. **`F2.WS.09` — latency.** Because a baseline is only worth recording once the code it
   measures has stopped changing. `docs/05` point 9 specifies it, and Annex H already assigns it
   `bench-t0`.
6. **The reference-trace recording** (`F0.ASSET.02`, finding 4). It must be **before**
   the gate: plan `:1360` says so, and it is recorded in observe-only mode so that making it
   perturbs nothing.
7. **GATE F2.**

*Is it coherent with the specs?* Yes, with one correction the gate itself needs, which is
finding 2 and finding 3.

*Can it be simplified?* The sequence cannot — each step is somebody's input. The **gate** can, and
that is the decision below.

### 2. Verification

**Finding 3's question is answered by the specs, and it was never the owner's to take.** Three
sentences settle it:

- **Plan `:1638`** — *"**Kernel-side** evaluation of that artefact is F3's first gate: at this shape
  the sensor is a tracepoint and **enforcement is seccomp**, so the kernel never reads the trie."*
  What `F3.PT.02` owns is evaluation **in the kernel**, not evaluation.
- **`docs/05` §5.3** — the allow path, step by step: *"… `openat2` with `RESOLVE_NO_MAGICLINKS` →
  **evaluate the opened file against the compiled policy** → `ADDFD`"*. The supervisor evaluating
  the compiled policy **is** `F2.WS.05`'s specified behaviour.
- **`docs/06` point 3** said *"it neither publishes (that is the loader) nor evaluates (that is
  F3)"*. **That sentence was the defect.** Its paragraph is about *the maps*, and it slid from
  "`agentd` does not open the maps" to "`agentd` does not evaluate", contradicting the two above.
  It is corrected where it was written rather than worked around here.

So: **the supervisor evaluates the compiled policy, in user space, and that is not a copy of
`F3.PT.02`** — F3's copy is the kernel-side reader of the trie. What `docs/06` point 3 refused was
`agentd` holding a policy **map**; it never refused `agentd` knowing a policy. The policy reaches
the supervisor from the session, which compiled it with the same F1 compiler the loader uses.

**And the security argument agrees, which is the test that matters.** A compiled `deny` **cannot be
answered away**: nobody is asked, so no answer exists to get wrong, and no timeout has to expire
for it to hold. An escalation that denies on timeout is strictly weaker — it depends on nobody
answering, and it spends a budget before it is safe. For a credential store the policy says *deny*,
and a policy deny that could be turned into a prompt is a policy deny that can be argued with. The
session-declared escalate list this document was going to enshrine is the weaker of the two, and
it was built because the implementation was narrower than the specification, not because anyone
chose it.

**What this makes owed, and it is a correction to a task already reported done:** `F2.WS.05`'s
done-condition — *a denied `openat` returns `-EACCES`* — is met and measured. But `docs/05` §5.3's
allow path is not: the supervisor applies a **session-declared prefix list**, not the compiled
policy. That is step 1 of the closing plan below, before anything else, because every later
measurement is taken against whatever the enforcer decides.

GATE F2's guest lines therefore carry `--policy`, and the plan's block now says why.

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
| 3 | The order: **`F2.WS.05`'s compiled-policy half first**, then `.11`, the cgroup, `.10`, `.09`, the recording, the gate. The supervisor evaluates the compiled policy — plan `:1638` reserves only *kernel-side* evaluation for F3, and a compiled `deny` cannot be answered away while a timeout-deny depends on nobody answering. **The policy is the daemon's, not the session's**: one the supervised party could choose is not enforcement, and the lowered trie is not the policy — it drops the globs, including the escalate rule the gate tests |

**Nothing is open for the owner.** The question point 3 first raised was answered by plan `:1638`,
`docs/05` §5.3 and the correction of `docs/06` point 3's one wrong sentence — and the security
argument points the same way: a compiled `deny` cannot be answered away, while an escalation that
denies on timeout depends on nobody answering. F2's scope row stands as written.

---

## Step 1, as executed — the compiled policy reaching the supervisor

`aisme-agentd --policy <file>` compiles at startup with `parse` + `compile`, holds the
`CompiledPolicy`, and the supervisor calls `aisme_core::policy::evaluate` for every trapped open.
`--escalate <prefix>` stays as the shorthand for a session with no daemon policy.

**Four runs against one daemon holding the skeleton's three rules.** The column that matters is
`asked`, because it is what separates a compiled deny from an escalation nobody answered:

| Command | delivered | denied | asked |
|---|---|---|---|
| `cat /etc/hostname` | 4 | 0 | **0** |
| `cat /etc/shadow` | 6 | 12 | **0** |
| `cat $D/aws/credentials`, answer `d` | 6 | 12 | 1 |
| `cat $D/aws/credentials`, answer `1` | 4 | 0 | 1 |

`/etc/shadow` was refused **without anyone being asked**, and the glob rule was honoured — the two
properties the first draft of this point would have lost.

### Two claims that fell, both mine

1. **"The supervisor turns a missing file's `ENOENT` into `EACCES`, and that is an undiscovered
   defect."** Measured — a missing file does report `Permiso denegado` under supervision and `No
   existe el archivo` without it, which is where the 12 denies in the failing runs come from:
   `cat`'s error path loading locale files that are not there. But it is **not undiscovered**.
   `crates/aisme-linux/src/seccomp.rs:934` already states it as the conservative choice, says it is
   visible in the record, and assigns the widening to `F3.EN.12` — which exists (plan `:1753`).
   Nothing to fix here. The lesson is the ordinary one: read the comment before filing the bug.
2. **The shipped policy's write-scope rule was inert, and the daemon said so with exit 0.** Both
   real, both fixed below.

### Two defects this step found — one fixed, one filed with its owner

1. **`deploy/policy/skeleton.aisme` writes `$workspace`, and the grammar's variable is
   `${workspace}`.** Without braces it is a literal, so rule 3 matches a directory no machine has
   while `3 rule(s) in force` reports it as present. **Damage today: none** — the rule's verdict is
   `allow` and `allow` is already §B.10's default, so no verdict changes. **The open path is
   `F2.WS.11`**, which derives its Landlock ruleset from exactly this rule, and there an inert rule
   is a write scope that permits everything.

   **It is not corrected here, and the reason is measured rather than preferred.** `Bindings` is
   per session by construction — *"what `${…}` variables resolve to for one session"*
   (`crates/aisme-core/src/policy/compile.rs:43`) — and the daemon compiles once at startup, before
   any session exists. Correcting the spelling alone therefore makes the shipped policy **refuse to
   load**: `${workspace}` unbound stops the daemon, naming the rule. That trades an inert rule for a
   gate whose `--policy` line cannot start, which is worse. The spelling and the binding are one
   change and they are `F2.WS.11`'s, which is the next step and the task that owns the write scope.
   Recorded in `docs/ai/memory/policy-variables-need-braces.md`.
2. **A daemon that refused its policy exited 0.** `run_slice`'s error was printed and returned,
   so `aisme-agentd --run … --policy <broken>` failed to start and reported success to anything
   reading only the status — the gate's guest script, a unit file, an operator's `&&`. This is the
   exact failure the code's own comment says the startup compile prevents. All of `main`'s argument
   and startup error paths now exit non-zero, following the convention `measure-idle` already set.

**Falsifier for both, and it runs in milliseconds:**
`the_shipped_policy_keeps_all_three_of_its_rules` evaluates the shipped file and asserts deny,
escalate-through-the-glob and default-allow; `an_unbound_variable_refuses_the_daemon_and_names_the_rule`
asserts `${nowhere}` is refused with the variable and the rule named.

---

## Step 2, as executed — `F2.WS.11`'s write scope, and what it uncovered

`aisme run` builds one Landlock ruleset from the session's declared scope and applies it before
`exec`. Measured on this host at **ABI 9**, through the shipped binary:

| Command | Result |
|---|---|
| `aisme run --scope $W -- sh -c 'touch /tmp/outside'` | `EACCES`, exit 1, and the file does not exist |
| `aisme run --scope $W -- sh -c 'touch $W/inside'` | created, exit 0 |

Four unit tests fix it, each forking because a Landlock domain cannot be left: the ABI and its
rights agree, a write outside is denied while one inside is not, **a second and broader ruleset
does not restore what the first denied**, and a symlink or a directory outside the scope is refused
too.

### Three claims of `docs/05` point 11 that were corrected before any code

1. **"`LandlockEnforcer` … implementing the `Enforcer` trait."** The frozen L1 trait is
   `publish` / `respond` / `suspend` / `resume` — a daemon-side contract. A ruleset applied once,
   irreversibly, in a process about to `exec` answers none of the four. It is a module, and
   `F3.EN.09` is where an `Enforcer` impl belongs, because that is where the daemon publishes into
   Landlock domains.
2. **"`landlock_restrict_self` in `aisme run` after the seccomp filter."** The design note numbers
   the filter 4 and the ruleset 5, which reads as an order and is not one. `landlock_add_rule`
   needs an `O_PATH` descriptor per allowed directory, so building the ruleset under a filter that
   traps every `openat` sends the session's own setup to the supervisor — and `I-28` requires the
   supervisor to refuse an `O_PATH` open. The filter is also irreversible, so anything that can
   still fail belongs above it. Corrected in `docs/design/02_aisme-run.md` where it was written.
3. **"`WRITE_FILE|MAKE_REG|MAKE_DIR|REMOVE_FILE`."** That list denies `touch` and permits
   `ln -s`, `mkfifo`, `mknod` and `rmdir` outside the scope. Every write-shaped right the running
   ABI knows is handled instead, `TRUNCATE` included from ABI 3 — truncating a file is a write, and
   asking for the right below that ABI is `EINVAL` rather than a degradation. A test creates a
   symlink and a directory outside the scope and asserts both are refused.

### The blocker this step uncovered, and it is not Landlock's

**`aisme run --trap-openat -- sh -c 'cat /etc/hostname'` fails: 2 opens delivered, 13 denied, every
one of them *"the path argument could not be read"*, and every one of them the **grandchild's**.**
The shell is supervised; the command the shell runs is not.

The cause is `PR_SET_PTRACER`, and it took three measurements because the first two were wrong:

* Landlock was not involved. The same command without a shell — `aisme run --trap-openat -- cat
  /etc/hostname` — delivers 4 and denies 0 with the ruleset applied.
* A first reproducer said descendants were readable. **It was invalid**: its supervisor was the
  *ancestor* of both processes, and Yama permits an ancestor by a different rule entirely. A
  supervisor that is an ancestor will report success no matter what the grant does.
* With a **sibling** supervisor, which is `agentd`'s actual topology, the answer is sharp: the
  declaring process is readable after `exec`, and a process it forks returns `EPERM`. Yama keys the
  exception to the declaring task, and nothing inherits it.

**Why this is architectural rather than a patch.** Reading a supervised *tree* needs either
`CAP_SYS_PTRACE` on the supervisor or a supervisor that is the tree's ancestor, and the project has
already decided against the first in a neighbouring case: `docs/06` point 3 refused `agentd` a
writable policy-map descriptor precisely because it would leave `CapabilityBoundingSet=`
decorative — *"the capability gone and the authority kept"*. `CAP_SYS_PTRACE` is broader than what
was refused there, not narrower: it reads any process's memory on the machine.
`deploy/systemd/aisme-agentd.service` states the position plainly — *"the unprivileged half
(`F1.RT.07`). agentd runs the hot loop with no capabilities at all"* — while plan `:321` says the
engine *"runs as root under systemd"*. Those two were written for different jobs and F2 is the
phase in which they collide, because `F2.WS.05` gave the unprivileged daemon a job that needs
privilege.

**The options, with what each costs:**

1. **`AmbientCapabilities=CAP_SYS_PTRACE` on `aisme-agentd`.** One line, and it contradicts the
   unit's own reason for existing.
2. **A small privileged supervisor process, as `aisme-loaderd` already is for `CAP_BPF`.** It
   follows the project's own precedent for privilege splitting and keeps the hot loop clean; it
   costs a new binary, a new unit and a new socket.
3. **`aisme run` stops `exec`-ing and stays as the session's parent**, resolving paths itself. It
   is then the tree's ancestor, so Yama permits every descendant and no daemon gains a capability.
   It also restores two things the design note already asks for and F2 had to move elsewhere:
   step 8 (*"serve terminal adjudication … for the life of the session"*) and step 9 (*"on exit:
   close the session, release the cgroup"*), both of which assume `aisme run` outlives `exec`. It
   costs the decision recorded in `F2.WS.08` — *"`exec`, not `fork`+`wait`, so the exit status is
   the child's with nothing between"* — which would have to be reversed and its exit-status
   handling written by hand.

**This is the owner's, and it is the only thing in F2 that is.** Every reading of the specs was
tried first and they point in two directions at once, which is the signal that a decision is owed
rather than a lookup. Until it is taken, `F2.WS.11`'s Landlock half stands measured and GATE F2's
`sh -c` lines cannot pass.
