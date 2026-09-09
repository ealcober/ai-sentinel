# Challenge-amplification — the rest of the walking skeleton

> **Status**: complete — five points. The first is a coherence review that found four defects,
> one of which reordered the other four and one of which was found while reading for point 2
> and sent the review back to be corrected
> **Scope**: `F2.WS.05` (`SeccompEnforcer`), `F2.WS.06` (`TerminalAdjudicator`), `F2.WS.07`
> (`forensicd` tails the WAL) and `F2.WS.08` (`aisme run`), amplified together because three of
> them are one thread: a session that owns a terminal, a syscall held on it, and an answer.
> **Method**: `/challenge-ampliar` — five sections per point, written in the declared future so
> whoever implements it decides nothing and only executes.

## How to read this

Point 1 is a coherence review and it runs first, deliberately. `docs/06` exists because its first
point measured the blocker the other five were about to assume; the same discipline is applied
here before four tasks are specified against a tree nobody re-read.

**It found two things that change what follows**, so the remaining points are written against the
tree as it is rather than as the plan describes it.

**The points:**

1. The coherence review. **Closed** — four findings. One reorders the work, one was found while
   reading for point 2, and one is a question this review asked before reading the plan section
   that answers it.
2. `F2.WS.08` — `aisme run`, **first**, because two of the others install their machinery inside it.
   Four of the design note's nine steps; the other five named with their owners, not half-built.
3. `F2.WS.05` — `SeccompEnforcer`: the syscall held, and the descriptor that answers it.
4. `F2.WS.06` — `TerminalAdjudicator`: the human, in the terminal the session already owns.
5. `F2.WS.07` — `forensicd` tails the WAL by offset and resumes without loss.

---

## Point 1 — The coherence review, before anything is specified

**Done when:** the four points that follow rest on the tree, not on the plan's description of it.

### 1. Challenge

*Is this the best solution?* The alternative is to amplify the four tasks directly from the plan
and `docs/05`. That is what was about to happen, and this project has twice measured what it
costs: `docs/06` point 1 refuted the fallback the other five points were written against, and
`docs/07` found eight defects in documents that had drifted from the code they describe. A review
that takes one point is cheaper than four points written against something false.

*Is it coherent with the specs?* It is the specs' own rule. `CLAUDE.md` general rule 1 admits no
claim that has not been verified against the code, and an amplification is a claim about what will
be built on what exists.

*Can it be simplified?* It is already the smallest useful form: four tasks, their citations, and
the tree. What follows is what the reading found.

### 2. Verification

**Finding 1 — `Enforcer::publish` is per-enforcer, and the plan says so. The question this review
first asked was answered in §3.2 all along.**

The first draft of this point asked the owner what `publish` means, because `enforce.rs:49` reads
*"publish compiled policy to wherever decisions are made"* and the only implementation is
`NullEnforcer`. That was a question this document had no business asking: the plan answers it
twice, in the section the read order lists as item 5.

`docs/01_phase5_implementation_plan.md:1129` composes **`Vec<Box<dyn Enforcer>>` — plural**, and
`:1116` catalogues eight: `LsmEnforcer`, `LandlockEnforcer`, `CgroupConnectEnforcer`,
`SeccompEnforcer`, `FreezerEnforcer`, `TunnelEnforcer`, `SdkEnforcer`, `NullEnforcer`. With many
enforcers live at once, "wherever decisions are made" is **that enforcer's** decision point, and
each renders the same `CompiledPolicy` into its own. The plan even shows one: `F3.EN.09` (`:1715`)
reads *"compile a Landlock ruleset from `CompiledPolicy`, apply it in `aisme run` before `exec`"* —
that is `LandlockEnforcer::publish`, described without being named.

So `SeccompEnforcer::publish` installs the classic filter, and `aisme_linux::publish` writing the
BPF maps is a different job belonging to a privileged loader, not a missing implementation. **The
claim that fell is mine**: I grepped for implementations and read the trait, and did not open §3.2.
Grepping the code and reading the interface is not the same as reading the design.

**Finding 4 — the seam `F2.WS.05` and `F2.WS.06` plug into does not exist, and the plan and the
code disagree about where it should be.**

Found while confirming finding 1, and it is the one that mattered. `Engine::new`
(`crates/aisme-core/src/engine.rs:72`) takes `(sensors, sink, detectors, batch_capacity)` — **no
enforcers and no adjudicators**. The plan's §3.2 composition (`:1129`) shows
`Engine::new(sensors, enforcers, adjudicators, sink).run()`. `platform::enforcers` (`:173`) and
`platform::adjudicators` (`:195`) are implemented and are called in exactly one place that is not
a test: `main.rs:160-161`, **to print how many there are**.

They are constructed and nobody uses them.

Which side is right is not open, and this point resolves it rather than asking: `docs/05` §5.3
states that the notification loop *"runs on `agentd`'s control thread, never the hot loop: a
human's answer takes seconds and the hot loop's budget is microseconds"*. An engine that owned the
enforcers would put a human on the T0 path. **The code is right and the plan's composition line is
the stale artefact** — and `CLAUDE.md` is explicit that when the plan is wrong, the plan is fixed,
with an ADR reserved for `H-xx` findings and invariants. This is neither.

What follows from it, and points 3 and 4 are written against it: the enforcers and the adjudicator
ladder are held by **`agentd`'s control thread**, beside the IPC server that already runs there
and already shares the generation cell with the WAL sink. `Engine` is not touched.

**Finding 2 — `F2.WS.05` and `F2.WS.06` both install their machinery inside `F2.WS.08`, which the
plan orders after them.**

`docs/05` §5.3 (`:661`): the classic seccomp filter is installed *"from `aisme run` before
`exec` (it cannot be installed later without a window)"*. `docs/05` §6 (`:756`): the unattended
answer variable is *"read once, in `aisme run`, before `exec`"*. The plan's F2 table (`:1623`
onwards) lists `F2.WS.05`, `.06`, `.07`, `.08` in that order, and `STATE.md` says to work the
table top to bottom unless a Notes column says otherwise. It does not.

So the task order as written builds two tasks whose only delivery vehicle arrives last. Neither is
untestable in isolation — a test harness can `fork` and install a filter itself — but the *product*
path does not exist until `.08`, and a test harness that installs the filter is testing the harness.

**The direction matters:** this biases toward *appearing* further along. `.05` could be reported
done against a harness while nothing a user runs has ever installed a filter.

**Finding 3 — `docs/design/02_aisme-run.md` attributes the seccomp filter to the task `Q-13` took
it away from, and omits two tasks it cites.**

Found while reading that note for point 2, which is the review working rather than the review
failing. Its step table (`:39`) gives step 4, *"Install the seccomp filter for the escalate
class"*, to **`F3.EN.12`**. `Q-13` was answered on 2026-09-07 and moved that mechanism into
`F2.WS.05`, leaving `F3.EN.12` as the widening — `docs/05` §5.3 says so in as many words. The note
was not updated with it.

Its `Feeds:` line (`:4`) lists `F2.WS.08`, `F2.WS.11`, `F3.EN.09`, `F3.EN.12`, `F4.CO.04`,
`F7.PS.07` and `F8.CLI.01`. **`F2.WS.06` is absent although step 8 cites it**, and `F2.WS.05` is
absent although step 4 is now its work. A note whose purpose is stated as *"without one
specification it drifts"* has drifted in the one field that lists who depends on it.

Damage today: an implementer reading the note builds step 4 under the wrong task ID and finds no
row for it. Direction: it makes `F2.WS.05` look unowned and `F3.EN.12` look larger than it is.

**What was checked and holds**, so the following points can lean on it:

* `docs/design/01_permission-model.md` §7.3 does specify the terminal prompt the plan's `F2.WS.06`
  row cites — *"Tier 3: prompt in the terminal"*, with the `aisme run` argument beside it. The
  citation is good.
* `aisme_core::wal::replay(segment, from, out) -> Resume` (`:245`) and `read_record` (`:223`) exist,
  so `F2.WS.07`'s "tails by offset" has its API and does not need one invented.
* `CapabilitySet::seccomp_addfd` (`crates/aisme-core/src/capability.rs:52`) and `tier_of` reading it
  (`tier.rs:70`) are **already implemented** — `docs/05` §5.3 lists them as work `F2.WS.05` will do.
  Point 13 did it on 2026-09-07. That bullet is done and the amplification should not re-plan it.

### 3. Implementation

Nothing in the repository. This point produces two things and both are text:

- **A plan fix, not a question.** §3.2's composition line becomes the one the code implements and
  `docs/05` §5.3 argues for: the engine takes sensors, a sink and detectors, and the enforcers and
  the adjudicator ladder are held by `agentd`'s control thread. No ADR — `CLAUDE.md` reserves
  those for `H-xx` findings and invariants, and this is a diagram that fell behind its code.
- **A stated implementation order for the rest of F2**, which the following points assume:
  **`F2.WS.08` → `F2.WS.05` → `F2.WS.06`**, with `F2.WS.07` independent of all three and runnable
  whenever. The plan's task table will gain a Notes entry saying so, in the commit that implements
  the first of them — the table is not reordered, because task IDs are stable and their order in
  the table is not a schedule.

### 4. Tests

None. A coherence review is not a property of the product, and a test that asserted "the
amplification matches the tree" would be a second copy of the review that rots at the same rate.

What the review *does* owe is the discipline the following points inherit: each of them cites
`file:line` for anything it claims already exists, so the next reader can check rather than trust.

### 5. Documentation

- `docs/01_phase5_implementation_plan.md`: the F2 task table gains a Notes entry recording that
  `.05` and `.06` install their machinery inside `.08`, so `.08` is built first.
- `docs/05_challenge_ampliacion_f2.md` §5.3: the `CapabilitySet` bullet is marked done rather than
  future, with the date and the point that did it.
- `docs/01_phase5_implementation_plan.md` §3.2: the composition line, corrected to what the code
  does and `docs/05` §5.3 requires — the human is not on the T0 path.
- `docs/design/02_aisme-run.md`: step 4's task becomes `F2.WS.05`, `F3.EN.12` is named beside it as
  the widening rather than the owner, and `Feeds:` gains `F2.WS.05` and `F2.WS.06`.

**Closing.** Verified against `crates/aisme-core/src/enforce.rs:49` (the trait's own words),
`grep -rn "impl Enforcer for" crates/` (**one** implementation, `NullEnforcer` at
`mock.rs:164`), `docs/05_challenge_ampliacion_f2.md:661` and `:756` (both tasks installing inside
`aisme run`), `docs/01_phase5_implementation_plan.md:1623` (the table order),
`docs/design/01_permission-model.md:184-211` (§7.3 does specify the terminal prompt),
`crates/aisme-core/src/wal.rs:223,245`, and `crates/aisme-core/src/capability.rs:52` with
`tier.rs:70`. **Two claims fell, and one of them was mine.** The skeleton said these four
tasks would be amplified in the plan's order; two of them cannot be built in it. And this review's
own first draft asked the owner what `Enforcer::publish` means — a question §3.2 answers, in the
section the read order lists as item 5. Grepping for implementations is not reading the design, and
the lesson is cheaper written down than repeated. **Open: nothing.**

---

## Point 2 — `F2.WS.08`: `aisme run`, and why it is built first

**Done when:** the session's own process tree is correctly attributed, with no heuristic.

### 1. Challenge

*Is this the best solution?* `aisme run -- <cmd>` is the documented default onboarding path
(`H-18`) because it gives session identity for free: the supervisor owns the process from before
its first syscall, so nothing is inferred. Every alternative in the plan — binary catalogues,
lineage guessing, `/proc` scanning — exists for the case where we did **not** start the process,
and each is a heuristic that can be wrong.

Point 1 established the ordering: `.05` installs its filter and `.06` reads its unattended-answer
variable inside this command, so this is built first. That is not a preference; two tasks have no
product path without it.

*Is it coherent with the specs?* `docs/design/02_aisme-run.md` §3 lists nine steps across seven
tasks in five phases. **F2 gets four of them**, and the plan's out-of-scope column is as binding as
its task list: steps 1 (scope), 2 (session cgroup), 7 (`exec`) and 9 (exit summary). Step 3
registers with `agentd` and is `F8.CLI.01`; step 4 is `F2.WS.05`; step 5 is `F2.WS.11`; step 6 is
`F4.CO.04`; step 8 is `F2.WS.06`. What this point specifies is the four, **plus the seams the
other tasks plug into**, because a seam invented later is a rewrite.

*Can it be simplified?* Yes, in the place that matters most. Step 1's full form — `--scope`, then
`.aisme/scope.toml` narrowing only, then VCS-root detection, then a per-agent baseline — is
`F7.PS.07`. F2 needs **one** scope and it can come from `--scope` or the working directory, with
detection deferred and *said to be deferred* rather than half-built. A half-built detector is the
kind of thing that later looks implemented.

### 2. Verification

- **The cgroup is created and joined before `exec`, and the process places *itself* in it.** Any
  other order leaves a window in which the child is outside the tree, and the whole point of this
  path is that there is no window. Delegation makes it unprivileged: `aisme-agentd.service` carries
  `Delegate=yes` with `DelegateSubgroup=sessions`, so writing `cgroup.procs` inside the delegated
  subtree is an ordinary write by its owner.
- **A cgroup v2 that is not delegated, or a v1 host, is a named failure and not a silent fallback.**
  `aisme run` without a session cgroup cannot attribute the tree, and attributing it by heuristic
  is what this command exists to avoid. It will refuse with the reason.
- **The seams are declared here and are three:** a hook that runs after the cgroup and before
  `exec` (where `.05` installs its filter and `.11` its ruleset); the environment map that `.06`
  reads its variable from **once, in the parent, before `exec`**; and the session id that the WAL
  and the control plane both use. All three exist in F2 even where their occupants do not.
- **`exec`, not `fork`+`wait`.** The supervised command must *be* the process the caller started —
  replacing it keeps the pid, the terminal and the exit status honest, and means nothing in the
  chain can be skipped by killing an intermediary. The adjudication server of `.06` therefore runs
  in `agentd`, not in a parent that `exec` has replaced. **This is the seam `.06` depends on and it
  is stated here rather than discovered there.**

### 3. Implementation

- `crates/aisme-cli` will gain `run.rs`: parse `aisme run [--scope <path>…] -- <cmd> [args…]`,
  refusing an empty command with the usage line rather than exec'ing a shell.
- The session id will be a random `u64` printed on the summary line and passed to `agentd`; F2 does
  not need it to be a UUID and `F8.CLI.01` will say if that changes.
- The session cgroup will be created under the delegated subtree named by
  `DelegateSubgroup=sessions`, the process will write its own pid to `cgroup.procs`, and both will
  be verified by reading back — a write that reports success and a `cgroup.procs` that does not
  contain us is the failure mode this check exists for.
- A `pre_exec` hook point will be defined and left **empty**, with a comment naming `F2.WS.05` and
  `F2.WS.11` as its occupants and the reason it must run there: after the cgroup, before `exec`,
  no window.
- On exit: print one line with the session id, the WAL segment and the exit status of the child,
  and propagate that status as `aisme run`'s own.

### 4. Tests

**Existing to change:** none; `crates/aisme-cli` has no behaviour yet.

**New:**

- The command's process tree is inside the session cgroup: `aisme run -- sh -c 'sleep 1'` and, from
  the parent, read `cgroup.procs` and find the child's pid. Host-only where cgroup v2 delegation is
  available, and **skipped with its reason** where it is not — never passed.
- The exit status is the child's, for a command that succeeds and one that fails.
- An empty command is refused with usage, and does not exec a shell.
- A `--scope` argument that names a path that does not exist is refused before anything is created.

**Not tested here:** that the filter and the ruleset are installed. There is nothing in the hook
yet, and a test asserting an empty hook runs would pass for the wrong reason.

### 5. Documentation

- `docs/design/02_aisme-run.md`: step 4's task becomes `F2.WS.05` (point 1's finding 3), `Feeds:`
  gains `F2.WS.05` and `F2.WS.06`, and each step gains a mark for whether F2 implements it.
- Plan `F2.WS.08`'s row: the four steps F2 covers, named, so "establishes session identity and
  scope" is not read as all nine.
- `docs/ai/STATE.md` and `docs/CHANGELOG.md`: the usual rows.

**Closing.** Verified against `docs/design/02_aisme-run.md:26-50` (the nine steps and their tasks),
the plan's F2 scope table (`:1600` onwards, whose out-of-scope column is binding),
`deploy/systemd/aisme-agentd.service` (`Delegate=yes`, `DelegateSubgroup=sessions`, so the cgroup
write is unprivileged), and `crates/aisme-cli/src/main.rs` (10 lines, no behaviour). **One claim of
the skeleton fell**: the skeleton called this the fourth of four tasks; it is the first, and points
3 and 4 depend on the seams named here. Open: nothing in this point — the scope-detection ladder is
deferred to `F7.PS.07` deliberately and said so.

---

## Point 3 — `F2.WS.05`: `SeccompEnforcer`, and the descriptor that answers

**Done when:** a denied `openat` returns `-EACCES` to the caller, and a permitted one returns a
descriptor the supervisor opened.

### 1. Challenge

*Is this the best solution?* The decision was taken by the owner as `Q-13` and its reasoning is in
`docs/05` §5.3; this point does not re-litigate it, it specifies it. The single sentence that
constrains everything: **`SECCOMP_USER_NOTIF_FLAG_CONTINUE` may never permit a syscall that carries
a path**, because the kernel re-resolves the string after the decision and a rename of any
directory component — by any process on the machine, inside the session or not — changes what it
names. That is `I-28`, and the freezer does not close it either: the attack does not need the bytes
to change.

So a permitted open is delivered as a **validated descriptor**: the supervisor opens the file
itself and hands it over with `SECCOMP_IOCTL_NOTIF_ADDFD`.

*Is it coherent with the specs?* Yes, and it is bounded by two limits that make it small and
fail-closed, both from `Q-13`:

1. **Only what F2 can reproduce faithfully**: `openat` for reading with `O_CLOEXEC`. `O_CREAT`,
   `O_TRUNC`, `O_APPEND`, `O_DIRECTORY`, and the `open`/`openat2` entry points are **denied with
   the flag named** — a descriptor that does not mean what the caller asked for is worse than a
   refusal.
2. **Only when the target's uid is the supervisor's.** Opening with credentials the target lacks
   would be a privilege escalation served by the guard itself. `F3.EN.12` widens this.

*Can it be simplified?* `publish` is settled by point 1: with `Vec<Box<dyn Enforcer>>` live at
once, it publishes to **this** enforcer's decision point. `SeccompEnforcer::publish` therefore
installs the classic filter and returns the generation it was compiled from, and the BPF maps stay
the privileged loader's business. Nothing here is open.

### 2. Verification

Safe, clear and fail-closed, with each ordering constraint named because the order *is* the
security:

- **The filter is installed before `exec` and cannot be installed later without a window** — that
  is why it lives in point 2's hook.
- **The classic filter defaults the escalate class to `EACCES`, not to `ALLOW`.** A supervisor that
  dies must deny. This is checked by a test that kills `agentd` with a notification outstanding.
- **`SECCOMP_IOCTL_NOTIF_ID_VALID` before every response**, so an answer never lands in a reused
  id after the target died.
- **The allow path, in this order and no other**: `ID_VALID` → read the request → check `flags`
  against the F2 subset → check the target's uid → obtain the target's cwd via `pidfd` → `openat2`
  with `RESOLVE_NO_MAGICLINKS` → evaluate the **opened** file against the compiled policy →
  `ADDFD` (with `SECCOMP_ADDFD_FLAG_SEND` where the kernel has it, ≥ 5.14) → respond. Evaluating
  the *opened* file rather than the requested string is the whole point: the decision and the
  object are then the same thing.
- **The loop runs on `agentd`'s control thread, never the hot loop.** A human answer takes seconds;
  the hot loop's budget is microseconds.
- **`unsafe` is permitted here and nowhere above it.** `aisme-linux` is L2, where platform FFI
  lives, and every block will carry its `SAFETY` comment. `aisme-core` stays free of it.
- **Where `ADDFD` is absent the escalate class denies**, the tier already says so (`tier_of` reads
  `seccomp_addfd`), and the degradation sentence is already written in `tier.rs`. **That work is
  done and this point does not re-plan it** (point 1).

### 3. Implementation

- `crates/aisme-linux` will gain `seccomp.rs` with `SeccompEnforcer`, implementing `Enforcer`:
  `publish` installs the classic filter compiled from the policy's escalate class and returns its
  generation; `respond` answers an outstanding notification; `suspend`/`resume` return
  `Unsupported` naming the freezer as F3's; `tier` returns `EnforcementTier::Partial`.
- The filter itself is a small BPF classic program: `openat` from the session → `SECCOMP_RET_USER_NOTIF`;
  everything else → `SECCOMP_RET_ALLOW`. Built by hand rather than with a filter library: it is a
  dozen instructions and a dependency here would be a supply-chain surface for a security product.
- The notification loop will be a function `agentd`'s control thread drives, taking the notify fd
  and the policy, so it is testable without a daemon.
- Every answer emits a `VerdictIssued` event carrying `decided_by`, the channel, and **whether the
  target received a validated descriptor** — so the WAL distinguishes a permitted open from a
  re-executed one, which is the distinction `I-28` is about.

### 4. Tests

**New, and the first two are written before the enforcer**, because a test written after the
mechanism is a test written to pass:

- **The TOCTOU test in both forms.** (i) A target that rewrites its path buffer between the syscall
  and the supervisor's read receives the descriptor for the file the supervisor validated. (ii) A
  second process renames a directory component between the decision and the response, and the
  target still receives the validated file. **Form (ii) is the one the freezer would not have
  caught**, and it is why the design is what it is.
- A flags test: `O_CREAT`, `O_TRUNC`, `O_DIRECTORY` and an `openat2` entry are each denied **with
  the flag named**, not with "unsupported".
- A credentials test: a target running as another uid is denied with the reason and receives no
  descriptor.
- A supervisor-death test: kill the supervisor with a notification outstanding; the syscall fails
  closed with `EACCES`.
- A stale-notification test: the target dies before the answer; `ID_VALID` catches it.
- The gate's own line, in a guest: `cat /etc/shadow` inside a session returns `-EACCES` and the WAL
  carries the deny with its rule id.

**Existing to change:** `crates/aisme-agentd/src/platform/mod.rs` composes a `NullEnforcer` today;
it will compose `SeccompEnforcer` behind `cfg(target_os = "linux")` when the capability set says
`seccomp_addfd`, and `NullEnforcer` otherwise — which is the composition root doing its job.

### 5. Documentation

- Plan `F2.WS.05`'s row: the two limits, and that `CONTINUE` is never used for a path-bearing
  syscall.
- `docs/05` §5.3: the `CapabilitySet` bullet marked done (point 1).
- `docs/ai/memory/`: the `ADDFD`/`CONTINUE` rule, linking `[[seccomp-unotify-toctou]]`.

**Closing.** Verified against `crates/aisme-core/src/enforce.rs:42-72` (the frozen trait's four
methods), `docs/ai/invariants.md:92` (`I-28` as registered), `docs/05_challenge_ampliacion_f2.md:601-700`
(the decision and its limits), `crates/aisme-core/src/capability.rs:52` and `tier.rs:70` (already
implemented), and the plan's F2 scope table, whose Enforcement row names `seccomp_unotify` for the
escalate class. **Nothing of the skeleton fell.** Open: nothing — point 1
settled `publish` against the plan, and the enforcer is held by the control thread, not the
engine, so the human is never on the T0 path.

---

## Point 4 — `F2.WS.06`: `TerminalAdjudicator`, in the terminal the session already owns

**Done when:** a human answers in the terminal and the syscall obeys.

### 1. Challenge

*Is this the best solution?* `docs/design/01_permission-model.md` §7.3 makes the argument and it is
the reason `aisme run` is the default onboarding path: when the session is started as
`aisme run -- <cmd>` **we own the terminal**, so the prompt goes where the developer is already
looking — over SSH, in a container, in tmux, and in WSL2 where the daemon is in Linux and the
desktop is in Windows. It sidesteps the entire GNOME/KDE/Wayland/X11 problem for the most common
developer case.

*Is it coherent with the specs?* The `Adjudicator` trait is frozen and has four methods plus a
defaulted `notify`. `ask` returns a future and **must** resolve within `budget()` or yield the
channel's timeout default, which for the escalate class is `deny` (§2.20.5). A terminal prompt that
blocked forever would not be a slow adjudicator, it would be a hang.

*Can it be simplified?* Yes, and the simplification is the unattended path. The plan's row already
specifies `AISME_TERMINAL_ANSWER=<d|1|s|a>` for gates, and the constraint that makes it safe is an
ordering one: **the variable is read once, in `aisme run`, before `exec`, and never by the
adjudicator from the ambient environment**. An adjudicator that read its own environment could be
steered by anything that could set a variable in the daemon — including the supervised agent.

### 2. Verification

- **The answer is recorded as unattended.** A WAL that cannot distinguish a human's `deny` from a
  gate's `AISME_TERMINAL_ANSWER=d` would make every unattended run look like a human decision, and
  §4.6's numbers would measure the harness.
- **The budget is enforced by the adjudicator, not by the caller.** `ask` returns the timeout
  default itself when the human does not answer, so a caller that forgot to time out still fails
  closed.
- **The prompt goes to the controlling TTY, not to stdout.** A prompt on stdout would be captured
  by a pipe the agent controls, and an agent that can capture the prompt can answer it.
- **No prompt without a TTY.** Where there is none, `ask` yields the timeout default immediately and
  says so, rather than waiting a budget it cannot spend.
- **`I-05`'s never-promptable groups are refused before the prompt is composed**, not after the
  human answers: asking about something that cannot be permitted teaches the operator that their
  answer does not matter.

### 3. Implementation

- `crates/aisme-core` will gain nothing: the trait is frozen and complete.
- `crates/aisme-agentd` will gain `terminal.rs` with `TerminalAdjudicator`: `channel` returns the
  terminal channel, `budget` the §2.20.5 value for it, `ask` writes the prompt to the controlling
  TTY and reads one keystroke, `max_grant` the ceiling that channel is allowed.
- The prompt's text and its four answers come from `docs/design/01_permission-model.md` §7.3 and are
  **quoted there rather than invented here**, so the design note stays the source.
- `aisme run` reads `AISME_TERMINAL_ANSWER` **once, before `exec`**, and passes it to `agentd` on
  session registration; the adjudicator receives it as a value and never reads the environment.
- An unattended answer is recorded with a flag on the `VerdictIssued` event.

### 4. Tests

**New:**

- A pty test: a real pseudo-terminal, a written keystroke, and the verdict that results — one per
  answer letter.
- A timeout test: no answer within `budget()` yields `deny` for the escalate class, and the elapsed
  time is within a tolerance of the budget rather than unbounded.
- A no-TTY test: `ask` yields the default immediately and does not wait.
- An unattended test: the value passed in decides, **and the ambient environment does not** — the
  same test sets `AISME_TERMINAL_ANSWER` in the process environment to the opposite letter and
  asserts it is ignored. That is the test that fixes the ordering rule.
- An `I-05` test: a never-promptable group is refused without a prompt being written to the TTY.

### 5. Documentation

- Plan `F2.WS.06`'s row: that the unattended variable is read in `aisme run` and never by the
  adjudicator.
- `docs/design/01_permission-model.md` §7.3: nothing changes, and this point says so — it is the
  source, not a copy.

**Closing.** Verified against `crates/aisme-core/src/adjudicate.rs:146-163` (the frozen trait, with
`ask` returning a future bounded by `budget`), `docs/design/01_permission-model.md:184-211` (§7.3's
terminal tier and the `aisme run` argument), the plan's `F2.WS.06` row (the four answer letters),
and `docs/05_challenge_ampliacion_f2.md:756` (the variable read once before `exec`). **Nothing of
the skeleton fell.** Open: nothing.

---

## Point 5 — `F2.WS.07`: `forensicd` tails the WAL and resumes without loss

**Done when:** `forensicd` is killed mid-stream and resumes with zero loss.

### 1. Challenge

*Is this the best solution?* This is the smallest of the four and the only one with no dependency on
the others, which is why it can be built at any point. `aisme_core::wal` already gives it what it
needs: `read_record(segment, offset) -> (RawEvent, next_offset)` (`:223`) and
`replay(segment, from, out) -> Resume` (`:245`). The offset is the cursor, and the cursor is the
whole design.

*Is it coherent with the specs?* Yes, and it is the `H-03` split doing its job: everything expensive
lives in the cold path so the hot path stays inside its budget. F2's `forensicd` prints; DuckDB,
Parquet, the Merkle chain and OTLP are explicitly out of scope and stay out.

*Can it be simplified?* Yes. The resume cursor does not need a database or a lock file: it is one
`u64` in a file beside the WAL, written **after** the record it accounts for has been printed.
Written before, a crash between the write and the print loses a record silently — which is exactly
the failure the done-condition names.

### 2. Verification

- **The cursor is written after the effect, never before.** That ordering is the property; it makes
  a crash cost a *repeat*, not a loss, and a repeat is visible while a loss is not.
- **A truncated tail record is not an error, it is the normal state of a file being appended to.**
  `WalError::Truncated` names the offset and the bytes needed; the tail waits and retries from the
  same offset rather than skipping.
- **A segment roll is followed by offset, not by name.** The reader finishes the segment it holds
  before opening the next, so a roll cannot drop the records still unread behind it.
- **A cursor file that is missing means "from the beginning", and a cursor beyond the segment's
  length means the file was replaced.** Both are stated: the first is an absence with an honest
  default, the second is refused with the reason rather than clamped, because clamping a cursor
  silently skips whatever was between.

### 3. Implementation

- `crates/aisme-forensicd/src/main.rs` gains `aisme-forensicd --tail <wal-dir>`: open the newest
  segment, read the cursor from `<wal-dir>/.forensicd-cursor` (absent means 0), replay from it,
  print one line per record, and write the cursor after each print.
- Printing is one line per `RawEvent` with its sequence, kind, pid and resolved path — enough for
  `F2.WS.08`'s CLI line to be a filter over it rather than a second formatter.
- On `Truncated`, sleep briefly and retry from the same offset. On a new segment appearing, finish
  the current one first.

### 4. Tests

**New:**

- **The done-condition, as a test**: write N records, tail with a reader that is killed after M,
  restart it, and assert the union of both runs is exactly N records with no gap and no
  reordering. A repeat at the seam is allowed and asserted to be *at most one*.
- A truncated-record test: append half a record, assert the tail waits rather than erroring, then
  append the rest and assert it is read.
- A missing-cursor test: absent means from the beginning, and a cursor past the end is refused with
  its reason rather than clamped.

**Existing to change:** none.

### 5. Documentation

- Plan `F2.WS.07`'s row: the cursor file and the after-the-effect ordering, because "resumes with
  zero loss" names a property and not a mechanism.
- `docs/ai/STATE.md`, `docs/CHANGELOG.md`: the usual rows.

**Closing.** Verified against `crates/aisme-core/src/wal.rs:223` and `:245` (the two functions this
depends on, both present), `crates/aisme-forensicd/src/main.rs` (9 lines, no behaviour), and the
plan's F2 scope table, whose Persistence row is "WAL append + `forensicd` tail" with DuckDB,
Parquet, Merkle and OTLP out of scope. **Nothing of the skeleton fell.** Open: nothing.

---

## What this document changed

| Point | What it settled |
|---|---|
| 1 | Four coherence findings. `Enforcer::publish` is **per-enforcer** and the plan said so at `:1116`/`:1129` — a question this review asked before reading §3.2; `.05` and `.06` install inside `.08`, which the table orders last; `02_aisme-run.md` still gives the seccomp filter to the task `Q-13` took it from; and **the seam `.05` and `.06` plug into does not exist** — `platform::enforcers` is called once outside tests, to print how many there are |
| 2 | `F2.WS.08` is built **first**, and covers four of the design note's nine steps — the other five are named with their owners rather than half-built |
| 3 | `SeccompEnforcer::publish` installs the classic filter — that is what publishing to this enforcer's decision point means. `CONTINUE` never permits a path-bearing syscall; the allow path's order is the security, and the enforcer lives on the control thread so a human is never on the T0 path |
| 4 | `F2.WS.06`'s unattended variable is read once in `aisme run` before `exec` and **never** from the adjudicator's environment — an adjudicator that read its own environment could be steered by the agent it adjudicates |
| 5 | `F2.WS.07`'s cursor is written **after** the record is printed, so a crash costs a repeat and never a loss |

**Implementation order**: `F2.WS.08` → `F2.WS.05` → `F2.WS.06`, with `F2.WS.07` independent and
runnable at any point.

**Nothing is open for the owner.** The one question this review first raised was answered by the
plan's own §3.2, which it had not read; the divergence that question was hiding — an engine with no
enforcement seam — is a plan fix and not a decision, because `docs/05` §5.3 already requires the
enforcers to live off the hot loop.
