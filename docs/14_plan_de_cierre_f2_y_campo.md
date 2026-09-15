# Challenge-amplification — closing F2, and what the field record adds

Everything still owed, amplified until executing it requires no further decision. The skeleton is
eight points in the order that unblocks the most; each is then completed with its five sections, and
**each closes with a coherence pass against the points before it and against the specs**, because a
point that contradicts an earlier one is a defect and not a difference of opinion.

## The skeleton

| # | Point | Blocked by |
|---|---|---|
| 1 | Land what is in the working tree | nothing |
| 2 | Per-session policy bindings — `${workspace}` and `${home}` | nothing |
| 3 | `F2.WS.11`'s second half — the denial nobody was notified about | a guest, for one half |
| 4 | Host-executed configuration as an enforcement point | a measurement, then a decision |
| 5 | Legible denials | nothing |
| 6 | Enforcement that survives the agent's own permission flags | point 1 |
| 7 | `F0.ASSET.02` — the reference recording | **the owner**, for one half |
| 8 | GATE F2, the phase close, and the roadmap edits the field record argues for | points 1–6 |

Points 1, 2, 5 and 6 are executable today. Point 3 is half executable today and half needs a guest.
Point 4 needs one measurement before it needs a decision. Point 7 is the only one that is genuinely
the owner's. Point 8 is last by construction.

## How to read this

Each point is **Challenge** (is it the best answer, is it coherent with the specs, can it be
simplified), **Verification** (is it safe, clear and compliant — and if it is not, it asks rather than
resolving), **Implementation** (what will be done, already sieved), **Tests**, **Documentation**, and
a **Coherence** paragraph. Written in declared future so that whoever executes it decides nothing.

Nothing here touches the repository except where a point says a measurement is owed first, and those
are read-only.

---

## Point 1 — Land what is in the working tree

**Done when:** `git status` is clean, `origin/main...HEAD` reads `0 0`, and the two bypasses found on
2026-09-15 are both closed in a commit with their tests.

### 1. Challenge

*Is this the best solution?* It is not a solution, it is a debt. The working tree holds a security
fix that is measured and not committed, which is precisely the state `CLAUDE.md`'s rule 3-bis exists
to forbid: *"un commit local es una avería esperando a un disco"*. It goes first for that reason and
for one more — points 6 and 8 both build on it, and a base that is not committed is a base that can
be lost.

*Is it coherent with the specs?* Yes, and the fix restores a specification rather than amending one.
`docs/05` §5.3 already read *"`openat2` with `RESOLVE_NO_MAGICLINKS` → evaluate **the opened file**
against the compiled policy → `ADDFD`"*. What shipped evaluated the requested spelling and then
opened it. Inverting those two steps was the whole defect.

*Can it be simplified?* One thing in it can, and the challenge removes it: the `O_PATH` locate step
could have been skipped by opening for reading and deciding afterwards. It is kept because opening
before deciding means opening files the policy is about to refuse, and **a FIFO opened for reading
blocks until a writer appears** — so a denied path could hang the supervisor. `O_PATH` never blocks
and works for any file type. That is a security property, not a tidiness one.

### 2. Verification

Safe, clear and compliant, with four properties that must hold and are each checkable:

- **The descriptor the target receives names the file the policy judged.** It is reopened through
  `/proc/self/fd/<n>`, never through the string, so nothing is resolved twice. This is `I-28` and
  re-resolving here would give it away after paying for it.
- **A file the policy refuses is never opened for reading.** The locate step is `O_PATH`.
- **A deleted file is refused rather than decided about.** `/proc/self/fd` renders it as
  `"… (deleted)"`, which is not a path a rule can be matched against, and the code refuses that
  string explicitly rather than matching a rule against it.
- **The test asserts the two spellings differ**, not merely that the resolved one is right. A
  supervisor that returned the string it was given would pass a weaker assertion.

**One thing is not verified and must be before the commit lands:** the test added to
`crates/aisme-linux/src/seccomp.rs` was written while the shell was unavailable and **has not been
compiled**. `cargo test --workspace` and `cargo xtask gate --level commit` are the gate, and rule 14
applies — a `FAIL` is fixed before committing, never declared in the body.

### 3. Implementation

The code is already written. What remains is to run it and land it.

- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` and `cargo xtask gate --level commit`, in that order. If the new test does
  not compile, fix it; if it cannot be fixed quickly, **drop that hunk and commit the fix alone**
  rather than delaying a security correction, and open the test as its own numbered point.
- Delete `docs/13_investigacion_incidentes_y_guardarrailes.md`. It is an untracked stub whose only
  content says it is superseded; it has never been committed, so its number is free and the gap it
  leaves is harmless.
- Commit in **two** commits, because they are two things: the security fix with its test, its memory
  file and its plan row; and the research report with its changelog line. A single commit mixing a
  kernel-path correction with a field study is a commit nobody can review.

### 4. Tests

**New, and already written:**
`the_decision_is_taken_on_the_resolved_path_and_not_the_spelling` in `aisme-linux`'s seccomp tests. A
child opens a **symlink**; the supervisor asserts the asked path is the link, that the resolved path
is the real file, that the two differ, and that the target reads through the descriptor it is handed.
It would have failed before the fix at the second assertion.

**Existing, unchanged:** every other seccomp test asks for a file by its real name, which is why none
of them caught this. That is worth stating rather than fixing: they test other properties correctly.

### 5. Documentation

Already written and in the tree: the plan's `F2.WS.05` row, `docs/ai/memory/a-path-is-a-spelling.md`,
the `STATE.md` Done row, and the changelog lines for both the fix and the research report.
`deploy/hooks/aisme-hooks.json` has been corrected to name **only** the user's settings file, with
the four CVEs and the in-the-wild worm that make a project settings file the wrong place for a
security control.

### Coherence

Consistent with `ADR-09` (the supervisor is the session's ancestor — this point changes what it
decides on, not who decides), with the syscall-class fix committed the same day (the two are the same
lesson at different levels: a gate that names one door, and a rule that names one spelling), and with
`I-28`, which it restores. **No claim of the skeleton fell.** Open: the new test is uncompiled, which
point 1 states as the one thing to check first rather than assume.

---

## Point 2 — Per-session policy bindings

**Done when:** `deploy/policy/skeleton.aisme` carries `${workspace}` and `${home}`, the daemon binds
both per session, and a rule using either is measured deciding correctly for two sessions with
different values.

### 1. Challenge

*Is this the best solution?* It is the only one. The shipped policy has carried two defects since
`F2.WS.05`, both recorded and neither fixed: rule 3 reads `path_under = "$workspace"`, which the
grammar treats as a **literal** — so it matches a directory no machine has while `3 rule(s) in force`
reports it present — and rule 2 was `~/.aws/**`, a tilde the shell expands and the kernel never sees,
which the compiler now refuses by name. Rule 2 was made to work with `**/.aws/credentials`; **that is
a workaround, not the form**, and it matches any `.aws` directory anywhere rather than the session's
own user.

*Is it coherent with the specs?* `Bindings` is documented as *"what `${…}` variables resolve to for
**one session**"* (`crates/aisme-core/src/policy/compile.rs:43`). The daemon compiles **once at
startup**, before any session exists. The two cannot both be true, and the specification is right.

*Can it be simplified?* The obvious simplification is wrong and must be named so nobody proposes it:
the session could send its own `home` and `workspace`. It must not. A session that named its own
`${home}` would point a credential rule at an empty directory. **Both bindings come from facts the
kernel or the system supplies**, exactly as the declaring pid does.

### 2. Verification

Safe and clear, with the trust of each binding stated:

- **`${home}`** comes from the **peer's uid**, taken from `SO_PEERCRED` and resolved through the
  password database by the daemon. Unforgeable, and it is the same fact the whole authorization model
  already rests on.
- **`${workspace}`** comes from the session's declared scope, which is the value the **person** who
  typed `aisme run --scope` chose. That is the same trust position `--scope` already has and
  `docs/design/02_aisme-run.md` step 1 already documents. A wider workspace widens what a rule with
  verdict `allow` permits, and the person widening it is the person launching the agent — not the
  agent.
- **A policy that fails to compile for a session refuses that session**, not the daemon. The daemon
  now holds a *parsed* policy and compiles per registration, so an unbound variable is a registration
  error with the rule named, and other sessions are unaffected.

**Not verified, and it must be:** whether compiling per registration is affordable. `compile` runs
once per session, not per open, and a session lasts minutes — so the expectation is that it is
irrelevant. It will be measured and stated rather than assumed.

### 3. Implementation

- `aisme-agentd` stores the **parsed** `Policy` and the source path instead of a compiled one.
  `--policy` still parses at startup, so a syntactically broken policy still refuses the daemon and
  the reason is still named; what moves later is only the binding.
- `register_session` builds `Bindings` with `workspace` from the registration's declared scope and
  `home` from the peer's uid, compiles, and stores the `CompiledPolicy` in that session's
  `SessionFacts`. A compile failure answers the registration with the rule and the variable named.
- `registerSession`'s params gain `scope`, which the session already knows and already prints.
- `decideOpen` evaluates the **session's** compiled policy, falling back to the declared escalate
  list exactly as it does today when there is no daemon policy.
- `deploy/policy/skeleton.aisme` rule 2 becomes `${home}/.aws/**` and rule 3 keeps `${workspace}`,
  now spelled correctly.
- `crates/aisme-agentd`'s test that compiles the shipped policy binds both, as `aisme-core`'s tests
  already bind `workspace`.

### 4. Tests

**Existing, changed:** `the_shipped_policy_keeps_all_three_of_its_rules` binds `${home}` and
`${workspace}` and keeps asserting deny, escalate **through the glob**, and default-allow. The
escalate assertion moves to a path under the bound home, which is what a kernel produces.

**New:**

- **Two sessions, two homes, one policy.** Two registrations with different `home` bindings; a path
  under the first session's home escalates for the first and is **allowed** for the second. A daemon
  that compiled once would answer both the same, and this is the test that catches it.
- **A session whose policy will not compile is refused, and the daemon is not.** An unbound variable
  in the shipped policy refuses that registration naming the variable and the rule, and a second
  registration that does bind it still succeeds.
- **The binding is not a parameter.** A registration that tries to send `home` is ignored; the value
  used is the one derived from the peer. Driven through `serve_line`, so the production path runs.

### 5. Documentation

- `deploy/policy/skeleton.aisme`: rules 2 and 3, and the comment that currently explains why rule 2
  is a workaround is replaced by what the rule now says.
- Plan `F2.WS.11`'s row loses the "it also owns one defect" clause, and `F2.WS.05`'s gains that the
  policy is compiled **per session** with bindings the kernel supplies.
- Plan Annex I: `registerSession` gains `scope`; `decideOpen` gains that the policy it evaluates is
  the session's.
- `docs/ai/memory/policy-variables-need-braces.md` gains the answer taken, so the memory records the
  resolution and not only the trap.

### Coherence

Consistent with point 1 (which changes what a decision is taken *on*; this changes which policy takes
it) and with `ADR-09`'s split — the daemon still decides, and now decides with the session's own
bindings. Consistent with `docs/10` step 1's property that **the policy is the daemon's**: the session
supplies neither the rules nor the bindings, only the scope its operator typed. **One claim of the
skeleton fell**: `${home}` cannot come from the session's environment, which was the obvious source,
because a session that named its own home would aim a credential rule at nothing. Open: the
per-registration compile cost, which will be measured rather than assumed.

---

## Point 3 — `F2.WS.11`'s second half: the denial nobody was notified about

**Done when:** a write outside the workspace is denied **with zero notification traffic**, and the
denial is recorded from the syscall's return value with `FLAG_INFERRED_FROM_EXIT`.

### 1. Challenge

*Is this the best solution?* The done-condition is the most interesting sentence in F2 and the
challenge is that **half of it is not measurable the way it is written**.

`seccomp_unotify` fires **before** the LSM hook. So in a session with `--trap-openat`, a write-mode
`openat` outside the workspace is trapped by the filter and refused by `reproducible` — which means
it produces **one notification**, and Landlock never gets to decide. Measuring "zero notification
traffic" on that operation measures seccomp, not Landlock.

The property is real. It applies to **the operations the filter does not trap**: a write through an
already-open descriptor, `unlink`, `unlinkat`, `rename`, `truncate`, `mkdir`. For those, Landlock
denies in kernel and nothing is notified, which is §2.2.1's whole argument and is measurable **on the
host today**, because the supervisor already counts and prints its notifications.

*Is it coherent with the specs?* The second half — recording the denial from the exit tracepoint —
needs a loaded BPF program and therefore a guest (`I-12`). That half is unchanged.

*Can it be simplified?* Yes, into two halves that can land separately: the zero-traffic assertion on
the host now, and the exit-tracepoint recording in a guest after. Treating them as one has kept both
from landing.

### 2. Verification

- **The zero-traffic claim must be made about an operation the filter does not trap**, or it is a
  claim about seccomp wearing Landlock's name. The test will use `unlink` of a file outside the
  workspace, which no F2 filter traps.
- **A denial the supervisor never sees must still be counted somewhere**, or the product is claiming
  a property it cannot evidence. That is what the exit tracepoint is for, and until it exists the
  honest statement is that the denial is *enforced* and *not recorded* — which the row must say.
- **`FLAG_INFERRED_FROM_EXIT` must be on the wire**, beside `FLAG_PATH_UNRESOLVED`, so two distinct
  honesties stay distinct: *we did not resolve this path* and *we did not observe this decision, we
  inferred it*.
- **An `EACCES` is not necessarily ours.** A write can fail for ordinary permission reasons. The
  record will say *an access denial consistent with the session's ruleset*, and attribute it only
  where the path lies outside the declared scope — which is knowable in user space without asking the
  kernel who denied it. Where it is ambiguous the record says ambiguous.

### 3. Implementation

**Half A, on the host, now.** A test asserts that `unlink` of a file outside the workspace fails with
`EACCES` under a session with `--trap-openat`, and that the supervisor's summary shows **no
notification** for it. The counters already exist and are already printed.

**Half B, in a guest.** `crates/aisme-ebpf` gains `sys_exit_openat`, enabled per session, emitting a
`FileOpen` with `outcome = Denied`, `FLAG_INFERRED_FROM_EXIT` and the errno in the payload's spare
bits when the return is negative. `agentd` joins the exit event to the enter event by `(tgid, seq)`
and keeps one record with the errno attached, not two.

### 4. Tests

**New:**

- **Half A**: the zero-traffic assertion above, in `tests/session.rs`, on an operation the filter does
  not trap. It fails if somebody later adds `unlink` to the filter without re-reading this point.
- **Half B, in a guest**: the WAL contains exactly one denial record carrying
  `FLAG_INFERRED_FROM_EXIT`; a write **inside** the workspace produces no denial; and an `EACCES`
  arising from ordinary permissions is recorded as ambiguous rather than attributed.
- **ABI gating on an older kernel**: the ruleset is skipped, the tier reads `L2-`, the banner names
  the lost function, and the run still works.

### 5. Documentation

- Plan `F2.WS.11`'s row: the done-condition splits into the two halves, and says why the first must be
  measured on an operation the filter does not trap.
- Plan §F1.1's `RawEvent` block: `FLAG_INFERRED_FROM_EXIT`.
- `docs/ai/memory/landlock-l2-file-deny.md`: that seccomp fires before the LSM, which is the fact that
  makes the zero-traffic property measurable only outside the trapped set.

### Coherence

Consistent with point 1 and `ADR-09`: the supervisor's counters, which this point's first half
asserts on, are the ones `aisme run` now prints. **One claim of the skeleton fell, and it is the
point's own done-condition**: "a write outside the workspace produces zero notification traffic" is
false for a write-mode `openat` under `--trap-openat`, because seccomp precedes the LSM. The property
survives, narrowed to the operations the filter does not trap, and it becomes measurable on the host
today instead of waiting for a guest. Open: half B needs a guest and a BPF program, and nothing here
changes that.

---

## Point 4 — Host-executed configuration as an enforcement point

**Done when:** it is measured whether a supervised agent can write `<workspace>/.claude/settings.json`,
and either it cannot or the reason it still can is a plan row with an owner.

### 1. Challenge

*Is this the best solution?* The question is not settled enough to have a solution yet, which is why
this point begins with a measurement and not with a design.

The field record is unambiguous that the file matters: hooks in a repository's settings execute on
clone-and-run with no confirmation (CVE-2025-59536); the same file sends an API key to an attacker
before the trust dialog (CVE-2026-21852); an agent writing one in the workspace gets it executed
unsandboxed by the host (CVE-2026-48124, CVSS 8.5); a variant through a task file is **unfixed**; and
CHAINDROP — a worm, in the wild, August 2026 — commits one into victim repositories so that opening
the folder re-runs its payload. `DT-14` already names these paths as an escalate-class detector.

*Is it coherent with the specs?* It is the gap between a detector and an enforcer. `DT-14` detects;
nothing denies. `F3.EN.11` is the task that would.

*Can it be simplified?* **No, and the reason is a property of Landlock rather than of this design.**
Landlock rules only *grant*. There is no deny rule and no way to subtract a subtree from an allowed
one, so "allow the workspace except `.claude`" means granting the workspace's entries individually
and omitting that one — which then denies creating any new entry at the workspace root, and breaks
ordinary work.

### 2. Verification

**This point is not 100 % clear and the ambiguity is the owner's, so it asks rather than resolving.**

What is owed first is one read-only measurement: under `aisme run --scope <repo>`, can the supervised
process create `<repo>/.claude/settings.json`? `docs/12`'s M5 measured the **outside**-the-workspace
case and found it denied in kernel. The inside case is inferred from the scope's construction and has
**not** been measured. It must be, because a finding acted on before it is measured is exactly what
this project's rules forbid.

**If it is writable, the question for the owner is which of three:**

1. **Enumerate and exclude.** Grant the workspace's entries individually, omitting the agent
   configuration directories. Costs the creation of new top-level entries, which is a real
   restriction on ordinary work.
2. **Wait for `F3.EN.11`.** The kernel-side path policy can express a deny. Costs the gap staying open
   until F3.
3. **Trap the write class.** The supervisor reproduces write-mode opens faithfully and refuses the
   configured paths. Costs `F3.EN.12`'s widening, and it is the largest of the three.

None of them is free, and choosing among them is a scope decision rather than an implementation one.

### 3. Implementation

**Only the measurement, and only after it the rest.** A read-only script that starts a daemon,
launches a session scoped to a scratch workspace, attempts to create `.claude/settings.json` inside
it, and reports whether the file exists afterwards. Symmetrically for `.vscode/tasks.json`,
`.mcp.json` and `.git/config`, because the field record names all four and a measurement of one is a
measurement of one.

Whatever it returns becomes a numbered plan row against `F3.EN.11` naming the three options and their
costs. **No enforcement is implemented in this point.**

### 4. Tests

**New, and only after the decision:** whichever route is chosen gets a test that a supervised session
cannot create or modify the configuration files named, **present or absent** — the second half
mattering because CVE-2026-25725 is exactly the absent case, where a protection applied only to a
file that already existed was defeated by creating it.

Until then, one test is owed regardless of the route: **a regression test that the file is
writable**, so that the day it stops being writable, somebody has to come and delete the test and
read why it was there. A known gap with a test on it is a gap somebody will close; a known gap with
nothing on it is a gap that survives three phases.

### 5. Documentation

- Plan: a row under `F3.EN.11` with the three options and their costs, citing
  `docs/research/01_incidentes_y_defensas_de_agentes_ia.md` Part II §6 and Part V D-4.
- `docs/security/01_threat-model.md`: the class named, since it is a *host* executing content the
  agent wrote and the threat model currently ranks adversaries but not this handoff.
- `docs/ai/STATE.md` → *Open, not blocking*, with the measurement's result.

### Coherence

Consistent with point 2, which changes what the scope's rules *say* and not what the scope *is*.
Consistent with `DT-14`, which it gives an enforcer to rather than replacing. **No claim fell, because
the point makes none**: it records that the inside-the-workspace case is unmeasured and refuses to
design on it. Open, and explicitly the owner's: which of the three routes, after the measurement.

---

## Point 5 — Legible denials

**Done when:** a supervised process that is refused can tell *forbidden* from *missing*, and the
reason reaches the record.

### 1. Challenge

*Is this the best solution?* The evidence for it is thin and the argument is strong, which is an
uncomfortable combination and should be said plainly.

Two independent accounts describe an agent reading a denial and reasoning its way around it, and one
research system names the mechanism directly: *"OS sandboxes control resource access instead of
actions, returning opaque errors that confuse the agent"*. Every escape in the field record begins
with the agent trying another spelling after a refusal it could not interpret.

Today AISME answers `EACCES` and nothing else. A missing file, a policy denial and a supervisor that
could not reproduce the call are indistinguishable to the caller — which is the same conflation
`F3.EN.12` already owns for the errno.

*Is it coherent with the specs?* `I-19` says the system never fails silently and declares its
degradations loudly. This is that rule applied to the one audience it currently excludes: the
supervised process.

*Can it be simplified?* Yes, and the simplification is what makes it safe. **No new channel.** The
errno is widened to the truth the supervisor already knows — `ENOENT` when the file is not there,
`EACCES` when the policy refused — and the *reason string* goes where it already goes, to the record
and the operator. Inventing a side channel to explain a denial to an agent would be inventing a
surface.

### 2. Verification

- **Widening the errno tells the caller nothing it could not learn by asking again**, since it can
  stat the path itself. It leaks no policy content: a denial says *refused*, never *refused by rule
  `deny-shadow`*.
- **It must not become an oracle.** The distinction is between "this does not exist" and "this is
  refused", and nothing finer. A caller that could enumerate *which* rule matched could map the
  policy by probing.
- **It is `F3.EN.12`'s by ownership**, and this point takes only the half that is free: the
  supervisor already distinguishes the two cases internally and records them with different reasons.
  What changes is that the caller sees the difference too.
- **No evidence is claimed for the effect.** The argument is that an agent which can tell the two
  apart has no reason to try eleven spellings of a file that is simply absent. Whether that reduces
  evasion is **unmeasured**, here and in the field, and the plan row will say so.

### 3. Implementation

- `serve_notifications_with`'s deny path answers `ENOENT` where the supervisor's own locate failed
  with `ENOENT`, and `EACCES` where the policy refused. The two are already separate branches with
  separate reason strings; only the errno is shared.
- Every other refusal — a shape the supervisor cannot reproduce, a flag outside the subset, a path it
  could not read — keeps `EACCES`, because those are refusals and not absences.
- The reason string already reaches the operator. It is left alone.

### 4. Tests

**Existing, changed:** the tests that assert `EACCES` on a denial keep asserting it; they are about a
refusal, not an absence.

**New:**

- **A missing file reports missing.** A supervised open of a path that does not exist returns
  `ENOENT`, and a supervised open of a path the policy denies returns `EACCES`. Both in the same
  test, because a supervisor that answered one errno for everything would pass either alone.
- **The errno is not an oracle.** A denied path and a denied path under a *different* rule return the
  same errno and the same absence of detail.

### 5. Documentation

- Plan `F2.WS.05`'s row: the errno distinction and the sentence that its effect on evasion is
  unmeasured.
- `docs/ai/invariants.md`: nothing changes. `I-19` already covers it; the row cites it.
- `crates/aisme-linux/src/seccomp.rs`: the comment that currently says answering `EACCES` for an
  absence is *"the conservative choice … widening it is `F3.EN.12`'s"* is rewritten to say what the
  code now does, since a comment that describes the old behaviour is worse than none.

### Coherence

Consistent with point 1, which created the locate step this point reads the errno from — before it,
the supervisor's open and its decision were the same call and the two failures could not be told
apart. **This point is only cheap because point 1 landed**, which is worth recording as an argument
for the order. Consistent with `F3.EN.12`'s ownership: this takes the half the supervisor already
knows and leaves the widening. Open: the effect is unmeasured and the row will say so.

---

## Point 6 — Enforcement that survives the agent's own permission flags

**Done when:** a gate line runs a session with every agent-side permission disabled and asserts the
same verdicts.

### 1. Challenge

*Is this the best solution?* It asserts a property the design already has, which is the best kind of
test to write and the easiest kind to never write.

In the one supply-chain incident where agents were used as the attack instrument, the malware did not
bypass the permission system: it **invoked the agents with their own permission-skipping flags**. The
human gate was not defeated, it was not present. 2,349 credentials from 1,079 systems.

AISME's enforcement never consults the agent, so the property holds by construction. **By
construction is not the same as under test.** A future change that made any verdict depend on
something the session supplies would break it silently, and the gate would not notice.

*Is it coherent with the specs?* It is `I-20`'s determinism and `H-11`'s "no LLM in the decision path"
expressed as an executable check.

*Can it be simplified?* It is already one line. What it must not do is grow into a harness that
emulates an agent; it runs the same three verdicts with the environment an attacker would set.

### 2. Verification

- **The flags are the agent's, not AISME's.** The test sets the environment variables and arguments a
  compromised caller would use to disable the *agent's* own approvals, and asserts AISME's verdicts do
  not move. It must not test AISME's own flags, which is a different property.
- **It must assert the `asked` column too.** A session that skipped the prompt and was *allowed*
  would look identical to one that was never asked, and the difference is the whole point.
- **It belongs in the phase gate, not only in the suite.** A property that is the product's central
  claim should fail the gate, not a test somebody runs.

### 3. Implementation

A line in the `GATE F2` block and a test in `tests/session.rs`: the three verdicts of the skeleton
policy are re-run with the agent-side permission environment set to its most permissive, and the
results compared to the same three without it. The comparison is on the verdicts **and** on the
`asked` counts.

### 4. Tests

**New:** `enforcement_does_not_move_when_the_agent_disables_its_own_approvals`. Two runs, same
assertions, one with the permissive environment. It fails if any verdict or any `asked` count
differs.

### 5. Documentation

- Plan `GATE F2`: the line, and one sentence saying what it is for, citing the incident.
- `docs/security/01_threat-model.md`: adversary **A1** already covers the misaligned agent; this adds
  that the agent's own approval state is **not** part of AISME's decision, which the threat model
  currently implies and does not state.

### Coherence

Consistent with point 5: legible denials tell the *caller* more, and this asserts that telling the
caller more does not change the *verdict*. The two could have conflicted and do not, because the
errno is an outcome and never an input. Consistent with `ADR-09`: the supervisor is the session's
parent, so the agent's environment reaches the child and not the decision. **No claim fell.** Open:
nothing.

---

## Point 7 — `F0.ASSET.02`, the reference recording

**Done when:** `tests/fixtures/reference-trace/` holds a recording whose manifest names what produced
it, and both gates it exists for can read it.

### 1. Challenge

*Is this the best solution?* Everything that does not need the owner is built: the recorder
(`aisme-agentsim --to-trace`), the synthetic generator (`--emit-trace`), the attribution by process
subtree, and the declaration path (`aisme declare`, 1 ms per call). What is owed is the recording.

*Is it coherent with the specs?* Two questions remain and the field record settled the harder one.

**Where it may be recorded** is now the only open half. A session record **cannot** be the source, and
`docs/12` refuted it on completeness — intents and no actions. The field record refutes it again and
harder, on **reliability**: in the home-directory wipe the destructive tool call **was never written
to the transcript**. A recording derived from an agent's own log can be missing the single event a
forensic reader would look for, and missing it silently.

*Can it be simplified?* One thing can, and it is worth naming so nobody proposes it: recording through
the seccomp trap needs no BPF at all. It fails on `F0.ASSET.02`'s own sentence — *"recorded in
observe-only mode … so recording it perturbs nothing"* — because a trapped open costs **+17 µs**
(measured) and the overhead is proportional to open density, so it flattens exactly the short bursty
commands §2.22 replays the fixture for. It also sees only opens.

### 2. Verification

**This point is genuinely the owner's and it asks rather than resolving.** Two questions, both stated
in `docs/12` and neither changed by the field record except in weight:

- **May the sensor load, once, on the machine where a real session runs?** `I-12` says no
  kernel-touching test runs on a host, and the project's operative reading — in its own code — is *no
  BPF program is loaded on a host running the test suite*. A one-off recording is not the suite. A
  guest cannot host a real session. Narrowing an invariant needs an ADR, not a decision in a plan.
- **What declares the tool calls?** A pre-tool hook, and `aisme declare` exists. The field record
  changed **where it may live**: the user's settings file and nowhere else, because a repository's
  settings file is the attack surface itself. `deploy/hooks/aisme-hooks.json` has been corrected.

### 3. Implementation

**Nothing, until the first question is answered.** What is already built is listed above and needs no
further work to be useful; what is owed is one recording and the manifest fields that come with it
(`agent`, `model`, `repository_commit`, `wallclock_seconds`, and the content hash sealed by `xtask`).

### 4. Tests

**Already written:** the round trip, attribution by subtree under interleaved tool calls, an
unexplained action kept with token `0` and counted, a kind with no action counted by name, and the
determinism of the synthetic generator.

**Owed with the recording:** that the manifest's hash is over the content it names, and that an empty
recording is refused rather than written — a zero-entry fixture that passes a gate is the failure this
asset exists to prevent.

### 5. Documentation

- `tests/fixtures/reference-trace/manifest.toml`: `produced_by` written by the recorder from what
  actually ran, rather than a sentence somebody maintains.
- Plan `F0.ASSET.02`'s row already says the recorder exists and the recording is owed. It gains that a
  transcript is not a permitted source, with the reason.
- `docs/ai/STATE.md` → *Next up*: the two questions, unchanged in substance and sharper in form.

### Coherence

Consistent with point 2 — the recorder attributes by process subtree, and per-session bindings do not
touch attribution. Consistent with `ADR-09`, which made `aisme run` the tree's root and therefore made
subtree attribution exact rather than heuristic; that was not why `ADR-09` was taken, and it is a
benefit worth recording. **No claim fell here; one was reinforced from outside.** Open, and the
owner's: whether the sensor may load once.

---

## Point 8 — GATE F2, the phase close, and the roadmap edits

**Done when:** `GATE F2`'s output is in `STATE.md` verbatim, every line measured against the shipped
configuration, and the field record's ordering arguments are plan rows rather than a document nobody
cites.

### 1. Challenge

*Is this the best solution?* The gate is not a solution, it is the phase's definition of done. What
this point adds is that **its output must be earned against the configuration that ships**, which it
now is: the five enforcement lines were re-run on the host against a daemon with `CapEff
0000000000000000` and every line went through `sh -c`, therefore through a grandchild.

*Is it coherent with the specs?* Yes, and the one thing it must not do is close the phase on a gate
that passes for a reason the product does not have. That happened once already — the guest daemon ran
as `uid 0`, where `CAP_SYS_PTRACE` makes Yama irrelevant — and it is the reason `ADR-09` exists.

*Can it be simplified?* The gate itself, no: each line is somebody's input. The **roadmap edits**
can, and they must be, because a field record that produces ten decisions and no plan rows is a
document that will be read once.

### 2. Verification

- **`PASS` and `PENDING` are acceptable; `SKIP` needs its reason beside it.** Unchanged.
- **The output goes in verbatim.** A gate summarised is a gate nobody can check.
- **The phase does not close on points 3B and 7.** `F2.WS.11`'s guest half and the reference recording
  are both owed, and the row must say which of them blocks the phase and which does not. Plan `:1360`
  places the recording **before** the gate, so it blocks; `F2.WS.11`'s half B is a done-condition of a
  task whose first half is measured, so it blocks its task and not the phase.
- **The roadmap edits are arguments, not conclusions.** Three of them reorder F3 and one reframes a
  deliverable. Each becomes a plan row **citing its evidence**, and any that the owner rejects becomes
  a recorded rejection rather than a silent omission.

### 3. Implementation

- Run the gate: `test-skeleton`, the five enforcement lines in one guest boot, `verify-budgets
  --profile skeleton`, `bench-t0 --syscalls 100000`. Paste the output into `STATE.md`.
- Four plan edits, each one row, each citing `docs/research/01`:
  - **D-3** — raise `F3.EN.09` and `F3.EN.11` above `F3.EN.12`. The kernel documents that seccomp
    cannot dereference pointers by design, so object-shaped enforcement belongs in an LSM; widening
    seccomp buys fidelity on one class, the LSM buys the classes AISME cannot reach at all.
  - **D-5** — the session boundary against the trust-handoff class, in the threat model, with a
    marker. Three of seven July 2026 escapes execute in the **host's** process tree after the agent's
    turn, and a product that says it supervises a session without saying where the session ends is
    making a claim it does not hold.
  - **D-9** — `F0.ASSET.02` and the correlation harness reframed as deliverables with an external
    audience. Two independent 2026 papers say the field's missing artefact is a shared benchmark, and
    no third-party evaluation of any commercial kernel-level agent guardrail exists.
  - **D-10** — egress: the honest conclusion is that it is necessary and **not** sufficient, that the
    three largest exfiltrations left through trusted domains, and that what would have caught them is
    session-aggregate shape. That is an argument for finishing `F0.ASSET.02`, **not** for reordering
    F3, and the row says so to stop a future reader concluding the opposite.
- **D-6 is not a plan edit.** Whether the escalate class is a control or a friction-and-recording
  mechanism changes what F2 claims, and it is the owner's.

### 4. Tests

None of its own. Every line of the gate is somebody else's test, and the gate is the test of the
whole. What this point adds is one rule: **the gate's output is recorded verbatim**, and a line whose
result is `SKIP` carries its reason on the same line.

### 5. Documentation

- `docs/ai/STATE.md`: the gate output, and *Next up* reduced to what remains.
- Plan: the four rows above, plus `GATE F2`'s block gaining point 6's line.
- `docs/research/01`: its Part V gains, per decision, whether it became a row, was rejected, or is
  still open. A research document whose proposals have no recorded fate is a document that will be
  re-litigated.

### Coherence

Consistent with every point before it: point 1 lands the base the gate measures, point 2 makes the
shipped policy the one the gate compiles, point 3A adds a line the gate can run on the host, point 5
changes an errno the gate's assertions do not read, and point 6 adds a line. **One claim of the
skeleton fell**: the phase cannot close on this point alone, because plan `:1360` places
`F0.ASSET.02`'s recording *before* the gate and that recording is the owner's — so point 8 produces a
gate output and a closed F2 only if point 7 has been answered. Open: D-6, and point 7's first
question.

---

## Whole-document coherence

Read end to end after all eight were closed, looking for a point that contradicts another or leaves
one in false.

**Three things the points do to each other, and one that had to be corrected.**

1. **Point 1 is load-bearing for point 5 and nobody would guess it.** Legible denials are cheap only
   because point 1 split the supervisor's *locate* from its *open*; before that, the failure to find a
   file and the failure to open it were the same call and the two errnos could not be told apart. The
   order in the skeleton was chosen for a different reason — committing a security fix first — and
   happens to be the only order that works.
2. **Point 2 and point 4 touch the same object from opposite sides.** Point 2 changes what the write
   scope's rules *say*; point 4 asks whether the scope can express a deny at all. They do not
   conflict, and point 4's answer does not change point 2's: `${workspace}` is a *grant*, and the
   agent-configuration question is about *subtracting* from one.
3. **Point 6 could have conflicted with point 5 and does not.** Point 5 gives the caller more
   information; point 6 asserts the verdict does not move. They are compatible because the errno is an
   outcome and never an input — which is worth stating, because a future change that fed a refusal
   back into a decision would break both at once and neither test alone would see it.
4. **Corrected while reading:** the skeleton's table said point 3 was "blocked by a guest". That is
   true of half of it and false of the other half, and stating it as one thing is what has kept both
   halves from landing. The table now says "a guest, for one half", and point 3 splits them.

**Against the specs**, nothing here contradicts an invariant or an `H-xx` finding. Point 5 applies
`I-19` to an audience it excluded. Point 6 makes `I-20` executable. Points 1 and 2 restore
specifications rather than amending them — `docs/05` §5.3's ordering, and `Bindings` being per
session. Point 4 refuses to design before it measures, which is the one thing the rules require of it.

**Two things are the owner's and neither is a blocker of the other:** whether the sensor may load once
on this machine (point 7), and whether the escalate class is a control or a recording mechanism
(D-6). Everything else in this plan is executable.
