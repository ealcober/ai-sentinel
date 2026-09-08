# Challenge-amplification — the recorded state and the host it was measured on

> **Status**: complete and implemented, except where a point defers on purpose — point 6 does
> nothing by design and lands with `docs/06` point 5, and `--publish` joins `check_loaderd`'s
> flag list in the change that implements it. Eight points, two of which grew under measurement
> **Scope**: the eight defects a full-repository review found on 2026-09-09. Six are coherence
> defects between documents that already disagree. Two are not: one is a pair of unit files that
> describe a process no binary implements, and one is a remedy in shipped tooling that does not
> work when followed.
> **Method**: `/challenge-ampliar` — five sections per point, written in the declared future so
> whoever implements it decides nothing and only executes.

## How to read this

**Line numbers cite the tree this review read: commit `23af800`.** The points below are the record
of what was found there, so their citations are not moved when the fix moves a line — a record
that follows the repair stops being evidence. Where a point specifies future work, it cites the
current tree and says so.

The review that produced this skeleton started by trying to reproduce the numbers in
`docs/ai/handoff/02_f2-walking-skeleton.md` §3. The first command failed — there was no Rust
toolchain on the host — and the shape of that failure is what point 1 is about. The remaining
seven points are what a document-by-document read then found.

**No defect here is in the product's runtime logic** — but two are in artefacts that run.
`deploy/systemd/*.service` ships and would not start a machine as written (point 4), and
`xtask/src/doctor.rs` prints an install line that fails when followed (point 7). The review's
skeleton called both of them documentation defects; measurement moved them, and the two closing
paragraphs say so. The one live defect in product code — `PolicyGeneration(0)` — is already
specified in `docs/06` point 5, and point 6 here exists precisely so that nobody specifies it a
second time.

**Direction matters more than count.** Four of the eight bias toward **optimism** — points 1, 4,
5 and 7 make the project or the host look healthier than it is, and those are the urgent ones.
Two bias toward understatement and are cheap (2, 3). Two are neither: point 6 changes nothing by
design, and point 8 is a typographical slip.

**The points:**

1. The host state is recorded as a dated fact and never measured again. **Closed** — measured at
   5 of 15 while three documents said 15 of 15.
2. `STATE.md` says F2 has not started, four rows above its own record of four F2 tasks.
3. `STATE.md`'s header stayed on the previous session's numbers.
4. **Both** units name a flag no binary implements, and `agentd` declares a startup protocol it
   does not speak. Grew from one unit to two plus `Type=notify` under measurement.
5. `docs/06` point 3 writes in the future two directives the file already carries.
6. `PolicyGeneration(0)` was alive and already specified elsewhere; **closed** by `docs/06` point 5's WAL half, exactly as this point said it would be — without a second specification.
7. `doctor`'s printed remedy for `bpf-linker` **does not work**. Written in the skeleton as a
   missing memory entry; the memory entry turned out to be the smaller half.
8. `STATE.md:148` repeats a sentence verbatim.
9. **890 build artefacts are tracked in git, 631 MB of them.** Found while implementing points 1–8
   and **recorded rather than fixed**, per the implementation algorithm: what appears on the way
   and is not in a point becomes a new numbered point. **Amplified as `docs/08` and its first two
   points are implemented**; the third — the 75 MB already in history — is the owner's.

---

## Point 1 — The host state is recorded as a dated fact and never measured again

**Done when:** a session cannot begin work holding a false belief about the machine under it.

### 1. Challenge

*Is this the best solution?* The current shape is worth stating before judging it.
`docs/ai/AGENTS.md` §1 "On start" lists seven documents to read and **no command to run**.
`CLAUDE.md`'s read order repeats that list verbatim, and a gate checks the two agree. So a
session's first knowledge of its host is a sentence in a file — and `CLAUDE.md` instructs it to
trust `STATE.md` over its own assumptions.

The sentence is `docs/ai/STATE.md:160`: *"Host state, checked 2026-09-07. `doctor` reports 15 of
15…"*.

**Measured on 2026-09-09, before anything was installed:** `cargo xtask doctor` reported
**5 of 15**, exit 1. Missing: the nightly `crates/aisme-ebpf` pins, `rust-src` on it, `bpf-linker`,
the LLVM major match, `cargo-deny`, `bpftool`, `clang`, `genisoimage`, `virtme-ng`, `tpm2-tools`.
There was no Rust toolchain of any kind: `command -v cargo rustc rustup` under a login shell
returned nothing, `~/.cargo` and `~/.rustup` did not exist, and the workspace had no `target/`.
The first command of the review, `cargo test --workspace`, died with `cargo: orden no encontrada`.

Two more sentences had decayed with it. `STATE.md:150` states the pre-commit hook
*"reports 7 PASS · 0 FAIL · 1 SKIP · 1 PENDING today"*; on the morning of 2026-09-09 it reported
**1 FAIL**, because `doctor` is one of its members. And the handoff note's §3 tabulates four gate
results as the current state of the machine.

None of the three was wrong when written. All three were wrong when read, and **nothing in the
protocol asks the reader to check**.

Three shapes were weighed:

1. **Leave it.** The next session finds out when a build fails. This is close to what happened and
   it looks survivable — but only because this review's first act happened to be a build. A session
   doing documentation work never builds, and can close a task claiming gate compliance it never
   had. The failure is silent exactly for the work where it is hardest to notice.
2. **Add `cargo xtask doctor` as step 0 of the read order.** One command, no new code, and it
   already prints the remedy for every miss.
3. **Stop asserting host state in `STATE.md` at all** and point at the command instead.

*Is it coherent with the specs?* (2) and (3) are the same fix seen from two files, and together
they close a hole that `AGENTS.md` §3-bis already argues against everywhere else: *"Run it, do not
read it"* and *"verify the effect of an edit, never its report"*. The host is the one thing the
protocol currently asks a session to take on trust.

*Can it be simplified?* Yes, and the simplification is the whole point: **no new command, no new
gate, no new test of the host.** `cargo xtask doctor` exists, exits 0 or 1, never installs, and
names what each miss unblocks. What is missing is one step in two files and the removal of a
decaying claim from a third.

### 2. Verification

Safe, clear and compliant, with the one failure mode the change could introduce named:

- **It adds a read, not an action.** `doctor` never installs anything — its own final block says
  so and `xtask/src/doctor.rs` implements it. Making it step 0 cannot change the machine.
- **`I-27` is untouched.** Local command, zero hosted anything, no file that a hosted runner could
  ever pick up.
- **The failure mode to avoid is a session that reads `FAIL` and stops.** Most of what remains in
  F2 needs no kernel tooling at all: `docs/06` point 5 is pure Rust with host-only tests, and so
  are `F2.WS.07` and `F2.WS.08`. A step 0 that reads as a hard gate would block work that a missing
  `virtme-ng` does not block. **The step will therefore state what a `FAIL` blocks and what it does
  not**, in the same line, rather than leaving that judgement to the reader.
- **The count is not the interesting part; the row is.** "5 of 15" says nothing about whether the
  session's task is blocked. The wording will direct the reader to the missing rows and to the
  "unblocks" text `doctor` already prints against each.

**One question for the owner, not resolved here:** whether a `doctor` `FAIL` should block a
*commit*. That is the same decision as enabling `.githooks/pre-commit` (`STATE.md:150`), which is
already open and already the owner's. This point will not pre-empt it: step 0 will be a read
obligation, and nothing in it will change what the gate does.

### 3. Implementation

- **`docs/ai/AGENTS.md` §1 "On start"** will gain a step **0** above the numbered read list:
  `cargo xtask doctor`, with one sentence saying that a `FAIL` names each missing prerequisite and
  what it unblocks, that documentation and host-only Rust work may proceed on a `FAIL`, and that
  anything which builds the eBPF objects, benchmarks, or boots a VM may not.
- **`CLAUDE.md` "Read order"** will gain the identical step, in identical wording. The two lists
  are compared by a gate (`xtask/src/docgate.rs`), and `CLAUDE.md` itself records that
  *"a gate checks the two path lists agree"* — so the wording will be copied, not paraphrased.
- **`xtask/src/docgate.rs` will be extended, and the measurement says why.**
  `read_order_agrees` (`:143`) compares the two lists through `ordered_paths` (`:176`), which keeps
  a token only if it starts with `docs/` or equals `CLAUDE.md`. A step reading
  `0. cargo xtask doctor` begins with a digit, so the line **is** scanned — and contributes no
  token at all. The checker would ignore step 0 in both files and report agreement while the two
  drifted apart. Read in the source rather than inferred from the function's name. The check will
  therefore gain a second comparison: that **both files carry a step 0 naming
  `cargo xtask doctor`**. Not "identically", which is what this amplification first said and what
  the source refutes: `CLAUDE.md` writes the read order as a prose list with bold entries and
  `AGENTS.md` writes it as a fenced code block, so no line is identical between them today either
  — `ordered_paths` normalises `**This file**` to `CLAUDE.md` (`:185`–`:188`) for exactly that
  reason. The check compares presence and the command, which is what can be compared exactly.
  Left alone, this change would add the exact kind of line the gate cannot see.
- **`docs/ai/STATE.md:160`** will be rewritten to keep what is durable about that line — the
  `/dev/kvm` group fix, the interop registration, the date — and to stop implying the count is
  still true. The count will be attributed to its measurement and its date, in the past tense,
  with a pointer to step 0 for the current one.
- **`docs/ai/STATE.md:150`**: the numbers stay, the word **"today"** goes, for the same reason.

Nothing else. In particular **no new `xtask` command is added**, and Annex H does not change.

### 4. Tests

**Existing to change:** `xtask/src/docgate.rs`'s read-order equality check and its tests. Step 0
must be present and identical in both files, or the check must say why it is exempt. Per
`AGENTS.md` §3-bis, **the extended check will be seen failing before it is trusted**: step 0 will
be deleted from `AGENTS.md` alone, the check run and required to name the divergence, and the
deletion reverted. Per `CLAUDE.md` rule 12, that canary runs **after** the commit, not before it.

**New:** none, and the absence is the argument. A test asserting the host is healthy is `doctor`
run twice; a test asserting the *documents* mention `doctor` is the docgate check above. There is
no third property here to guard.

### 5. Documentation

- `docs/ai/AGENTS.md` §1: step 0, with the blocks/does-not-block sentence.
- `CLAUDE.md` "Read order": the same step, verbatim.
- `docs/ai/STATE.md`: lines 150 and 160 de-dated as described.
- `docs/CHANGELOG.md`: one line under `[Unreleased]`.
- **No `docs/ai/memory/` entry.** The discovery is not a durable fact about a kernel or a library;
  it is a rule about how a session starts, and rules live in `AGENTS.md`. The memory entry this
  session does owe belongs to point 7.

**Closing.** Verified against `docs/ai/AGENTS.md:9-19` (the read list, with no command in it),
`docs/ai/STATE.md:160` and `:150` (the two decayed claims), `xtask/src/doctor.rs` (fifteen checks,
never installs), `xtask/src/docgate.rs:176` (`ordered_paths` keeps only `docs/…` tokens, so a
command step is invisible to the equality check as it stands), and two measurements of `doctor`
on the same host four hours apart: **5 of 15,
exit 1** before the owner reinstalled the toolchain, **15 of 15, exit 0** after. **One claim of
the skeleton fell**: the review's first finding was written as "no Rust toolchain on this machine",
which is true and too narrow — `doctor` measured ten missing prerequisites, of which the toolchain
was four. The finding is the decay of a recorded host claim, not the absence of `cargo`.
**Open, and the owner's**: whether a `doctor` `FAIL` should block a commit, which is the
`.githooks/pre-commit` decision at `STATE.md:150` and is deliberately not decided here.

---

## Point 2 — `STATE.md` says F2 has not started, above its own record of four F2 tasks

**Done when:** the file cannot claim a task is unstarted while another of its sections records it done.

### 1. Challenge

*Is this the best solution?* `docs/ai/STATE.md:136`, inside `## Next up` (`:122`), reads:
*"Task order, top to bottom of Plan §F2 … **Nothing in F2 is started; `F2.WS.01` is next.**"*
Its own `## Done` table (`:12`) carries four rows above it: `F2.WS.01` at `:22`, `F2.WS.02` at
`:21`, `F2.WS.03` at `:20` and `F2.WS.04`'s two halves at `:17` and `:18`, each with the
measurement that closed it.

`CLAUDE.md` names this file as the one to *"trust over your assumptions"*. A session that trusts
it restarts `F2.WS.01`.

The cause is structural, not careless: `## Done` is **appended to** as work closes, while
`## Next up` is **prose** written when a phase opened and revised only when someone remembers.
The two drift by construction, and nothing compares them — `xtask/src/docgate.rs` has exactly one
check on this file, `state_headings` (`:211`), and it verifies that the §7.3 headings are present
and ordered. Headings, not contents.

*Is it coherent with the specs?* No, and the project already refuses this shape elsewhere:
`task_citations_resolve` (`:381`) exists because a citation that names a task must actually
contain that task ID, and its own doc comment says it *"checks what it can check exactly"*. The
same reasoning applies one file over and was never applied.

*Can it be simplified?* Yes. Fixing line 136 is a five-second edit and leaves the mechanism that
produced it intact — the next phase transition writes the same sentence again. The root is that
`STATE.md` asserts task status in two places with no check that they agree, and **a task ID is a
token a machine can compare**.

### 2. Verification

- **The check must be exact or absent.** A fuzzy match on prose would fire on sentences that are
  fine and be ignored within a week. The exact form: any task ID appearing in `## Done` must not
  appear in `## Next up` inside a sentence claiming nothing is started. That is still prose
  matching. The narrower and honest version: **`## Next up` may not contain the literal phrase
  "Nothing in `F<n>` is started" for a phase whose ID appears in `## Done`.**
- **False positives cost more than the defect.** This file is read at the start of every session;
  a check that cries wolf gets its rule deleted rather than obeyed. The check will name the task
  ID and the two line numbers, so the reader can settle it in one look.
- **What the check cannot do**, and will say in its doc comment: it cannot tell whether a task in
  `## Done` is *actually* done. It compares two sections of one file, and that is all it claims.

### 3. Implementation

- `xtask/src/docgate.rs` will gain `state_next_up_agrees_with_done()`, beside `state_headings`
  (`:211`), which extracts every `F<n>.<block>.<task>` ID from `## Done`, and fails if `## Next up`
  asserts that any phase owning one of them is unstarted. It will report the ID and both line
  numbers. It will be registered in the same list `verify-docs` already walks.
- `docs/ai/STATE.md:136` will be rewritten to name what is actually next — the unimplemented half
  of `F2.WS.04` (`docs/06` points 3–6), then `F2.WS.05` onwards — rather than to be deleted, so
  the section keeps saying what a reader comes to it for.

### 4. Tests

**Existing to change:** none. `state_headings` keeps its own tests untouched.

**New:** one test in `docgate`'s module, built the way the file's neighbours are: a synthetic
`STATE.md` body with `F2.WS.01` in `## Done` and *"Nothing in F2 is started"* in `## Next up` must
be **refused**, and the same body with the sentence removed must pass. Per `AGENTS.md` §3-bis the
check will also be seen failing against the **real** file before line 136 is corrected — that run
is the proof it would have caught this, and its output goes in the commit body.

### 5. Documentation

- `docs/ai/STATE.md:136` as described.
- Plan Annex H: `verify-docs`'s row gains the new check in its description, if the row enumerates
  them; it will be read first rather than assumed to.
- `docs/CHANGELOG.md`: one line.

**Closing.** Verified against `docs/ai/STATE.md:136` (the claim), `:17`–`:22` (the four rows that
refute it), `:122` (the section boundary), and `xtask/src/docgate.rs:211` (`state_headings` is the
only existing check on the file, and it reads headings only). **Nothing of the skeleton fell.**
Open: whether `verify-docs` should also compare `STATE.md` against the plan's task table, which is
a larger check and is deliberately not specified here.

---

## Point 3 — `STATE.md`'s header stayed on the previous session's numbers

**Done when:** the header's numbers are either measured at write time or not stated.

### 1. Challenge

*Is this the best solution?* `docs/ai/STATE.md:4` reads: *"Last updated: **2026-09-07** … Phase:
**F2 — the walking skeleton, starting** … Code written: **~20 800 lines of Rust over 19 members;
223 tests pass**"*.

Measured on 2026-09-09: `cargo test --workspace` reports **272 passed**, 0 failed, 0 ignored, over
44 test binaries. Three commits landed on 2026-09-08 after that header was written
(`76ee984`, `499f221`, `34ba389`). The member count is the one part still true — `Cargo.toml`
lists 19, and `crates/aisme-ebpf` and `crates/aisme-windows` are deliberately excluded.

`AGENTS.md` §1 "On finish" makes updating this file **non-optional**, and it was partly done: the
`## Done` table gained its F2 rows on 2026-09-08. The header did not. So the rule was followed
where the work felt like work and skipped where it felt like bookkeeping.

*Is it coherent with the specs?* The count is a measurement, and `CLAUDE.md` rule 5 says a number
gets its prediction written first and its measurement after. A number copied forward from a
previous session is neither.

*Can it be simplified?* Yes, and this is the lazy answer that also fixes the root: **the header
should not carry the test count at all.** It is a number that decays every session, that nobody
acts on, and whose true value is one command away. The date and the phase are worth keeping
because they are cheap to maintain and expensive to derive.

### 2. Verification

- **Deleting a number is not hiding it.** The count is reproducible in one command and reported by
  every gate run. What is being removed is a *stale copy*, not the fact.
- **The date must stay honest**, and it is the one field a check can verify: the file's last commit
  date is knowable. A check that compares them is cheap and cannot false-positive on prose.
- **The phase string stays**, and gains nothing automatic. "F2 — starting" was wrong for a day;
  a reader who also sees `## Next up` corrected by point 2 is not misled by it, and a gate on a
  free-text phase label would be the fuzzy matching point 2 refused.

### 3. Implementation

- `docs/ai/STATE.md:4`: the test count will be **removed**, replaced by the command that produces
  it. `Last updated` will be set to the session's own date; `Phase` will read as F2 in flight
  rather than starting.
- `xtask/src/docgate.rs` will gain `state_last_updated_is_recent()`: it reads the `Last updated`
  date from the header and compares it with the file's most recent commit date from
  `git log -1 --format=%aI -- docs/ai/STATE.md`. A header older than its own last commit fails,
  naming both dates. **A git that cannot answer fails too, and does not pass.** The amplification
  said it would `SKIP`; that claim fell against the source. `cross_document_checks`
  (`xtask/src/verify.rs:493`) holds a `Vec<(&str, Result<(), String>)>` — the registry has `Ok`
  and `Err` and no third state — and the neighbouring check that shells out to git,
  `changelog_covers_commits` (`xtask/src/docgate.rs:317`), returns
  `Err("git log failed; not a repository?")`. Failing loudly keeps the property the `SKIP` was
  reaching for — an absence is never a success — and follows the idiom already in the file,
  instead of adding a third state to a registry for the sake of one check.

### 4. Tests

**Existing to change:** none.

**New:** a unit test over the date comparison alone, with the git call injected as a parameter, so
the two orderings and the missing-git case are all exercised without a repository. Seen failing by
back-dating the header in a scratch copy.

### 5. Documentation

- `docs/ai/STATE.md:4` as described.
- `docs/ai/AGENTS.md` §1 "On finish" step 1: it will say that the header's date is part of the
  update, since the omission that produced this defect was of exactly that.
- `docs/CHANGELOG.md`: one line.

**Closing.** Verified against `docs/ai/STATE.md:4` (the header as written), a measured
`cargo test --workspace` (**272 passed, 0 failed, 0 ignored, 44 binaries**, exit 0),
`git log` (three commits on 2026-09-08 after the header's date), and `Cargo.toml`'s `members`
(19, so that figure is **not** stale and will not be touched). **One claim of the skeleton fell**:
the skeleton listed the whole header as obsolete; the member count is correct and stays.
Open: nothing.

---

## Point 4 — Both units describe a process that does not exist

**Done when:** no unit file names a flag or a startup protocol the binary does not implement.

### 1. Challenge

*Is this the best solution?* The review found one defect here and measurement found three, all of
one kind.

1. `deploy/systemd/aisme-loaderd.service:16` — `ExecStart=… aisme-loaderd --handoff
   /run/aisme/loader.sock`, and its header comment (`:3`–`:6`) explains that the loader *"hands
   the resulting file descriptors to agentd over the socket"*. That is precisely the `SCM_RIGHTS`
   design `docs/06` point 3 **refuses on a specification**: handing `agentd` a writable policy-map
   fd would leave `CapabilityBoundingSet=` decorative — the capability gone and the authority kept.
2. `deploy/systemd/aisme-agentd.service:16` — the **same flag on the other side**:
   `aisme-agentd --handoff /run/aisme/loader.sock`. The review's first pass found only the loader.
3. `grep -rn '"--handoff"' crates/` returns **nothing**. No binary implements it. `aisme-agentd`
   parses `--run`, `--serve-ipc`, `--ticks`, `--load-sensor`, `--load-policy-probe` and
   `--measure-idle`; `aisme-loaderd` parses no arguments at all.
4. `deploy/systemd/aisme-agentd.service:15` — `Type=notify`, and
   `grep -rn "sd_notify\|NOTIFY_SOCKET\|READY=1" crates/` returns **nothing**. A `notify` unit
   whose process never sends `READY=1` is held in "activating" until `TimeoutStartSec` and then
   failed. `aisme-loaderd.service` has `Requires=`/`After=` on it, so the failure propagates.

None of this bites today, because nothing is deployed through systemd yet. All of it biases
**optimistic**: the units read as production-ready and would not start a machine.

`crates/aisme-loaderd/src/units.rs` is the checker for exactly this file pair, and it passes.
It verifies `CapabilityBoundingSet`, `AmbientCapabilities`, `NoNewPrivileges`, `Delegate`, `User`
and `Type=oneshot` (`:106`) — the **hardening** directives. It never reads `ExecStart`, and it
reads `Type` only on the loader. So the directives that say *what the process is* are the ones
nobody checks.

*Is it coherent with the specs?* The comment at `:3`–`:6` now contradicts `docs/06` point 3, which
is the decision of record. `CLAUDE.md` rule 3 is explicit: a comment a change makes false is
rewritten and the rewrite is declared in the commit.

*Can it be simplified?* The correction is three edits and one extended checker. What must **not**
be done is inventing the replacement design here: `docs/06` point 3 already specifies
`aisme-loaderd --publish <policy-file>` as the loader's invocation, so the unit adopts that rather
than a new one.

### 2. Verification

- **The `ExecStart` check cannot verify that a flag parses.** `units.rs` lives in `aisme-loaderd`
  and cannot depend on `aisme-agentd` — they are siblings at L3. What it *can* check exactly is
  that `ExecStart` names the expected binary path and that every flag on it appears in a list the
  same file owns. That is weaker than "the binary accepts it" and it is stated as such: it catches
  a unit drifting away from a design, which is this defect, and not a binary dropping a flag.
- **`Type=notify` is the sharper half and needs a decision, not a check.** Two ways to make the
  file honest: implement the notify protocol in `aisme-agentd`, or set `Type=exec`. `Type=exec` is
  correct for what `agentd` does today, costs nothing, and does not add a dependency;
  `Type=notify` is better once the daemon has a real readiness point, and `F2.WS.02`'s hot loop
  has one. **This point takes `Type=exec` and records why**: the unit must describe today's
  binary, and readiness notification is a feature with its own task, not a side effect of a
  coherence fix. If the owner prefers notify now, it becomes a task and the unit waits for it.
- **`RemainAfterExit=yes` is present and unchecked** (`aisme-loaderd.service:15`; zero matches in
  `units.rs`). With pinning under `bpffs`, `docs/06` point 3 makes it load-bearing: it is what
  makes systemd's model agree with a loader that exits. It joins the checked set.

### 3. Implementation

- `deploy/systemd/aisme-loaderd.service`: `ExecStart` becomes the `--publish` invocation
  `docs/06` point 3 specifies, and the header comment `:3`–`:6` is **rewritten**, not patched, to
  say that the loader pins to `bpffs` and exits, and that it hands `agentd` no file descriptor —
  with the reason. The commit body will state that a comment was made false and by which decision.
- `deploy/systemd/aisme-agentd.service`: `--handoff /run/aisme/loader.sock` is removed;
  `ExecStart` becomes the `--run` invocation the binary implements. `Type=notify` becomes
  `Type=exec`, with a comment naming the readiness point that would justify `notify` later.
- `crates/aisme-loaderd/src/units.rs`: `check_agentd` and `check_loaderd` each gain an `ExecStart`
  check (expected binary path; every flag drawn from a list the file owns and documents), the
  agentd `Type` check, and the loader's `RemainAfterExit=yes`.
- **Ordering matters and is stated:** the unit cannot name `--publish` before `docs/06` point 3
  implements it, or `units.rs` will be checking a flag that does not exist — the same defect in a
  new place. That argument bars **adding** the new flag early; it does not bar **removing** the
  false one, and this amplification conflated the two. So the loader's `--handoff` and its
  `SCM_RIGHTS` comment go now, together with the `agentd` half, and its `ExecStart` names the
  binary with no flags — which is what the binary parses today. `check_loaderd`'s allowed-flag list
  is empty for the same reason, and `--publish` joins it in the change that implements it. Leaving
  a comment that contradicts the decision of record until a later commit is what `CLAUDE.md` rule 1
  refuses.

### 4. Tests

**Existing to change:** `units.rs`'s `the_shipped_units_implement_the_split` will now also cover
`ExecStart`, `Type` and `RemainAfterExit`; and
`a_unit_that_kept_a_capability_or_lost_delegation_is_refused` — the test that shows the checks
failing — gains the new ways to rot: an `ExecStart` naming an unknown flag, an `agentd` unit back
on `Type=notify`, and a loader without `RemainAfterExit`.

**New:** none beyond those. The checker is the test.

### 5. Documentation

- Both `.service` files' comments, as described.
- `docs/06` point 3 §3: it will name the unit's `ExecStart` as part of that point's work, since
  point 4 defers to it rather than duplicating it.
- Plan `F1.RT.07`'s row: that the split is a `bpffs` pin and not an fd handoff, because the row is
  where a reader looks for the mechanism.
- `docs/CHANGELOG.md`: one line, naming the false comment.

**Closing.** Verified against `deploy/systemd/aisme-loaderd.service:3-6,15,16`,
`deploy/systemd/aisme-agentd.service:15,16`, `grep -rn '"--handoff"' crates/` (**no matches**),
`grep -rn "sd_notify\|NOTIFY_SOCKET\|READY=1" crates/` (**no matches**), and
`crates/aisme-loaderd/src/units.rs:64-117` (the directives it checks, and the two it does not).
**Two claims of the skeleton fell, both by understating it**: the review reported the defect on
the loader alone — it is on both units — and reported it as a stale comment, when `Type=notify`
against a binary with no readiness signal is an operational failure rather than a documentation
one. Open, and the owner's: whether `agentd` should implement the notify protocol now instead of
taking `Type=exec`; this point takes `exec` and names the alternative.

---

## Point 5 — `docs/06` point 3 writes in the future two directives the file already carries

**Done when:** the amplification describes the unit as it is.

### 1. Challenge

*Is this the best solution?* `docs/06` point 3 §2 states that the loader's unit *"will gain
`Type=oneshot` with `RemainAfterExit=yes`"*. Both are present:
`deploy/systemd/aisme-loaderd.service:14` and `:15`. `Type=oneshot` is not merely present, it is
**already enforced** — `crates/aisme-loaderd/src/units.rs:106` fails the check without it.

The defect is small and its direction is the reason it is written down: an implementer reading
that sentence adds a directive that is already there, sees no change, and concludes the file was
edited when nothing happened. It biases toward believing work was done.

*Is it coherent with the specs?* It contradicts the file it describes. `CLAUDE.md` rule 13 makes
that a defect on its own terms.

*Can it be simplified?* Yes: two words. And the honest thing to add is that **no mechanical guard
is proposed** for this class. A document that says "will gain X" about an existing X is not
cheaply detectable, and inventing a check for it would cost more than the defect and produce the
false positives point 2 refused. The guard here is the algorithm itself — reading the file before
writing the sentence — and that is where it stays.

### 2. Verification

- **The correction must not delete the reasoning.** The sentence carries *why* `oneshot` is
  correct for a loader that pins and exits; that survives. What changes is the tense.
- **The `units.rs` half is worth adding to the sentence**, because it is the part a reader would
  otherwise not know: the directive is not just present, it is guarded.

### 3. Implementation

- `docs/06` point 3 §2's sentence will be rewritten in the present: the unit **carries**
  `Type=oneshot` and `RemainAfterExit=yes`, `units.rs` already enforces the first, and point 4
  adds the second to the checked set.
- Point 3 §3's matching bullet — *"will gain `Type=oneshot`, `RemainAfterExit=yes` and the
  `--publish` invocation"* — keeps only the `--publish` half, which is genuinely future.

### 4. Tests

None, and the absence is argued in §1 rather than assumed.

### 5. Documentation

- `docs/06` point 3 §2 and §3, surgically. The document's number does not change and nothing else
  in it is touched.

**Closing.** Verified against `deploy/systemd/aisme-loaderd.service:14-15` (both directives
present) and `crates/aisme-loaderd/src/units.rs:106` (`Type=oneshot` enforced, `RemainAfterExit`
not). **One claim of the skeleton was strengthened rather than fell**: it recorded the directives
as present; they are present *and* one of them is already gated, which is the part worth writing.
Open: nothing.

---

## Point 6 — `PolicyGeneration(0)` is alive and already specified

**Done when:** nobody writes a second specification for a defect that has one.

### 1. Challenge

*Is this the best solution?* The review confirmed the defect at
`crates/aisme-agentd/src/main.rs:75` — `wal::WalSink::create(dir, PolicyGeneration(0))` — and
confirmed it is the **only** site: `grep -rn "PolicyGeneration(0)" crates/` returns one line.
Every WAL segment records generation 0, which is an absence written as a value, and a forensic
reader cannot tell it from a real first generation.

`docs/06` point 5 already specifies the fix in full: `Option<PolicyGeneration>` at every boundary,
`SegmentHeader::UNKNOWN_GENERATION` or a flag bit decided by reading `SegmentHeader::encode`,
`Method::SetPolicyGeneration` in Annex I, and three tests including one that asserts unknown does
**not** encode as 0.

So the correct action for this point is to specify **nothing**. Its whole content is the
verification that the defect is real, unchanged, and singly-owned.

*Is it coherent with the specs?* Yes, and re-specifying it would violate the coherence rule this
document exists to serve: two specifications of one fix is exactly the drift being cleaned up.

*Can it be simplified?* It is already the smallest thing: a confirmation and a pointer.

### 2. Verification

- **The citation in `docs/06` point 5 was re-checked**, because a pointer to a wrong line is worse
  than no pointer. It cites `crates/aisme-core/src/wal.rs:54` for the header field; line 54 is
  `pub generation: PolicyGeneration,`. It holds.
- **The count matters.** One site, not several — so `docs/06` point 5's implementation touches one
  call and cannot silently miss a second.

### 3. Implementation

Nothing in this document. The work is `docs/06` point 5 and is owned by `F2.WS.04`.

The one thing this point adds: when point 5 is implemented, `docs/07`'s row here will be closed by
reference rather than by its own commit, so the CHANGELOG does not record the same fix twice.

### 4. Tests

None here. The three tests belong to `docs/06` point 5 §4.

### 5. Documentation

None here, deliberately.

**Closing.** Verified against `crates/aisme-agentd/src/main.rs:75` (the single call site),
`grep -rn "PolicyGeneration(0)" crates/` (**one match**), and `crates/aisme-core/src/wal.rs:54`
(`docs/06` point 5's citation, which holds). **Nothing of the skeleton fell.** Open: nothing —
and that is the point of the point.

---

## Point 7 — `doctor`'s remedy for `bpf-linker` does not work on this host

**Done when:** following `doctor`'s printed line installs `bpf-linker`.

### 1. Challenge

*Is this the best solution?* The skeleton framed this as a missing memory entry. Measurement made
it a defect in shipped tooling.

`xtask/src/doctor.rs:44` prints, as the remedy for a missing `bpf-linker`:

```
cargo +nightly install bpf-linker --no-default-features --features llvm-21
```

Run verbatim on this host it **fails**, twice measured, at the build script:

```
Error: could not find llvm-config in directories specified by environment variable `PATH`
```

The cause, read in `bpf-linker`'s own `build.rs` (`:584`–`:625`) rather than inferred: when
`LLVM_PREFIX` is unset it searches `PATH` for a file named exactly `llvm-config`. Debian and
Ubuntu install LLVM 21 as `/usr/bin/llvm-config-21`, with the suffix. Nothing named `llvm-config`
exists, so the search fails even with the correct LLVM present and working —
`/usr/lib/llvm-21/bin/llvm-config --version` reports **21.1.8**, which is exactly the version
`crates/aisme-ebpf/rust-toolchain.toml` requires.

The remedy line also omits the version. `cargo install bpf-linker` resolved to **0.11.1**, while
the pin comment validates **0.11.0**.

A remedy that does not work is worse than no remedy: `doctor` is the one command that tells an
operator how to fix a host, and following it produced two failed builds before the cause was read.
It biases toward **optimism** — the line looks authoritative.

*Is it coherent with the specs?* `F0.REPO.06` gives `doctor` the job of printing *"the exact line
that fixes it"*. This line is not exact.

*Can it be simplified?* Yes. The two environment variables are all that is missing, and the
version pin is one flag.

### 2. Verification

- **`LLVM_SYS_211_PREFIX` is needed as well as `LLVM_PREFIX`**, and they are read by different
  crates: `LLVM_PREFIX` by `bpf-linker`'s `build.rs`, `LLVM_SYS_211_PREFIX` by `llvm-sys 211.0.0`,
  which `bpf-linker 0.11.0` pulls in behind `--features llvm-21` (read in the cached manifest:
  `llvm-21 = ["dep:llvm-sys-21"]`, `version = "211.0.0"`). Setting only one is a coin flip on
  which crate fails first, so both go in the line.
- **The prefix must not be hard-coded blindly.** `/usr/lib/llvm-21` is right on this host and on
  any Debian-family machine using `apt.llvm.org`; it is not universal. `doctor` already knows the
  LLVM major it wants (`:254`, "the LLVM major `bpf-linker` was built against"), so the line will
  be **composed** from that major rather than written as a constant, and the printed path will be
  the one `doctor` verified exists.
- **The nightly must be named, not `+nightly`.** The current line says `cargo +nightly`, which
  selects whatever nightly is default and not the pinned `nightly-2026-01-01`. The pin's own
  comment says any other nightly is the wrong one, and `doctor`'s adjacent remedy already says
  so — the two lines disagree with each other today.
- **This is a remedy string, not an installer.** `doctor` still installs nothing. Verified in
  `xtask/src/doctor.rs` and stated in its own output.

### 3. Implementation

- `xtask/src/doctor.rs:44`'s remedy becomes a composed line carrying: the **pinned** nightly by
  name, `--version` with the pinned `bpf-linker` version, and both `LLVM_PREFIX` and
  `LLVM_SYS_211_PREFIX` set to the prefix `doctor` resolved for the required LLVM major. Where the
  prefix cannot be resolved, the line will say which LLVM major is needed and that the prefix must
  point at it, rather than printing a path that does not exist.
- The nightly channel and the `bpf-linker` version will be **read from
  `crates/aisme-ebpf/rust-toolchain.toml` and the pin comment**, not duplicated as constants in
  `doctor.rs`, so the remedy cannot drift from the pin it serves. If the version is only available
  in a comment, that is the moment to give it a machine-readable home, and the change will say so.
- `docs/ai/memory/` gains one file — the durable half — recording that Debian-family LLVM installs
  are suffixed, that `bpf-linker`'s `build.rs` searches for an unsuffixed `llvm-config`, and that
  both environment variables are required. It will link `[[cloud-images-are-the-kernel-matrix]]`
  as the neighbouring host fact.

### 4. Tests

**Existing to change:** whatever test covers `doctor`'s remedy strings, which will be read first;
if none exists, that is recorded rather than assumed.

**New:** a unit test that the composed remedy contains the pinned channel name, a `--version`, and
both environment variables, driven by a synthetic pin file so it does not depend on the host.
It will be seen failing against the current remedy string — which is the run that proves it would
have caught this — and that output goes in the commit body.

**Not tested:** that the remedy *succeeds*. Running it would download and build LLVM bindings
inside a gate, and `I-27`'s sibling concern — gates stay local and cheap — makes that the wrong
trade. The measurement that it succeeds was made once, by hand, and is recorded in the memory file.

### 5. Documentation

- `docs/ai/memory/<slug>.md`: the durable fact, with its `[[links]]`.
- `docs/ai/STATE.md`: the host row, once point 1's rewrite lands.
- `docs/CHANGELOG.md`: one line naming `F0.REPO.06`.

**Closing.** Verified against `xtask/src/doctor.rs:44` (the remedy as printed) and `:254`,
`bpf-linker 0.11.0`'s `build.rs:584-625` read in the cargo registry cache,
`bpf-linker 0.11.1`'s manifest (`llvm-21 = ["dep:llvm-sys-21"]`, `llvm-sys` `211.0.0`),
`/usr/lib/llvm-21/bin/llvm-config --version` → **21.1.8**, and two failed installs on this host
whose error text is quoted above. **The skeleton's claim fell entirely**: it recorded a missing
memory entry, and the defect is a remedy line in shipped tooling that does not work — the memory
entry is the smaller half. Open: whether the pinned `bpf-linker` version should move from a
comment into something a program can read, which the implementation will decide by looking rather
than by guessing here.

---

## Point 8 — `STATE.md:148` repeats a sentence verbatim

**Done when:** the sentence appears once.

### 1. Challenge

*Is this the best solution?* `docs/ai/STATE.md:148` ends with *"The two items below were blockers,
are not now, and keep their reasoning because both recur."* — twice, consecutively, in one
paragraph. An editing slip, no consequence beyond a reader stumbling.

It is written as a numbered point because `CLAUDE.md` rule 2 admits no "noted debt" category, not
because it deserves equal weight. Its correct treatment is the smallest possible one.

*Can it be simplified?* Yes: delete one copy. **No check is proposed.** A duplicate-sentence
detector over prose would fire on legitimate repetition — this project's documents repeat phrases
deliberately, and `CLAUDE.md`'s read order is repeated verbatim in `AGENTS.md` **by design and by
gate**. Building a guard here would create the false positives point 2 refused.

### 2. Verification

Nothing to verify beyond the line itself, which was read.

### 3. Implementation

- `docs/ai/STATE.md:148`: the second copy of the sentence is deleted. Nothing else on the line is
  touched.

### 4. Tests

None, argued above.

### 5. Documentation

The edit is the documentation. No CHANGELOG line: it changes no behaviour and closes no task, and
`docs/CHANGELOG.md` is for closed tasks.

**Closing.** Verified against `docs/ai/STATE.md:148`. **Nothing of the skeleton fell.** Open:
nothing.

---

## Point 9 — 890 build artefacts are tracked in git — recorded, not amplified

**Found on 2026-09-09** while running `cargo xtask build-ebpf` for points 1–8: the build produced a
diff of over 150 files that had nothing to do with the change. It is written here as a numbered
point because `CLAUDE.md` general rule 2 admits no other category, and it is **deliberately not
implemented in this plan** — the implementation algorithm says what appears on the way and is not
in a point is recorded, not fixed while passing.

**Measured, not inferred:**

- `git ls-files | grep -c "/target/"` → **890 tracked files**, `du -ch` over them → **631 MB**.
- They arrived in commit `ccd5632` (2026-09-07), the one that added `crates/aisme-ebpf-policy`.
- `.gitignore` covers `/target` and `/crates/aisme-ebpf/target`. It does **not** cover
  `/crates/aisme-ebpf-policy/target` or `/tests/probes/ebpf/target` — the two out-of-workspace
  crates created after that file was written. `.rlib`, `.so` and linked binaries are among them.

**Where the error biases, which is why it ranks above a tidiness complaint:** every `build-ebpf`
run now produces a 150-file diff, and **a real change to a tracked file would be invisible inside
it**. That is the direction that matters — not the 631 MB every clone pays, but a review that
cannot see what it is reviewing. Compounding it: a security product shipping compiled artefacts in
version control is a supply-chain surface the threat model does not discuss.

**What would falsify it:** that the artefacts are tracked deliberately — a reproducibility fixture,
or an input some gate reads. Nothing found says so, and the two directories are absent from
`docs/04`'s asset inventory, but the check is `git log` on the commit that added them and a read of
what reads those paths, and that check has not been run.

**What it needs:** its own `/challenge-ampliar` pass, because removing 890 files from the index is
a reorganisation under `CLAUDE.md` rule 6 — `git rm --cached`, `.gitignore` extended, tests passing
before and after and the two outputs compared — and because whether history is rewritten to reclaim
the 631 MB is the owner's decision, not a step inside a cleanup.

---

## What this document changed

| Point | What it settled |
|---|---|
| 1 | The host is measured at session start, not read; and `ordered_paths` would have made the new step invisible to the gate that compares the two read orders |
| 2 | `STATE.md`'s two sections get a check that compares them, because a task ID is a token a machine can compare |
| 3 | The header stops carrying a test count that decays; the date gets a check, and an absent git answer **SKIPs** rather than passes |
| 4 | **Both** units name a flag no binary implements, and `agentd` is `Type=notify` with no readiness signal; `units.rs` checks hardening and never what the process is |
| 5 | Two directives already exist and one is already gated; no guard is invented for this class, and the reason is written |
| 6 | `PolicyGeneration(0)` is confirmed, single-sited, and **already specified** — this point exists to prevent a second specification |
| 7 | `doctor`'s `bpf-linker` remedy does not work as printed: wrong nightly selector, no version pin, and two missing environment variables |
| 8 | One duplicated sentence, deleted, with no detector built |
| 9 | **Recorded, not fixed**: 890 tracked build artefacts, 631 MB, which make a real change invisible in a `build-ebpf` diff. Owed its own amplification |

**Order of implementation.** Points 3, 7 and 8 are independent and land first. Point 2's checker
and point 1's step 0 both touch `xtask/src/docgate.rs` and land together. Point 4's `agentd` half
lands with them; its **loader** half waits for `docs/06` point 3, because a unit may not name
`--publish` before `--publish` exists. Point 6 lands with `docs/06` point 5 or not at all.

**Still open for the owner:** whether a `doctor` `FAIL` blocks a commit — the same decision as
enabling `.githooks/pre-commit` — and whether `aisme-agentd` should implement the systemd notify
protocol now rather than the unit taking `Type=exec`.
