# Challenge-amplification — the open decisions, and how F2 closes

Four decisions are open. Two block F2 and two do not, and the difference is worth stating first
because they have been sitting in one list and reading as one weight.

## The short version

| # | Decision | Blocks F2? | Whose |
|---|---|---|---|
| 1 | The daemon serves one connection at a time | **Yes** — directly | Mine, with your nod. A route is recommended below |
| 2 | May the sensor load once on this machine | **Yes** | Yours — you said yes; what is owed is the ADR |
| 3 | What the escalate class *claims* (`D-6`) | **Only the wording** | Yours |
| 4 | Host-executed configuration (`D-4`) | No — it is F3's | Yours, and it can wait |

**The recommendation, in one line:** take point 1 (a thread per connection), then point 2's ADR,
then record. Point 3 is a paragraph you dictate and I write. Point 4 should not be decided now.

**What this changes versus what I told you last message:** I said point 1 "touches `F1.RT.02`'s
two-worker cap". **It does not**, and the challenge below says why with the line numbers. That makes
point 1 much smaller than I made it sound, and it is why I now recommend a route instead of handing
you three.

## How to read this

Each point is **Challenge** (is it the best answer, is it coherent with the specs, can it be
simplified), **Verification** (is it safe, clear and compliant — and where it is not, it asks),
**Implementation** (what will be done, already sieved), **Tests**, **Documentation**, and a short
**Closing** paragraph saying what was verified against what, which claim of the skeleton fell, and
what stays open. Written in declared future so that executing it requires no further decision.

Nothing here touches the repository. The measurements it cites were taken on 2026-09-15 and are
recorded in `docs/CHANGELOG.md` and `docs/ai/STATE.md`.

---

## Point 1 — The daemon serves one connection at a time

**Done when:** a hook declaring from inside a supervised session is answered within its budget, and
a fixture recorded from that session carries both planes.

### 1. Challenge

*Is this the best solution?* The defect is not in question — it is measured, and it is the one that
blocks the reference recording. What the challenge settles is **which of three routes**, and it
eliminates two of them on evidence rather than on taste.

`ipc::serve_with` is `for stream in listener.incoming()` with an inner read loop
(`crates/aisme-agentd/src/ipc.rs:1120`), and `aisme run` holds one connection open for the whole
session. A hook connecting from inside that session queues behind it and is never reached. Measured:
with no budget on the hook's socket the session **hung for ever**; with the 100 ms budget now in
`aisme declare`, five declarations from inside an observe-only session took **103 ms each** and
**one of five** reached the WAL.

**Route A — a thread per connection.** Accept, hand the connection to a thread, keep serving.

**Route B — one thread, `poll` over every accepted connection.** The classic single-threaded
multiplexer: no new threads, no `Send` bounds, no locking changes, and the smallest diff of the
three.

**Route C — a second socket for the session's long-lived connection.** Two listeners, two threads,
the hot one separate from the chatty one.

*Route B is eliminated, and the thing that eliminates it is in this repository's own code:*
`decide_open` calls `ask_a_human` (`ipc.rs:461`) **on the serving thread**, and the terminal budget
is **10 seconds** (`aisme-core/src/adjudicate.rs:44`). Under a single-threaded multiplexer, one
escalation prompt would freeze every other session and every hook for ten seconds. The daemon's own
design has a handler that blocks by the second, so a design that assumes handlers are quick is wrong
here.

*Route C is eliminated as a fix, though not as an idea:* it makes the deadlock less likely rather
than impossible — two hooks and one session still serialise, and a second escalation behind a first
still waits ten seconds. It also adds a socket to Annex I, a path to the installer and a second
`SO_PEERCRED` surface, for a property route A gives outright.

*Is it coherent with the specs?* **This is where a claim I made to you falls.** `F1.RT.02` caps
**Tokio** at two worker threads — *"Tokio runtime explicitly capped at 2 worker threads, `LocalSet`
for the hot loop"* (plan `:1574`) — and the IPC server does not run on Tokio at all: `main.rs:254`
starts it with `std::thread::spawn`. The daemon **already** spawns a thread per session at
`main.rs:269`, for `release_when_empty`. So route A neither violates `F1.RT.02` nor introduces a
pattern this daemon does not already use. I told you otherwise last message; that was wrong, and it
made point 1 sound larger than it is.

*Can it be simplified?* Yes, in one way that matters: **the per-connection state does not have to
move.** `Declarations` is already created per connection (`ipc.rs:1131`) with its own recorded
rationale, so the rate-limit window is per connection today and stays per connection after. Only
`Supervision`, the generation cell and the two callbacks need to be shareable, and `Supervision` is
already built out of mutexes.

### 2. Verification

Safe and clear, with four properties that must hold and are each checkable:

- **The 50 MB budget must survive.** A thread costs its stack. The daemon already runs one thread
  per session, so the new cost is one thread per *concurrent connection*, which for a real agent is
  the session's one plus one short-lived hook at a time. `verify-budgets --profile skeleton` is the
  check, and it will be run rather than reasoned about.
- **A slow handler must not become a slow *lock*.** `ask_a_human` blocks for up to ten seconds. It
  must not be holding `supervision.sessions` while it does: the facts it needs are cloned out of the
  map before the prompt, which is what `decide_open` already does (`ipc.rs`, the `facts` binding), and
  that will be preserved deliberately rather than by luck.
- **The generation cell is taken per request and released.** It already is, with a comment saying
  why. Under concurrency that comment becomes load-bearing, and it stays.
- **A panic in one connection must not take the daemon down.** Today a panic unwinds the whole
  serving loop. Per connection, it must kill that connection and leave the rest — otherwise
  concurrency turns one bad client into an outage.

**One thing is not decided and it is yours:** whether the daemon should bound the number of
concurrent connections. Unbounded, a local user who can reach the socket can spawn threads until the
RSS budget breaks — and the socket is uid-matched, so that user is *you*, not the agent. My view is
that a bound is worth having anyway because `I-19` prefers a named refusal to a silent degradation,
and that **64** is a number nothing in F2 comes near. I will not pick it unilaterally: say the word
and it goes in, say nothing and it does not.

### 3. Implementation

- `serve_with` will take `Arc<Supervision>` and `Arc<GenerationCell>` instead of references, and its
  two callbacks will become `Fn + Send + Sync + 'static` — `counter` already produces a fresh value
  per connection, and `on_session` already only spawns a thread.
- The accept loop will spawn one thread per accepted connection, carrying the clones. The body of the
  loop moves into that thread **unchanged**: same `Requests`, same per-connection `Declarations`, same
  `serve_line`.
- The `until` predicate keeps its place on the accept loop, so the existing shutdown path is
  untouched.
- `catch_unwind` around the per-connection body, logging the connection that failed, so a panic costs
  a client and not the daemon.
- `aisme declare`'s 100 ms budget **stays**. It is the right behaviour regardless: the daemon may be
  down, or busy, and a hook in front of every tool call must never be the thing that stops the agent.

### 4. Tests

**Existing, unchanged:** every `serve_line` test drives one request at a time and is unaffected —
which is also the reason none of them caught this. That is worth stating rather than fixing: they
test what a request does, and the defect was in what the *server* does between requests.

**New:**

- **A hook is answered while a session holds a connection open.** One connection registers a session
  and stays open; a second connection declares a tool call and is answered. It fails by timing out
  before this change, which is exactly the measured behaviour.
- **An escalation does not freeze the daemon.** One connection asks a `decideOpen` that escalates
  with no terminal, so it spends its budget; a second connection's `getCapabilities` is answered
  while the first is still waiting. This is the assertion route B could not pass, and it is written so
  that choosing route B later fails it.
- **A panicking connection does not take the daemon with it.** A request crafted to panic the handler
  closes that connection, and the next connection is still served.
- **End to end, the two planes in one session** (`crates/aisme-cli/tests/session.rs`): a supervised
  session that declares a tool call and then opens a file yields a WAL containing both, and
  `--to-trace` attributes the action. Today it yields one of the two.

### 5. Documentation

- Plan Annex I gains one paragraph: the control plane serves connections concurrently, one thread
  each, because the daemon's own adjudication blocks by the second.
- `docs/ai/STATE.md`: the *Blocked* entry becomes a Done row carrying the measurement that found it —
  103 ms per declaration, one of five landing — because the number is the evidence.
- `docs/ai/memory/`: a new memory, *the two planes were never exercised together*. The durable and
  non-obvious part is not the deadlock, it is that `F2.WS.03`'s **1 ms per call** was measured with no
  session registered, and that a per-component measurement can be right and mean nothing.
- `F1.RT.02`'s row gains a clause saying the cap is on the **Tokio worker pool** and not on the
  daemon's threads, since I misread it once and the next reader will too.

### Closing

Verified against `ipc.rs:1120` (the serial loop), `ipc.rs:1131` (the per-connection counter),
`ipc.rs:461` and `adjudicate.rs:44` (a handler that blocks for ten seconds), `main.rs:254` and
`main.rs:269` (the server is already off-runtime and the daemon already threads per session), and
plan `:1574` (`F1.RT.02`). **One claim fell, and it was mine to you**: that this touches the
two-worker cap. It does not, and route A is therefore the smallest route that actually fixes the
defect rather than narrowing it. Open, and yours: whether to bound concurrent connections, and at
what number.

---

## Point 2 — May the sensor load once on this machine

**Done when:** an ADR records the narrowing, its scope and its expiry, and `--load-sensor` has
answered on this kernel.

### 1. Challenge

*Is this the best solution?* The question changed shape while I was answering it, and the new shape
is the one that matters.

It used to be *"is loading safe?"* — you have answered that. What the measurements added is that
**there is no alternative to loading**, which was not established before:

- The recording must be made in **observe-only** mode. Under `--trap-openat`, every write-mode open
  is denied — measured twice, and it is `Q-13`'s documented subset, not a bug. An agent that cannot
  write a file is not an agent session, so a fixture recorded that way would be a recording of a
  crippled process.
- In observe-only there is no seccomp path, and therefore **no actions at all**: measured, the WAL of
  an observe-only session held the declaration and zero `FileOpen` records.

So the sensor is not the *cheap* way to record. It is the only way. `F0.ASSET.02` already said the
recording is made *"in observe-only mode … so recording it perturbs nothing"*; what is new is that
the alternative reading — record through the trap and accept the +17 µs — is not available at all.

*Is it coherent with the specs?* Not yet, and that is the whole point of the ADR. `I-12` reads *"No
kernel-touching test ever runs on a host OS. Snapshot-restored disposable VMs only, for every
developer and every local gate run"* (`docs/ai/invariants.md:44`). A one-off recording is not a test
and not a gate run, and the invariant's own sentence is about tests and gate runs — but that is a
*reading*, and `CLAUDE.md` is explicit: when an invariant is wrong, **write an ADR; do not implement
around it.** A verbal yes in a chat is not where a security product records a narrowing of its own
rules.

*Can it be simplified?* One thing can be dropped, and dropping it makes the ADR narrower and
therefore easier to accept: **the recording does not need the sensor to stay loaded.** `--load-sensor`
already detaches immediately — *"this is a question, not a session"* (`platform/mod.rs`). The
recording needs it attached for the duration of one session, and nothing beyond.

### 2. Verification

**This point asks rather than resolving, and it asks about scope and not about permission.**

What is safe, stated plainly: the program is an observe-only tracepoint on `sys_enter_openat`, it
goes through the kernel's verifier like any `bpftrace` one-liner, and `H-05` forbids
`bpf_probe_write_user` outright so it cannot modify anything it observes. The risk is the ordinary
risk of running a profiler.

What is **not** verified, and must be before anything is recorded:

- **Whether it loads at all on this kernel.** `probe()` never sets `ringbuf` or BTF on any host,
  because those probes are `F3.LD.01`'s and unwritten (`platform/mod.rs:49`). So the composition will
  not attempt a load even with permission — the capability set says the sensor is absent. Loading
  therefore goes through `--load-sensor`, explicitly, and **that has never been run on this host**.
- **Whether it needs root.** It does — `CAP_BPF` at least. That is a `sudo` I will ask for once, when
  the ADR exists, and not before.
- **What `probe()` should say afterwards.** If the sensor loads here, the honest capability probe is
  `F3.LD.01`'s work, and a one-off recording must **not** quietly turn it on for the test suite. The
  ADR must say the narrowing is for a recording and not for `probe()`.

**The question for you** is the ADR's scope, and there are two defensible shapes:

1. **One recording, named and expiring.** The ADR permits exactly this: a manual, out-of-band
   `--load-sensor` and one observe-only session, on this machine, for `F0.ASSET.02`. It expires when
   the recording is made. Anything else still needs a VM.
2. **Host loading permitted for out-of-band work generally**, with the test suite and every gate still
   forbidden. Broader, and it would also unblock measuring the sensor's real overhead here rather
   than in a guest.

My recommendation is **(1)**, because `I-12`'s value is that it has no exceptions anybody has to
remember, and a narrowing with an expiry keeps it that way. But (2) is a legitimate reading and it is
yours.

### 3. Implementation

**Nothing until the ADR is written and you have approved it.** Then, in order:

- `docs/adr/10_*.md`: the decision, its scope, what it does not permit, and how it ends.
- `cargo xtask doctor` gains nothing; this is deliberately out of band.
- Run `aisme-agentd --load-sensor` on this host, under `sudo`, and record the answer verbatim —
  `ACCEPTED` with its capabilities, or `REFUSED` with the kernel's own words. Either outcome is a
  measurement worth having and both go into `STATE.md`.
- Only if it is `ACCEPTED`, and only after point 1 lands, make the recording.

### 4. Tests

None of its own — a one-off manual act is not a test, and pretending otherwise is how an exception
becomes a habit. What the *recording* owes is already specified in `docs/14` point 7 and stands: the
manifest's hash is over the content it names, and an empty recording is refused rather than written.

One existing test is affected and must **not** be weakened:
`nothing_measured_means_no_bpf_load_is_attempted_on_the_host` (`platform/mod.rs:450`) asserts that
`probe()` claims nothing it did not measure. The narrowing is about an out-of-band command, not about
the composition, so that test stays exactly as it is. If it ever needs changing, the narrowing has
grown beyond what was agreed.

### 5. Documentation

- `docs/adr/10_*.md`, as above, linked from `docs/ai/invariants.md` beside `I-12` so that the
  invariant and its one exception are read together.
- `docs/ai/STATE.md` → the `F0.ASSET.02` item loses "blocked on where the recording may be made" and
  gains the ADR and the `--load-sensor` result.
- Plan `F0.ASSET.02`'s row gains one sentence: the recording is observe-only **because the trap
  denies every write**, which is the measured reason and is stronger than the perturbation argument
  it currently gives.

### Closing

Verified against `invariants.md:44`, `platform/mod.rs:49` and `:450`, and two measurements: an
observe-only session's WAL carries zero actions, and a trapped session denies every write-mode open.
**One claim of the skeleton fell:** the recording was described as choosing between the sensor and
the seccomp path, and there is no choice — the seccomp path cannot carry a working agent. Open, and
yours: which of the two ADR scopes. Nothing is loaded until you answer.

---

## Point 3 — What the escalate class claims (`D-6`)

**Done when:** one paragraph in the threat model says what an escalation is for, and the plan's F2
rows agree with it.

### 1. Challenge

*Is this the best solution?* This point is not a change to the product. It is a change to what the
product **says**, and it is on this list because saying the wrong thing about a security control is a
defect of the same kind as a rule that cannot fire.

The evidence is the best-supported section of the field record and the least comfortable: users
approve **93 %** of permission prompts, and when they do look they miss **33.4 %** of exfiltrations
and **35.0 %** of scope violations. AISME's escalate class is a prompt. `I-05` already says *"a prompt
is an attack surface"* and that three groups are never promptable — so the architecture has always
half-believed this. What it has not done is say what the escalate class is *for*.

*Is it coherent with the specs?* The tension is visible in F2 already. A **compiled deny** asks nobody
and cannot be answered away; the plan says so, and GATE F2's `asked` column exists to tell the two
apart. That is a design that already treats *not asking* as the stronger property. The wording has
not caught up.

*Can it be simplified?* Yes, and the simplification is the recommendation: it is **one paragraph**,
not a redesign. Nothing in F2 changes behaviour either way.

### 2. Verification

**This is yours, and it is a positioning decision rather than a technical one.** Two shapes:

1. **An escalation is friction and a record, not a control.** It slows an action down, it puts a
   human in the loop, and it writes down that it happened — and the product does not claim that the
   human will catch what is wrong, because measured, they do not. Enforcement is what the kernel
   denies without asking.
2. **An escalation is a control**, and the 93 % is a reason to improve the prompt rather than to
   demote it.

My recommendation is **(1)**, for a reason from this project rather than from the literature: F2's
own gate was built to distinguish a compiled deny from a timed-out prompt precisely because the second
is weaker. Saying so out loud costs nothing and it is what makes the **deny** class the headline —
which is also the more defensible product.

Shape (2) is not unreasonable, and if you take it the honest version still needs the 93 % stated
somewhere, because a claim that a prompt protects the user is a claim the field has measured and
refuted.

### 3. Implementation

**Nothing but prose, and not until you choose.** Then: one paragraph in
`docs/security/01_threat-model.md` §4, beside the existing *"the prompt itself"* entry, which already
argues half of this; and a clause in the plan's F2 scope table so the phase does not claim more than
the paragraph allows.

### 4. Tests

None. There is nothing here a test could hold — which is itself the argument for getting the wording
right, since nothing else will catch it.

### 5. Documentation

`docs/security/01_threat-model.md` and the plan's F2 scope table, as above. `docs/research/01`'s
Part V `D-6` gains its fate, so the decision is recorded where the evidence is.

### Closing

Verified against `I-05` and the plan's `asked` column, both of which already treat *not asking* as the
stronger property. No claim of the skeleton fell. Open, and yours: which of the two shapes. It blocks
nothing except the sentence itself.

---

## Point 4 — Host-executed configuration (`D-4`)

**Done when:** `F3.EN.11` names a route, or the gap is accepted for F3 with a date.

### 1. Challenge

*Is this the best solution?* The best solution today is **to not decide it today**, and that is the
whole content of this point.

The gap is measured and recorded: a supervised session writes `.claude/settings.json`,
`.vscode/tasks.json`, `.mcp.json` and `.git/config` inside its own scope, the host executes them, and
three CVEs and a live worm turn on exactly that. It carries a test asserting it is open, so it cannot
be forgotten.

*Is it coherent with the specs?* Yes: it is `F3.EN.11`'s, it is on that row with its three routes
costed, and `F2`'s out-of-scope list is as binding as its task list. Deciding it now would be adding
a feature to the walking skeleton, which the plan forbids in as many words.

*Can it be simplified?* It already is. The one thing that would make it worse is deciding it under
time pressure at the end of F2, because the cheapest-looking route — enumerate the workspace and omit
the agent directories — has a cost that only shows up in use: it denies creating any new top-level
entry in the workspace, which breaks ordinary work in a way a demo would not reveal.

### 2. Verification

Safe, clear and compliant as it stands, because **nothing is claimed**. The threat model now carries
the class as a trust boundary, an attack-surface entry and a non-goal, each `[RISK]`-marked, so the
product does not imply a capability it does not have — which is the rule that applies here.

The one thing to verify before F3 decides is a measurement nobody has taken: **how often does real
work create a new top-level entry in a workspace?** That number decides between route 1 and the
others, and it can be taken from the reference recording once it exists. Which is another reason this
waits.

### 3. Implementation

Nothing, deliberately. The row, the threat-model entries and the test already exist.

### 4. Tests

`a_session_can_still_write_the_agent_configuration_its_host_executes` exists and asserts the gap is
open. When F3 closes it, that test is deleted and replaced by one asserting the denial for a file that
is **absent** as well as one that is present — CVE-2026-25725 was a protection applied only to a file
that already existed, defeated by creating it.

### 5. Documentation

Already written. When F3 decides, `docs/research/01` Part V `D-4` gains its fate.

### Closing

Verified against the `F3.EN.11` row, the threat model's three new entries and the standing test. No
claim fell. Open, and explicitly deferred: the route, and the measurement that should inform it.

---

## Recommended next steps, in order

1. **Point 1, route A** — a thread per connection. I can start now; the only input I need from you is
   whether to bound concurrent connections, and my suggestion is yes, at 64. *Unblocks the fixture and
   makes the intent plane work at all during supervision.*
2. **Point 2's ADR** — I draft `ADR-10` with scope (1), you read it, and if you approve it I ask for
   `sudo` once and run `--load-sensor` on this kernel. *Either answer is a measurement; a `REFUSED`
   here would be worth knowing before F3 plans around it.*
3. **Record `F0.ASSET.02`** — only after 1 and 2. A real session on this repository, observe-only,
   with the hook installed in `~/.claude/settings.json`.
4. **Point 3's paragraph** — you dictate the shape, I write it. Ten minutes, and it changes what F2
   claims.
5. **GATE F2 and the phase close** — last by construction, because plan `:1360` puts the recording
   before it.

Point 4 is not on this list on purpose.

## Whole-document coherence

Read end to end after the four points were closed, looking for a point that contradicts another or
leaves one in false.

1. **Points 1 and 2 are sequential and not parallel, and that is new.** Before the measurements they
   looked independent — one a concurrency defect, the other a permission question. They are not: the
   recording needs the sensor *and* a daemon that answers the hook, so doing point 2 first would buy a
   loaded sensor and a fixture still missing half its content. The order in the list is the only order
   that produces something.
2. **Point 2 removed an option point 1 did not know it had.** While point 1 was being written, the
   fallback for a busy daemon was *record through the seccomp path instead* — and point 2's
   measurement killed it, because the trap denies every write. Point 1 is therefore load-bearing
   rather than merely an improvement.
3. **Points 3 and 4 do not touch the other two**, and saying so is the useful part: they have been
   sitting in the same "open, the owner's" list, which made four decisions look like one wall. Two
   block a phase and two are prose and F3.
4. **Corrected while reading:** the summary table first said point 3 blocks F2. It blocks F2's
   *wording*, not its gate — no task's done-condition depends on it — and conflating the two is what
   makes a list of open decisions feel heavier than it is.

**Against the specs**, nothing here contradicts an invariant or an `H-xx` finding. Point 1 restores a
property Annex I always implied and never stated. Point 2 narrows `I-12` **through an ADR**, which is
the mechanism `CLAUDE.md` requires. Points 3 and 4 add nothing and claim nothing.

**One claim from the previous conversation fell and is corrected here:** that point 1 touches
`F1.RT.02`'s two-worker cap. It does not — the cap is on the Tokio pool, the IPC server has always
run on its own `std::thread`, and the daemon already threads per session.
