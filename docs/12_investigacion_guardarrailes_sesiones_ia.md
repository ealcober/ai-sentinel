# Investigation — what a guardrail for an AI session can actually be

`docs/11` left two questions to the owner: where a reference recording may be made, and what
declares an agent's tool calls. Investigating them turned out to be investigating the guardrail
itself, because both questions are the same question asked twice: **what can be known about an AI
session, by whom, and at what altitude.**

Everything below was measured. Where something is documentation rather than measurement it says so,
and where a measurement of mine was wrong it says that too.

## The measurements

Taken on this host, 2026-09-15, with read-only scripts, before any conclusion was written.

| # | What | Result |
|---|---|---|
| M1 | Tool composition of **17 real sessions**, 13 686 calls | `Bash` **91.1 %**; Edit 3.2 %; Write 1.8 %; Read 1.4 %; web 1.5 % |
| M2 | What **one** `Bash` call expands into (`cargo test -p aisme-agentsim`) | **1 713 `openat`**, 58 `execve`, 314 `clone` |
| M3 | Parallel tool calls, by model turn (11 182 turns) | **14.4 %** issue more than one, up to eight |
| M4 | Unprivileged `fanotify`: does it name the actor? | Own process: pid reported. **Another process: `pid=0`** |
| M5 | Does the write scope protect the agent's own hook configuration? | Unsupervised: writable. Under `aisme run`: **denied in kernel** |
| M6 | Cost of a declaration from a hook | **1 ms** per call, debug build |
| M7 | Perturbation of observing through the seccomp trap | **+17 µs per open**; +29 ms for M2's call |
| M8 | Yama: can a **sibling** read a descendant's memory? | Declaring process yes, its children **`EPERM`** |
| M9 | Yama: can an **ancestor**, with no grant at all? | **Yes**, at depth 1, 2 and 3 |

M1 to M3 are about what an agent is. M4, M8 and M9 are about what Linux will tell you. M5 to M7 are
about what it costs.

---

## Finding 1 — the intent plane and the action plane are three orders of magnitude apart

Nine in ten things an agent does is *run a subprocess* (M1). One of those expands into seventeen
hundred file opens across fifty-eight programs (M2).

So the harness sees **one** event where the kernel sees **1 713**. That ratio is the whole design
problem, and it has two consequences that point in opposite directions:

**Enforcement cannot live at the tool boundary.** A pre-tool hook inspecting a `Bash` call is
handed a shell string. Deciding what that string will do is not decidable — it can be `eval`, a
pipeline, a variable, a script it downloads. Anything that pattern-matches it is a denylist over a
Turing-complete input, which is the shape of control that always loses. The repo already says this
about a neighbouring case: an agent's own sandbox is *"inside the agent's trust domain … escapable
— a published case had an agent reach a denied binary through `/proc/self/root`"*
(plan Annex G §G.4).

**Observation of intent cannot live in the kernel.** The kernel never sees "the agent decided to
read the config". `docs/10` already states it; M2 quantifies it. One intent, seventeen hundred
actions, and no field anywhere ties them.

**Neither plane is a guardrail. The pair is.**

---

## Finding 2 — Linux hides the actor from an unprivileged observer, and that is the spine

This is the result that reorganises everything, and it took a refuted hypothesis to find.

`fanotify` looked like an unprivileged, kernel-free way to watch file activity — no eBPF, no
per-syscall cost. It half is. `FAN_CLASS_NOTIF` alone is `EPERM`, but with `FAN_REPORT_FID` an
ordinary user may create a group **and mark a directory**, and events arrive. Then M4:

| who opened the file | pid reported |
|---|---|
| the listener itself | its own pid |
| **any other process** | **`0`** |

The kernel tells an unprivileged listener that something happened and refuses to say who did it.
That is not a quirk of `fanotify`. It is the same rule Yama enforces for `ptrace`: M8, a sibling
supervisor reads the process that granted it and **not that process's children**.

And M9 is the exception that proves the shape: an **ancestor** reads its descendants at any depth
with no grant at all.

> **There are exactly two ways to observe an AI session's actions on Linux: own the process tree, or
> hold a capability. There is no unprivileged third way, and every design that assumes one is
> assuming something the kernel is built to refuse.**

This is why `docs/11` point 1 is not a privilege tidy-up. Making `aisme run` the session's ancestor
is what buys the *only* attribution route that costs no privilege anywhere.

---

## Finding 3 — a pre-tool hook is the desktop `SdkEnforcer`, and it fails open

The plan's `Enforcer` table already lists `SdkEnforcer` — a tool-call veto — beside the kernel
enforcers, and argues for it in terms this investigation did not have to improve on: it *"can deny
'send this file to this address' as an **intent** rather than as a packet"* (plan `:722`). But F9 is
scoped to mobile, `aisme-sdkhost` is a five-line doc comment, and there is **no cooperative
enforcement tier on the workstation**. On desktop, "cooperative" has so far meant *capture* — tier A
of the F4 ladder, the JSONL tail — and never *enforcement*.

Claude Code's hooks are that missing tier, and they are documented to do more than declare:

- A `PreToolUse` hook receives the tool name and the **full tool input** — the actual command
  string, the actual file path — plus the session id, the working directory and the permission mode.
- It can **block**: exit 2, or a decision of `deny`, `ask` or `allow`. Hooks *tighten only*; an
  `allow` cannot override a deny rule, and an exit 2 blocks even in a bypass permission mode.
- `ask` forces the human prompt, which is the escalate class with a person in the loop, at the
  altitude where the question is answerable — "may this tool call run", not "may this `openat`
  succeed".
- They run inside subagents and skills.

**And three things weaken them, each of which the kernel plane already answers:**

1. **They fail open.** A hook that times out is a non-blocking error and the tool proceeds. That is
   the documented behaviour. It is acceptable *only* because the action plane below is fail-closed:
   measured earlier in this phase, a supervised process whose supervisor is killed has every
   subsequent path-bearing syscall refused — 297 361 of them in one run.
2. **The agent can rewrite the configuration that installs them.** Hook settings are picked up by a
   file watcher while the session runs, so an agent with write access to `.claude/settings.json`
   disables its own guard mid-session. The repo names this attack already: `DT-14` lists *"Writes by
   the agent to `.aisme/**`, **`.claude/settings*.json`**, `.mcp.json` …"* as an escalate-class
   detector. What this investigation adds is that **it is already prevented, in kernel** — M5.
3. **They are semantically weak on the 91 %.** Finding 1. A hook is an excellent place to *observe*
   a `Bash` call and a poor place to *judge* one.

**The composition is the point, and it is not a slogan:** the intent plane sees what the action
plane cannot, and the action plane protects the intent plane's own configuration, which the intent
plane cannot protect itself. Each layer covers exactly the other's blind spot, and both were
measured doing it.

---

## Finding 4 — a claim of mine that was wrong, and the arithmetic that corrects it

`docs/11`'s coherence section said that recording through the seccomp trap *"would preserve the
counts and destroy the timings the fixture exists for"*. I wrote that from a ratio — 46.6 µs against
1.8 µs — without measuring what it costs a real command.

M7 measures it: **+17 µs per open**. For M2's `cargo test`, 1 713 opens, that is **+29 ms** on a
command that natively runs for a second or more. That is a distortion of a few percent, not a
destruction.

The claim is corrected rather than deleted, because a weaker version of it survives and matters:
the overhead is **proportional to open density**, so it flattens exactly the bursts §2.22 says the
totals do not capture. A one-second command taking 29 ms more is fine. A 40 ms `git status` taking
80 ms is not, and short open-heavy commands are what a burst is made of.

---

## The two open questions, answered

### Question B first, because it is the one that is now settled

**What declares the tool calls: a pre-tool hook, and `aisme declare` now exists to be that hook.**

It reads the hook's JSON on stdin, extracts the tool and session, and sends `declareToolCall` over
the control socket. Measured: **1 ms per call**, and 50 declarations crossed a real socket, landed
in a real WAL, and came back as a trace with 50 distinct tokens.

**It exits 0 on every path** — no daemon, empty stdin, malformed JSON — and that is a decision, not
laziness. A declaration authorizes nothing (`DT-04`: it may be a lie), so a failure here has nothing
to protect; and a declaration hook that failed closed would turn the guard's observability into an
outage for the user's entire workflow. Enforcement belongs where failure is already closed.

What is **not** settled and is the owner's: whether to install it. That is a change to the owner's
own environment, and the whole point of a hook is that the supervised party does not get to choose
it.

**One budget consequence to record.** `budgets.toml` reserves `sdk.per_call_overhead_us` at 50 µs
target, 200 hard, for an **in-process** `check_tool_call`. A hook is a process spawn: 1 ms, twenty
times the hard ceiling. The cooperative tier on desktop needs its own budget rather than borrowing
the SDK's, and stating that now is cheaper than discovering it at a gate.

### Question A — where a recording may be made

Three routes were tested. Two close and one survives, each for a stated reason.

- **Unprivileged `fanotify`: closed.** M4. Events without an actor cannot be attributed to a session
  or to a tool call, which is the only thing a recording is for.
- **The seccomp trap: usable, with two named losses.** It sees `openat` and nothing else, so
  `execve`, writes and network are absent; and it costs the perturbation in Finding 4, which lands
  hardest on the short bursty commands the workload is made of. It needs no privilege and no BPF.
- **The BPF sensor: complete, cheap, and the only one that sees everything** — and it is what `I-12`
  keeps off a host running the test suite.

So the question is unchanged in substance and much sharper in form: **a complete recording needs the
BPF sensor, and the only machine with a real Claude Code session is the one the rule keeps it off.**
The alternatives are not equivalent and the report no longer pretends they might be.

---

## What this changes in the plan, if the owner agrees

Nothing here contradicts a finding or an invariant. Four things are additive:

1. **A cooperative enforcement tier on the workstation**, which the `Enforcer` table already has a
   name for (`SdkEnforcer`) and the plan already has the argument for (`:722`), but which no task
   owns on desktop. `aisme declare` is its first half; the veto is its second.
2. **`DT-14` gains a mechanism.** It already names `.claude/settings*.json` as an escalate-class
   write. M5 shows the session's Landlock scope already denies it, so the detector has an enforcer
   under it rather than only a signal.
3. **A budget for the cooperative tier on desktop**, because a hook is out-of-process by
   construction and cannot meet an in-process figure.
4. **The recording's blocker is one sentence shorter.** It is not "how do we observe an agent". It
   is "may the sensor load on this machine, once".

**And one thing to resist.** The temptation, once hooks can block, is to move enforcement up to
where the decisions are legible. Finding 1 is the argument against: 91 % of what an agent does is an
opaque string, and a guard that judges strings is a guard that reads a denylist to a
Turing-complete input. The hook plane declares and asks. The kernel plane decides.
