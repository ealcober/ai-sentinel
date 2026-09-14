# Handoff — F2, after the enforcement thread

**Written 2026-09-15 at commit `83b1247`.** Every number below was measured by a
command named beside it. Where something is unproven, it says so.

---

## 1. Where F2 is

Eight of eleven tasks are done. The walking skeleton walks:

```bash
AISME_TERMINAL_ANSWER=d aisme run --trap-openat \
    --escalate /etc/hostname -- cat /etc/hostname
# cat: /etc/hostname: Permiso denegado    exit 1
AISME_TERMINAL_ANSWER=1 …
# pop-os                                   exit 0
# agentd, both: 1 asked (1 unattended)
```

A session is created and attributed by construction, a syscall is held by the
kernel, a question reaches a human in the session's own terminal, and the answer
is what the syscall obeys.

| Task | State |
|---|---|
| `F2.WS.01` `BpfSensor` | Done, kernel-verified (6.8 `ACCEPTED`, 5.4 refuses by name) |
| `F2.WS.02` hot loop | Done |
| `F2.WS.03` `declareToolCall` | Done |
| `F2.WS.04` policy | **Done** — publication measured on 6.8: generations 1 then 2, `meta` `[2, 0]`, **200 000 samples with 493 swaps, none torn** |
| `F2.WS.05` `SeccompEnforcer` | **Done** — deny and allow paths, both TOCTOU forms tested, wired end to end |
| `F2.WS.06` `TerminalAdjudicator` | **Done** — five tests against a real pseudo-terminal |
| `F2.WS.07` `forensicd` tail | **Done** — killed mid-stream, union is every record with at most one repeat |
| `F2.WS.08` `aisme run` | **Done** — the child's own `/proc/self/cgroup` is the session's |
| `F2.WS.09` latency | **Not started.** T1, T2, T-tel and the Landlock deny cost |
| `F2.WS.10` slice on `MockSensor` | **Partial** — `vm run --with-dist` exists; the slice itself does not |
| `F2.WS.11` Landlock | **Not started.** Its pre-`exec` seam is the hook `F2.WS.05` already uses |

Gates at `83b1247`: `cargo test --workspace` **326 passed, 0 failed**;
`gate --level commit` **GATE PASSES** (7 PASS · 0 FAIL · 1 SKIP · 1 PENDING);
`doctor` 15 of 15. The pre-commit hook is **enabled** and has already refused a
commit.

---

## 2. Read these first

1. `CLAUDE.md`, then `docs/ai/AGENTS.md` — and note the read order now begins
   with **step 0, `cargo xtask doctor`**. The host is measured, not read: this
   machine was found at 5 of 15 while three documents said 15 of 15.
2. `docs/ai/STATE.md` — trust it over your assumptions.
3. `docs/09_challenge_ampliacion_f2_enforcement.md` — the enforcement thread,
   amplified and implemented. Its point 1 is a coherence review that found five
   defects before a line was written, and its point 6 is recorded and unfixed.
4. `docs/ai/memory/` — three files were added here and each cost a failed run:
   `seccomp-args-are-32-bit`, `yama-blocks-the-supervisor`,
   `llvm-config-is-suffixed`.

---

## 3. What is next, in order

1. **`F2.WS.11` — Landlock.** The smallest of the three and the seam exists:
   `crates/aisme-cli/src/run.rs`'s `pre_exec` already runs after the cgroup and
   before `exec`, which is where a ruleset must be applied to be inherited.
   `F0.VER.04` gates it.
2. **`F2.WS.10` — the whole slice on `MockSensor`.** The gate's fast path, and
   the thing that makes the rest testable in milliseconds.
3. **`F2.WS.09` — latency.** T1, T2 and T-tel at this shape.
4. **GATE F2**, which `docs/05` §12 already records cannot run as written
   without `vm run --with-dist` — which now exists.

---

## 4. Three limits that are measured, not guesses

**A filtered session can read and cannot write.** A classic BPF filter sees
syscall numbers and register values, never paths, so it traps *every* `openat`;
the kernel's only "permit unchanged" is `SECCOMP_USER_NOTIF_FLAG_CONTINUE`,
which `I-28` forbids for a path-bearing syscall. So an open the supervisor
cannot reproduce cannot be permitted either, and limit one of `Q-13` reproduces
`O_RDONLY` only. **This is why `aisme run --trap-openat` is opt-in.** Making it
the default would break every session. `F3.PT.02`'s kernel-side trie is what
will let the filter trap the escalate class alone.

**The supervisor cannot read the target's memory unless the session says so.**
Yama's default scope grants ptrace to an ancestor, and `agentd` is the session's
sibling. `aisme run` grants it with `PR_SET_PTRACER` to one pid, before the
irreversible filter goes in. The failure mode looks like success: a supervisor
that can decide nothing denies everything, which reads as fail-closed.

**The engine holds no enforcers.** The plan's §3.2 composition line shows
`Engine::new(sensors, enforcers, adjudicators, sink)`; the code takes sensors, a
sink and detectors, and the enforcers live on `agentd`'s control thread — which
`docs/05` §5.3 requires, because an engine owning them would put a human on the
T0 path. **The code is right and the plan's line is stale**; fixing it is owed.

---

## 5. Habits that paid, every one of them at least once

**Predict, then measure.** The publication's `[2, 0]`, the 272 tests, the guest
probe: each was written down first. The predictions that *fell* were worth more
than the ones that held — `GATE PASSES` fell and found a stripped host.

**Run it, do not read it.** Reading found nothing; running found a
`/dev/urandom` read that never returns, a unit test that moved the test harness
into a cgroup, an `exit 0` that truncated the harness's own output, a filler
byte that broke a protocol, and Yama.

**A guard nobody has seen fail is a guard nobody should trust.** Two `verify-docs`
checks were seen failing on the real files before the fix, and
`state_last_updated_is_recent` later refused a commit from the person who wrote
it.

**When a claim does not survive contact with the source, stop and say so.**
`docs/09` asked the owner a question the plan answers in §3.2. Recording that —
"grepping the code and reading the interface is not reading the design" — is
worth more than quietly deleting the question.
